"""100% on-device PII detection and deterministic tokenizer core.

Design goals
------------
* **Zero egress**   – the engine performs no network I/O of any kind. All
  detection is done with local regular expressions and lightweight validators.
* **Deterministic** – within a session, the same source value always maps to
  the same token, so masked prompts stay coherent for a downstream LLM.
* **Reversible**    – every token can be mapped back to its exact original
  substring via a per-session, in-memory vault.
* **Bounded memory** – vaults expire (TTL), the number of concurrent sessions
  is capped with LRU eviction, and per-session entries are capped. A background
  sweeper plus lazy sweeps guarantee there is no unbounded growth even under a
  sustained stream of documents.
"""

from __future__ import annotations

import re
import threading
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Pattern, Tuple

from .schemas import StrictnessLevel

# --------------------------------------------------------------------------- #
# Validators
# --------------------------------------------------------------------------- #


def _luhn_valid(digits: str) -> bool:
    """Return True if ``digits`` (already stripped to 0-9) passes the Luhn check."""
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    parity = len(digits) % 2
    for index, char in enumerate(digits):
        value = ord(char) - 48  # fast int()
        if index % 2 == parity:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def _validate_credit_card(match: str) -> bool:
    digits = re.sub(r"[^0-9]", "", match)
    return _luhn_valid(digits)


def _validate_phone(match: str) -> bool:
    digits = re.sub(r"[^0-9]", "", match)
    # Reject things that are too short/long to be a phone number, and reject
    # repdigit noise like "0000000".
    if not 7 <= len(digits) <= 15:
        return False
    return len(set(digits)) > 1


# --------------------------------------------------------------------------- #
# Detector definitions
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Detector:
    """A single named PII pattern.

    ``priority`` resolves overlaps: lower wins (e.g. a credit-card span beats a
    phone-number span covering the same digits).
    """

    name: str  # category label used in tokens, e.g. "EMAIL"
    pattern: Pattern[str]
    priority: int
    validator: Optional[Callable[[str], bool]] = None


# Order here is documentation only; resolution uses ``priority``.
_DETECTORS: Tuple[Detector, ...] = (
    Detector(
        name="CREDIT_CARD",
        pattern=re.compile(r"(?<![\d-])(?:\d[ -]?){13,19}(?![\d-])"),
        priority=0,
        validator=_validate_credit_card,
    ),
    Detector(
        name="IBAN",
        pattern=re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
        priority=1,
    ),
    Detector(
        name="SSN",
        pattern=re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        priority=2,
    ),
    Detector(
        name="EMAIL",
        pattern=re.compile(
            r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
        ),
        priority=3,
    ),
    Detector(
        name="IP_ADDRESS",
        pattern=re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
        ),
        priority=4,
    ),
    Detector(
        name="URL",
        pattern=re.compile(r"\bhttps?://[^\s<>\"'()]+", re.IGNORECASE),
        priority=5,
    ),
    Detector(
        name="PHONE",
        pattern=re.compile(
            r"(?<![\w])"
            r"(?:\+\d{1,3}[\s.\-]?)?"          # optional country code
            r"(?:\(\d{1,4}\)[\s.\-]?)?"        # optional area code in parens
            r"\d{2,4}(?:[\s.\-]\d{2,4}){1,4}"  # grouped digits
            r"(?![\w])"
        ),
        priority=6,
        validator=_validate_phone,
    ),
    # --- strict-only heuristics ------------------------------------------- #
    Detector(
        name="ADDRESS",
        pattern=re.compile(
            r"\b\d{1,6}\s+(?:[A-Z][A-Za-z]+\.?\s){1,4}"
            r"(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|"
            r"Drive|Dr|Court|Ct|Way|Place|Pl|Terrace|Ter|Square|Sq)\b\.?",
            re.IGNORECASE,
        ),
        priority=7,
    ),
    Detector(
        name="PERSON",
        pattern=re.compile(
            r"\b(?:Mr|Mrs|Ms|Miss|Dr|Prof)\.?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2}"
            r"|\b[A-Z][a-z]+\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b"
        ),
        priority=8,
    ),
)

_DETECTORS_BY_NAME: Dict[str, Detector] = {d.name: d for d in _DETECTORS}

# Which detectors are active at each strictness level.
_LEVEL_DETECTORS: Dict[StrictnessLevel, Tuple[str, ...]] = {
    StrictnessLevel.LENIENT: ("CREDIT_CARD", "IBAN", "SSN", "EMAIL"),
    StrictnessLevel.STANDARD: (
        "CREDIT_CARD",
        "IBAN",
        "SSN",
        "EMAIL",
        "IP_ADDRESS",
        "URL",
        "PHONE",
    ),
    StrictnessLevel.STRICT: tuple(d.name for d in _DETECTORS),
}


# --------------------------------------------------------------------------- #
# Session vault + store
# --------------------------------------------------------------------------- #


@dataclass
class SessionVault:
    """Holds the reversible token mapping for a single session."""

    session_id: str
    created_at: float = field(default_factory=time.monotonic)
    last_accessed: float = field(default_factory=time.monotonic)
    # original substring -> token
    forward: Dict[str, str] = field(default_factory=dict)
    # token -> original substring
    reverse: Dict[str, str] = field(default_factory=dict)
    # category -> next counter value
    counters: Dict[str, int] = field(default_factory=dict)

    def touch(self) -> None:
        self.last_accessed = time.monotonic()

    def token_for(self, category: str, original: str, max_entries: int) -> str:
        """Return a deterministic token for ``original`` within this vault."""
        existing = self.forward.get(original)
        if existing is not None:
            return existing
        if len(self.forward) >= max_entries:
            # Soft cap reached: do not grow this vault any further. The caller
            # leaves the raw value in place rather than risk unbounded memory.
            raise VaultCapacityError(self.session_id)
        index = self.counters.get(category, 0) + 1
        self.counters[category] = index
        token = f"[MASKED_{category}_{index}]"
        self.forward[original] = token
        self.reverse[token] = original
        return token


class VaultCapacityError(RuntimeError):
    """Raised when a single session vault hits its per-session entry cap."""

    def __init__(self, session_id: str) -> None:
        super().__init__(f"session '{session_id}' reached its entry cap")
        self.session_id = session_id


class VaultStore:
    """Thread-safe, memory-bounded store of session vaults.

    Bounding strategy (all enforced together):

    * **TTL**          – a vault untouched for ``ttl_seconds`` is purged.
    * **Max sessions** – when the cap is reached, the least-recently-used vault
      is evicted (``OrderedDict`` as an LRU).
    * **Per-session cap** – a single vault cannot hold more than
      ``max_entries_per_session`` distinct values.

    A daemon sweeper thread purges expired vaults periodically; every mutating
    call also triggers a cheap lazy sweep.
    """

    def __init__(
        self,
        ttl_seconds: float = 3600.0,
        max_sessions: int = 10_000,
        max_entries_per_session: int = 50_000,
        sweep_interval_seconds: float = 60.0,
    ) -> None:
        self._ttl = ttl_seconds
        self._max_sessions = max_sessions
        self._max_entries = max_entries_per_session
        self._sweep_interval = sweep_interval_seconds
        self._vaults: "OrderedDict[str, SessionVault]" = OrderedDict()
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._sweeper: Optional[threading.Thread] = None

    # -- lifecycle --------------------------------------------------------- #

    def start(self) -> None:
        """Start the background sweeper thread (idempotent)."""
        with self._lock:
            if self._sweeper and self._sweeper.is_alive():
                return
            self._stop.clear()
            self._sweeper = threading.Thread(
                target=self._sweep_loop, name="vault-sweeper", daemon=True
            )
            self._sweeper.start()

    def stop(self) -> None:
        """Signal the sweeper to stop and wait briefly for it to exit."""
        self._stop.set()
        sweeper = self._sweeper
        if sweeper and sweeper.is_alive():
            sweeper.join(timeout=5.0)

    def _sweep_loop(self) -> None:
        while not self._stop.wait(self._sweep_interval):
            self.sweep()

    # -- core operations --------------------------------------------------- #

    @property
    def max_entries_per_session(self) -> int:
        return self._max_entries

    def get_or_create(self, session_id: Optional[str]) -> SessionVault:
        """Fetch an existing, unexpired vault or create a fresh one."""
        with self._lock:
            self._sweep_locked()
            if session_id:
                vault = self._vaults.get(session_id)
                if vault is not None and not self._is_expired(vault):
                    vault.touch()
                    self._vaults.move_to_end(session_id)
                    return vault
                # Honor a caller-supplied id even if it had expired / is new.
                new_id = session_id
            else:
                new_id = uuid.uuid4().hex

            vault = SessionVault(session_id=new_id)
            self._vaults[new_id] = vault
            self._vaults.move_to_end(new_id)
            self._evict_if_needed_locked()
            return vault

    def get(self, session_id: str) -> Optional[SessionVault]:
        """Return an existing, unexpired vault, or None."""
        with self._lock:
            self._sweep_locked()
            vault = self._vaults.get(session_id)
            if vault is None or self._is_expired(vault):
                return None
            vault.touch()
            self._vaults.move_to_end(session_id)
            return vault

    def sweep(self) -> int:
        """Purge expired vaults. Returns the number removed."""
        with self._lock:
            return self._sweep_locked()

    def active_sessions(self) -> int:
        with self._lock:
            self._sweep_locked()
            return len(self._vaults)

    def clear(self) -> None:
        with self._lock:
            self._vaults.clear()

    # -- internals --------------------------------------------------------- #

    def _is_expired(self, vault: SessionVault) -> bool:
        return (time.monotonic() - vault.last_accessed) > self._ttl

    def _sweep_locked(self) -> int:
        expired = [
            sid for sid, vault in self._vaults.items() if self._is_expired(vault)
        ]
        for sid in expired:
            del self._vaults[sid]
        return len(expired)

    def _evict_if_needed_locked(self) -> None:
        while len(self._vaults) > self._max_sessions:
            # popitem(last=False) removes the least-recently-used entry.
            self._vaults.popitem(last=False)


# --------------------------------------------------------------------------- #
# Tokenizer engine
# --------------------------------------------------------------------------- #


@dataclass
class MaskResult:
    masked_text: str
    session_id: str
    detections: int
    detections_by_type: Dict[str, int]


@dataclass
class UnmaskResult:
    unmasked_text: str
    restored: int


# Matches any token this engine can emit, used for fast reverse replacement.
_TOKEN_RE = re.compile(r"\[MASKED_[A-Z_]+_\d+\]")


class TokenizerEngine:
    """Stateless detector wired to a memory-bounded :class:`VaultStore`."""

    def __init__(self, store: Optional[VaultStore] = None) -> None:
        self.store = store or VaultStore()

    # -- masking ----------------------------------------------------------- #

    def mask(
        self,
        text: str,
        strictness: StrictnessLevel = StrictnessLevel.STANDARD,
        session_id: Optional[str] = None,
    ) -> MaskResult:
        """Detect PII in ``text`` and replace each span with a token."""
        vault = self.store.get_or_create(session_id)
        spans = self._detect(text, strictness)

        if not spans:
            return MaskResult(
                masked_text=text,
                session_id=vault.session_id,
                detections=0,
                detections_by_type={},
            )

        out: List[str] = []
        cursor = 0
        counts: Dict[str, int] = {}
        detections = 0
        max_entries = self.store.max_entries_per_session

        for start, end, category in spans:
            original = text[start:end]
            try:
                token = vault.token_for(category, original, max_entries)
            except VaultCapacityError:
                # Vault is full: skip masking this span rather than grow memory.
                continue
            out.append(text[cursor:start])
            out.append(token)
            cursor = end
            counts[category] = counts.get(category, 0) + 1
            detections += 1

        out.append(text[cursor:])

        return MaskResult(
            masked_text="".join(out),
            session_id=vault.session_id,
            detections=detections,
            detections_by_type=counts,
        )

    def _detect(
        self, text: str, strictness: StrictnessLevel
    ) -> List[Tuple[int, int, str]]:
        """Return non-overlapping (start, end, category) spans, ordered by start."""
        active = _LEVEL_DETECTORS[strictness]
        candidates: List[Tuple[int, int, int, str]] = []  # (priority, start, end, cat)

        for name in active:
            detector = _DETECTORS_BY_NAME[name]
            for match in detector.pattern.finditer(text):
                value = match.group(0)
                if detector.validator and not detector.validator(value):
                    continue
                start, end = match.start(), match.end()
                if start == end:
                    continue
                candidates.append((detector.priority, start, end, detector.name))

        # Resolve overlaps: highest priority (lowest number) first, then the
        # longest span, then earliest start. Greedily accept non-overlapping.
        candidates.sort(key=lambda c: (c[0], -(c[2] - c[1]), c[1]))

        accepted: List[Tuple[int, int, str]] = []
        occupied: List[Tuple[int, int]] = []
        for _priority, start, end, category in candidates:
            if any(start < o_end and end > o_start for o_start, o_end in occupied):
                continue
            accepted.append((start, end, category))
            occupied.append((start, end))

        accepted.sort(key=lambda s: s[0])
        return accepted

    # -- unmasking --------------------------------------------------------- #

    def unmask(self, text: str, session_id: str) -> UnmaskResult:
        """Map every known token in ``text`` back to its original value.

        Raises :class:`KeyError` if the session is unknown or expired.
        """
        vault = self.store.get(session_id)
        if vault is None:
            raise KeyError(session_id)

        reverse = vault.reverse
        restored = 0

        def _replace(match: "re.Match[str]") -> str:
            nonlocal restored
            token = match.group(0)
            original = reverse.get(token)
            if original is None:
                return token  # unknown token: leave untouched
            restored += 1
            return original

        unmasked = _TOKEN_RE.sub(_replace, text)
        return UnmaskResult(unmasked_text=unmasked, restored=restored)
