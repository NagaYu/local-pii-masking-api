"""FastAPI entrypoint for the Local Secure Tokenizer & PII Masking API.

A pure, headless REST service. It exposes:

* ``GET  /health``        – liveness / readiness probe.
* ``POST /api/v1/mask``   – sanitize raw text into tokenized, safe text.
* ``POST /api/v1/unmask`` – restore tokenized text back to its originals.

CORS is locked down to loopback and RFC-1918 private networks so the gateway
can only be reached from the host or the local/private network it runs on.
"""

from __future__ import annotations

import logging
import os
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware

from . import __version__
from .engine import TokenizerEngine, VaultStore
from .schemas import (
    HealthResponse,
    MaskRequest,
    MaskResponse,
    UnmaskRequest,
    UnmaskResponse,
)

# --------------------------------------------------------------------------- #
# Configuration (environment-overridable, sane production defaults)
# --------------------------------------------------------------------------- #

_SESSION_TTL_SECONDS = float(os.getenv("PII_SESSION_TTL_SECONDS", "3600"))
_MAX_SESSIONS = int(os.getenv("PII_MAX_SESSIONS", "10000"))
_MAX_ENTRIES_PER_SESSION = int(os.getenv("PII_MAX_ENTRIES_PER_SESSION", "50000"))
_SWEEP_INTERVAL_SECONDS = float(os.getenv("PII_SWEEP_INTERVAL_SECONDS", "60"))

# Loopback + RFC-1918 private ranges only. No public origins are ever allowed.
_PRIVATE_ORIGIN_REGEX = (
    r"^https?://("
    r"localhost"
    r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|\[::1\]"
    r")(:\d{1,5})?$"
)

# Audit logger. Records request metadata only (client id, session id, counts,
# latency) — never the raw text or any detected PII value.
_audit_log = logging.getLogger("pii_gateway.audit")

_START_TIME = time.monotonic()

# Single shared engine + bounded vault store for the process lifetime.
_store = VaultStore(
    ttl_seconds=_SESSION_TTL_SECONDS,
    max_sessions=_MAX_SESSIONS,
    max_entries_per_session=_MAX_ENTRIES_PER_SESSION,
    sweep_interval_seconds=_SWEEP_INTERVAL_SECONDS,
)
_engine = TokenizerEngine(store=_store)


def _configure_audit_logging() -> None:
    """Route audit records through Uvicorn's handlers (or a basic fallback)."""
    if _audit_log.handlers:
        return
    uvicorn_logger = logging.getLogger("uvicorn")
    if uvicorn_logger.handlers:
        for handler in uvicorn_logger.handlers:
            _audit_log.addHandler(handler)
    else:
        # Standalone (e.g. imported without Uvicorn): emit to stderr.
        logging.basicConfig(level=logging.INFO)
    _audit_log.setLevel(logging.INFO)
    _audit_log.propagate = False


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Start the background vault sweeper on boot, stop it on shutdown."""
    _configure_audit_logging()
    _store.start()
    try:
        yield
    finally:
        _store.stop()


app = FastAPI(
    title="Local Secure Tokenizer & PII Masking API",
    version=__version__,
    summary="A 100% on-device, zero-egress PII masking and de-masking gateway.",
    description=(
        "Detects Personally Identifiable Information (PII) in raw text entirely "
        "on the local device and replaces it with deterministic, reversible "
        "tokens such as `[MASKED_EMAIL_1]`. Use it as a security wall in front "
        "of any external LLM: mask outbound prompts, then unmask the model's "
        "reply. No data ever leaves the host."
    ),
    lifespan=lifespan,
    contact={"name": "Local Secure Tokenizer"},
    license_info={"name": "MIT"},
)

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=_PRIVATE_ORIGIN_REGEX,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["system"],
    summary="Health check",
)
async def health() -> HealthResponse:
    """Report service liveness.

    Returns the running version, the number of live token vaults currently held
    in memory, and the process uptime. Suitable for container and load-balancer
    health probes.
    """
    return HealthResponse(
        status="ok",
        version=__version__,
        active_sessions=_store.active_sessions(),
        uptime_seconds=round(time.monotonic() - _START_TIME, 3),
    )


@app.post(
    "/api/v1/mask",
    response_model=MaskResponse,
    tags=["tokenizer"],
    summary="Mask PII in raw text",
)
async def mask(request: MaskRequest) -> MaskResponse:
    """Scan raw text on-device and replace every PII span with a safe token.

    The scan runs fully locally using regular expressions and lightweight
    validators (for example, credit card numbers are confirmed with the Luhn
    algorithm). Detected values are stored in a per-session, in-memory vault so
    that:

    * the same value always maps to the same token within a session
      (deterministic, keeping the masked prompt coherent for an LLM), and
    * the values can later be restored via `/api/v1/unmask`.

    Pass the returned `session_id` to subsequent calls to reuse the same
    mapping. Omit `session_id` to start a fresh session.
    """
    started = time.perf_counter()
    result = _engine.mask(
        text=request.text,
        strictness=request.strictness,
        session_id=request.session_id,
    )
    latency_ms = (time.perf_counter() - started) * 1000.0

    _audit_log.info(
        "mask client_id=%s session_id=%s detections=%d strictness=%s latency_ms=%.3f",
        request.client_id,
        result.session_id,
        result.detections,
        request.strictness.value,
        latency_ms,
    )

    return MaskResponse(
        masked_text=result.masked_text,
        session_id=result.session_id,
        detections=result.detections,
        detections_by_type=result.detections_by_type,
        latency_ms=round(latency_ms, 3),
    )


@app.post(
    "/api/v1/unmask",
    response_model=UnmaskResponse,
    tags=["tokenizer"],
    summary="Restore tokens back to original PII",
)
async def unmask(request: UnmaskRequest) -> UnmaskResponse:
    """Restore a masked text (e.g. an LLM response) to its original values.

    Every token that exists in the referenced session's vault is mapped back to
    the exact original substring it replaced. Unknown tokens are left untouched.

    Returns HTTP 404 if the session is unknown or has expired, in which case the
    original values are no longer recoverable and the text must be re-masked.
    """
    started = time.perf_counter()
    try:
        result = _engine.unmask(text=request.text, session_id=request.session_id)
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"Session '{request.session_id}' is unknown or has expired; "
                "original values are no longer recoverable."
            ),
        )
    latency_ms = (time.perf_counter() - started) * 1000.0

    _audit_log.info(
        "unmask client_id=%s session_id=%s restored=%d latency_ms=%.3f",
        request.client_id,
        request.session_id,
        result.restored,
        latency_ms,
    )

    return UnmaskResponse(
        unmasked_text=result.unmasked_text,
        restored=result.restored,
        latency_ms=round(latency_ms, 3),
    )
