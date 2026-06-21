"""End-to-end and unit tests for the masking gateway."""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from app.engine import TokenizerEngine, VaultStore
from app.main import app
from app.schemas import StrictnessLevel


@pytest.fixture()
def client() -> TestClient:
    with TestClient(app) as test_client:
        yield test_client


# --------------------------------------------------------------------------- #
# Engine unit tests
# --------------------------------------------------------------------------- #


def test_email_and_phone_detection():
    engine = TokenizerEngine()
    text = "Reach me at jane.doe@example.com or +1 (415) 555-0132 today."
    result = engine.mask(text, StrictnessLevel.STANDARD)
    assert "jane.doe@example.com" not in result.masked_text
    assert "[MASKED_EMAIL_1]" in result.masked_text
    assert "[MASKED_PHONE_1]" in result.masked_text
    assert result.detections == 2


def test_credit_card_luhn_valid_vs_invalid():
    engine = TokenizerEngine()
    # 4111 1111 1111 1111 is a well-known Luhn-valid test number.
    valid = engine.mask("Card 4111 1111 1111 1111 expires soon.")
    assert "[MASKED_CREDIT_CARD_1]" in valid.masked_text
    # Flip a digit -> Luhn fails -> must NOT be masked as a credit card.
    invalid = engine.mask("Card 4111 1111 1111 1112 expires soon.")
    assert "CREDIT_CARD" not in invalid.masked_text


def test_deterministic_tokens_within_session():
    engine = TokenizerEngine()
    text = "a@x.com and again a@x.com and b@x.com"
    result = engine.mask(text)
    # same value -> same token; different value -> different token
    assert result.masked_text.count("[MASKED_EMAIL_1]") == 2
    assert "[MASKED_EMAIL_2]" in result.masked_text
    assert result.detections == 3


def test_mask_then_unmask_roundtrip():
    engine = TokenizerEngine()
    original = "Contact john@acme.com at 10.0.0.5 now."
    masked = engine.mask(original, StrictnessLevel.STANDARD)
    restored = engine.unmask(masked.masked_text, masked.session_id)
    assert restored.unmasked_text == original
    assert restored.restored == 2


def test_unmask_unknown_session_raises():
    engine = TokenizerEngine()
    with pytest.raises(KeyError):
        engine.unmask("[MASKED_EMAIL_1]", "does-not-exist")


def test_overlap_credit_card_beats_phone():
    engine = TokenizerEngine()
    # A Luhn-valid 16-digit number should be classified as a card, not a phone.
    result = engine.mask("Pay with 4111111111111111 please.")
    assert "[MASKED_CREDIT_CARD_1]" in result.masked_text
    assert "PHONE" not in result.masked_text


def test_strictness_levels_change_recall():
    engine = TokenizerEngine()
    text = "John Smith lives at 123 Main Street."
    lenient = engine.mask(text, StrictnessLevel.LENIENT)
    strict = engine.mask(text, StrictnessLevel.STRICT)
    assert lenient.detections == 0
    assert strict.detections >= 1  # person and/or address picked up


# --------------------------------------------------------------------------- #
# Vault store / memory-bounding tests
# --------------------------------------------------------------------------- #


def test_vault_ttl_expiry():
    store = VaultStore(ttl_seconds=0.05, sweep_interval_seconds=100)
    vault = store.get_or_create(None)
    sid = vault.session_id
    assert store.get(sid) is not None
    time.sleep(0.1)
    assert store.get(sid) is None


def test_vault_lru_eviction():
    store = VaultStore(max_sessions=3, ttl_seconds=1000, sweep_interval_seconds=100)
    ids = [store.get_or_create(None).session_id for _ in range(3)]
    # Touch the first so it is most-recently-used.
    store.get(ids[0])
    # Adding a 4th should evict the LRU (ids[1]), not ids[0].
    store.get_or_create(None)
    assert store.get(ids[0]) is not None
    assert store.get(ids[1]) is None


def test_per_session_entry_cap_does_not_grow():
    store = VaultStore(max_entries_per_session=2, ttl_seconds=1000)
    engine = TokenizerEngine(store=store)
    text = "a@x.com b@x.com c@x.com"
    result = engine.mask(text)
    # Only the first two distinct values fit; the third stays raw.
    assert result.detections == 2
    assert "c@x.com" in result.masked_text


# --------------------------------------------------------------------------- #
# HTTP API tests
# --------------------------------------------------------------------------- #


def test_health_endpoint(client: TestClient):
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert "version" in body


def test_mask_endpoint_validation(client: TestClient):
    # Missing required client_id -> 422
    resp = client.post("/api/v1/mask", json={"text": "hello"})
    assert resp.status_code == 422
    # Blank text -> 422
    resp = client.post(
        "/api/v1/mask", json={"text": "   ", "client_id": "c1"}
    )
    assert resp.status_code == 422
    # Unknown extra field -> 422 (extra="forbid")
    resp = client.post(
        "/api/v1/mask",
        json={"text": "hi", "client_id": "c1", "bogus": 1},
    )
    assert resp.status_code == 422


def test_mask_unmask_http_roundtrip(client: TestClient):
    payload = {
        "text": "Email jane@acme.com, phone +1 (212) 555-7788.",
        "client_id": "support-bot",
        "strictness": "standard",
    }
    mask_resp = client.post("/api/v1/mask", json=payload)
    assert mask_resp.status_code == 200
    masked = mask_resp.json()
    assert masked["detections"] == 2
    assert "jane@acme.com" not in masked["masked_text"]

    unmask_resp = client.post(
        "/api/v1/unmask",
        json={
            "text": masked["masked_text"],
            "session_id": masked["session_id"],
            "client_id": "support-bot",
        },
    )
    assert unmask_resp.status_code == 200
    assert unmask_resp.json()["unmasked_text"] == payload["text"]


def test_unmask_unknown_session_http_404(client: TestClient):
    resp = client.post(
        "/api/v1/unmask",
        json={"text": "[MASKED_EMAIL_1]", "session_id": "nope"},
    )
    assert resp.status_code == 404
