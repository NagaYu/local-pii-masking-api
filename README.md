# Local Secure Tokenizer & PII Masking API

[![CI](https://github.com/NagaYu/local-pii-masking-api/actions/workflows/ci.yml/badge.svg)](https://github.com/NagaYu/local-pii-masking-api/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

A **100% on-device, headless proxy API** that detects Personally Identifiable
Information (PII) in raw text and replaces it with deterministic, reversible
tokens — then restores the originals on the way back.

Drop it in front of any external LLM (or any third-party API) to build a hard
**security wall**: mask the outbound prompt, send only tokens to the cloud, then
unmask the model's reply locally. **Your sensitive data physically never leaves
the host.**

---

## Design Principles

| Principle | What it means |
| --- | --- |
| **100% Data Residency** | Detection and tokenization run entirely on the local CPU using regular expressions and lightweight validators. The service performs **zero outbound network calls** of its own. |
| **Zero-Knowledge Gateway Proxy** | The token ↔ original mapping lives only in process memory, scoped per session. Downstream systems (LLMs, logs, analytics) ever only see opaque tokens like `[MASKED_EMAIL_1]`. |
| **Zero External Infrastructure Cost** | No database, no message queue, no cloud service, no model download. A single container is the entire deployment. |
| **Deterministic & Reversible** | Within a session, the same value always yields the same token (keeping prompts coherent for an LLM), and every token maps back to its exact original substring. |
| **Bounded Memory** | Session vaults expire (TTL), the number of concurrent sessions is capped with LRU eviction, and each vault is size-capped — so sustained, high-volume document streams cannot leak memory. |

---

## What it detects

| Category | Token example | Notes |
| --- | --- | --- |
| Email addresses | `[MASKED_EMAIL_1]` | |
| Phone numbers | `[MASKED_PHONE_1]` | 7–15 digits, intl/US grouping |
| Credit card numbers | `[MASKED_CREDIT_CARD_1]` | Confirmed with the **Luhn** checksum |
| IBAN | `[MASKED_IBAN_1]` | |
| US SSN | `[MASKED_SSN_1]` | |
| IP addresses | `[MASKED_IP_ADDRESS_1]` | IPv4, octet-validated |
| URLs | `[MASKED_URL_1]` | |
| Person names | `[MASKED_PERSON_1]` | heuristic, **strict** level only |
| Postal addresses | `[MASKED_ADDRESS_1]` | heuristic, **strict** level only |

### Strictness levels

- **`lenient`** — unambiguous identifiers only (email, credit card, IBAN, SSN).
- **`standard`** *(default)* — lenient set **+** phone, IP address, URL.
- **`strict`** — standard set **+** heuristic person-name and address detection
  (highest recall, may produce false positives).

---

## Quick Start (3 minutes)

### Option A — Docker (recommended)

```bash
docker build -t local-pii-api .
docker run --rm -p 8080:8080 local-pii-api
```

### Option B — Local Python (3.10+)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8080
```

Then open the interactive, fully-English API docs:

- **Swagger UI:** http://127.0.0.1:8080/docs
- **Health check:** http://127.0.0.1:8080/health

Run the test suite:

```bash
pip install -r requirements-dev.txt
pytest -q
```

---

## API Reference

### `POST /api/v1/mask`

**Request**

```json
{
  "text": "Contact John Doe at john.doe@acme.com or +1 (415) 555-0132.",
  "strictness": "standard",
  "client_id": "support-bot-01",
  "session_id": null
}
```

**Response**

```json
{
  "masked_text": "Contact John Doe at [MASKED_EMAIL_1] or [MASKED_PHONE_1].",
  "session_id": "1c4f0b9e7c3a4a9e9d2f3a1b2c3d4e5f",
  "detections": 2,
  "detections_by_type": { "EMAIL": 1, "PHONE": 1 },
  "latency_ms": 0.19
}
```

> Save the returned `session_id`. Pass it back to keep tokens deterministic
> across calls and to unmask the downstream response later.

### `POST /api/v1/unmask`

**Request**

```json
{
  "text": "I've emailed [MASKED_EMAIL_1] and called [MASKED_PHONE_1].",
  "session_id": "1c4f0b9e7c3a4a9e9d2f3a1b2c3d4e5f"
}
```

**Response**

```json
{
  "unmasked_text": "I've emailed john.doe@acme.com and called +1 (415) 555-0132.",
  "restored": 2,
  "latency_ms": 0.02
}
```

Returns **404** if the session is unknown or has expired (originals are no
longer recoverable; re-mask the source text).

### `GET /health`

```json
{ "status": "ok", "version": "1.0.0", "active_sessions": 3, "uptime_seconds": 1287.4 }
```

---

## Using it as a security wall in front of a cloud LLM

The pattern is always the same three steps: **mask → call the cloud → unmask**.

```python
import requests

GATEWAY = "http://127.0.0.1:8080"

raw_prompt = (
    "Summarize this ticket from John Doe (john.doe@acme.com, "
    "+1 (415) 555-0132): the customer cannot log in."
)

# 1) MASK locally — strip PII before anything leaves the building.
m = requests.post(
    f"{GATEWAY}/api/v1/mask",
    json={"text": raw_prompt, "client_id": "ticket-summarizer"},
).json()

safe_prompt = m["masked_text"]   # contains only tokens, no PII
session_id = m["session_id"]

# 2) CALL THE CLOUD with the sanitized prompt only.
#    (replace this with your provider's SDK / HTTP call)
cloud_reply = call_your_favorite_cloud_llm(safe_prompt)
#   e.g. -> "I've drafted a reply to [MASKED_EMAIL_1] about the login issue."

# 3) UNMASK the response locally to restore the real values.
u = requests.post(
    f"{GATEWAY}/api/v1/unmask",
    json={"text": cloud_reply, "session_id": session_id},
).json()

print(u["unmasked_text"])
# -> "I've drafted a reply to john.doe@acme.com about the login issue."
```

```bash
# Same flow with curl:
curl -s -X POST http://127.0.0.1:8080/api/v1/mask \
  -H "Content-Type: application/json" \
  -d '{"text":"Email john.doe@acme.com","client_id":"cli"}'
```

---

## Configuration

All settings are environment variables with production-safe defaults:

| Variable | Default | Description |
| --- | --- | --- |
| `PORT` | `8080` | Listen port (container). |
| `PII_SESSION_TTL_SECONDS` | `3600` | Idle lifetime of a session vault before it is purged. |
| `PII_MAX_SESSIONS` | `10000` | Max concurrent vaults; oldest (LRU) evicted beyond this. |
| `PII_MAX_ENTRIES_PER_SESSION` | `50000` | Max distinct values stored per vault. |
| `PII_SWEEP_INTERVAL_SECONDS` | `60` | How often the background sweeper purges expired vaults. |

---

## Scope & Limitations

This project is an **open-source MVP / reference implementation**. It is
intentionally small and dependency-light. Know these boundaries before relying
on it:

- **Single-process state.** Session vaults live in the memory of one process.
  Run it with a **single worker** (the default). Running multiple Uvicorn/Gunicorn
  workers — or multiple replicas — will route `mask` and `unmask` to different
  processes and break restoration. Horizontal scaling would require a shared
  store (e.g. Redis); that is out of scope here.
- **English / US-centric detection.** Detectors target email, phone, credit
  card, IBAN, SSN, IP, URL, and (heuristically) English names and US-style
  addresses. They do **not** cover locale-specific identifiers such as Japanese
  My Number, Japanese phone/postal formats, or non-Latin names.
- **Regex-based, best-effort.** Detection trades completeness for speed and zero
  dependencies. Expect both false negatives and false positives, especially for
  the heuristic `strict`-level name/address detectors. This is defense in depth,
  **not** a compliance guarantee.
- **No built-in authentication or rate limiting.** Deploy it behind your own
  auth/gateway, and keep it on a trusted local/private network.

## Security Notes

- **No egress.** The service never initiates outbound connections. You can run
  it in an air-gapped network or with egress firewalled off entirely.
- **CORS is locked down** to loopback and RFC-1918 private ranges
  (`localhost`, `127.0.0.0/8`, `10/8`, `172.16/12`, `192.168/16`, `[::1]`).
  No public origin is ever allowed.
- **Memory-only mappings.** Token ↔ original mappings are never written to disk.
  Restart the process and all secrets are gone.
- **Defense in depth, not a silver bullet.** Heuristic detectors (names,
  addresses) trade precision for recall. Choose the strictness level that fits
  your risk tolerance, and keep this gateway behind your own authentication.

---

## Architecture

```
            ┌─────────────────────────── your host / private LAN ───────────────────────────┐
            │                                                                                │
 raw text ──┼──► POST /api/v1/mask ──► engine.py (regex + Luhn, 100% local)                  │
            │                              │                                                 │
            │                              ▼                                                 │
            │                       in-memory session vault (TTL + LRU bounded)              │
            │                              │                                                 │
 tokens  ◄──┼──────────────────────────────┘                                                 │
            │       │                                                                        │
            │       └──► (you send tokens to any external LLM — no PII crosses the boundary) │
            │                                                                                │
 LLM reply ─┼──► POST /api/v1/unmask ──► restore via vault ──► original values returned      │
            │                                                                                │
            └────────────────────────────────────────────────────────────────────────────────┘
```

| File | Responsibility |
| --- | --- |
| `app/schemas.py` | Strict Pydantic v2 request/response contracts and validation. |
| `app/engine.py` | On-device PII detectors, deterministic tokenizer, bounded vault store. |
| `app/main.py` | FastAPI app: CORS lockdown, `/health`, `/mask`, `/unmask`, OpenAPI docs. |
| `tests/test_api.py` | Unit + HTTP integration tests (detection, round-trip, memory bounds). |
| `Dockerfile` | Multi-stage, non-root, health-checked production image. |

---

## License

Released under the [MIT License](LICENSE).
