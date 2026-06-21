"""Strict Pydantic (v2) data contracts for the masking / unmasking API.

Every field is validated for type, length and shape so that malformed or
oversized payloads are rejected at the edge, before they ever reach the
tokenizer engine.
"""

from __future__ import annotations

from enum import Enum
from typing import Dict

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Hard upper bound for any single inbound document. Large enough for real
# prompts, small enough to keep per-request memory and latency bounded.
MAX_TEXT_LENGTH = 100_000


class StrictnessLevel(str, Enum):
    """Controls how aggressively the engine scans for PII.

    * ``lenient``  – only unambiguous, high-confidence identifiers
      (email, credit card, IBAN, SSN).
    * ``standard`` – the lenient set plus phone numbers, IP addresses and URLs.
      This is the recommended default for most workloads.
    * ``strict``   – the standard set plus heuristic person-name and postal
      address detection. Higher recall, but may produce false positives.
    """

    LENIENT = "lenient"
    STANDARD = "standard"
    STRICT = "strict"


class MaskRequest(BaseModel):
    """Input payload for the ``/api/v1/mask`` endpoint."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "text": "Contact John Doe at john.doe@acme.com or +1 (415) 555-0132.",
                "strictness": "standard",
                "client_id": "support-bot-01",
                "session_id": "1c4f0b9e-7c3a-4a9e-9d2f-3a1b2c3d4e5f",
            }
        },
    )

    text: str = Field(
        ...,
        min_length=1,
        max_length=MAX_TEXT_LENGTH,
        description="Raw text to scan and sanitize. Scanned entirely on-device.",
    )
    strictness: StrictnessLevel = Field(
        default=StrictnessLevel.STANDARD,
        description="Cleansing aggressiveness level. Defaults to 'standard'.",
    )
    client_id: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Identifier of the calling client or system (for auditing).",
    )
    session_id: str | None = Field(
        default=None,
        max_length=128,
        description=(
            "Optional existing session id. Reuse the id returned by a previous "
            "mask call to keep tokens deterministic and to later unmask the "
            "downstream response. If omitted, a new session is created."
        ),
    )

    @field_validator("text")
    @classmethod
    def _text_not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("text must not be blank or whitespace only")
        return value

    @field_validator("client_id")
    @classmethod
    def _client_id_clean(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("client_id must not be blank")
        return cleaned


class MaskResponse(BaseModel):
    """Result of a successful mask operation."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "masked_text": (
                    "Contact [MASKED_PERSON_1] at [MASKED_EMAIL_1] "
                    "or [MASKED_PHONE_1]."
                ),
                "session_id": "1c4f0b9e-7c3a-4a9e-9d2f-3a1b2c3d4e5f",
                "detections": 3,
                "detections_by_type": {"PERSON": 1, "EMAIL": 1, "PHONE": 1},
                "latency_ms": 0.84,
            }
        }
    )

    masked_text: str = Field(
        ...,
        description="The sanitized text with every PII span replaced by a token.",
    )
    session_id: str = Field(
        ...,
        description=(
            "Session id holding the token <-> original mapping. Pass this to "
            "the unmask endpoint to restore the original values."
        ),
    )
    detections: int = Field(
        ...,
        ge=0,
        description="Total number of PII spans that were detected and replaced.",
    )
    detections_by_type: Dict[str, int] = Field(
        default_factory=dict,
        description="Per-category breakdown of detected items.",
    )
    latency_ms: float = Field(
        ...,
        ge=0,
        description="Server-side processing time in milliseconds.",
    )


class UnmaskRequest(BaseModel):
    """Input payload for the ``/api/v1/unmask`` endpoint."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "text": (
                    "Sure, I have emailed [MASKED_PERSON_1] at [MASKED_EMAIL_1]."
                ),
                "session_id": "1c4f0b9e-7c3a-4a9e-9d2f-3a1b2c3d4e5f",
                "client_id": "support-bot-01",
            }
        },
    )

    text: str = Field(
        ...,
        min_length=1,
        max_length=MAX_TEXT_LENGTH,
        description="Masked text (e.g. an LLM response) whose tokens to restore.",
    )
    session_id: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Session id returned by the corresponding mask call.",
    )
    client_id: str | None = Field(
        default=None,
        max_length=128,
        description="Optional identifier of the calling client (for auditing).",
    )

    @field_validator("session_id")
    @classmethod
    def _session_id_clean(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("session_id must not be blank")
        return cleaned


class UnmaskResponse(BaseModel):
    """Result of a successful unmask operation."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "unmasked_text": "Sure, I have emailed John Doe at john.doe@acme.com.",
                "restored": 2,
                "latency_ms": 0.12,
            }
        }
    )

    unmasked_text: str = Field(
        ...,
        description="Text with every known token mapped back to its original value.",
    )
    restored: int = Field(
        ...,
        ge=0,
        description="Number of token occurrences that were restored.",
    )
    latency_ms: float = Field(
        ...,
        ge=0,
        description="Server-side processing time in milliseconds.",
    )


class HealthResponse(BaseModel):
    """Liveness / readiness probe payload."""

    status: str = Field(..., description="Always 'ok' when the service is healthy.")
    version: str = Field(..., description="Running API version.")
    active_sessions: int = Field(
        ..., ge=0, description="Number of live token vaults currently held in memory."
    )
    uptime_seconds: float = Field(
        ..., ge=0, description="Seconds since the process started."
    )
