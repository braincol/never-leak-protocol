"""NL Protocol wire-protocol message models and helpers.

This module provides:

* **MessageEnvelope** -- the standard message wrapper defined in
  Chapter 08, Section 3.3.
* **Error response models** -- structured error payloads per Section 6.2.
* **Parsing / serialisation** helpers for NDJSON and HTTP transports.
* **Version negotiation** -- comparison of client-requested and
  server-supported versions.
* **Content-Type validation** -- enforcement of the ``application/
  nl-protocol+json`` media type.

All helpers are *synchronous* and side-effect-free; they can be used
inside both sync and async code paths.
"""
from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from nl_protocol.core.errors import (
    InvalidTimestamp,
    MalformedMessage,
    NLProtocolError,
    UnknownMessageType,
    UnsupportedMediaType,
    VersionMismatch,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NL_PROTOCOL_VERSION: str = "1.0"
"""Current NL Protocol version supported by this implementation."""

NL_CONTENT_TYPE: str = "application/nl-protocol+json"
"""Canonical Content-Type for NL Protocol messages (Section 3.2)."""

NL_CONTENT_TYPE_COMPAT: str = "application/json"
"""Backward-compatible Content-Type accepted by NL Protocol servers."""

VALID_MESSAGE_TYPES: frozenset[str] = frozenset(
    {
        # Identity & registration (Chapter 01)
        "handshake",
        "handshake_ack",
        "agent_register",
        "agent_register_ack",
        "agent_get",
        "agent_get_response",
        # Action lifecycle (Chapters 02, 03, 04)
        "action_request",
        "action_response",
        # Delegation & revocation (Chapter 07)
        "delegation_request",
        "delegation_response",
        "delegation_revoke",
        "delegation_revoke_ack",
        "revocation_request",
        "revocation_response",
        # Audit (Chapter 05)
        "audit_query",
        "audit_query_response",
        # Discovery & operational (Chapter 08)
        "discovery_request",
        "discovery_response",
        "error",
        "rotation_notification",
        # Federation (Chapter 07)
        "federated_action",
        "federated_response",
        "federation_revocation",
        "federation_revocation_ack",
    }
)


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class MessageEnvelope(BaseModel):
    """Standard NL Protocol message envelope (Section 3.3).

    Every message -- regardless of transport -- is wrapped in this
    structure.  The ``payload`` field carries the message-type-specific
    data and is intentionally typed as ``dict[str, Any]`` so that the
    envelope can be parsed *before* the payload is interpreted.
    """

    model_config = ConfigDict(strict=True, populate_by_name=True)

    nl_version: str = NL_PROTOCOL_VERSION
    message_type: str
    message_id: str = Field(default_factory=lambda: f"msg_{uuid.uuid4()}")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
    )
    payload: dict[str, Any] = Field(default_factory=dict)


class ErrorPayload(BaseModel):
    """Machine-readable error object (Section 6.2)."""

    model_config = ConfigDict(strict=True)

    code: str = Field(description="NL Protocol error code (NL-EXXX).")
    message: str
    detail: dict[str, Any] = Field(default_factory=dict)
    resolution: str = ""
    doc_url: str = ""


class ErrorResponse(BaseModel):
    """Top-level error response wrapper."""

    model_config = ConfigDict(strict=True)

    error: ErrorPayload


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------

def serialize_message(envelope: MessageEnvelope) -> str:
    """Serialise a :class:`MessageEnvelope` to a compact JSON string.

    The output is suitable for both HTTP response bodies and NDJSON
    lines (no embedded newlines).
    """
    return envelope.model_dump_json(by_alias=True)


def parse_message(raw: str | bytes) -> MessageEnvelope:
    """Parse raw JSON into a :class:`MessageEnvelope`.

    Validates the envelope structure but does **not** interpret the
    ``payload`` -- that is the responsibility of the handler for the
    specific ``message_type``.

    Raises
    ------
    MalformedMessage
        If the input is not valid JSON or fails envelope validation.
    UnknownMessageType
        If ``message_type`` is not in :data:`VALID_MESSAGE_TYPES`.
    """
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")

    # Strip NDJSON framing whitespace
    raw = raw.strip()
    if not raw:
        raise MalformedMessage("Empty message")

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise MalformedMessage(f"Invalid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise MalformedMessage("Message must be a JSON object")

    # Check required envelope fields
    for field in ("nl_version", "message_type", "message_id", "timestamp"):
        if field not in data:
            raise MalformedMessage(
                f"Missing required envelope field: {field}"
            )

    # Validate message_type
    msg_type = data.get("message_type")
    if msg_type not in VALID_MESSAGE_TYPES:
        raise UnknownMessageType(
            f"Unknown message type: {msg_type!r}",
            details={"message_type": msg_type},
        )

    try:
        # Use model_validate_json for correct strict-mode handling of
        # ISO 8601 timestamp strings coming from JSON payloads.
        envelope = MessageEnvelope.model_validate_json(raw)
    except ValidationError as exc:
        raise MalformedMessage(
            f"Envelope validation failed: {exc}"
        ) from exc

    return envelope


# ---------------------------------------------------------------------------
# Error response formatting
# ---------------------------------------------------------------------------

def format_error_response(error: NLProtocolError) -> MessageEnvelope:
    """Wrap an :class:`NLProtocolError` in a wire-protocol error envelope.

    Returns a :class:`MessageEnvelope` with ``message_type="error"`` and
    the structured error payload in ``payload.error``.
    """
    payload = ErrorPayload(
        code=error.code,
        message=error.message,
        detail=error.details,
        resolution=error.resolution,
        doc_url=f"https://nlprotocol.org/docs/errors/{error.code}",
    )
    return MessageEnvelope(
        nl_version=NL_PROTOCOL_VERSION,
        message_type="error",
        payload={"error": payload.model_dump()},
    )


def format_error_dict(error: NLProtocolError) -> dict[str, Any]:
    """Return the RFC 7807-style error dict for an HTTP response body.

    This is the compact form used in action responses and standalone
    error messages.
    """
    return error.to_dict()


# ---------------------------------------------------------------------------
# Version negotiation
# ---------------------------------------------------------------------------

_SUPPORTED_VERSIONS: frozenset[str] = frozenset({"1.0"})


def negotiate_version(
    requested: str,
    *,
    supported: frozenset[str] | None = None,
) -> str:
    """Validate and return the negotiated protocol version.

    Parameters
    ----------
    requested:
        The ``nl_version`` value from the incoming message.
    supported:
        Set of versions this server supports.  Defaults to the
        implementation's built-in set.

    Returns
    -------
    str
        The negotiated version string (currently always ``"1.0"``).

    Raises
    ------
    VersionMismatch
        If *requested* is not in *supported*.
    """
    versions = supported or _SUPPORTED_VERSIONS
    if requested not in versions:
        raise VersionMismatch(
            f"Unsupported NL Protocol version: {requested!r}",
            details={"requested": requested, "supported_versions": sorted(versions)},
        )
    return requested


# ---------------------------------------------------------------------------
# Content-Type validation
# ---------------------------------------------------------------------------

def validate_content_type(content_type: str) -> Literal["nl", "json"]:
    """Validate the ``Content-Type`` header of an incoming request.

    Returns
    -------
    ``"nl"``
        If the content type is ``application/nl-protocol+json``.
    ``"json"``
        If the content type is ``application/json`` (backward-compat).

    Raises
    ------
    UnsupportedMediaType
        If the content type is neither of the accepted values.
    """
    # Normalise: strip parameters (charset, etc.) and lowercase
    base = content_type.split(";")[0].strip().lower()

    if base == NL_CONTENT_TYPE:
        return "nl"
    if base == NL_CONTENT_TYPE_COMPAT:
        return "json"

    raise UnsupportedMediaType(
        f"Unsupported Content-Type: {content_type!r}",
        details={"received": content_type, "accepted": [NL_CONTENT_TYPE, NL_CONTENT_TYPE_COMPAT]},
    )


# ---------------------------------------------------------------------------
# Timestamp validation helper
# ---------------------------------------------------------------------------

def validate_timestamp(
    ts: datetime,
    *,
    tolerance_seconds: int = 300,
) -> None:
    """Validate that *ts* is within the acceptable time window.

    Parameters
    ----------
    ts:
        The timestamp from the incoming message.
    tolerance_seconds:
        Maximum allowed drift in seconds (default 300 = 5 minutes,
        per Chapter 08 Section 3.6).

    Raises
    ------
    InvalidTimestamp
        If the timestamp is outside the acceptable window.
    """
    now = datetime.now(UTC)
    # Ensure ts is timezone-aware
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    delta = abs((now - ts).total_seconds())
    if delta > tolerance_seconds:
        raise InvalidTimestamp(
            f"Message timestamp is {delta:.1f}s from server time "
            f"(tolerance: {tolerance_seconds}s)",
            details={
                "message_timestamp": ts.isoformat(),
                "server_timestamp": now.isoformat(),
                "drift_seconds": round(delta, 1),
                "tolerance_seconds": tolerance_seconds,
            },
        )
