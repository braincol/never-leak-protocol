"""AuditRecord construction helpers and canonical JSON serialisation.

This module provides factory functions for building :class:`AuditRecord`
instances with all required fields, plus an RFC 8785 (JCS) canonical JSON
serialiser used to produce deterministic byte representations for hashing.
"""
from __future__ import annotations

import json
import math
import uuid
from datetime import UTC, datetime
from typing import Any

from nl_protocol.core.types import AgentURI, AuditRecord

# ---------------------------------------------------------------------------
# RFC 8785 canonical JSON serialisation
# ---------------------------------------------------------------------------

def _jcs_serialize_value(value: Any) -> str:
    """Serialise a single JSON value per RFC 8785 (JCS).

    * Strings: minimal UTF-8 encoding, mandatory escapes only.
    * Numbers: shortest representation, no trailing zeros, integers
      preferred when the value has no fractional part.
    * Booleans / null: lowercase literals.
    * Objects: keys sorted by Unicode code-point order.
    * Arrays: elements in order.
    """
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            msg = "NaN and Infinity are not valid JSON values"
            raise ValueError(msg)
        # RFC 8785: use shortest representation; integers must omit ".0"
        if value == int(value) and not math.isinf(value):
            return str(int(value))
        return repr(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        elements = ",".join(_jcs_serialize_value(v) for v in value)
        return f"[{elements}]"
    if isinstance(value, dict):
        sorted_keys = sorted(value.keys())
        pairs = ",".join(
            f"{json.dumps(k, ensure_ascii=False)}:{_jcs_serialize_value(value[k])}"
            for k in sorted_keys
        )
        return "{" + pairs + "}"
    msg = f"Unsupported type for JCS serialisation: {type(value)}"
    raise TypeError(msg)


def canonical_json(data: dict[str, Any] | AuditRecord) -> str:
    """Return an RFC 8785 canonical JSON string.

    Parameters
    ----------
    data:
        Either a plain ``dict`` or a :class:`AuditRecord` instance.

    Returns
    -------
    str
        A deterministic JSON string suitable for hashing.
    """
    obj = data.model_dump(mode="json") if isinstance(data, AuditRecord) else data
    return _jcs_serialize_value(obj)


# ---------------------------------------------------------------------------
# AuditRecord factory
# ---------------------------------------------------------------------------

_GENESIS_PREV_HASH = "sha256:" + "0" * 64


def create_audit_record(
    *,
    agent_uri: AgentURI,
    action_type: str,
    target: str,
    result: str,
    secrets_used: list[str] | None = None,
    previous_hash: str = _GENESIS_PREV_HASH,
    record_hash: str = "",
    hmac_signature: str | None = None,
    hmac_key_id: str | None = None,
    hash_algorithm: str = "sha256",
    correlation_id: str | None = None,
    metadata: dict[str, Any] | None = None,
    timestamp: datetime | None = None,
    record_id: str | None = None,
) -> AuditRecord:
    """Build an :class:`AuditRecord` with all required fields populated.

    The caller is responsible for computing ``record_hash`` (using
    :func:`~nl_protocol.audit.chain.compute_hash`) after the record is
    constructed.  Pass ``record_hash=""`` initially and update it after
    hashing.

    Parameters
    ----------
    agent_uri:
        The agent that performed the action.
    action_type:
        The action performed (e.g. ``"exec"``, ``"blocked"``).
    target:
        The secret reference or resource targeted.
    result:
        The outcome (``"success"``, ``"denied"``, ``"blocked"``, ``"error"``,
        ``"timeout"``).
    secrets_used:
        Secret names used in this action (NEVER values).
    previous_hash:
        Hash of the preceding record.  Defaults to genesis value.
    record_hash:
        Hash of this record.  Typically set after construction.
    hmac_signature:
        Optional HMAC-SHA256 signature.
    hmac_key_id:
        Optional key identifier for HMAC verification.
    hash_algorithm:
        Hash algorithm identifier (default ``"sha256"``).
    correlation_id:
        Cross-platform correlation identifier.
    metadata:
        Optional extensible metadata map.
    timestamp:
        Record timestamp; defaults to current UTC time.
    record_id:
        Record identifier; defaults to a new UUID v4.

    Returns
    -------
    AuditRecord
        A fully populated audit record.
    """
    return AuditRecord(
        record_id=record_id or str(uuid.uuid4()),
        timestamp=timestamp or datetime.now(UTC),
        agent_uri=agent_uri,
        action_type=action_type,
        secrets_used=secrets_used or [],
        result_summary=result,
        hash_algorithm=hash_algorithm,
        previous_hash=previous_hash,
        record_hash=record_hash,
        hmac_signature=hmac_signature,
        hmac_key_id=hmac_key_id,
        correlation_id=correlation_id,
        metadata=metadata or {},
    )
