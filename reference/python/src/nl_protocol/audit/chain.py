"""SHA-256 hash chain management for audit records.

This module implements the hash chain defined in Chapter 05, Section 3 of
the NL Protocol specification.  Each audit record includes the hash of the
previous record, creating a tamper-evident chain.

The hash is calculated over a canonical input string composed of key fields
as defined in the spec:

    ``<sequence>\\n<timestamp>\\n<agent.uri>\\n<action>\\n<target>\\n<result>\\n<prev_hash>``

Since the existing :class:`AuditRecord` model does not carry ``sequence`` or
``target`` as explicit fields, :class:`ChainManager` tracks the sequence
internally and the caller supplies the target when appending records.
"""
from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

from nl_protocol.audit.records import create_audit_record
from nl_protocol.core.errors import AuditWriteFailure, ChainIntegrityFailure
from nl_protocol.core.interfaces import AuditStore
from nl_protocol.core.types import AgentURI, AuditRecord

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

GENESIS_PREV_HASH = "sha256:" + "0" * 64
"""The ``prev_hash`` value for the first entry in any audit chain."""

HASH_PREFIX = "sha256:"


# ---------------------------------------------------------------------------
# Hash computation
# ---------------------------------------------------------------------------

def compute_hash(canonical_input: str) -> str:
    """Compute the SHA-256 hex digest of *canonical_input*.

    Returns the hash prefixed with ``sha256:`` per the spec.
    """
    digest = hashlib.sha256(canonical_input.encode("utf-8")).hexdigest()
    return f"{HASH_PREFIX}{digest}"


def build_canonical_input(
    *,
    sequence: int,
    timestamp: str,
    agent_uri: str,
    action: str,
    target: str,
    result: str,
    prev_hash: str,
) -> str:
    """Build the canonical input string for hash computation.

    The fields are concatenated with ``\\n`` separators in the exact order
    specified by the NL Protocol (Section 3.3).
    """
    return "\n".join([
        str(sequence),
        timestamp,
        agent_uri,
        action,
        target,
        result,
        prev_hash,
    ])


# ---------------------------------------------------------------------------
# Genesis entry
# ---------------------------------------------------------------------------

def create_genesis_entry(
    agent_uri: AgentURI,
    *,
    target: str = "audit-chain-genesis",
    timestamp: datetime | None = None,
) -> tuple[AuditRecord, int]:
    """Create the first entry (sequence 1) in an audit chain.

    Parameters
    ----------
    agent_uri:
        The agent (or system URI) creating the chain.
    target:
        The target field for the genesis record.
    timestamp:
        Optional timestamp; defaults to current UTC time.

    Returns
    -------
    tuple[AuditRecord, int]
        The genesis AuditRecord (with computed hash) and the sequence
        number (always ``1``).
    """
    ts = timestamp or datetime.now(UTC)
    ts_iso = ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"
    sequence = 1

    canonical = build_canonical_input(
        sequence=sequence,
        timestamp=ts_iso,
        agent_uri=str(agent_uri),
        action="genesis",
        target=target,
        result="success",
        prev_hash=GENESIS_PREV_HASH,
    )
    record_hash = compute_hash(canonical)

    record = create_audit_record(
        agent_uri=agent_uri,
        action_type="genesis",
        target=target,
        result="success",
        previous_hash=GENESIS_PREV_HASH,
        record_hash=record_hash,
        timestamp=ts,
        metadata={"sequence": sequence, "target": target},
    )
    return record, sequence


def link_record(
    *,
    prev_hash: str,
    sequence: int,
    agent_uri: AgentURI,
    action_type: str,
    target: str,
    result: str,
    secrets_used: list[str] | None = None,
    timestamp: datetime | None = None,
    hmac_signature: str | None = None,
    hmac_key_id: str | None = None,
    hash_algorithm: str = "sha256",
    correlation_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> AuditRecord:
    """Create a new record linked to the chain via *prev_hash*.

    Computes the ``record_hash`` from the canonical input and returns a
    fully populated :class:`AuditRecord`.
    """
    ts = timestamp or datetime.now(UTC)
    ts_iso = ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"

    canonical = build_canonical_input(
        sequence=sequence,
        timestamp=ts_iso,
        agent_uri=str(agent_uri),
        action=action_type,
        target=target,
        result=result,
        prev_hash=prev_hash,
    )
    record_hash = compute_hash(canonical)

    md = dict(metadata) if metadata else {}
    md["sequence"] = sequence
    md["target"] = target

    return create_audit_record(
        agent_uri=agent_uri,
        action_type=action_type,
        target=target,
        result=result,
        secrets_used=secrets_used,
        previous_hash=prev_hash,
        record_hash=record_hash,
        hmac_signature=hmac_signature,
        hmac_key_id=hmac_key_id,
        hash_algorithm=hash_algorithm,
        correlation_id=correlation_id,
        metadata=md,
        timestamp=ts,
    )


# ---------------------------------------------------------------------------
# ChainManager
# ---------------------------------------------------------------------------

class ChainManager:
    """Manages hash chain state: sequence counter, head hash, and appends.

    The ``ChainManager`` is the primary high-level interface for building
    audit chains.  It maintains the current sequence number, the head hash,
    and optionally persists records to an :class:`AuditStore`.

    Parameters
    ----------
    store:
        An optional :class:`AuditStore` backend.  If ``None``, records are
        tracked in-memory only.
    agent_uri:
        The default agent URI for records created through this manager.
    """

    _DEFAULT_AGENT_URI = AgentURI("nl://system/audit-manager")

    __slots__ = ("_agent_uri", "_head_hash", "_records", "_sequence", "_store")

    def __init__(
        self,
        *,
        store: AuditStore | None = None,
        agent_uri: AgentURI = _DEFAULT_AGENT_URI,
    ) -> None:
        self._store = store
        self._agent_uri = agent_uri
        self._sequence = 0
        self._head_hash = GENESIS_PREV_HASH
        self._records: list[AuditRecord] = []

    @property
    def sequence(self) -> int:
        """The current (last used) sequence number."""
        return self._sequence

    @property
    def head_hash(self) -> str:
        """The hash of the most recent record in the chain."""
        return self._head_hash

    @property
    def records(self) -> list[AuditRecord]:
        """All records managed by this instance (in-memory copy)."""
        return list(self._records)

    async def initialise(self) -> AuditRecord:
        """Create and persist the genesis entry.

        Raises
        ------
        ChainIntegrityFailure
            If the chain has already been initialised (sequence > 0).
        """
        if self._sequence > 0:
            raise ChainIntegrityFailure(
                "Chain already initialised",
                details={"current_sequence": self._sequence},
            )
        record, seq = create_genesis_entry(self._agent_uri)
        self._sequence = seq
        self._head_hash = record.record_hash
        self._records.append(record)
        if self._store is not None:
            await self._store.append(record)
        return record

    async def append(
        self,
        *,
        action_type: str,
        target: str,
        result: str,
        agent_uri: AgentURI | None = None,
        secrets_used: list[str] | None = None,
        timestamp: datetime | None = None,
        hmac_signature: str | None = None,
        hmac_key_id: str | None = None,
        correlation_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AuditRecord:
        """Create, link, and persist a new audit record.

        Raises
        ------
        AuditWriteFailure
            If the chain has not been initialised (no genesis entry).
        """
        if self._sequence == 0:
            raise AuditWriteFailure(
                "Chain not initialised; call initialise() first",
            )
        self._sequence += 1
        record = link_record(
            prev_hash=self._head_hash,
            sequence=self._sequence,
            agent_uri=agent_uri or self._agent_uri,
            action_type=action_type,
            target=target,
            result=result,
            secrets_used=secrets_used,
            timestamp=timestamp,
            hmac_signature=hmac_signature,
            hmac_key_id=hmac_key_id,
            correlation_id=correlation_id,
            metadata=metadata,
        )
        self._head_hash = record.record_hash
        self._records.append(record)
        if self._store is not None:
            await self._store.append(record)
        return record
