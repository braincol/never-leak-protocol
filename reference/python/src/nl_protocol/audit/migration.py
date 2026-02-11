"""Hash algorithm migration support for audit chains.

This module implements the algorithm migration procedure defined in
Chapter 05, Section 3.3 ("Algorithm Agility") of the NL Protocol
specification.  It supports:

* Transitioning from one hash algorithm to another.
* A dual-write period where new records carry both the new and legacy hash.
* Verification of records written with either algorithm.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from nl_protocol.audit.chain import build_canonical_input
from nl_protocol.core.types import AuditRecord

# ---------------------------------------------------------------------------
# Algorithm registry
# ---------------------------------------------------------------------------

ALGORITHM_REGISTRY: dict[str, str] = {
    "sha256": "sha256",
    "sha384": "sha384",
    "sha3_256": "sha3_256",
}
"""Map from spec algorithm identifier to :mod:`hashlib` name."""


def _hashlib_name(algorithm: str) -> str:
    """Resolve a spec algorithm identifier to a hashlib name."""
    name = ALGORITHM_REGISTRY.get(algorithm)
    if name is None:
        msg = f"Unknown hash algorithm: {algorithm}"
        raise ValueError(msg)
    return name


def compute_hash_with_algorithm(canonical_input: str, algorithm: str) -> str:
    """Compute a hash using the specified algorithm.

    Parameters
    ----------
    canonical_input:
        The canonical string to hash.
    algorithm:
        A spec algorithm identifier (e.g. ``"sha256"``, ``"sha384"``).

    Returns
    -------
    str
        The hash value prefixed with ``<algorithm>:``.
    """
    hl_name = _hashlib_name(algorithm)
    digest = hashlib.new(hl_name, canonical_input.encode("utf-8")).hexdigest()
    return f"{algorithm}:{digest}"


# ---------------------------------------------------------------------------
# Migration state
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class MigrationConfig:
    """Configuration for a hash algorithm migration.

    Attributes
    ----------
    old_algorithm:
        The algorithm currently in use (e.g. ``"sha256"``).
    new_algorithm:
        The algorithm to migrate to (e.g. ``"sha3_256"``).
    dual_write:
        Whether to include a ``legacy_hash`` field during the transition.
    """

    old_algorithm: str = "sha256"
    new_algorithm: str = "sha3_256"
    dual_write: bool = True


@dataclass(slots=True)
class MigrationCheckpoint:
    """A checkpoint record anchoring the transition between algorithms.

    Per the spec, a ``chain_migration_checkpoint`` record is created at
    the migration point, signed with the new algorithm, and referencing
    the last record of the old chain.

    Attributes
    ----------
    sequence:
        Sequence number of the checkpoint.
    old_algorithm:
        The outgoing algorithm.
    new_algorithm:
        The incoming algorithm.
    last_old_hash:
        The hash of the last record produced with the old algorithm.
    checkpoint_hash:
        The hash of this checkpoint, computed with the new algorithm.
    """

    sequence: int
    old_algorithm: str
    new_algorithm: str
    last_old_hash: str
    checkpoint_hash: str


# ---------------------------------------------------------------------------
# Dual-write helpers
# ---------------------------------------------------------------------------

def compute_dual_hash(
    canonical_input: str,
    config: MigrationConfig,
) -> tuple[str, str | None]:
    """Compute the primary and (optionally) legacy hash during migration.

    Parameters
    ----------
    canonical_input:
        The canonical string to hash.
    config:
        The migration configuration.

    Returns
    -------
    tuple[str, str | None]
        A ``(primary_hash, legacy_hash)`` pair.  ``legacy_hash`` is
        ``None`` when dual-write is disabled.
    """
    primary = compute_hash_with_algorithm(canonical_input, config.new_algorithm)
    legacy: str | None = None
    if config.dual_write:
        legacy = compute_hash_with_algorithm(canonical_input, config.old_algorithm)
    return primary, legacy


def create_migration_checkpoint(
    *,
    sequence: int,
    config: MigrationConfig,
    last_old_hash: str,
    agent_uri: str,
    timestamp_iso: str,
) -> MigrationCheckpoint:
    """Create a migration checkpoint record.

    The checkpoint is a trust anchor between the old and new chain
    segments.

    Parameters
    ----------
    sequence:
        The sequence number for this checkpoint.
    config:
        The migration configuration.
    last_old_hash:
        The ``chain.hash`` of the last record using the old algorithm.
    agent_uri:
        The agent or system URI creating the checkpoint.
    timestamp_iso:
        ISO 8601 timestamp for the checkpoint.

    Returns
    -------
    MigrationCheckpoint
        The checkpoint data.
    """
    canonical = build_canonical_input(
        sequence=sequence,
        timestamp=timestamp_iso,
        agent_uri=agent_uri,
        action="chain_migration_checkpoint",
        target="audit-chain",
        result="success",
        prev_hash=last_old_hash,
    )
    checkpoint_hash = compute_hash_with_algorithm(canonical, config.new_algorithm)

    return MigrationCheckpoint(
        sequence=sequence,
        old_algorithm=config.old_algorithm,
        new_algorithm=config.new_algorithm,
        last_old_hash=last_old_hash,
        checkpoint_hash=checkpoint_hash,
    )


# ---------------------------------------------------------------------------
# Verification with algorithm awareness
# ---------------------------------------------------------------------------

def verify_record_hash(
    record: AuditRecord,
    *,
    sequence: int,
    target: str,
    accepted_algorithms: list[str] | None = None,
) -> bool:
    """Verify a record's hash using its declared algorithm.

    During the migration transition period, this function accepts
    records signed with either the old or new algorithm.

    Parameters
    ----------
    record:
        The audit record to verify.
    sequence:
        The record's sequence number.
    target:
        The record's target field.
    accepted_algorithms:
        Algorithms accepted for verification.  If ``None``, only the
        record's declared ``hash_algorithm`` is used.

    Returns
    -------
    bool
        ``True`` if the hash is valid, ``False`` otherwise.
    """
    algorithms = accepted_algorithms or [record.hash_algorithm]

    ts = record.timestamp
    ts_iso = ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"

    canonical = build_canonical_input(
        sequence=sequence,
        timestamp=ts_iso,
        agent_uri=str(record.agent_uri),
        action=str(record.action_type),
        target=target,
        result=record.result_summary,
        prev_hash=record.previous_hash,
    )

    for algo in algorithms:
        try:
            expected = compute_hash_with_algorithm(canonical, algo)
        except ValueError:
            continue
        if expected == record.record_hash:
            return True

    return False
