"""Chain verification and fork detection for audit records.

This module implements the verification protocol defined in Chapter 05,
Section 5 of the NL Protocol specification:

* **Full chain verification** -- recalculates the entire hash chain from
  the genesis entry (Section 5.1).
* **Fork detection** -- identifies divergence points where two chains
  share a common ancestor but contain different records (Section 4.3).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from nl_protocol.audit.chain import GENESIS_PREV_HASH, build_canonical_input, compute_hash
from nl_protocol.core.types import AuditRecord

# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class BrokenLink:
    """Describes a single broken link in the hash chain."""

    sequence: int
    record_id: str
    expected_hash: str
    actual_hash: str
    reason: str


@dataclass(slots=True)
class ChainVerificationResult:
    """Result of a full or incremental chain verification.

    Attributes
    ----------
    valid:
        ``True`` if the entire chain is intact, ``False`` otherwise.
    broken_links:
        List of :class:`BrokenLink` instances describing each integrity
        failure detected.
    missing_records:
        List of sequence numbers that are missing (gap detection).
    entries_verified:
        Total number of entries that were checked.
    """

    valid: bool
    broken_links: list[BrokenLink] = field(default_factory=list)
    missing_records: list[int] = field(default_factory=list)
    entries_verified: int = 0


@dataclass(slots=True)
class ForkDetectionResult:
    """Result of fork detection between two chains.

    Attributes
    ----------
    forked:
        ``True`` if a fork was detected, ``False`` otherwise.
    fork_point_sequence:
        The sequence number at which the chains diverge, or ``None``
        if no fork was found.
    common_length:
        The number of records that are identical in both chains.
    chain_a_length:
        Total length of chain A.
    chain_b_length:
        Total length of chain B.
    """

    forked: bool
    fork_point_sequence: int | None = None
    common_length: int = 0
    chain_a_length: int = 0
    chain_b_length: int = 0


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def _get_sequence(record: AuditRecord) -> int:
    """Extract the sequence number from a record's metadata."""
    return int(record.metadata.get("sequence", 0))


def _get_target(record: AuditRecord) -> str:
    """Extract the target from a record's metadata."""
    return str(record.metadata.get("target", ""))


def verify_chain(records: list[AuditRecord]) -> ChainVerificationResult:
    """Verify the integrity of an ordered list of audit records.

    Implements the full chain verification procedure from Section 5.1:

    1. Verify genesis entry has the correct ``prev_hash``.
    2. For each record, recompute the hash and compare.
    3. Verify ``prev_hash`` linkage between consecutive records.
    4. Detect gaps in sequence numbers.

    Parameters
    ----------
    records:
        An ordered list of :class:`AuditRecord` instances sorted by
        sequence number (ascending).

    Returns
    -------
    ChainVerificationResult
        The verification outcome.
    """
    if not records:
        return ChainVerificationResult(valid=True, entries_verified=0)

    broken_links: list[BrokenLink] = []
    missing_records: list[int] = []

    for i, record in enumerate(records):
        seq = _get_sequence(record)
        target = _get_target(record)
        ts = record.timestamp
        ts_iso = ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"

        # 1. Recompute hash
        canonical = build_canonical_input(
            sequence=seq,
            timestamp=ts_iso,
            agent_uri=str(record.agent_uri),
            action=str(record.action_type),
            target=target,
            result=record.result_summary,
            prev_hash=record.previous_hash,
        )
        expected_hash = compute_hash(canonical)

        if expected_hash != record.record_hash:
            broken_links.append(BrokenLink(
                sequence=seq,
                record_id=record.record_id,
                expected_hash=expected_hash,
                actual_hash=record.record_hash,
                reason="hash_mismatch",
            ))

        # 2. Verify prev_hash linkage
        if i == 0:
            # Genesis entry: prev_hash must be the genesis value
            if record.previous_hash != GENESIS_PREV_HASH:
                broken_links.append(BrokenLink(
                    sequence=seq,
                    record_id=record.record_id,
                    expected_hash=GENESIS_PREV_HASH,
                    actual_hash=record.previous_hash,
                    reason="invalid_genesis_prev_hash",
                ))
        else:
            # Non-genesis: prev_hash must match the previous record's hash
            prev_record = records[i - 1]
            if record.previous_hash != prev_record.record_hash:
                broken_links.append(BrokenLink(
                    sequence=seq,
                    record_id=record.record_id,
                    expected_hash=prev_record.record_hash,
                    actual_hash=record.previous_hash,
                    reason="prev_hash_mismatch",
                ))

        # 3. Gap detection
        if i > 0:
            prev_seq = _get_sequence(records[i - 1])
            if seq != prev_seq + 1:
                for gap_seq in range(prev_seq + 1, seq):
                    missing_records.append(gap_seq)

    valid = len(broken_links) == 0 and len(missing_records) == 0
    return ChainVerificationResult(
        valid=valid,
        broken_links=broken_links,
        missing_records=missing_records,
        entries_verified=len(records),
    )


# ---------------------------------------------------------------------------
# Fork detection
# ---------------------------------------------------------------------------

def detect_fork(
    chain_a: list[AuditRecord],
    chain_b: list[AuditRecord],
) -> ForkDetectionResult:
    """Detect whether two chains have forked.

    A fork occurs when two records at the same position in their
    respective chains have different hashes.  This detects the scenario
    described in Section 4.3 where two audit records claim the same
    ``prev_hash``.

    Parameters
    ----------
    chain_a:
        The first chain of records (ordered by sequence).
    chain_b:
        The second chain of records (ordered by sequence).

    Returns
    -------
    ForkDetectionResult
        The detection outcome.
    """
    if not chain_a or not chain_b:
        return ForkDetectionResult(
            forked=False,
            common_length=0,
            chain_a_length=len(chain_a),
            chain_b_length=len(chain_b),
        )

    common_length = 0
    min_len = min(len(chain_a), len(chain_b))

    for i in range(min_len):
        if chain_a[i].record_hash == chain_b[i].record_hash:
            common_length += 1
        else:
            return ForkDetectionResult(
                forked=True,
                fork_point_sequence=_get_sequence(chain_a[i]),
                common_length=common_length,
                chain_a_length=len(chain_a),
                chain_b_length=len(chain_b),
            )

    # Chains are identical up to the shorter length
    forked = len(chain_a) != len(chain_b)
    fork_seq: int | None = None
    if forked and common_length < len(chain_a):
        fork_seq = _get_sequence(chain_a[common_length])
    elif forked and common_length < len(chain_b):
        fork_seq = _get_sequence(chain_b[common_length])
    return ForkDetectionResult(
        forked=forked,
        fork_point_sequence=fork_seq,
        common_length=common_length,
        chain_a_length=len(chain_a),
        chain_b_length=len(chain_b),
    )
