"""Tests for NL Protocol Level 5 -- Audit Integrity.

Covers the audit subpackage:

1. **Record creation** -- factory with all fields, defaults.
2. **Canonical JSON** -- RFC 8785 determinism, spec test vectors.
3. **Hash chain** -- hash computation, genesis, linking, ChainManager.
4. **HMAC** -- signing, verification, key rotation.
5. **Verification** -- valid chain, broken chain, empty chain, gap detection.
6. **Fork detection** -- identical chains, divergent chains, empty inputs.
7. **Algorithm migration** -- dual-write, checkpoint, multi-algorithm verify.
"""
from __future__ import annotations

import hashlib
from datetime import UTC, datetime

import pytest

from nl_protocol.audit import (
    GENESIS_PREV_HASH,
    ChainManager,
    MigrationCheckpoint,
    MigrationConfig,
    RotationResult,
    build_canonical_input,
    canonical_json,
    compute_dual_hash,
    compute_hash,
    compute_hash_with_algorithm,
    create_audit_record,
    create_genesis_entry,
    create_migration_checkpoint,
    detect_fork,
    link_record,
    rotate_key,
    sign_record,
    verify_chain,
    verify_record_hash,
    verify_signature,
)
from nl_protocol.core.errors import AuditWriteFailure, ChainIntegrityFailure
from nl_protocol.core.interfaces import InMemoryAuditStore
from nl_protocol.core.types import AgentURI

# ---------------------------------------------------------------------------
# Constants used across tests
# ---------------------------------------------------------------------------

AGENT_URI = AgentURI("nl://anthropic.com/claude-code/1.5.2")
HMAC_KEY = b"test-hmac-key-for-audit-integrity"
HMAC_KEY_2 = b"rotated-hmac-key-for-audit-integrity"


# ===================================================================
# Test: Record creation
# ===================================================================


class TestCreateAuditRecord:
    """Tests for the create_audit_record factory function."""

    def test_basic_creation(self) -> None:
        """Factory creates a record with all required fields."""
        record = create_audit_record(
            agent_uri=AGENT_URI,
            action_type="exec",
            target="api/API_KEY",
            result="success",
        )
        assert record.agent_uri == AGENT_URI
        assert record.action_type == "exec"
        assert record.result_summary == "success"
        assert record.previous_hash == GENESIS_PREV_HASH
        assert record.hash_algorithm == "sha256"
        assert record.record_id  # non-empty UUID

    def test_custom_fields(self) -> None:
        """Factory respects explicit field values."""
        ts = datetime(2026, 2, 8, 10, 30, 0, tzinfo=UTC)
        record = create_audit_record(
            agent_uri=AGENT_URI,
            action_type="blocked",
            target="api/API_KEY",
            result="blocked",
            secrets_used=["api/API_KEY"],
            timestamp=ts,
            record_id="custom-id-001",
            correlation_id="req-abc-123",
            metadata={"rule_id": "NL-4-DENY-001"},
        )
        assert record.record_id == "custom-id-001"
        assert record.timestamp == ts
        assert record.secrets_used == ["api/API_KEY"]
        assert record.correlation_id == "req-abc-123"
        assert record.metadata["rule_id"] == "NL-4-DENY-001"

    def test_secrets_used_defaults_to_empty(self) -> None:
        """secrets_used defaults to an empty list."""
        record = create_audit_record(
            agent_uri=AGENT_URI,
            action_type="list",
            target="project:myapp",
            result="success",
        )
        assert record.secrets_used == []

    def test_hmac_fields(self) -> None:
        """HMAC signature and key ID can be set."""
        record = create_audit_record(
            agent_uri=AGENT_URI,
            action_type="exec",
            target="api/API_KEY",
            result="success",
            hmac_signature="sha256:abcdef",
            hmac_key_id="key-001",
        )
        assert record.hmac_signature == "sha256:abcdef"
        assert record.hmac_key_id == "key-001"

    def test_no_secret_values_in_record(self) -> None:
        """Records reference secret names, never values."""
        record = create_audit_record(
            agent_uri=AGENT_URI,
            action_type="exec",
            target="api/API_KEY",
            result="success",
            secrets_used=["api/API_KEY"],
        )
        dumped = record.model_dump_json()
        assert "api/API_KEY" in dumped
        # No actual secret value present (we didn't pass one and
        # the model has no field for secret values)


# ===================================================================
# Test: Canonical JSON (RFC 8785)
# ===================================================================


class TestCanonicalJson:
    """Tests for RFC 8785 canonical JSON serialisation."""

    def test_field_ordering(self) -> None:
        """Keys are sorted lexicographically."""
        result = canonical_json({"zebra": 1, "alpha": 2})
        assert result == '{"alpha":2,"zebra":1}'

    def test_nested_objects(self) -> None:
        """Nested object keys are also sorted."""
        result = canonical_json({"b": {"z": 1, "a": 2}, "a": 3})
        assert result == '{"a":3,"b":{"a":2,"z":1}}'

    def test_unicode_preserved(self) -> None:
        """UTF-8 characters are preserved, not escaped."""
        result = canonical_json({"key": "caf\u00e9"})
        assert result == '{"key":"caf\u00e9"}'

    def test_numbers_normalised(self) -> None:
        """Numbers use shortest representation; 1.0 -> 1, 1e2 -> 100."""
        result = canonical_json({"val": 1.0, "big": 1e2})
        assert result == '{"big":100,"val":1}'

    def test_null_and_boolean(self) -> None:
        """null, true, false are lowercase literals."""
        result = canonical_json({"n": None, "t": True, "f": False})
        assert result == '{"f":false,"n":null,"t":true}'

    def test_determinism(self) -> None:
        """Same input always produces the same output."""
        data = {"c": 3, "a": 1, "b": 2}
        assert canonical_json(data) == canonical_json(data)

    def test_array_order_preserved(self) -> None:
        """Array element order is preserved."""
        result = canonical_json({"arr": [3, 1, 2]})
        assert result == '{"arr":[3,1,2]}'

    def test_empty_object(self) -> None:
        """Empty objects serialise correctly."""
        assert canonical_json({}) == "{}"

    def test_empty_array(self) -> None:
        """Empty arrays serialise correctly."""
        assert canonical_json({"a": []}) == '{"a":[]}'

    def test_spec_vector_1_hash(self) -> None:
        """Test vector 1: field ordering SHA-256."""
        canon = canonical_json({"zebra": 1, "alpha": 2})
        digest = hashlib.sha256(canon.encode("utf-8")).hexdigest()
        assert digest == "b38943f3398f7057224689aa44865d70c1143669a51b010f27e8495094c97b6e"

    def test_spec_vector_2_hash(self) -> None:
        """Test vector 2: nested objects SHA-256."""
        canon = canonical_json({"b": {"z": 1, "a": 2}, "a": 3})
        digest = hashlib.sha256(canon.encode("utf-8")).hexdigest()
        assert digest == "b375125e33a203b70f14be432a2d7b0823e92ae82f505063e8b21ca5b7a73f42"

    def test_spec_vector_3_hash(self) -> None:
        """Test vector 3: unicode SHA-256."""
        canon = canonical_json({"key": "caf\u00e9"})
        digest = hashlib.sha256(canon.encode("utf-8")).hexdigest()
        assert digest == "6f0a62bb4f435d032b67c7a8719afe68a157bfa0a90897f977ba38dbd9be9d8e"

    def test_spec_vector_4_hash(self) -> None:
        """Test vector 4: numbers SHA-256."""
        canon = canonical_json({"val": 1.0, "big": 1e2})
        digest = hashlib.sha256(canon.encode("utf-8")).hexdigest()
        assert digest == "c2ee8c03a063b35bf4b71b34c34508544022597b6b06f0990f0cc592b91a1ab6"

    def test_spec_vector_5_hash(self) -> None:
        """Test vector 5: null and boolean SHA-256."""
        canon = canonical_json({"n": None, "t": True, "f": False})
        digest = hashlib.sha256(canon.encode("utf-8")).hexdigest()
        assert digest == "22e00dc2f7b01420f940fbdbfbdf34fa0667cc6500186495023ba37722cbd05e"

    def test_audit_record_serialisation(self) -> None:
        """AuditRecord instances can be canonicalised."""
        record = create_audit_record(
            agent_uri=AGENT_URI,
            action_type="exec",
            target="api/API_KEY",
            result="success",
            record_id="test-id",
        )
        result = canonical_json(record)
        assert '"agent_uri":"nl://anthropic.com/claude-code/1.5.2"' in result


# ===================================================================
# Test: Hash chain
# ===================================================================


class TestComputeHash:
    """Tests for SHA-256 hash computation."""

    def test_returns_prefixed_hash(self) -> None:
        """compute_hash returns a sha256:-prefixed hex string."""
        h = compute_hash("test input")
        assert h.startswith("sha256:")
        assert len(h) == 7 + 64  # prefix + 64 hex chars

    def test_deterministic(self) -> None:
        """Same input produces the same hash."""
        assert compute_hash("hello") == compute_hash("hello")

    def test_different_inputs_different_hashes(self) -> None:
        """Different inputs produce different hashes."""
        assert compute_hash("hello") != compute_hash("world")


class TestBuildCanonicalInput:
    """Tests for canonical input string construction."""

    def test_format(self) -> None:
        """Canonical input follows the spec format with newline separators."""
        result = build_canonical_input(
            sequence=1,
            timestamp="2026-02-08T10:30:00.000Z",
            agent_uri="nl://anthropic.com/claude-code/1.5.2",
            action="exec",
            target="api/API_KEY",
            result="success",
            prev_hash=GENESIS_PREV_HASH,
        )
        parts = result.split("\n")
        assert len(parts) == 7
        assert parts[0] == "1"
        assert parts[1] == "2026-02-08T10:30:00.000Z"
        assert parts[2] == "nl://anthropic.com/claude-code/1.5.2"
        assert parts[3] == "exec"
        assert parts[4] == "api/API_KEY"
        assert parts[5] == "success"
        assert parts[6] == GENESIS_PREV_HASH


class TestGenesisEntry:
    """Tests for genesis entry creation."""

    def test_genesis_has_zero_prev_hash(self) -> None:
        """Genesis entry uses the all-zeros prev_hash."""
        record, seq = create_genesis_entry(AGENT_URI)
        assert record.previous_hash == GENESIS_PREV_HASH
        assert seq == 1

    def test_genesis_hash_is_computed(self) -> None:
        """Genesis entry has a non-empty, computed record_hash."""
        record, _ = create_genesis_entry(AGENT_URI)
        assert record.record_hash.startswith("sha256:")
        assert len(record.record_hash) == 7 + 64

    def test_genesis_sequence_is_1(self) -> None:
        """Genesis always has sequence 1."""
        _, seq = create_genesis_entry(AGENT_URI)
        assert seq == 1

    def test_genesis_action_type(self) -> None:
        """Genesis uses action_type 'genesis'."""
        record, _ = create_genesis_entry(AGENT_URI)
        assert record.action_type == "genesis"

    def test_genesis_with_custom_timestamp(self) -> None:
        """Genesis respects a custom timestamp."""
        ts = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
        record, _ = create_genesis_entry(AGENT_URI, timestamp=ts)
        assert record.timestamp == ts


class TestLinkRecord:
    """Tests for linking new records to the chain."""

    def test_link_uses_prev_hash(self) -> None:
        """Linked record references the provided prev_hash."""
        genesis, _ = create_genesis_entry(AGENT_URI)
        linked = link_record(
            prev_hash=genesis.record_hash,
            sequence=2,
            agent_uri=AGENT_URI,
            action_type="exec",
            target="api/API_KEY",
            result="success",
        )
        assert linked.previous_hash == genesis.record_hash

    def test_link_hash_changes_with_content(self) -> None:
        """Different targets produce different hashes."""
        genesis, _ = create_genesis_entry(AGENT_URI)
        ts = datetime(2026, 2, 8, 12, 0, 0, tzinfo=UTC)
        r1 = link_record(
            prev_hash=genesis.record_hash,
            sequence=2,
            agent_uri=AGENT_URI,
            action_type="exec",
            target="api/KEY_A",
            result="success",
            timestamp=ts,
        )
        r2 = link_record(
            prev_hash=genesis.record_hash,
            sequence=2,
            agent_uri=AGENT_URI,
            action_type="exec",
            target="api/KEY_B",
            result="success",
            timestamp=ts,
        )
        assert r1.record_hash != r2.record_hash

    def test_link_sequence_in_metadata(self) -> None:
        """Linked record stores sequence in metadata."""
        genesis, _ = create_genesis_entry(AGENT_URI)
        linked = link_record(
            prev_hash=genesis.record_hash,
            sequence=2,
            agent_uri=AGENT_URI,
            action_type="exec",
            target="api/API_KEY",
            result="success",
        )
        assert linked.metadata["sequence"] == 2
        assert linked.metadata["target"] == "api/API_KEY"


# ===================================================================
# Test: ChainManager
# ===================================================================


class TestChainManager:
    """Tests for the high-level ChainManager."""

    async def test_initialise_creates_genesis(self) -> None:
        """initialise() creates a genesis record with sequence 1."""
        manager = ChainManager(agent_uri=AGENT_URI)
        genesis = await manager.initialise()
        assert manager.sequence == 1
        assert genesis.action_type == "genesis"
        assert manager.head_hash == genesis.record_hash

    async def test_double_initialise_raises(self) -> None:
        """Calling initialise() twice raises ChainIntegrityFailure."""
        manager = ChainManager(agent_uri=AGENT_URI)
        await manager.initialise()
        with pytest.raises(ChainIntegrityFailure):
            await manager.initialise()

    async def test_append_before_init_raises(self) -> None:
        """append() before initialise() raises AuditWriteFailure."""
        manager = ChainManager(agent_uri=AGENT_URI)
        with pytest.raises(AuditWriteFailure):
            await manager.append(
                action_type="exec",
                target="api/API_KEY",
                result="success",
            )

    async def test_append_increments_sequence(self) -> None:
        """Each append increments the sequence number."""
        manager = ChainManager(agent_uri=AGENT_URI)
        await manager.initialise()
        await manager.append(action_type="exec", target="key1", result="success")
        assert manager.sequence == 2
        await manager.append(action_type="exec", target="key2", result="success")
        assert manager.sequence == 3

    async def test_chain_links_correctly(self) -> None:
        """Each record's prev_hash matches the previous record's hash."""
        manager = ChainManager(agent_uri=AGENT_URI)
        await manager.initialise()
        await manager.append(action_type="exec", target="key1", result="success")
        await manager.append(action_type="exec", target="key2", result="success")

        records = manager.records
        assert len(records) == 3
        assert records[0].previous_hash == GENESIS_PREV_HASH
        assert records[1].previous_hash == records[0].record_hash
        assert records[2].previous_hash == records[1].record_hash

    async def test_with_store(self) -> None:
        """ChainManager persists records to the backing store."""
        store = InMemoryAuditStore()
        manager = ChainManager(store=store, agent_uri=AGENT_URI)
        await manager.initialise()
        await manager.append(action_type="exec", target="key1", result="success")

        latest = await store.get_latest()
        assert latest is not None
        assert latest.action_type == "exec"

    async def test_records_property_returns_copy(self) -> None:
        """records property returns a copy, not the internal list."""
        manager = ChainManager(agent_uri=AGENT_URI)
        await manager.initialise()
        records = manager.records
        records.clear()
        assert len(manager.records) == 1  # internal list unchanged


# ===================================================================
# Test: HMAC signing and verification
# ===================================================================


class TestHMAC:
    """Tests for HMAC-SHA256 signing and verification."""

    def test_sign_returns_prefixed_hmac(self) -> None:
        """sign_record returns a sha256:-prefixed HMAC."""
        sig = sign_record("sha256:abcdef1234", HMAC_KEY)
        assert sig.startswith("sha256:")
        assert len(sig) == 7 + 64

    def test_verify_valid_signature(self) -> None:
        """verify_signature returns True for a correct HMAC."""
        record_hash = "sha256:abc123"
        sig = sign_record(record_hash, HMAC_KEY)
        assert verify_signature(record_hash, sig, HMAC_KEY) is True

    def test_verify_invalid_signature(self) -> None:
        """verify_signature returns False for an incorrect HMAC."""
        record_hash = "sha256:abc123"
        assert verify_signature(record_hash, "sha256:badbadbad", HMAC_KEY) is False

    def test_verify_wrong_key(self) -> None:
        """verify_signature returns False when using the wrong key."""
        record_hash = "sha256:abc123"
        sig = sign_record(record_hash, HMAC_KEY)
        assert verify_signature(record_hash, sig, b"wrong-key") is False

    def test_sign_deterministic(self) -> None:
        """Same input and key always produces the same HMAC."""
        h = "sha256:determinism"
        assert sign_record(h, HMAC_KEY) == sign_record(h, HMAC_KEY)

    def test_different_hashes_different_hmacs(self) -> None:
        """Different record hashes produce different HMACs."""
        sig1 = sign_record("sha256:hash_a", HMAC_KEY)
        sig2 = sign_record("sha256:hash_b", HMAC_KEY)
        assert sig1 != sig2


class TestKeyRotation:
    """Tests for HMAC key rotation."""

    async def test_rotation_verifies_old_records(self) -> None:
        """rotate_key verifies historical records with the old key."""
        store = InMemoryAuditStore()
        manager = ChainManager(store=store, agent_uri=AGENT_URI)
        genesis = await manager.initialise()

        # Sign a record with the old key
        sig = sign_record(genesis.record_hash, HMAC_KEY)
        signed_record = create_audit_record(
            agent_uri=AGENT_URI,
            action_type="exec",
            target="key",
            result="success",
            record_hash=genesis.record_hash,
            previous_hash=GENESIS_PREV_HASH,
            hmac_signature=sig,
            hmac_key_id="old-key",
        )
        await store.append(signed_record)

        result = await rotate_key(HMAC_KEY, HMAC_KEY_2, store, new_key_id="new-key")
        assert isinstance(result, RotationResult)
        assert result.new_key_id == "new-key"
        # At least the signed record should be verified
        assert result.verified_count >= 1

    async def test_rotation_detects_unverifiable_records(self) -> None:
        """rotate_key flags records that cannot be verified."""
        store = InMemoryAuditStore()
        bad_record = create_audit_record(
            agent_uri=AGENT_URI,
            action_type="exec",
            target="key",
            result="success",
            record_hash="sha256:somehash",
            hmac_signature="sha256:bad_signature",
            hmac_key_id="unknown",
        )
        await store.append(bad_record)

        result = await rotate_key(HMAC_KEY, HMAC_KEY_2, store)
        assert len(result.unverifiable_record_ids) >= 1
        assert bad_record.record_id in result.unverifiable_record_ids


# ===================================================================
# Test: Chain verification
# ===================================================================


class TestVerifyChain:
    """Tests for full chain verification."""

    async def test_valid_chain(self) -> None:
        """A correctly built chain passes verification."""
        manager = ChainManager(agent_uri=AGENT_URI)
        await manager.initialise()
        await manager.append(action_type="exec", target="key1", result="success")
        await manager.append(action_type="exec", target="key2", result="success")

        result = verify_chain(manager.records)
        assert result.valid is True
        assert result.entries_verified == 3
        assert result.broken_links == []
        assert result.missing_records == []

    def test_empty_chain(self) -> None:
        """An empty chain is considered valid."""
        result = verify_chain([])
        assert result.valid is True
        assert result.entries_verified == 0

    async def test_broken_hash(self) -> None:
        """A record with a tampered hash is detected."""
        manager = ChainManager(agent_uri=AGENT_URI)
        await manager.initialise()
        await manager.append(action_type="exec", target="key1", result="success")

        records = manager.records
        # Tamper with the second record's hash
        tampered = records[1].model_copy(update={"record_hash": "sha256:" + "f" * 64})
        records[1] = tampered

        result = verify_chain(records)
        assert result.valid is False
        assert len(result.broken_links) > 0

    async def test_broken_prev_hash(self) -> None:
        """A record with a wrong prev_hash is detected."""
        manager = ChainManager(agent_uri=AGENT_URI)
        await manager.initialise()
        await manager.append(action_type="exec", target="key1", result="success")
        await manager.append(action_type="exec", target="key2", result="success")

        records = manager.records
        # Tamper: overwrite record[2]'s previous_hash with garbage
        tampered = records[2].model_copy(update={"previous_hash": "sha256:" + "a" * 64})
        records[2] = tampered

        result = verify_chain(records)
        assert result.valid is False
        broken_reasons = {bl.reason for bl in result.broken_links}
        assert "prev_hash_mismatch" in broken_reasons or "hash_mismatch" in broken_reasons

    async def test_gap_detection(self) -> None:
        """Missing sequence numbers are detected."""
        manager = ChainManager(agent_uri=AGENT_URI)
        await manager.initialise()
        await manager.append(action_type="exec", target="key1", result="success")
        await manager.append(action_type="exec", target="key2", result="success")
        await manager.append(action_type="exec", target="key3", result="success")

        # Remove the middle record (sequence 3)
        records = manager.records
        records_with_gap = [records[0], records[1], records[3]]  # skip seq 3

        result = verify_chain(records_with_gap)
        assert result.valid is False
        assert len(result.missing_records) > 0

    async def test_invalid_genesis_prev_hash(self) -> None:
        """Genesis record with wrong prev_hash is detected."""
        record = create_audit_record(
            agent_uri=AGENT_URI,
            action_type="genesis",
            target="audit-chain-genesis",
            result="success",
            previous_hash="sha256:" + "a" * 64,
            record_hash="sha256:" + "b" * 64,
            metadata={"sequence": 1, "target": "audit-chain-genesis"},
        )
        result = verify_chain([record])
        assert result.valid is False
        broken_reasons = {bl.reason for bl in result.broken_links}
        assert "invalid_genesis_prev_hash" in broken_reasons

    async def test_single_valid_genesis(self) -> None:
        """A single valid genesis record passes verification."""
        record, _ = create_genesis_entry(AGENT_URI)
        result = verify_chain([record])
        assert result.valid is True
        assert result.entries_verified == 1


# ===================================================================
# Test: Fork detection
# ===================================================================


class TestForkDetection:
    """Tests for hash chain fork detection."""

    async def test_identical_chains_no_fork(self) -> None:
        """Two identical chains are not forked."""
        manager = ChainManager(agent_uri=AGENT_URI)
        await manager.initialise()
        await manager.append(action_type="exec", target="key1", result="success")

        result = detect_fork(manager.records, manager.records)
        assert result.forked is False
        assert result.common_length == 2

    async def test_divergent_chains(self) -> None:
        """Chains with different records at the same position are forked."""
        m1 = ChainManager(agent_uri=AGENT_URI)
        await m1.initialise()

        m2 = ChainManager(agent_uri=AGENT_URI)
        await m2.initialise()

        ts = datetime(2026, 2, 8, 12, 0, 0, tzinfo=UTC)
        await m1.append(action_type="exec", target="key_A", result="success", timestamp=ts)
        await m2.append(action_type="exec", target="key_B", result="success", timestamp=ts)

        result = detect_fork(m1.records, m2.records)
        # Genesis entries will have different hashes (different UUIDs),
        # so the fork is detected at position 0 or 1.
        assert result.forked is True

    def test_empty_chains_no_fork(self) -> None:
        """Two empty chains are not forked."""
        result = detect_fork([], [])
        assert result.forked is False
        assert result.common_length == 0

    def test_one_empty_chain(self) -> None:
        """One empty and one non-empty chain is not a fork."""
        record, _ = create_genesis_entry(AGENT_URI)
        result = detect_fork([record], [])
        assert result.forked is False
        assert result.chain_a_length == 1
        assert result.chain_b_length == 0

    async def test_different_lengths_same_prefix(self) -> None:
        """Chains with same prefix but different lengths are flagged."""
        manager = ChainManager(agent_uri=AGENT_URI)
        await manager.initialise()
        await manager.append(action_type="exec", target="key1", result="success")

        short_chain = manager.records[:1]  # just genesis
        full_chain = manager.records

        result = detect_fork(full_chain, short_chain)
        # Different lengths but shared prefix: this is a potential truncation
        assert result.chain_a_length == 2
        assert result.chain_b_length == 1


# ===================================================================
# Test: Algorithm migration
# ===================================================================


class TestAlgorithmMigration:
    """Tests for hash algorithm migration support."""

    def test_compute_hash_sha256(self) -> None:
        """compute_hash_with_algorithm works with sha256."""
        h = compute_hash_with_algorithm("test", "sha256")
        assert h.startswith("sha256:")
        assert len(h) == 7 + 64

    def test_compute_hash_sha384(self) -> None:
        """compute_hash_with_algorithm works with sha384."""
        h = compute_hash_with_algorithm("test", "sha384")
        assert h.startswith("sha384:")
        assert len(h) == 7 + 96  # sha384 produces 96 hex chars

    def test_compute_hash_sha3_256(self) -> None:
        """compute_hash_with_algorithm works with sha3_256."""
        h = compute_hash_with_algorithm("test", "sha3_256")
        assert h.startswith("sha3_256:")
        assert len(h) == 9 + 64  # "sha3_256:" + 64 hex chars

    def test_unknown_algorithm_raises(self) -> None:
        """Unknown algorithm raises ValueError."""
        with pytest.raises(ValueError, match="Unknown hash algorithm"):
            compute_hash_with_algorithm("test", "md5")

    def test_dual_write(self) -> None:
        """Dual-write produces both primary and legacy hashes."""
        config = MigrationConfig(
            old_algorithm="sha256",
            new_algorithm="sha3_256",
            dual_write=True,
        )
        primary, legacy = compute_dual_hash("test", config)
        assert primary.startswith("sha3_256:")
        assert legacy is not None
        assert legacy.startswith("sha256:")

    def test_dual_write_disabled(self) -> None:
        """Disabling dual-write produces no legacy hash."""
        config = MigrationConfig(dual_write=False)
        primary, legacy = compute_dual_hash("test", config)
        assert primary.startswith("sha3_256:")
        assert legacy is None

    def test_migration_checkpoint(self) -> None:
        """Migration checkpoint is created with correct fields."""
        config = MigrationConfig()
        checkpoint = create_migration_checkpoint(
            sequence=100,
            config=config,
            last_old_hash="sha256:" + "a" * 64,
            agent_uri="nl://system/audit-manager",
            timestamp_iso="2026-02-08T12:00:00.000Z",
        )
        assert isinstance(checkpoint, MigrationCheckpoint)
        assert checkpoint.sequence == 100
        assert checkpoint.old_algorithm == "sha256"
        assert checkpoint.new_algorithm == "sha3_256"
        assert checkpoint.last_old_hash == "sha256:" + "a" * 64
        assert checkpoint.checkpoint_hash.startswith("sha3_256:")

    def test_verify_record_with_declared_algorithm(self) -> None:
        """verify_record_hash works with the record's declared algorithm."""
        ts = datetime(2026, 2, 8, 12, 0, 0, tzinfo=UTC)
        record, _ = create_genesis_entry(AGENT_URI, timestamp=ts)
        seq = record.metadata["sequence"]
        target = record.metadata["target"]

        assert verify_record_hash(record, sequence=seq, target=target) is True

    def test_verify_record_with_wrong_algorithm(self) -> None:
        """verify_record_hash fails when the algorithm doesn't match."""
        ts = datetime(2026, 2, 8, 12, 0, 0, tzinfo=UTC)
        record, _ = create_genesis_entry(AGENT_URI, timestamp=ts)
        seq = record.metadata["sequence"]
        target = record.metadata["target"]

        # Only accept sha3_256, but record uses sha256
        assert verify_record_hash(
            record, sequence=seq, target=target, accepted_algorithms=["sha3_256"]
        ) is False

    def test_verify_record_multi_algorithm_acceptance(self) -> None:
        """verify_record_hash accepts records when any listed algorithm matches."""
        ts = datetime(2026, 2, 8, 12, 0, 0, tzinfo=UTC)
        record, _ = create_genesis_entry(AGENT_URI, timestamp=ts)
        seq = record.metadata["sequence"]
        target = record.metadata["target"]

        # Accept both: sha3_256 won't match but sha256 will
        assert verify_record_hash(
            record, sequence=seq, target=target,
            accepted_algorithms=["sha3_256", "sha256"],
        ) is True


# ===================================================================
# Test: Integration -- full chain build, sign, verify
# ===================================================================


class TestIntegration:
    """End-to-end integration tests combining chain, HMAC, and verification."""

    async def test_full_lifecycle(self) -> None:
        """Build a chain, sign with HMAC, verify chain, verify HMAC."""
        store = InMemoryAuditStore()
        manager = ChainManager(store=store, agent_uri=AGENT_URI)

        genesis = await manager.initialise()
        sig = sign_record(genesis.record_hash, HMAC_KEY)
        assert verify_signature(genesis.record_hash, sig, HMAC_KEY) is True

        for i in range(5):
            r = await manager.append(
                action_type="exec",
                target=f"secret/{i}",
                result="success",
            )
            s = sign_record(r.record_hash, HMAC_KEY)
            assert verify_signature(r.record_hash, s, HMAC_KEY) is True

        result = verify_chain(manager.records)
        assert result.valid is True
        assert result.entries_verified == 6

    async def test_tamper_detection_e2e(self) -> None:
        """Tampering with a middle record is detected by verification."""
        manager = ChainManager(agent_uri=AGENT_URI)
        await manager.initialise()
        for i in range(4):
            await manager.append(
                action_type="exec",
                target=f"secret/{i}",
                result="success",
            )

        records = manager.records
        # Tamper with middle record's result
        tampered = records[2].model_copy(update={"result_summary": "blocked"})
        records[2] = tampered

        result = verify_chain(records)
        assert result.valid is False
        assert any(bl.reason == "hash_mismatch" for bl in result.broken_links)
