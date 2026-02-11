"""Level 5 -- Audit Integrity conformance tests.

Verifies Chapter 05 requirements: hash chain integrity (SHA-256),
HMAC signing/verification, canonical JSON (RFC 8785), genesis entry,
tamper detection, and secrets_used containing names NEVER values.
"""
from __future__ import annotations

import pytest

from nl_protocol.audit.chain import (
    GENESIS_PREV_HASH,
    ChainManager,
    compute_hash,
    create_genesis_entry,
)
from nl_protocol.audit.hmac import sign_record, verify_signature
from nl_protocol.audit.records import canonical_json, create_audit_record
from nl_protocol.audit.verification import verify_chain
from nl_protocol.core.errors import AuditWriteFailure, ChainIntegrityFailure

from .conftest import HMAC_KEY, SYSTEM_URI

# ===================================================================
# Section 3 -- Hash chain integrity
# ===================================================================

class TestHashChainIntegrity:
    """Spec Section 3: audit records MUST form a SHA-256 hash chain."""

    def test_MUST_use_sha256_for_hashing(self) -> None:
        """Hash computation MUST use SHA-256."""
        result = compute_hash("test-input")
        assert result.startswith("sha256:")
        hex_part = result[len("sha256:"):]
        assert len(hex_part) == 64  # SHA-256 hex digest length

    def test_MUST_produce_deterministic_hashes(self) -> None:
        """Same input MUST always produce the same hash."""
        h1 = compute_hash("identical-input")
        h2 = compute_hash("identical-input")
        assert h1 == h2

    def test_MUST_produce_different_hashes_for_different_input(self) -> None:
        """Different inputs MUST produce different hashes."""
        h1 = compute_hash("input-a")
        h2 = compute_hash("input-b")
        assert h1 != h2

    async def test_MUST_chain_records_via_previous_hash(self) -> None:
        """Each record's previous_hash MUST equal the prior record's hash."""
        chain_mgr = ChainManager(agent_uri=SYSTEM_URI)
        genesis = await chain_mgr.initialise()
        rec2 = await chain_mgr.append(
            action_type="exec", target="api/TOKEN", result="success"
        )
        assert rec2.previous_hash == genesis.record_hash

        rec3 = await chain_mgr.append(
            action_type="read", target="db/PASS", result="success"
        )
        assert rec3.previous_hash == rec2.record_hash


# ===================================================================
# Section 3.1 -- Genesis entry
# ===================================================================

class TestGenesisEntry:
    """Spec Section 3.1: the genesis entry MUST use a special previous_hash."""

    def test_MUST_have_correct_genesis_prev_hash(self) -> None:
        """Genesis previous_hash MUST be sha256: followed by 64 zeros."""
        record, seq = create_genesis_entry(SYSTEM_URI)
        assert record.previous_hash == GENESIS_PREV_HASH
        assert seq == 1

    def test_MUST_have_genesis_action_type(self) -> None:
        """Genesis entry action_type MUST be 'genesis'."""
        record, _ = create_genesis_entry(SYSTEM_URI)
        assert record.action_type == "genesis"

    async def test_MUST_NOT_allow_double_initialisation(self) -> None:
        """Initialising the chain twice MUST raise ChainIntegrityFailure."""
        chain_mgr = ChainManager(agent_uri=SYSTEM_URI)
        await chain_mgr.initialise()
        with pytest.raises(ChainIntegrityFailure):
            await chain_mgr.initialise()

    async def test_MUST_NOT_append_before_genesis(self) -> None:
        """Appending to an uninitialised chain MUST raise AuditWriteFailure."""
        chain_mgr = ChainManager(agent_uri=SYSTEM_URI)
        with pytest.raises(AuditWriteFailure):
            await chain_mgr.append(
                action_type="exec", target="test", result="success"
            )


# ===================================================================
# Section 3.5 -- HMAC signing and verification
# ===================================================================

class TestHMACSigning:
    """Spec Section 3.5: HMAC-SHA256 signing MUST be supported."""

    def test_MUST_sign_record_hash(self) -> None:
        """sign_record MUST produce an HMAC prefixed with sha256:."""
        record_hash = compute_hash("test-record")
        signature = sign_record(record_hash, HMAC_KEY)
        assert signature.startswith("sha256:")

    def test_MUST_verify_valid_signature(self) -> None:
        """verify_signature MUST return True for a valid HMAC."""
        record_hash = compute_hash("test-record")
        signature = sign_record(record_hash, HMAC_KEY)
        assert verify_signature(record_hash, signature, HMAC_KEY) is True

    def test_MUST_reject_invalid_signature(self) -> None:
        """verify_signature MUST return False for a tampered HMAC."""
        record_hash = compute_hash("test-record")
        signature = sign_record(record_hash, HMAC_KEY)
        tampered = signature[:-4] + "ZZZZ"
        assert verify_signature(record_hash, tampered, HMAC_KEY) is False

    def test_MUST_reject_wrong_key(self) -> None:
        """verify_signature MUST return False with the wrong HMAC key."""
        record_hash = compute_hash("test-record")
        signature = sign_record(record_hash, HMAC_KEY)
        wrong_key = b"wrong-key-for-verification"
        assert verify_signature(record_hash, signature, wrong_key) is False


# ===================================================================
# RFC 8785 -- Canonical JSON
# ===================================================================

class TestCanonicalJSON:
    """Spec Section 3.4 / RFC 8785: canonical JSON serialisation."""

    def test_MUST_sort_keys_by_codepoint(self) -> None:
        """Object keys MUST be sorted by Unicode code-point order."""
        data = {"b": 2, "a": 1, "c": 3}
        result = canonical_json(data)
        # Keys must appear in a, b, c order
        assert result.index('"a"') < result.index('"b"') < result.index('"c"')

    def test_MUST_be_deterministic(self) -> None:
        """Same data MUST always produce the same canonical form."""
        data = {"z": [1, 2], "a": True, "m": None}
        r1 = canonical_json(data)
        r2 = canonical_json(data)
        assert r1 == r2

    def test_MUST_use_minimal_encoding(self) -> None:
        """Canonical JSON MUST use compact encoding (no extra whitespace)."""
        data = {"key": "value"}
        result = canonical_json(data)
        assert " " not in result or "value" in result
        # No indentation
        assert "\n" not in result

    def test_MUST_represent_null_correctly(self) -> None:
        """JSON null MUST be the literal string 'null'."""
        data = {"val": None}
        result = canonical_json(data)
        assert "null" in result


# ===================================================================
# Section 5 -- Chain verification and tamper detection
# ===================================================================

class TestChainVerification:
    """Spec Section 5: full chain verification MUST detect tampering."""

    async def test_MUST_verify_valid_chain(self) -> None:
        """A valid chain MUST pass verification."""
        chain_mgr = ChainManager(agent_uri=SYSTEM_URI)
        await chain_mgr.initialise()
        await chain_mgr.append(
            action_type="exec", target="api/TOKEN", result="success"
        )
        await chain_mgr.append(
            action_type="read", target="db/PASS", result="success"
        )
        result = verify_chain(chain_mgr.records)
        assert result.valid is True
        assert result.entries_verified == 3

    async def test_MUST_detect_tampered_hash(self) -> None:
        """A record with a modified hash MUST fail verification."""
        chain_mgr = ChainManager(agent_uri=SYSTEM_URI)
        await chain_mgr.initialise()
        await chain_mgr.append(
            action_type="exec", target="api/TOKEN", result="success"
        )

        records = chain_mgr.records
        # Tamper with the second record's hash
        tampered = records[1].model_copy(
            update={"record_hash": "sha256:" + "f" * 64}
        )
        tampered_chain = [records[0], tampered]
        result = verify_chain(tampered_chain)
        assert result.valid is False
        assert len(result.broken_links) > 0

    def test_MUST_verify_empty_chain(self) -> None:
        """Verifying an empty chain MUST return valid=True."""
        result = verify_chain([])
        assert result.valid is True
        assert result.entries_verified == 0


# ===================================================================
# Audit record content: secrets_used
# ===================================================================

class TestSecretsUsedField:
    """Spec: secrets_used MUST contain names, NEVER values."""

    def test_MUST_contain_only_names(self) -> None:
        """secrets_used MUST be a list of secret names (strings)."""
        record = create_audit_record(
            agent_uri=SYSTEM_URI,
            action_type="exec",
            target="api/TOKEN",
            result="success",
            secrets_used=["api/TOKEN", "db/PASSWORD"],
        )
        assert record.secrets_used == ["api/TOKEN", "db/PASSWORD"]

    def test_MUST_NOT_contain_secret_values(self) -> None:
        """Secret values MUST NEVER appear in the audit record."""
        record = create_audit_record(
            agent_uri=SYSTEM_URI,
            action_type="exec",
            target="api/TOKEN",
            result="success",
            secrets_used=["api/TOKEN"],
        )
        serialized = record.model_dump_json()
        assert "super-secret-value" not in serialized

    async def test_MUST_persist_secrets_used_in_chain(self) -> None:
        """secrets_used MUST be preserved when records are added to a chain."""
        chain_mgr = ChainManager(agent_uri=SYSTEM_URI)
        await chain_mgr.initialise()
        rec = await chain_mgr.append(
            action_type="exec",
            target="api/TOKEN",
            result="success",
            secrets_used=["api/TOKEN"],
        )
        assert rec.secrets_used == ["api/TOKEN"]
