"""NL Protocol Level 5 -- Audit Integrity.

This subpackage implements the Audit Integrity layer defined in Chapter 05
of the NL Protocol Specification v1.0.  It provides:

* **Record helpers** -- factory functions and RFC 8785 canonical JSON
  serialisation (:mod:`~nl_protocol.audit.records`).
* **Hash chain** -- SHA-256 hash chain construction and management
  (:mod:`~nl_protocol.audit.chain`).
* **HMAC signing** -- HMAC-SHA256 signing, verification, and key rotation
  (:mod:`~nl_protocol.audit.hmac`).
* **Verification** -- full chain verification and fork detection
  (:mod:`~nl_protocol.audit.verification`).
* **Migration** -- hash algorithm migration with dual-write support
  (:mod:`~nl_protocol.audit.migration`).
"""
from __future__ import annotations

from nl_protocol.audit.chain import (
    GENESIS_PREV_HASH,
    ChainManager,
    build_canonical_input,
    compute_hash,
    create_genesis_entry,
    link_record,
)
from nl_protocol.audit.hmac import (
    RotationResult,
    rotate_key,
    sign_record,
    verify_signature,
)
from nl_protocol.audit.migration import (
    ALGORITHM_REGISTRY,
    MigrationCheckpoint,
    MigrationConfig,
    compute_dual_hash,
    compute_hash_with_algorithm,
    create_migration_checkpoint,
    verify_record_hash,
)
from nl_protocol.audit.records import (
    canonical_json,
    create_audit_record,
)
from nl_protocol.audit.verification import (
    BrokenLink,
    ChainVerificationResult,
    ForkDetectionResult,
    detect_fork,
    verify_chain,
)

__all__ = [
    # Records
    "canonical_json",
    "create_audit_record",
    # Chain
    "GENESIS_PREV_HASH",
    "ChainManager",
    "build_canonical_input",
    "compute_hash",
    "create_genesis_entry",
    "link_record",
    # HMAC
    "RotationResult",
    "rotate_key",
    "sign_record",
    "verify_signature",
    # Verification
    "BrokenLink",
    "ChainVerificationResult",
    "ForkDetectionResult",
    "detect_fork",
    "verify_chain",
    # Migration
    "ALGORITHM_REGISTRY",
    "MigrationCheckpoint",
    "MigrationConfig",
    "compute_dual_hash",
    "compute_hash_with_algorithm",
    "create_migration_checkpoint",
    "verify_record_hash",
]
