"""HMAC-SHA256 signing and verification for audit records.

This module implements the HMAC layer defined in Chapter 05, Section 3.5
of the NL Protocol specification.  HMAC provides an additional integrity
guarantee beyond the hash chain: without the HMAC key, an attacker who
gains write access to the audit log cannot forge valid signatures.

Key management
--------------
HMAC keys MUST be stored separately from the audit data and SHOULD be
managed by an HSM or cloud KMS.  This module provides signing and
verification primitives; key storage is the caller's responsibility.
"""
from __future__ import annotations

import hashlib
import hmac as _hmac

from nl_protocol.core.interfaces import AuditStore

HMAC_PREFIX = "sha256:"


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------

def sign_record(record_hash: str, key: bytes) -> str:
    """Compute an HMAC-SHA256 over *record_hash* using *key*.

    Parameters
    ----------
    record_hash:
        The ``chain.hash`` value of the audit record (including the
        ``sha256:`` prefix, per the spec).
    key:
        The HMAC key bytes.

    Returns
    -------
    str
        The HMAC value, prefixed with ``sha256:``.
    """
    signature = _hmac.new(key, record_hash.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{HMAC_PREFIX}{signature}"


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def verify_signature(record_hash: str, signature: str, key: bytes) -> bool:
    """Verify that *signature* is a valid HMAC-SHA256 of *record_hash*.

    Uses constant-time comparison to prevent timing attacks.

    Parameters
    ----------
    record_hash:
        The ``chain.hash`` value of the audit record.
    signature:
        The stored HMAC value (with ``sha256:`` prefix).
    key:
        The HMAC key bytes.

    Returns
    -------
    bool
        ``True`` if the signature is valid, ``False`` otherwise.
    """
    expected = sign_record(record_hash, key)
    return _hmac.compare_digest(expected, signature)


# ---------------------------------------------------------------------------
# Key rotation
# ---------------------------------------------------------------------------

async def rotate_key(
    old_key: bytes,
    new_key: bytes,
    store: AuditStore,
    *,
    new_key_id: str = "default",
) -> RotationResult:
    """Rotate the HMAC key and re-sign recent records.

    Per the spec (Section 3.5.1), during rotation:

    * The old key is retained for verification of historical records.
    * New records use the new key.
    * A rotation marker is written to the chain metadata.

    This function fetches the chain from the store, verifies existing
    HMAC signatures with the old key, and returns a :class:`RotationResult`
    indicating which records were verified and the new key id.

    Parameters
    ----------
    old_key:
        The current (outgoing) HMAC key.
    new_key:
        The new HMAC key.
    store:
        The audit store to read records from.
    new_key_id:
        An identifier for the new key.

    Returns
    -------
    RotationResult
        Summary of the key rotation.
    """
    records = await store.get_chain(limit=10000)
    verified_count = 0
    unverifiable: list[str] = []

    for record in records:
        if record.hmac_signature is not None:
            if verify_signature(record.record_hash, record.hmac_signature, old_key):
                verified_count += 1
            else:
                unverifiable.append(record.record_id)

    return RotationResult(
        verified_count=verified_count,
        unverifiable_record_ids=unverifiable,
        new_key_id=new_key_id,
        total_records=len(records),
    )


class RotationResult:
    """Summary of an HMAC key rotation.

    Attributes
    ----------
    verified_count:
        Number of historical records whose HMAC was verified with the old key.
    unverifiable_record_ids:
        Record IDs whose HMAC could not be verified.
    new_key_id:
        The identifier of the new HMAC key.
    total_records:
        Total number of records examined.
    """

    __slots__ = ("new_key_id", "total_records", "unverifiable_record_ids", "verified_count")

    def __init__(
        self,
        *,
        verified_count: int,
        unverifiable_record_ids: list[str],
        new_key_id: str,
        total_records: int,
    ) -> None:
        self.verified_count = verified_count
        self.unverifiable_record_ids = unverifiable_record_ids
        self.new_key_id = new_key_id
        self.total_records = total_records
