"""NL Protocol Level 7 -- Nonce management for replay prevention.

This module implements the nonce generation and verification mechanism
described in Chapter 07, Section 3.7.1 of the NL Protocol specification.

Requirements per spec:
* Nonces MUST be generated using a CSPRNG with at least 128 bits of entropy.
* The nonce store MUST retain seen nonces for the lifetime of the
  corresponding delegation token.
* If the nonce store is unavailable, verification MUST fail (fail-closed).
* Nonce entropy MUST NOT be reduced below 128 bits.
"""
from __future__ import annotations

import secrets
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from nl_protocol.core.interfaces import NonceStore


class NonceManager:
    """Manages cryptographic nonces for delegation token replay prevention.

    Wraps a :class:`~nl_protocol.core.interfaces.NonceStore` to provide
    nonce generation with at least 128 bits of entropy and one-time-use
    consumption semantics.

    Parameters
    ----------
    nonce_store:
        The backend store for persisting and checking nonces.
    """

    def __init__(self, nonce_store: NonceStore) -> None:
        self._store = nonce_store

    def generate_nonce(self) -> str:
        """Generate a cryptographically random nonce.

        Uses :func:`secrets.token_urlsafe` with 32 bytes (256 bits) of
        entropy, exceeding the 128-bit minimum required by the spec.

        Returns
        -------
        str
            A URL-safe base64-encoded random string.
        """
        return secrets.token_urlsafe(32)

    async def check_and_consume(self, nonce: str, expires_at: datetime) -> bool:
        """Check if a nonce is fresh and consume it (one-time use).

        Per spec Section 3.7.1, if the nonce has already been seen,
        this constitutes a replay and the method returns ``False``.

        Parameters
        ----------
        nonce:
            The nonce to verify.
        expires_at:
            The expiration time of the associated delegation token.
            The nonce is retained until this time.

        Returns
        -------
        bool
            ``True`` if the nonce is novel (first use);
            ``False`` if replay detected.
        """
        return await self._store.check_and_store(nonce, expires_at)

    async def cleanup_expired(self) -> int:
        """Remove expired nonces from the store.

        Returns
        -------
        int
            The number of expired nonces removed.
        """
        return await self._store.cleanup_expired()
