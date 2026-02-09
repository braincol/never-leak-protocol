"""NL Protocol Level 7 -- HMAC-based token binding.

This module implements the token binding mechanism described in Chapter 07,
Section 3.4 of the NL Protocol specification.  Token binding prevents stolen
``token_id`` values from being used by unauthorized agents by cryptographically
tying the token to a specific agent identity.

Binding proof:
    ``HMAC-SHA256(secret_key, token_id || agent_uri || timestamp)``

The NL Provider verifies that the proof is valid for the presenting agent's
``agent_id`` and that the timestamp is within the acceptable window
(+/- 30 seconds by default).
"""
from __future__ import annotations

import hashlib
import hmac
import time


class TokenBinding:
    """HMAC-SHA256 based token binding for delegation security.

    Binds a delegation token to a specific agent so that a stolen
    ``token_id`` is useless without the corresponding binding secret.

    Parameters
    ----------
    timestamp_tolerance:
        Maximum allowed clock skew in seconds (default 30).
    """

    def __init__(self, *, timestamp_tolerance: int = 30) -> None:
        self._tolerance = timestamp_tolerance

    def create_proof(
        self,
        token_id: str,
        agent_uri: str,
        secret_key: str,
        *,
        timestamp: int | None = None,
    ) -> str:
        """Create an HMAC-SHA256 binding proof.

        Parameters
        ----------
        token_id:
            The delegation token identifier.
        agent_uri:
            The AID URI of the agent presenting the token.
        secret_key:
            The token binding key (shared secret).
        timestamp:
            Optional UNIX timestamp override (for testing).

        Returns
        -------
        str
            The hex-encoded HMAC-SHA256 proof in the format
            ``<timestamp>.<hex_hmac>``.
        """
        ts = timestamp if timestamp is not None else int(time.time())
        message = f"{token_id}||{agent_uri}||{ts}"
        mac = hmac.new(
            secret_key.encode("utf-8"),
            message.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return f"{ts}.{mac}"

    def verify_proof(
        self,
        token_id: str,
        agent_uri: str,
        proof: str,
        secret_key: str,
        *,
        current_time: int | None = None,
    ) -> bool:
        """Verify an HMAC-SHA256 binding proof.

        Parameters
        ----------
        token_id:
            The delegation token identifier.
        agent_uri:
            The AID URI of the agent that should be bound.
        proof:
            The proof string in ``<timestamp>.<hex_hmac>`` format.
        secret_key:
            The token binding key (shared secret).
        current_time:
            Optional UNIX timestamp override (for testing).

        Returns
        -------
        bool
            ``True`` if the proof is valid and within the time window.
        """
        parts = proof.split(".", 1)
        if len(parts) != 2:
            return False

        try:
            ts = int(parts[0])
        except ValueError:
            return False

        now = current_time if current_time is not None else int(time.time())
        if abs(now - ts) > self._tolerance:
            return False

        message = f"{token_id}||{agent_uri}||{ts}"
        expected = hmac.new(
            secret_key.encode("utf-8"),
            message.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        return hmac.compare_digest(parts[1], expected)
