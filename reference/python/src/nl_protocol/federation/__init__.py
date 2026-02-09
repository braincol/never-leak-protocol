"""NL Protocol Level 7 -- Cross-Agent Trust & Federation.

This subpackage implements the delegation model, token verification,
nonce management, revocation cascading, and token binding mechanisms
defined in Chapter 07 of the NL Protocol specification.

Public API
----------
- :class:`DelegationManager` -- create delegation tokens with subset enforcement.
- :class:`DelegationVerifier` -- 8-step delegation token verification.
- :class:`NonceManager` -- cryptographic nonce generation and replay prevention.
- :class:`CascadeEngine` -- transitive revocation across delegation chains.
- :class:`TokenBinding` -- HMAC-SHA256 based token-to-agent binding.
"""
from __future__ import annotations

from nl_protocol.federation.cascade import CascadeEngine
from nl_protocol.federation.delegation import DelegationManager
from nl_protocol.federation.nonce import NonceManager
from nl_protocol.federation.token_binding import TokenBinding
from nl_protocol.federation.verification import DelegationVerifier

__all__ = [
    "CascadeEngine",
    "DelegationManager",
    "DelegationVerifier",
    "NonceManager",
    "TokenBinding",
]
