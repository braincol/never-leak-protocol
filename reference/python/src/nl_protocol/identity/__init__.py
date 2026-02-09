"""NL Protocol Level 1 -- Agent Identity.

This subpackage implements the Agent Identity layer as defined in the
NL Protocol Specification v1.0, Chapter 01.  It provides:

* **AIDManager** -- creation, registration, retrieval, validation,
  verification, and scope-checking of Agent Identity Documents.
* **AttestationService** -- JWT-based platform attestation: token
  creation and cryptographic verification (ES256, EdDSA).
* **TrustLevelManager** -- trust-level capability evaluation,
  capability validation, and promotion/demotion guards.
* **LifecycleManager** -- state-machine for agent lifecycle
  transitions (provisioned -> active -> suspended / revoked).
"""
from __future__ import annotations

from nl_protocol.identity.aid import AIDManager
from nl_protocol.identity.attestation import AttestationService
from nl_protocol.identity.lifecycle import InvalidLifecycleTransition, LifecycleManager
from nl_protocol.identity.trust_levels import TrustLevelManager

__all__ = [
    "AIDManager",
    "AttestationService",
    "InvalidLifecycleTransition",
    "LifecycleManager",
    "TrustLevelManager",
]
