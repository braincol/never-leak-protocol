"""NL Protocol service discovery (``/.well-known/nl-protocol``).

This module implements the discovery protocol defined in Chapter 08,
Section 7 of the NL Protocol specification.  It provides:

* **DiscoveryDocument** -- a dataclass representing the complete discovery
  document schema (Section 7.2).
* **create_discovery_document** -- factory that builds a discovery document
  from an :class:`NLProviderConfig`.
* **serialize_discovery** -- JSON serialisation of a discovery document.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from nl_protocol.wire.messages import NL_PROTOCOL_VERSION

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class DiscoveryDocument:
    """NL Protocol discovery document (Section 7.2).

    Every NL-compliant system exposing an HTTP transport MUST serve this
    document at ``GET /.well-known/nl-protocol``.  The document describes
    the provider's capabilities, endpoints, and supported features.

    Attributes
    ----------
    protocol_version:
        NL Protocol version string (e.g. ``"1.0"``).
    provider_name:
        Human-readable name of the NL Provider.
    provider_vendor:
        Domain of the operating organisation.
    provider_version:
        Implementation version string.
    capabilities:
        Provider capability advertisement.
    endpoints:
        Mapping of endpoint names to URL paths.
    supported_algorithms:
        List of cryptographic algorithms supported.
    supported_levels:
        NL Protocol levels (1-7) that are implemented.
    supports_delegation:
        Whether delegation tokens are supported.
    supports_federation:
        Whether cross-organisation federation is supported.
    max_message_size_bytes:
        Maximum accepted message size.
    """

    protocol_version: str = NL_PROTOCOL_VERSION
    provider_name: str = ""
    provider_vendor: str = ""
    provider_version: str = ""
    capabilities: dict[str, Any] = field(default_factory=dict)
    endpoints: dict[str, str] = field(default_factory=dict)
    supported_algorithms: list[str] = field(default_factory=lambda: ["sha256"])
    supported_levels: list[int] = field(default_factory=lambda: [1, 2, 3, 4, 5, 6, 7])
    supports_delegation: bool = True
    supports_federation: bool = False
    max_message_size_bytes: int = 1_048_576


# ---------------------------------------------------------------------------
# Default endpoints per Section 5.3
# ---------------------------------------------------------------------------

_DEFAULT_ENDPOINTS: dict[str, str] = {
    "actions": "/nl/v1/actions",
    "agents_register": "/nl/v1/agents/register",
    "agents_get": "/nl/v1/agents/{agent_id}",
    "delegations": "/nl/v1/delegations",
    "delegations_revoke": "/nl/v1/delegations/{token_id}",
    "revocations": "/nl/v1/revocations",
    "audit": "/nl/v1/audit",
    "health": "/nl/v1/health",
}


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def create_discovery_document(
    config: Any,
    *,
    provider_name: str = "NL Protocol Reference Implementation",
    provider_vendor: str = "braincol.com",
    provider_version: str = "1.0.0a1",
    base_url: str = "",
) -> DiscoveryDocument:
    """Build a :class:`DiscoveryDocument` from a provider configuration.

    Parameters
    ----------
    config:
        An :class:`NLProviderConfig` instance.
    provider_name:
        Human-readable name of the provider.
    provider_vendor:
        Organisation domain.
    provider_version:
        Implementation version string.
    base_url:
        Base URL for endpoint paths.  When empty, relative paths are used.

    Returns
    -------
    DiscoveryDocument
        A fully populated discovery document.
    """
    # Build endpoints with optional base_url prefix
    endpoints: dict[str, str] = {}
    prefix = base_url.rstrip("/") if base_url else ""
    for name, path in _DEFAULT_ENDPOINTS.items():
        endpoints[name] = f"{prefix}{path}" if prefix else path

    if prefix:
        endpoints["base_url"] = prefix

    # Build capabilities from config
    capabilities: dict[str, Any] = {
        "conformance_level": "standard",
        "supported_levels": list(config.supported_levels),
        "action_types": ["exec", "template", "inject_stdin", "inject_tempfile", "sdk_proxy"],
        "trust_levels": ["L0", "L1", "L2", "L3"],
        "credential_types": ["api_key", "bearer_token"],
        "max_message_size_bytes": config.max_message_size_bytes,
        "max_timeout_ms": config.default_action_timeout * 1000,
        "supports_delegation": config.max_delegation_depth > 0,
        "supports_federation": 7 in config.supported_levels,
        "supports_dry_run": True,
        "supports_batch_actions": False,
    }

    return DiscoveryDocument(
        protocol_version=NL_PROTOCOL_VERSION,
        provider_name=provider_name,
        provider_vendor=provider_vendor,
        provider_version=provider_version,
        capabilities=capabilities,
        endpoints=endpoints,
        supported_levels=list(config.supported_levels),
        supports_delegation=config.max_delegation_depth > 0,
        supports_federation=7 in config.supported_levels,
        max_message_size_bytes=config.max_message_size_bytes,
    )


# ---------------------------------------------------------------------------
# Serialisation
# ---------------------------------------------------------------------------


def serialize_discovery(doc: DiscoveryDocument) -> str:
    """Serialise a :class:`DiscoveryDocument` to a JSON string.

    The output conforms to the schema defined in Section 7.2 of the
    NL Protocol specification.

    Parameters
    ----------
    doc:
        The discovery document to serialise.

    Returns
    -------
    str
        A JSON string suitable for the ``/.well-known/nl-protocol`` response body.
    """
    payload: dict[str, Any] = {
        "nl_protocol": {
            "versions": [doc.protocol_version],
            "preferred_version": doc.protocol_version,
        },
        "provider": {
            "name": doc.provider_name,
            "vendor": doc.provider_vendor,
            "version": doc.provider_version,
        },
        "endpoints": doc.endpoints,
        "capabilities": doc.capabilities,
    }

    return json.dumps(payload, indent=2)
