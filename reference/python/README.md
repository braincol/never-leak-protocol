# NL Protocol -- Python Reference Implementation

[![PyPI](https://img.shields.io/pypi/v/nl-protocol)](https://pypi.org/project/nl-protocol/)
[![Python](https://img.shields.io/pypi/pyversions/nl-protocol)](https://pypi.org/project/nl-protocol/)
[![License](https://img.shields.io/github/license/braincol/never-leak-protocol)](https://github.com/braincol/never-leak-protocol/blob/main/LICENSE)

**The canonical reference implementation of the Never-Leak Protocol -- an open standard for AI agent secret governance.**

> *"Agents request actions, not secrets."*

---

## What is the NL Protocol?

The Never-Leak Protocol (NL Protocol) defines a layered security architecture for AI agent systems that need to interact with secrets -- API keys, database credentials, tokens, certificates -- without ever exposing those secrets to the agents themselves.

In traditional integrations, secrets are passed directly to agents as environment variables, configuration files, or tool arguments. This creates a fundamental risk: any agent that can read a secret can also exfiltrate it, whether through prompt injection, model hallucination, or compromised tool code. The NL Protocol eliminates this attack surface entirely.

Instead of receiving secrets, agents submit **action requests** that contain opaque placeholders (`{{nl:api/DEPLOY_TOKEN}}`). An NL-compliant provider resolves these placeholders inside an isolated execution boundary, runs the action, sanitizes the output, and returns only the result. The agent never sees the secret value at any point in the pipeline.

The protocol is organized into **7 security levels**, from agent identity verification through cross-agent delegation, plus a wire protocol layer for transport. Each level can be adopted incrementally, allowing teams to start with basic access control and progressively harden their deployments.

## Quick Start

### Installation

```bash
pip install nl-protocol
```

With optional extras:

```bash
pip install nl-protocol[re2]    # RE2 pattern engine for deny rules
pip install nl-protocol[http]   # HTTP transport support
pip install nl-protocol[all]    # All optional dependencies
```

### Minimal Example

```python
import asyncio
import uuid
from datetime import UTC, datetime, timedelta

from nl_protocol import NLProvider, NLProviderConfig
from nl_protocol.core.interfaces import (
    InMemoryAgentRegistry,
    InMemoryAuditStore,
    InMemorySecretStore,
    InMemoryScopeGrantStore,
)
from nl_protocol.core.types import (
    AID, ActionPayload, ActionRequest, ActionType,
    AgentURI, ScopeConditions, ScopeGrant, SecretRef,
    SecretValue, TrustLevel,
)

async def main() -> None:
    # 1. Create the provider with in-memory stores
    secret_store = InMemorySecretStore()
    provider = NLProvider(
        config=NLProviderConfig(provider_id="my-provider"),
        secret_store=secret_store,
        agent_registry=InMemoryAgentRegistry(),
        scope_grant_store=InMemoryScopeGrantStore(),
        audit_store=InMemoryAuditStore(),
    )

    # 2. Register an agent
    agent_uri = AgentURI("nl://acme/web-deployer/1.0.0")
    aid = AID(
        agent_uri=agent_uri,
        display_name="ACME Web Deployer",
        vendor="acme",
        version="1.0.0",
        scope=["api/*"],
        trust_level=TrustLevel.L1,
        capabilities=[ActionType.HTTP],
        expires_at=datetime.now(UTC) + timedelta(days=365),
    )
    await provider.register_agent(aid)

    # 3. Add a secret (admin-only, out-of-band)
    secret_store.put(
        SecretRef("api/DEPLOY_TOKEN"),
        SecretValue("sk-live-abc123-NEVER-SHOWN-TO-AGENTS"),
    )

    # 4. Create a scope grant
    grant = ScopeGrant(
        grant_id=str(uuid.uuid4()),
        agent_uri=agent_uri,
        secret="api/*",
        actions=[ActionType.HTTP],
        conditions=ScopeConditions(
            valid_until=datetime.now(UTC) + timedelta(hours=8),
            max_uses=50,
        ),
    )
    await provider.create_scope_grant(grant)

    # 5. Process an action request
    request = ActionRequest(
        agent_uri=agent_uri,
        action=ActionPayload(
            type=ActionType.HTTP,
            template="curl -H 'Authorization: Bearer {{nl:api/DEPLOY_TOKEN}}' https://api.example.com/deploy",
            purpose="Trigger production deployment",
            timeout=30,
        ),
    )
    response = await provider.process_action(request)

    print(f"Status: {response.status}")
    # The agent never saw the secret value.

asyncio.run(main())
```

## Architecture

### Package Structure

```
nl_protocol/
    __init__.py              # Public API re-exports
    provider.py              # NLProvider -- main orchestrator
    core/
        types.py             # AID, ScopeGrant, ActionRequest, SecretValue, ...
        errors.py            # NLProtocolError hierarchy (40+ error codes)
        config.py            # NLProviderConfig
        interfaces.py        # Protocol classes + InMemory* implementations
    identity/                # Level 1: Agent Identity
        aid.py               # AIDManager
        lifecycle.py         # LifecycleManager
        trust_levels.py      # TrustLevelManager
        attestation.py       # AttestationService (JWT ES256/EdDSA)
    access/                  # Level 2: Action-Based Access
        scope_grants.py      # ScopeEvaluator
        placeholders.py      # PlaceholderResolver ({{nl:...}})
        policy.py            # PolicyEvaluator (5-step evaluation)
        sanitization.py      # OutputSanitizer
        actions.py           # ActionValidator
    isolation/               # Level 3: Execution Isolation
        subprocess.py        # IsolatedExecutor
        environment.py       # EnvironmentManager (env var injection)
        memory.py            # SecureMemory (memory wipe)
        sandbox.py           # SandboxConfig, ResourceLimits
    defense/                 # Level 4: Pre-Execution Defense
        deny_rules.py        # DenyRuleEngine (25+ built-in rules)
        pattern_engine.py    # PatternEngine (RE2 support)
        validation.py        # CommandValidator, evasion detection
    audit/                   # Level 5: Audit Integrity
        chain.py             # ChainManager (SHA-256 hash chain)
        hmac.py              # HMAC-SHA256 signing
        records.py           # Record creation, canonical JSON (RFC 8785)
        verification.py      # Chain verification, fork detection
        migration.py         # Chain migration utilities
    detection/               # Level 6: Attack Detection
        threat_scoring.py    # ThreatScorer (T1-T11 threat types)
        behavioral.py        # BehavioralBaseline (EWMA)
        honeypot.py          # HoneypotManager
        response.py          # ResponseEngine (automated response actions)
    federation/              # Level 7: Cross-Agent Trust
        delegation.py        # DelegationManager
        verification.py      # DelegationVerifier (8-step verification)
        cascade.py           # CascadeEngine (cascade revocation)
        nonce.py             # NonceManager (replay prevention)
        token_binding.py     # TokenBinding
    wire/                    # Level 8: Wire Protocol
        messages.py          # MessageEnvelope, parse/serialize
        ndjson.py            # NDJSONReader, NDJSONWriter, StdioTransport
        http.py              # HTTPTransport
        discovery.py         # Service discovery (DiscoveryDocument)
```

### The 7 Security Levels

| Level | Name | Module | Key Components | Purpose |
|-------|------|--------|----------------|---------|
| 1 | Agent Identity | `identity` | `AIDManager`, `AttestationService`, `TrustLevelManager` | AID lifecycle, trust levels (L0-L3), JWT attestation (ES256, EdDSA) |
| 2 | Action-Based Access | `access` | `ScopeEvaluator`, `PlaceholderResolver`, `PolicyEvaluator` | Scope grants, `{{nl:...}}` placeholders, 5-step policy evaluation |
| 3 | Execution Isolation | `isolation` | `IsolatedExecutor`, `EnvironmentManager`, `SecureMemory` | Subprocess env injection, memory wipe, timeout enforcement |
| 4 | Pre-Execution Defense | `defense` | `DenyRuleEngine`, `PatternEngine`, `CommandValidator` | 25+ deny rules, RE2 pattern matching, unicode evasion detection |
| 5 | Audit Integrity | `audit` | `ChainManager`, `sign_record`, `verify_chain` | SHA-256 hash chain, HMAC-SHA256 signing, canonical JSON (RFC 8785) |
| 6 | Attack Detection | `detection` | `ThreatScorer`, `BehavioralBaseline`, `HoneypotManager` | T1-T11 threat scoring, EWMA behavioral baseline, honeypot secrets |
| 7 | Cross-Agent Trust | `federation` | `DelegationManager`, `DelegationVerifier`, `CascadeEngine` | Delegation tokens, subset rule, 8-step verification, cascade revocation |
| 8 | Wire Protocol | `wire` | `StdioTransport`, `HTTPTransport`, `DiscoveryDocument` | NDJSON stdio, HTTP transport, service discovery |

## Usage

### Setting Up the Provider

The `NLProvider` is the main entry point. It composes all level-specific components and routes action requests through the pipeline.

```python
from nl_protocol import NLProvider, NLProviderConfig
from nl_protocol.core.interfaces import (
    InMemoryAgentRegistry,
    InMemoryAuditStore,
    InMemorySecretStore,
    InMemoryScopeGrantStore,
    InMemoryNonceStore,
    InMemoryDelegationStore,
)

provider = NLProvider(
    config=NLProviderConfig(
        provider_id="production-provider",
        supported_levels=[1, 2, 3, 4, 5, 6, 7],
        default_action_timeout=30,
        audit_fail_closed=True,
    ),
    secret_store=InMemorySecretStore(),        # Replace with your backend
    agent_registry=InMemoryAgentRegistry(),     # Replace with your backend
    scope_grant_store=InMemoryScopeGrantStore(),# Replace with your backend
    audit_store=InMemoryAuditStore(),           # Optional: Level 5
    nonce_store=InMemoryNonceStore(),           # Optional: replay prevention
    delegation_store=InMemoryDelegationStore(), # Optional: Level 7
)
```

### Working with Scope Grants

Scope grants bind agents to permitted secrets and actions. They support glob patterns, time windows, and use limits.

```python
from nl_protocol.core.types import (
    ActionType, AgentURI, ScopeConditions, ScopeGrant,
)

grant = ScopeGrant(
    grant_id="grant-001",
    agent_uri=AgentURI("nl://acme/deployer/1.0.0"),
    secret="production/db/*",       # Glob pattern
    actions=[ActionType.EXEC, ActionType.TEMPLATE],
    conditions=ScopeConditions(
        valid_from=datetime.now(UTC),
        valid_until=datetime.now(UTC) + timedelta(hours=4),
        max_uses=100,
    ),
)
await provider.create_scope_grant(grant)

# Revoke when no longer needed
await provider.revoke_scope_grant("grant-001")
```

### Processing Actions

Agents submit action requests with opaque `{{nl:...}}` placeholders. The provider resolves secrets, executes the action, and returns a sanitized result.

```python
from nl_protocol.core.types import (
    ActionPayload, ActionRequest, ActionType, AgentURI,
)

request = ActionRequest(
    agent_uri=AgentURI("nl://acme/deployer/1.0.0"),
    action=ActionPayload(
        type=ActionType.EXEC,
        template="psql -U admin -d mydb -c 'SELECT 1' --password={{nl:production/db/PASSWORD}}",
        purpose="Health check on production database",
        timeout=15,
    ),
)
response = await provider.process_action(request)

if response.status == "success":
    print(response.result.stdout)
elif response.status == "denied":
    print(f"Denied: [{response.error.code}] {response.error.message}")
elif response.status == "error":
    print(f"Error: [{response.error.code}] {response.error.message}")

# Every response includes an audit reference
if response.audit_ref:
    print(f"Audit ref: {response.audit_ref}")
```

### Audit Chain

The audit system produces a tamper-evident hash chain. Each record includes the SHA-256 hash of the previous record and an optional HMAC signature.

```python
from nl_protocol.audit import (
    ChainManager,
    create_audit_record,
    compute_hash,
    sign_record,
    verify_chain,
)

# Records are created automatically by the provider pipeline.
# For manual chain verification:
chain = await audit_store.get_chain(limit=100)
result = verify_chain(chain)
print(f"Chain valid: {result.valid}")
print(f"Records verified: {result.records_checked}")
```

## Configuration

`NLProviderConfig` controls all tunable parameters. Every field has a sensible default, so a minimal configuration requires only `provider_id`.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `provider_id` | `str` | *(required)* | Unique identifier for this NL Provider instance |
| `supported_levels` | `list[int]` | `[1, 2, 3, 4, 5, 6, 7]` | NL Protocol levels implemented by this provider |
| `max_delegation_depth` | `int` | `3` | Maximum allowed re-delegation depth (Level 7) |
| `default_action_timeout` | `int` | `30` | Default action timeout in seconds (1-600) |
| `max_output_size` | `int` | `10485760` | Maximum output size in bytes (10 MiB) |
| `sanitization_timeout_ms` | `int` | `500` | Max time for output sanitization before withholding |
| `threat_score_decay_per_hour` | `float` | `1.0` | Points/hour subtracted from cumulative threat score |
| `hmac_key_id` | `str` | `"default"` | Identifier for the HMAC key used in audit records |
| `clock_drift_tolerance_seconds` | `int` | `30` | Allowable clock drift for timestamp validation |
| `audit_fail_closed` | `bool` | `True` | Block actions if the audit subsystem is unavailable |
| `max_message_size_bytes` | `int` | `1048576` | Maximum wire-protocol message size (1 MiB) |
| `idempotency_window_seconds` | `int` | `300` | Duration for message-id idempotency enforcement |
| `timestamp_tolerance_seconds` | `int` | `300` | Max message timestamp deviation from server time |
| `rate_limit_requests_per_minute` | `int` | `120` | Default per-agent rate limit |

## Backend Interfaces

The protocol defines six abstract interfaces (Python `typing.Protocol` classes) for persistence. You provide implementations that match your infrastructure; the library ships in-memory versions for testing and development.

| Interface | Purpose | In-Memory Implementation |
|-----------|---------|--------------------------|
| `SecretStore` | Secret value resolution | `InMemorySecretStore` |
| `AgentRegistry` | Agent identity persistence | `InMemoryAgentRegistry` |
| `ScopeGrantStore` | Scope grant persistence | `InMemoryScopeGrantStore` |
| `AuditStore` | Append-only audit chain | `InMemoryAuditStore` |
| `NonceStore` | Replay prevention (nonce tracking) | `InMemoryNonceStore` |
| `DelegationStore` | Delegation token storage | `InMemoryDelegationStore` |

All interfaces are decorated with `@runtime_checkable`, so `isinstance` checks work at runtime alongside static analysis.

### Implementing a Custom Store

```python
from nl_protocol.core.interfaces import SecretStore
from nl_protocol.core.types import SecretRef, SecretValue
from nl_protocol.core.errors import SecretNotFound

class VaultSecretStore:
    """Custom SecretStore backed by HashiCorp Vault."""

    def __init__(self, vault_client):
        self._client = vault_client

    async def get(self, ref: SecretRef) -> SecretValue:
        path = str(ref).replace("/", "/data/")
        result = await self._client.read(f"secret/{path}")
        if result is None:
            raise SecretNotFound(f"Secret not found: {ref}")
        return SecretValue(result["data"]["value"])

    async def exists(self, ref: SecretRef) -> bool:
        path = str(ref).replace("/", "/data/")
        result = await self._client.read(f"secret/{path}")
        return result is not None

    async def list_refs(self) -> list[SecretRef]:
        keys = await self._client.list("secret/metadata")
        return [SecretRef(k) for k in keys]
```

The custom store can then be passed to `NLProvider`:

```python
provider = NLProvider(
    config=NLProviderConfig(provider_id="vault-provider"),
    secret_store=VaultSecretStore(vault_client),
    agent_registry=InMemoryAgentRegistry(),
    scope_grant_store=InMemoryScopeGrantStore(),
)
```

## Error Handling

All errors inherit from `NLProtocolError` and carry a structured error code, HTTP status recommendation, human-readable message, and machine-readable details. Errors are organized into eight categories corresponding to the protocol levels.

| Code Range | Category | Class | HTTP Status | Description |
|------------|----------|-------|-------------|-------------|
| NL-E1xx | Authentication | `AuthenticationError` | 401/403 | Agent identity, attestation, trust level |
| NL-E2xx | Authorization | `AuthorizationError` | 403/429 | Scope grants, conditions, approval |
| NL-E3xx | Execution | `ExecutionError` | 400/404/408/500/502 | Placeholders, secrets, timeouts, isolation |
| NL-E4xx | Defense | `DefenseError` | 403 | Deny rules, evasion, interceptor failures |
| NL-E5xx | Audit | `AuditError` | 403/500 | Hash chain integrity, write failures |
| NL-E6xx | Detection | `DetectionError` | 403 | Threat score, auto-revocation, honeypots |
| NL-E7xx | Federation | `FederationError` | 400/403/404/429/502 | Delegation, trust domains, subset violations |
| NL-E8xx | Transport | `TransportError` | 400/409/413/415 | Wire protocol, versioning, replay, message format |

Catch errors by category:

```python
from nl_protocol.core.errors import AuthorizationError, NLProtocolError

try:
    response = await provider.process_action(request)
except AuthorizationError as exc:
    # Handles NoScopeGrant, ScopeExpired, UseLimitExceeded, etc.
    print(f"[{exc.code}] {exc.message}")
except NLProtocolError as exc:
    # Catch-all for any NL Protocol error
    print(f"[{exc.code}] {exc.message}")
```

Or look up an error by code:

```python
from nl_protocol.core.errors import error_from_code

exc = error_from_code("NL-E302", "Secret 'db/password' not found")
```

## Conformance Tiers

Implementations may conform at three tiers, each adding levels to the pipeline:

| Tier | Levels | Requirements |
|------|--------|--------------|
| **Basic** | L1-L3 | Agent identity, action-based access, execution isolation |
| **Standard** | L1-L5 | Basic + pre-execution defense, audit integrity |
| **Advanced** | L1-L7 | Standard + attack detection, cross-agent trust |

The `supported_levels` field in `NLProviderConfig` declares which levels an instance implements. The provider automatically skips pipeline stages for levels not listed.

## Development

### Prerequisites

- Python >= 3.11
- [Hatch](https://hatch.pypa.io/) (build backend) or pip with editable installs

### Setup

```bash
git clone https://github.com/braincol/never-leak-protocol.git
cd never-leak-protocol/reference/python
pip install -e ".[dev]"
```

### Running Tests

```bash
# Run the full test suite (718 unit + 189 conformance = 907 tests)
pytest

# With coverage
pytest --cov=nl_protocol --cov-report=term-missing

# Run tests for a specific level
pytest tests/test_identity.py      # Level 1
pytest tests/test_access.py        # Level 2
pytest tests/test_isolation.py     # Level 3
pytest tests/test_defense.py       # Level 4
pytest tests/test_audit.py         # Level 5
pytest tests/test_detection.py     # Level 6
pytest tests/test_federation.py    # Level 7
pytest tests/test_wire.py          # Level 8
pytest tests/test_provider.py      # Orchestrator integration
```

### Type Checking

```bash
mypy src/nl_protocol --strict
```

### Linting

```bash
ruff check src/ tests/
ruff format --check src/ tests/
```

## Implementation Stats

- **49** source files, **~11,100** lines of implementation
- **9** test files, **~9,600** lines of tests
- **907** tests passing (718 unit + 189 conformance)
- **40+** structured error codes (NL-E100 through NL-E806)
- **100%** async/await API
- **Full** Pydantic v2 model validation
- **Strict** mypy type checking

## Links

- **Specification:** https://neverleakprotocol.org/spec
- **Website:** https://neverleakprotocol.org
- **Repository:** https://github.com/braincol/never-leak-protocol
- **Package:** https://pypi.org/project/nl-protocol/

## License

Apache-2.0. See [LICENSE](https://github.com/braincol/never-leak-protocol/blob/main/LICENSE) for details.

---

Built by [Braincol](https://braincol.com) -- protocol@braincol.com
