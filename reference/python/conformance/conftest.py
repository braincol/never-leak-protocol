"""Shared fixtures for NL Protocol conformance tests.

Provides common setup for agents, secrets, scope grants, stores,
and other reusable test infrastructure.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from nl_protocol.core.interfaces import (
    InMemoryAgentRegistry,
    InMemoryAuditStore,
    InMemoryDelegationStore,
    InMemoryNonceStore,
    InMemoryScopeGrantStore,
    InMemorySecretStore,
)
from nl_protocol.core.types import (
    AID,
    ActionPayload,
    ActionRequest,
    ActionType,
    AgentURI,
    DelegationScope,
    DelegationToken,
    LifecycleState,
    ScopeConditions,
    ScopeGrant,
    SecretRef,
    SecretValue,
    TrustLevel,
)

# ---------------------------------------------------------------------------
# Common URIs and refs used across tests
# ---------------------------------------------------------------------------
AGENT_URI = AgentURI("nl://acme.com/test-agent/1.0.0")
AGENT_URI_B = AgentURI("nl://acme.com/sub-agent/1.0.0")
SYSTEM_URI = AgentURI("nl://system/audit-manager")
SECRET_REF = SecretRef("api/TOKEN")
SECRET_VALUE = "super-secret-value-1234"
HMAC_KEY = b"conformance-test-hmac-key-32bytes"


# ---------------------------------------------------------------------------
# Store fixtures
# ---------------------------------------------------------------------------
@pytest.fixture()
def secret_store() -> InMemorySecretStore:
    store = InMemorySecretStore()
    store.put(SecretRef("api/TOKEN"), SecretValue(SECRET_VALUE))
    store.put(SecretRef("db/PASSWORD"), SecretValue("db-pass-5678"))
    return store


@pytest.fixture()
def agent_registry() -> InMemoryAgentRegistry:
    return InMemoryAgentRegistry()


@pytest.fixture()
def scope_grant_store() -> InMemoryScopeGrantStore:
    return InMemoryScopeGrantStore()


@pytest.fixture()
def audit_store() -> InMemoryAuditStore:
    return InMemoryAuditStore()


@pytest.fixture()
def nonce_store() -> InMemoryNonceStore:
    return InMemoryNonceStore()


@pytest.fixture()
def delegation_store() -> InMemoryDelegationStore:
    return InMemoryDelegationStore()


# ---------------------------------------------------------------------------
# Agent AID helpers
# ---------------------------------------------------------------------------
def make_aid(
    agent_uri: AgentURI = AGENT_URI,
    *,
    trust_level: TrustLevel = TrustLevel.L2,
    lifecycle_state: LifecycleState = LifecycleState.ACTIVE,
    scope: list[str] | None = None,
    capabilities: list[ActionType] | None = None,
    expires_at: datetime | None = None,
) -> AID:
    """Build an AID with sensible defaults for testing."""
    return AID(
        agent_uri=agent_uri,
        display_name="Test Agent",
        vendor="acme.com",
        version="1.0.0",
        scope=scope or ["api/*", "db/*"],
        trust_level=trust_level,
        capabilities=capabilities or [ActionType.READ, ActionType.TEMPLATE],
        created_at=datetime.now(UTC) - timedelta(hours=1),
        expires_at=expires_at or (datetime.now(UTC) + timedelta(days=30)),
        lifecycle_state=lifecycle_state,
    )


@pytest.fixture()
async def active_agent(agent_registry: InMemoryAgentRegistry) -> AID:
    aid = make_aid()
    await agent_registry.register(aid)
    return aid


# ---------------------------------------------------------------------------
# Scope grant helpers
# ---------------------------------------------------------------------------
def make_grant(
    agent_uri: AgentURI = AGENT_URI,
    secret: str = "api/*",
    actions: list[ActionType] | None = None,
    *,
    max_uses: int | None = None,
    valid_until: datetime | None = None,
    revoked: bool = False,
) -> ScopeGrant:
    """Build a ScopeGrant with sensible defaults for testing."""
    return ScopeGrant(
        grant_id=str(uuid.uuid4()),
        agent_uri=agent_uri,
        secret=secret,
        actions=actions or [ActionType.EXEC, ActionType.TEMPLATE, ActionType.READ],
        conditions=ScopeConditions(
            valid_from=datetime.now(UTC) - timedelta(hours=1),
            valid_until=valid_until or (datetime.now(UTC) + timedelta(days=7)),
            max_uses=max_uses,
        ),
        revoked=revoked,
    )


@pytest.fixture()
async def active_grant(
    scope_grant_store: InMemoryScopeGrantStore,
) -> ScopeGrant:
    grant = make_grant()
    await scope_grant_store.create_grant(grant)
    return grant


# ---------------------------------------------------------------------------
# Delegation token helper
# ---------------------------------------------------------------------------
def make_delegation_token(
    issuer: AgentURI = AGENT_URI,
    subject: AgentURI = AGENT_URI_B,
    *,
    expires_at: datetime | None = None,
    max_depth: int = 3,
    current_depth: int = 0,
) -> DelegationToken:
    """Build a DelegationToken with sensible defaults for testing."""
    return DelegationToken(
        token_id=str(uuid.uuid4()),
        issuer=issuer,
        subject=subject,
        scope=DelegationScope(
            secrets=["api/*"],
            actions=[ActionType.READ],
        ),
        expires_at=expires_at or (datetime.now(UTC) + timedelta(hours=1)),
        max_delegation_depth=max_depth,
        current_depth=current_depth,
    )


# ---------------------------------------------------------------------------
# Action request helper
# ---------------------------------------------------------------------------
def make_action_request(
    agent_uri: AgentURI = AGENT_URI,
    template: str = "echo {{nl:api/TOKEN}}",
    action_type: ActionType = ActionType.EXEC,
    purpose: str = "conformance test",
) -> ActionRequest:
    """Build an ActionRequest with sensible defaults."""
    return ActionRequest(
        agent_id=agent_uri,
        action=ActionPayload(
            type=action_type,
            template=template,
            purpose=purpose,
        ),
    )
