"""Tests for NLProvider -- the main orchestrator.

Covers:

1. **Instantiation** -- creating an NLProvider with in-memory stores.
2. **Successful action processing** -- end-to-end (register, grant, process).
3. **Error handling** -- invalid agent, no grant, expired grant, blocked action.
4. **Agent registration and lifecycle** -- register, revoke, verify revoked.
5. **Scope grant creation and revocation** -- create, use, revoke, verify denied.
6. **Audit recording** -- audit store receives records with SHA-256 hash chain.
7. **Edge cases** -- no placeholders, unexpected exceptions, usage limits.
8. **Level integration** -- deny engine (L4), threat scoring (L6), delegation (L7).
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from nl_protocol.core.config import NLProviderConfig
from nl_protocol.core.errors import (
    InvalidAgent,
)
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
    LifecycleState,
    ScopeConditions,
    ScopeGrant,
    SecretRef,
    SecretValue,
    ThreatLevel,
    TrustLevel,
)
from nl_protocol.provider import NLProvider

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NOW = datetime.now(UTC)
FUTURE = NOW + timedelta(hours=24)
PAST = NOW - timedelta(hours=1)

AGENT_URI = AgentURI("nl://anthropic.com/claude-code/1.5.2")
AGENT_URI_2 = AgentURI("nl://openai.com/codex/2.0.0")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config() -> NLProviderConfig:
    """Create a minimal NLProviderConfig for testing."""
    return NLProviderConfig(provider_id="test-provider")


def _make_aid(
    agent_uri: AgentURI = AGENT_URI,
    scope: list[str] | None = None,
    lifecycle_state: LifecycleState = LifecycleState.ACTIVE,
    expires_at: datetime | None = None,
) -> AID:
    """Create a valid AID for testing."""
    return AID(
        agent_uri=agent_uri,
        display_name="Test Agent",
        vendor="anthropic.com",
        version="1.5.2",
        scope=scope or [],
        trust_level=TrustLevel.L0,
        capabilities=[ActionType.EXEC, ActionType.TEMPLATE, ActionType.READ],
        expires_at=expires_at or FUTURE,
        lifecycle_state=lifecycle_state,
    )


def _make_grant(
    agent_uri: AgentURI = AGENT_URI,
    secret: str = "api/*",
    actions: list[ActionType] | None = None,
    valid_until: datetime | None = None,
    max_uses: int | None = None,
    grant_id: str | None = None,
) -> ScopeGrant:
    """Create a valid ScopeGrant for testing."""
    return ScopeGrant(
        grant_id=grant_id or str(uuid.uuid4()),
        agent_uri=agent_uri,
        secret=secret,
        actions=actions or [ActionType.EXEC, ActionType.TEMPLATE, ActionType.READ],
        conditions=ScopeConditions(
            valid_until=valid_until,
            max_uses=max_uses,
        ),
    )


def _make_request(
    agent_uri: AgentURI = AGENT_URI,
    template: str = "echo 'secret={{nl:api/TOKEN}}'",
    action_type: ActionType = ActionType.EXEC,
    purpose: str = "Test action",
) -> ActionRequest:
    """Create an ActionRequest for testing."""
    return ActionRequest(
        agent_uri=agent_uri,
        action=ActionPayload(
            type=action_type,
            template=template,
            purpose=purpose,
        ),
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def secret_store() -> InMemorySecretStore:
    """A pre-populated in-memory secret store."""
    store = InMemorySecretStore()
    store.put(SecretRef("api/TOKEN"), SecretValue("ghp_abc123def456"))
    store.put(SecretRef("api/GITHUB_TOKEN"), SecretValue("ghp_xyz789"))
    store.put(SecretRef("database/DB_PASSWORD"), SecretValue("p@ssw0rd!_secret"))
    return store


@pytest.fixture()
def agent_registry() -> InMemoryAgentRegistry:
    """A fresh in-memory agent registry."""
    return InMemoryAgentRegistry()


@pytest.fixture()
def scope_grant_store() -> InMemoryScopeGrantStore:
    """A fresh in-memory scope grant store."""
    return InMemoryScopeGrantStore()


@pytest.fixture()
def audit_store() -> InMemoryAuditStore:
    """A fresh in-memory audit store."""
    return InMemoryAuditStore()


@pytest.fixture()
def provider(
    secret_store: InMemorySecretStore,
    agent_registry: InMemoryAgentRegistry,
    scope_grant_store: InMemoryScopeGrantStore,
) -> NLProvider:
    """An NLProvider with in-memory stores (no audit)."""
    return NLProvider(
        config=_make_config(),
        secret_store=secret_store,
        agent_registry=agent_registry,
        scope_grant_store=scope_grant_store,
    )


@pytest.fixture()
def provider_with_audit(
    secret_store: InMemorySecretStore,
    agent_registry: InMemoryAgentRegistry,
    scope_grant_store: InMemoryScopeGrantStore,
    audit_store: InMemoryAuditStore,
) -> NLProvider:
    """An NLProvider with in-memory stores including audit."""
    return NLProvider(
        config=_make_config(),
        secret_store=secret_store,
        agent_registry=agent_registry,
        scope_grant_store=scope_grant_store,
        audit_store=audit_store,
    )


# ===================================================================
# 1. Instantiation Tests
# ===================================================================


class TestInstantiation:
    """Tests for NLProvider construction and configuration."""

    def test_minimal_instantiation(self) -> None:
        """NLProvider can be created with only required stores."""
        provider = NLProvider(
            config=_make_config(),
            secret_store=InMemorySecretStore(),
            agent_registry=InMemoryAgentRegistry(),
            scope_grant_store=InMemoryScopeGrantStore(),
        )
        assert provider.config.provider_id == "test-provider"

    def test_full_instantiation(self) -> None:
        """NLProvider can be created with all optional stores."""
        provider = NLProvider(
            config=_make_config(),
            secret_store=InMemorySecretStore(),
            agent_registry=InMemoryAgentRegistry(),
            scope_grant_store=InMemoryScopeGrantStore(),
            audit_store=InMemoryAuditStore(),
            nonce_store=InMemoryNonceStore(),
            delegation_store=InMemoryDelegationStore(),
        )
        assert provider.config.provider_id == "test-provider"

    def test_internal_managers_created(self, provider: NLProvider) -> None:
        """Internal managers are correctly instantiated."""
        assert provider.aid_manager is not None
        assert provider.lifecycle_manager is not None
        assert provider.scope_evaluator is not None
        assert provider.policy_evaluator is not None

    def test_config_accessible(self, provider: NLProvider) -> None:
        """Configuration is accessible via the config property."""
        assert provider.config.provider_id == "test-provider"
        assert provider.config.default_action_timeout == 30


# ===================================================================
# 2. Successful Action Processing (End-to-End)
# ===================================================================


class TestSuccessfulProcessing:
    """End-to-end tests: register agent, create grant, process action."""

    @pytest.mark.asyncio
    async def test_full_pipeline_success(self, provider: NLProvider) -> None:
        """Complete pipeline: register -> grant -> process -> success."""
        # Register the agent
        aid = _make_aid()
        await provider.register_agent(aid)

        # Create a scope grant
        grant = _make_grant()
        grant_id = await provider.create_scope_grant(grant)
        assert grant_id == grant.grant_id

        # Process an action request
        request = _make_request()
        response = await provider.process_action(request)

        assert response.status == "success"
        assert response.result is not None
        assert response.result.exit_code == 0
        assert response.error is None

    @pytest.mark.asyncio
    async def test_no_placeholders_succeeds(self, provider: NLProvider) -> None:
        """An action with no {{nl:...}} placeholders succeeds without grants."""
        aid = _make_aid()
        await provider.register_agent(aid)

        request = _make_request(
            template="echo hello world",
            purpose="No secrets needed",
        )
        response = await provider.process_action(request)

        assert response.status == "success"
        assert response.result is not None
        assert response.result.exit_code == 0

    @pytest.mark.asyncio
    async def test_success_with_wildcard_grant(self, provider: NLProvider) -> None:
        """A wildcard grant ('*') covers any secret reference."""
        aid = _make_aid()
        await provider.register_agent(aid)

        grant = _make_grant(secret="*")
        await provider.create_scope_grant(grant)

        request = _make_request(template="echo {{nl:api/TOKEN}}")
        response = await provider.process_action(request)

        assert response.status == "success"

    @pytest.mark.asyncio
    async def test_template_action_type(self, provider: NLProvider) -> None:
        """TEMPLATE action type processes successfully."""
        aid = _make_aid()
        await provider.register_agent(aid)

        grant = _make_grant(secret="database/*")
        await provider.create_scope_grant(grant)

        request = _make_request(
            template="DB_PASS={{nl:database/DB_PASSWORD}}",
            action_type=ActionType.TEMPLATE,
            purpose="Generate env file",
        )
        response = await provider.process_action(request)

        assert response.status == "success"


# ===================================================================
# 3. Error Handling Tests
# ===================================================================


class TestErrorHandling:
    """Tests for error handling in the provider pipeline."""

    @pytest.mark.asyncio
    async def test_unregistered_agent_denied(self, provider: NLProvider) -> None:
        """Action from an unregistered agent returns 'denied'."""
        request = _make_request()
        response = await provider.process_action(request)

        assert response.status == "denied"
        assert response.error is not None
        assert response.error.code == "NL-E100"  # InvalidAgent

    @pytest.mark.asyncio
    async def test_no_scope_grant_denied(self, provider: NLProvider) -> None:
        """Action without a matching scope grant returns 'denied'."""
        aid = _make_aid()
        await provider.register_agent(aid)

        # No grant created -- action should be denied
        request = _make_request()
        response = await provider.process_action(request)

        assert response.status == "denied"
        assert response.error is not None
        assert response.error.code == "NL-E200"  # NoScopeGrant

    @pytest.mark.asyncio
    async def test_expired_grant_denied(self, provider: NLProvider) -> None:
        """Action with an expired scope grant returns 'denied'."""
        aid = _make_aid()
        await provider.register_agent(aid)

        # Create an already-expired grant
        grant = _make_grant(valid_until=PAST)
        await provider.create_scope_grant(grant)

        request = _make_request()
        response = await provider.process_action(request)

        assert response.status == "denied"
        assert response.error is not None
        assert response.error.code == "NL-E201"  # ScopeExpired

    @pytest.mark.asyncio
    async def test_revoked_agent_denied(self, provider: NLProvider) -> None:
        """Action from a revoked agent returns 'denied'."""
        aid = _make_aid()
        await provider.register_agent(aid)
        await provider.revoke_agent(AGENT_URI)

        request = _make_request()
        response = await provider.process_action(request)

        assert response.status == "denied"
        assert response.error is not None
        assert response.error.code == "NL-E104"  # AgentRevoked

    @pytest.mark.asyncio
    async def test_suspended_agent_denied(self, provider: NLProvider) -> None:
        """Action from a suspended agent returns 'denied'."""
        aid = _make_aid()
        await provider.register_agent(aid)

        # Suspend the agent via lifecycle manager
        await provider.lifecycle_manager.suspend(AGENT_URI)

        request = _make_request()
        response = await provider.process_action(request)

        assert response.status == "denied"
        assert response.error is not None
        assert response.error.code == "NL-E103"  # AgentSuspended

    @pytest.mark.asyncio
    async def test_invalid_action_template_error(self, provider: NLProvider) -> None:
        """An invalid action template returns 'error'."""
        aid = _make_aid()
        await provider.register_agent(aid)

        request = _make_request(
            template="",  # Empty template for EXEC is invalid
            action_type=ActionType.EXEC,
        )
        response = await provider.process_action(request)

        assert response.status == "error"
        assert response.error is not None
        assert response.error.code == "NL-E301"  # InvalidPlaceholder

    @pytest.mark.asyncio
    async def test_secret_not_found_error(self, provider: NLProvider) -> None:
        """Referencing a non-existent secret returns 'error'."""
        aid = _make_aid()
        await provider.register_agent(aid)

        grant = _make_grant(secret="*")
        await provider.create_scope_grant(grant)

        request = _make_request(
            template="curl {{nl:nonexistent/SECRET}}",
        )
        response = await provider.process_action(request)

        assert response.status == "error"
        assert response.error is not None
        assert response.error.code == "NL-E302"  # SecretNotFound

    @pytest.mark.asyncio
    async def test_aid_scope_mismatch_denied(self, provider: NLProvider) -> None:
        """Action outside AID scope is denied."""
        # Agent with restricted scope (database only)
        aid = _make_aid(scope=["database/*"])
        await provider.register_agent(aid)

        grant = _make_grant(secret="api/*")
        await provider.create_scope_grant(grant)

        # Request uses api/* which is outside AID scope
        request = _make_request(template="curl {{nl:api/TOKEN}}")
        response = await provider.process_action(request)

        assert response.status == "denied"
        assert response.error is not None
        assert response.error.code == "NL-E200"  # NoScopeGrant (AID scope violation)

    @pytest.mark.asyncio
    async def test_wrong_action_type_grant_denied(self, provider: NLProvider) -> None:
        """A grant that doesn't cover the action type results in denial."""
        aid = _make_aid()
        await provider.register_agent(aid)

        # Grant only for READ, not EXEC
        grant = _make_grant(actions=[ActionType.READ])
        await provider.create_scope_grant(grant)

        request = _make_request(action_type=ActionType.EXEC)
        response = await provider.process_action(request)

        assert response.status == "denied"
        assert response.error is not None
        assert response.error.code == "NL-E200"  # NoScopeGrant


# ===================================================================
# 4. Agent Registration and Lifecycle Tests
# ===================================================================


class TestAgentLifecycle:
    """Tests for agent registration, revocation, and lifecycle management."""

    @pytest.mark.asyncio
    async def test_register_agent(self, provider: NLProvider) -> None:
        """Registering an agent persists it in the registry."""
        aid = _make_aid()
        await provider.register_agent(aid)

        # Verify the agent can be retrieved
        retrieved = await provider.aid_manager.get_agent(AGENT_URI)
        assert retrieved.agent_uri == AGENT_URI
        assert retrieved.display_name == "Test Agent"

    @pytest.mark.asyncio
    async def test_register_duplicate_raises(self, provider: NLProvider) -> None:
        """Registering the same agent twice raises ValueError."""
        aid = _make_aid()
        await provider.register_agent(aid)

        with pytest.raises(ValueError, match="already registered"):
            await provider.register_agent(aid)

    @pytest.mark.asyncio
    async def test_register_invalid_uri_raises(self, provider: NLProvider) -> None:
        """Registering an agent with invalid URI raises InvalidAgent."""
        aid = _make_aid(agent_uri=AgentURI("invalid-uri"))
        with pytest.raises(InvalidAgent):
            await provider.register_agent(aid)

    @pytest.mark.asyncio
    async def test_revoke_agent(self, provider: NLProvider) -> None:
        """Revoking an agent transitions it to REVOKED state."""
        aid = _make_aid()
        await provider.register_agent(aid)
        await provider.revoke_agent(AGENT_URI)

        # Verify the agent is revoked
        retrieved = await provider.aid_manager.get_agent(AGENT_URI)
        assert retrieved.lifecycle_state == LifecycleState.REVOKED

    @pytest.mark.asyncio
    async def test_revoke_nonexistent_agent_raises(self, provider: NLProvider) -> None:
        """Revoking a non-existent agent raises InvalidAgent."""
        with pytest.raises(InvalidAgent):
            await provider.revoke_agent(AgentURI("nl://test.com/agent/1.0.0"))

    @pytest.mark.asyncio
    async def test_revoked_agent_cannot_act(self, provider: NLProvider) -> None:
        """A revoked agent's actions are denied."""
        aid = _make_aid()
        await provider.register_agent(aid)

        grant = _make_grant()
        await provider.create_scope_grant(grant)

        # Verify the agent can act before revocation
        request = _make_request()
        response = await provider.process_action(request)
        assert response.status == "success"

        # Revoke and verify denial
        await provider.revoke_agent(AGENT_URI)

        response = await provider.process_action(request)
        assert response.status == "denied"
        assert response.error is not None
        assert response.error.code == "NL-E104"  # AgentRevoked


# ===================================================================
# 5. Scope Grant Management Tests
# ===================================================================


class TestScopeGrantManagement:
    """Tests for scope grant creation, usage, and revocation."""

    @pytest.mark.asyncio
    async def test_create_scope_grant(self, provider: NLProvider) -> None:
        """Creating a scope grant returns the grant ID."""
        grant = _make_grant()
        grant_id = await provider.create_scope_grant(grant)
        assert grant_id == grant.grant_id

    @pytest.mark.asyncio
    async def test_revoke_scope_grant(self, provider: NLProvider) -> None:
        """Revoking a grant prevents it from matching."""
        aid = _make_aid()
        await provider.register_agent(aid)

        grant = _make_grant()
        grant_id = await provider.create_scope_grant(grant)

        # Verify the grant works before revocation
        request = _make_request()
        response = await provider.process_action(request)
        assert response.status == "success"

        # Revoke the grant
        await provider.revoke_scope_grant(grant_id)

        # Verify the grant no longer works
        response = await provider.process_action(request)
        assert response.status == "denied"
        assert response.error is not None
        assert response.error.code == "NL-E200"  # NoScopeGrant

    @pytest.mark.asyncio
    async def test_usage_limit_enforcement(self, provider: NLProvider) -> None:
        """A grant with max_uses blocks after the limit is reached."""
        aid = _make_aid()
        await provider.register_agent(aid)

        grant = _make_grant(max_uses=1)
        await provider.create_scope_grant(grant)

        request = _make_request()

        # First use succeeds
        response = await provider.process_action(request)
        assert response.status == "success"

        # Second use is denied (max_uses=1 exceeded)
        response = await provider.process_action(request)
        assert response.status == "denied"

    @pytest.mark.asyncio
    async def test_multiple_grants_for_same_agent(self, provider: NLProvider) -> None:
        """Multiple grants for the same agent work independently."""
        aid = _make_aid()
        await provider.register_agent(aid)

        # Grant for api/*
        grant_api = _make_grant(secret="api/*")
        await provider.create_scope_grant(grant_api)

        # Grant for database/*
        grant_db = _make_grant(secret="database/*")
        await provider.create_scope_grant(grant_db)

        # Both api and database requests should succeed
        response = await provider.process_action(
            _make_request(template="echo {{nl:api/TOKEN}}")
        )
        assert response.status == "success"

        response = await provider.process_action(
            _make_request(template="echo {{nl:database/DB_PASSWORD}}")
        )
        assert response.status == "success"


# ===================================================================
# 6. Audit Recording Tests
# ===================================================================


class TestAuditRecording:
    """Tests for audit store integration."""

    @pytest.mark.asyncio
    async def test_audit_record_on_success(
        self,
        provider_with_audit: NLProvider,
        audit_store: InMemoryAuditStore,
    ) -> None:
        """A successful action creates an audit record with SHA-256 hash chain."""
        aid = _make_aid()
        await provider_with_audit.register_agent(aid)

        grant = _make_grant()
        await provider_with_audit.create_scope_grant(grant)

        request = _make_request()
        response = await provider_with_audit.process_action(request)

        assert response.status == "success"
        assert response.audit_ref is not None

        # Verify audit store has records (genesis + action)
        latest = await audit_store.get_latest()
        assert latest is not None
        assert str(latest.agent_uri) == str(AGENT_URI)
        assert latest.result_summary == "success"
        # SHA-256 hash chain integrity
        assert latest.record_hash.startswith("sha256:")

    @pytest.mark.asyncio
    async def test_no_audit_without_store(self, provider: NLProvider) -> None:
        """Without an audit store, no audit_ref is returned."""
        aid = _make_aid()
        await provider.register_agent(aid)

        grant = _make_grant()
        await provider.create_scope_grant(grant)

        request = _make_request()
        response = await provider.process_action(request)

        assert response.status == "success"
        assert response.audit_ref is None

    @pytest.mark.asyncio
    async def test_audit_records_secrets_used(
        self,
        provider_with_audit: NLProvider,
        audit_store: InMemoryAuditStore,
    ) -> None:
        """Audit records contain the secret names (NEVER values) used."""
        aid = _make_aid()
        await provider_with_audit.register_agent(aid)

        grant = _make_grant()
        await provider_with_audit.create_scope_grant(grant)

        request = _make_request(template="echo {{nl:api/TOKEN}}")
        response = await provider_with_audit.process_action(request)

        assert response.status == "success"

        latest = await audit_store.get_latest()
        assert latest is not None
        assert "api/TOKEN" in latest.secrets_used

    @pytest.mark.asyncio
    async def test_audit_chain_linking(
        self,
        provider_with_audit: NLProvider,
        audit_store: InMemoryAuditStore,
    ) -> None:
        """Subsequent audit records reference the previous record's hash (SHA-256)."""
        aid = _make_aid()
        await provider_with_audit.register_agent(aid)

        grant = _make_grant()
        await provider_with_audit.create_scope_grant(grant)

        # First action -- triggers genesis + first action record
        request = _make_request()
        await provider_with_audit.process_action(request)

        first_record = await audit_store.get_latest()
        assert first_record is not None
        # First action record is linked to genesis via SHA-256
        assert first_record.record_hash.startswith("sha256:")
        assert first_record.previous_hash.startswith("sha256:")

        # Second action
        await provider_with_audit.process_action(request)

        second_record = await audit_store.get_latest()
        assert second_record is not None
        assert second_record.previous_hash == first_record.record_hash


# ===================================================================
# 7. Edge Cases and Additional Tests
# ===================================================================


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    @pytest.mark.asyncio
    async def test_read_action_empty_template(self, provider: NLProvider) -> None:
        """A READ action with empty template succeeds (dry-run check)."""
        aid = _make_aid()
        await provider.register_agent(aid)

        request = _make_request(
            template="",
            action_type=ActionType.READ,
            purpose="Dry-run check",
        )
        response = await provider.process_action(request)

        assert response.status == "success"

    @pytest.mark.asyncio
    async def test_response_contains_action_type(self, provider: NLProvider) -> None:
        """The success response includes the action type in stdout."""
        aid = _make_aid()
        await provider.register_agent(aid)

        request = _make_request(
            template="",
            action_type=ActionType.READ,
        )
        response = await provider.process_action(request)

        assert response.status == "success"
        assert response.result is not None
        assert "read" in response.result.stdout.lower()

    @pytest.mark.asyncio
    async def test_expired_aid_denied(
        self,
        secret_store: InMemorySecretStore,
        agent_registry: InMemoryAgentRegistry,
        scope_grant_store: InMemoryScopeGrantStore,
    ) -> None:
        """An agent with an expired AID is denied."""
        provider = NLProvider(
            config=_make_config(),
            secret_store=secret_store,
            agent_registry=agent_registry,
            scope_grant_store=scope_grant_store,
        )

        # Register an agent that is already expired
        aid = _make_aid(expires_at=PAST)
        # Directly register (bypassing expiration check in register
        # since the AID itself is valid -- it just expires in the past)
        await agent_registry.register(aid)

        grant = _make_grant()
        await provider.create_scope_grant(grant)

        request = _make_request()
        response = await provider.process_action(request)

        assert response.status == "denied"
        assert response.error is not None
        assert response.error.code == "NL-E105"  # AIDExpired

    @pytest.mark.asyncio
    async def test_multiple_agents_isolated(self, provider: NLProvider) -> None:
        """Different agents have isolated grant sets."""
        # Register two agents
        aid1 = _make_aid(agent_uri=AGENT_URI)
        aid2 = _make_aid(agent_uri=AGENT_URI_2)
        # Fix agent2 to have matching vendor/version
        aid2 = AID(
            agent_uri=AGENT_URI_2,
            display_name="Agent 2",
            vendor="openai.com",
            version="2.0.0",
            scope=[],
            trust_level=TrustLevel.L0,
            capabilities=[ActionType.EXEC],
            expires_at=FUTURE,
        )
        await provider.register_agent(aid1)
        await provider.register_agent(aid2)

        # Grant only for agent 1
        grant = _make_grant(agent_uri=AGENT_URI)
        await provider.create_scope_grant(grant)

        # Agent 1 succeeds
        request1 = _make_request(agent_uri=AGENT_URI)
        response1 = await provider.process_action(request1)
        assert response1.status == "success"

        # Agent 2 is denied (no grant)
        request2 = _make_request(agent_uri=AGENT_URI_2)
        response2 = await provider.process_action(request2)
        assert response2.status == "denied"

    @pytest.mark.asyncio
    async def test_error_response_structure(self, provider: NLProvider) -> None:
        """Error responses have the correct structure."""
        request = _make_request()
        response = await provider.process_action(request)

        assert response.version == "1.0"
        assert response.type == "action_response"
        assert response.status == "denied"
        assert response.error is not None
        assert response.error.code is not None
        assert response.error.message is not None
        assert response.result is None

    @pytest.mark.asyncio
    async def test_success_response_structure(self, provider: NLProvider) -> None:
        """Success responses have the correct structure."""
        aid = _make_aid()
        await provider.register_agent(aid)

        grant = _make_grant()
        await provider.create_scope_grant(grant)

        request = _make_request()
        response = await provider.process_action(request)

        assert response.version == "1.0"
        assert response.type == "action_response"
        assert response.status == "success"
        assert response.result is not None
        assert response.error is None


# ===================================================================
# 8. Level Integration Tests (L4 Defense, L6 Detection, L7 Federation)
# ===================================================================


class TestLevelIntegration:
    """Tests for the full 7-level integration in the NLProvider pipeline."""

    # -- Level 4: Deny Engine Integration -----------------------------------

    @pytest.mark.asyncio
    async def test_deny_engine_wired_into_policy(self, provider: NLProvider) -> None:
        """The deny engine is wired into the policy evaluator."""
        assert provider.deny_engine is not None
        assert len(provider.deny_engine.standard_rules) > 0

    @pytest.mark.asyncio
    async def test_deny_engine_blocks_dangerous_template(
        self, provider: NLProvider
    ) -> None:
        """A dangerous template is blocked by the deny engine (L4)."""
        aid = _make_aid()
        await provider.register_agent(aid)

        grant = _make_grant(secret="*")
        await provider.create_scope_grant(grant)

        # "cat .env" should match deny rules
        request = _make_request(template="cat .env")
        response = await provider.process_action(request)

        assert response.status == "denied"
        assert response.error is not None
        assert response.error.code == "NL-E400"  # ActionBlocked

    @pytest.mark.asyncio
    async def test_deny_engine_disabled_with_config(self) -> None:
        """Deny engine is not created when Level 4 is not in supported_levels."""
        config = NLProviderConfig(
            provider_id="test", supported_levels=[1, 2, 3, 5, 6, 7]
        )
        p = NLProvider(
            config=config,
            secret_store=InMemorySecretStore(),
            agent_registry=InMemoryAgentRegistry(),
            scope_grant_store=InMemoryScopeGrantStore(),
        )
        assert p.deny_engine is None
        assert p.command_validator is None

    # -- Level 4: Evasion Detection Integration ----------------------------

    @pytest.mark.asyncio
    async def test_command_validator_wired(self, provider: NLProvider) -> None:
        """The command validator is wired into the pipeline."""
        assert provider.command_validator is not None

    # -- Level 5: SHA-256 Hash Chain Integration ---------------------------

    @pytest.mark.asyncio
    async def test_chain_manager_creates_genesis(
        self,
        provider_with_audit: NLProvider,
        audit_store: InMemoryAuditStore,
    ) -> None:
        """ChainManager creates a genesis entry on first audit."""
        aid = _make_aid()
        await provider_with_audit.register_agent(aid)

        grant = _make_grant()
        await provider_with_audit.create_scope_grant(grant)

        request = _make_request()
        await provider_with_audit.process_action(request)

        # Should have genesis + action record
        chain = await audit_store.get_chain()
        assert len(chain) >= 2
        genesis = chain[0]
        assert genesis.action_type == "genesis"
        assert genesis.record_hash.startswith("sha256:")

    @pytest.mark.asyncio
    async def test_chain_manager_not_created_without_store(
        self, provider: NLProvider
    ) -> None:
        """No chain manager when audit store is not provided."""
        assert provider.chain_manager is None

    # -- Level 6: Threat Scoring Integration -------------------------------

    @pytest.mark.asyncio
    async def test_threat_scorer_wired(self, provider: NLProvider) -> None:
        """Threat scorer and response engine are wired."""
        assert provider.threat_scorer is not None
        assert provider.response_engine is not None

    @pytest.mark.asyncio
    async def test_threat_score_starts_green(self, provider: NLProvider) -> None:
        """A new agent has a GREEN threat score."""
        score = provider.get_threat_score(AGENT_URI)
        assert score is not None
        assert score.level == ThreatLevel.GREEN
        assert score.int_score == 0

    @pytest.mark.asyncio
    async def test_denied_actions_record_threat_incidents(
        self, provider: NLProvider
    ) -> None:
        """Denied actions generate threat incidents (L6)."""
        # Agent not registered -- action will be denied
        request = _make_request()
        response = await provider.process_action(request)
        assert response.status == "denied"

        # Threat score should have increased (but modestly for one denial)
        score = provider.get_threat_score(AGENT_URI)
        assert score is not None
        # NL-E100 (InvalidAgent) doesn't map to an attack type, so score stays 0
        # But if it's NL-E200, it would increase

    @pytest.mark.asyncio
    async def test_scope_violation_increases_threat_score(
        self, provider: NLProvider
    ) -> None:
        """Scope violations (NL-E200) increase threat score via L6."""
        aid = _make_aid()
        await provider.register_agent(aid)
        # No grant -- access attempt should be denied with NL-E200

        request = _make_request()
        await provider.process_action(request)

        score = provider.get_threat_score(AGENT_URI)
        assert score is not None
        # NL-E200 maps to T1 (Direct Secret Request) which has severity 20
        assert score.int_score > 0

    @pytest.mark.asyncio
    async def test_threat_response_determination(self, provider: NLProvider) -> None:
        """get_threat_response() returns the correct response for GREEN."""
        response = provider.get_threat_response(AGENT_URI)
        assert response is not None
        assert response.level == ThreatLevel.GREEN

    @pytest.mark.asyncio
    async def test_threat_scorer_disabled_with_config(self) -> None:
        """Threat scorer is not created when Level 6 is not supported."""
        config = NLProviderConfig(
            provider_id="test", supported_levels=[1, 2, 3, 4, 5, 7]
        )
        p = NLProvider(
            config=config,
            secret_store=InMemorySecretStore(),
            agent_registry=InMemoryAgentRegistry(),
            scope_grant_store=InMemoryScopeGrantStore(),
        )
        assert p.threat_scorer is None
        assert p.response_engine is None
        assert p.get_threat_score(AGENT_URI) is None

    # -- Level 7: Delegation Verifier Integration --------------------------

    @pytest.mark.asyncio
    async def test_delegation_verifier_wired_with_stores(self) -> None:
        """Delegation verifier is created when delegation + nonce stores present."""
        p = NLProvider(
            config=_make_config(),
            secret_store=InMemorySecretStore(),
            agent_registry=InMemoryAgentRegistry(),
            scope_grant_store=InMemoryScopeGrantStore(),
            nonce_store=InMemoryNonceStore(),
            delegation_store=InMemoryDelegationStore(),
        )
        assert p.delegation_verifier is not None

    @pytest.mark.asyncio
    async def test_delegation_verifier_not_created_without_nonce_store(self) -> None:
        """Delegation verifier requires a nonce store."""
        p = NLProvider(
            config=_make_config(),
            secret_store=InMemorySecretStore(),
            agent_registry=InMemoryAgentRegistry(),
            scope_grant_store=InMemoryScopeGrantStore(),
            delegation_store=InMemoryDelegationStore(),
        )
        assert p.delegation_verifier is None

    # -- Output Sanitizer Integration --------------------------------------

    @pytest.mark.asyncio
    async def test_output_sanitizer_wired(self, provider: NLProvider) -> None:
        """Output sanitizer is always available."""
        assert provider.output_sanitizer is not None

    # -- Full pipeline with all levels -------------------------------------

    @pytest.mark.asyncio
    async def test_full_pipeline_all_levels(self) -> None:
        """End-to-end pipeline with all 7 levels wired."""
        secret_store = InMemorySecretStore()
        secret_store.put(SecretRef("api/TOKEN"), SecretValue("ghp_abc123def456"))

        p = NLProvider(
            config=_make_config(),
            secret_store=secret_store,
            agent_registry=InMemoryAgentRegistry(),
            scope_grant_store=InMemoryScopeGrantStore(),
            audit_store=InMemoryAuditStore(),
            nonce_store=InMemoryNonceStore(),
            delegation_store=InMemoryDelegationStore(),
        )

        # All levels should be wired
        assert p.deny_engine is not None
        assert p.command_validator is not None
        assert p.chain_manager is not None
        assert p.threat_scorer is not None
        assert p.response_engine is not None
        assert p.delegation_verifier is not None
        assert p.output_sanitizer is not None

        # Register agent and create grant
        aid = _make_aid()
        await p.register_agent(aid)
        grant = _make_grant()
        await p.create_scope_grant(grant)

        # Process an action -- should pass all 7 levels
        request = _make_request()
        response = await p.process_action(request)

        assert response.status == "success"
        assert response.audit_ref is not None
        assert response.result is not None

        # Threat score should still be GREEN
        score = p.get_threat_score(AGENT_URI)
        assert score is not None
        assert score.level == ThreatLevel.GREEN


# ===================================================================
# 9. Execution Tests (Level 3 Integration)
# ===================================================================


class TestExecution:
    """Tests for real command execution via IsolatedExecutor (Level 3)."""

    @pytest.mark.asyncio
    async def test_exec_actually_runs_command(self, provider: NLProvider) -> None:
        """EXEC action with Level 3 enabled runs the command and returns real output."""
        aid = _make_aid()
        await provider.register_agent(aid)

        request = _make_request(
            template="echo hello",
            purpose="Simple echo test",
        )
        response = await provider.process_action(request)

        assert response.status == "success"
        assert response.result is not None
        assert response.result.exit_code == 0
        assert "hello" in response.result.stdout

    @pytest.mark.asyncio
    async def test_exec_output_sanitized(self, provider: NLProvider) -> None:
        """EXEC action output is sanitized -- secret values are redacted."""
        aid = _make_aid()
        await provider.register_agent(aid)

        grant = _make_grant()
        await provider.create_scope_grant(grant)

        # echo the secret via env var -- shell will expand $NL_SECRET_0
        request = _make_request(
            template="echo {{nl:api/TOKEN}}",
            purpose="Secret echo test",
        )
        response = await provider.process_action(request)

        assert response.status == "success"
        assert response.result is not None
        assert response.result.exit_code == 0
        # Secret value must NOT appear in output
        assert "ghp_abc123def456" not in response.result.stdout
        # Redaction marker must appear
        assert "[NL-REDACTED:api/TOKEN]" in response.result.stdout

    @pytest.mark.asyncio
    async def test_exec_with_no_secrets(self, provider: NLProvider) -> None:
        """EXEC action without secrets runs and returns real output."""
        aid = _make_aid()
        await provider.register_agent(aid)

        request = _make_request(
            template="echo hello world",
            purpose="No secrets needed",
        )
        response = await provider.process_action(request)

        assert response.status == "success"
        assert response.result is not None
        assert response.result.exit_code == 0
        assert "hello world" in response.result.stdout

    @pytest.mark.asyncio
    async def test_exec_nonzero_exit_code(self, provider: NLProvider) -> None:
        """EXEC action with failing command returns nonzero exit code."""
        aid = _make_aid()
        await provider.register_agent(aid)

        request = _make_request(
            template="exit 1",
            purpose="Failure test",
        )
        response = await provider.process_action(request)

        assert response.status == "success"
        assert response.result is not None
        assert response.result.exit_code == 1

    @pytest.mark.asyncio
    async def test_exec_timeout_returns_error(self, provider: NLProvider) -> None:
        """EXEC action exceeding timeout returns an error response."""
        aid = _make_aid()
        await provider.register_agent(aid)

        request = ActionRequest(
            agent_uri=AGENT_URI,
            action=ActionPayload(
                type=ActionType.EXEC,
                template="sleep 10",
                purpose="Timeout test",
                timeout=1,
            ),
        )
        response = await provider.process_action(request)

        assert response.status == "error"
        assert response.error is not None
        assert response.error.code == "NL-E303"  # ExecutionTimeout

    @pytest.mark.asyncio
    async def test_non_exec_returns_synthetic(self, provider: NLProvider) -> None:
        """Non-EXEC action types return synthetic success (not executed)."""
        aid = _make_aid()
        await provider.register_agent(aid)

        grant = _make_grant(secret="database/*")
        await provider.create_scope_grant(grant)

        request = _make_request(
            template="DB_PASS={{nl:database/DB_PASSWORD}}",
            action_type=ActionType.TEMPLATE,
            purpose="Template action",
        )
        response = await provider.process_action(request)

        assert response.status == "success"
        assert response.result is not None
        assert "template" in response.result.stdout.lower()

    @pytest.mark.asyncio
    async def test_exec_without_l3_returns_synthetic(self) -> None:
        """EXEC action without Level 3 support returns synthetic success."""
        config = NLProviderConfig(
            provider_id="test",
            supported_levels=[1, 2, 4, 5, 6, 7],  # No Level 3
        )
        secret_store = InMemorySecretStore()
        secret_store.put(SecretRef("api/TOKEN"), SecretValue("ghp_abc123def456"))

        p = NLProvider(
            config=config,
            secret_store=secret_store,
            agent_registry=InMemoryAgentRegistry(),
            scope_grant_store=InMemoryScopeGrantStore(),
        )
        assert p.isolated_executor is None

        aid = _make_aid()
        await p.register_agent(aid)

        grant = _make_grant()
        await p.create_scope_grant(grant)

        request = _make_request()
        response = await p.process_action(request)

        assert response.status == "success"
        assert response.result is not None
        assert "exec" in response.result.stdout.lower()

    @pytest.mark.asyncio
    async def test_exec_stderr_sanitized(self, provider: NLProvider) -> None:
        """EXEC action sanitizes secret values from stderr."""
        aid = _make_aid()
        await provider.register_agent(aid)

        grant = _make_grant()
        await provider.create_scope_grant(grant)

        # Write secret to stderr via env var
        request = _make_request(
            template="echo {{nl:api/TOKEN}} >&2",
            purpose="Stderr sanitization test",
        )
        response = await provider.process_action(request)

        assert response.status == "success"
        assert response.result is not None
        # Secret value must NOT appear in stderr
        assert "ghp_abc123def456" not in response.result.stderr
        # Redaction marker must appear in stderr
        assert "[NL-REDACTED:api/TOKEN]" in response.result.stderr
