"""Level 1 -- Agent Identity conformance tests.

Verifies Chapter 01 requirements: AID creation, agent_uri format,
TrustLevel ordering, lifecycle state machine transitions, and AID
expiry detection.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from nl_protocol.core.errors import (
    AgentRevoked,
    AgentSuspended,
    AIDExpired,
    AuthenticationError,
    InvalidAgent,
    TrustLevelInsufficient,
)
from nl_protocol.core.interfaces import InMemoryAgentRegistry
from nl_protocol.core.types import (
    ActionType,
    AgentURI,
    LifecycleState,
    TrustLevel,
)
from nl_protocol.identity.aid import AIDManager
from nl_protocol.identity.lifecycle import InvalidLifecycleTransition, LifecycleManager
from nl_protocol.identity.trust_levels import TrustLevelManager

from .conftest import AGENT_URI, make_aid

# ===================================================================
# Section 3 -- Agent URI format
# ===================================================================

class TestAgentURIFormat:
    """Spec Section 3.2: agent_uri MUST conform to nl://vendor/agent-type/version."""

    async def test_MUST_accept_valid_agent_uri(
        self, agent_registry: InMemoryAgentRegistry
    ) -> None:
        """Valid nl://vendor/agent-type/semver URI MUST be accepted."""
        mgr = AIDManager(agent_registry)
        aid = make_aid(AgentURI("nl://acme.com/my-agent/1.0.0"))
        await mgr.register_agent(aid)
        result = await mgr.get_agent(AgentURI("nl://acme.com/my-agent/1.0.0"))
        assert result.agent_uri == AgentURI("nl://acme.com/my-agent/1.0.0")

    async def test_MUST_reject_missing_scheme(
        self, agent_registry: InMemoryAgentRegistry
    ) -> None:
        """URI without nl:// scheme MUST be rejected."""
        mgr = AIDManager(agent_registry)
        aid = make_aid(AgentURI("https://acme.com/agent/1.0.0"))
        with pytest.raises(InvalidAgent):
            await mgr.register_agent(aid)

    async def test_MUST_reject_missing_version(
        self, agent_registry: InMemoryAgentRegistry
    ) -> None:
        """URI without version segment MUST be rejected."""
        mgr = AIDManager(agent_registry)
        aid = make_aid(AgentURI("nl://acme.com/agent"))
        with pytest.raises(InvalidAgent):
            await mgr.register_agent(aid)

    async def test_MUST_reject_uppercase_vendor(
        self, agent_registry: InMemoryAgentRegistry
    ) -> None:
        """Spec Section 3.2: vendor MUST be lowercase DNS-style labels."""
        mgr = AIDManager(agent_registry)
        aid = make_aid(AgentURI("nl://ACME.COM/agent/1.0.0"))
        with pytest.raises(InvalidAgent):
            await mgr.register_agent(aid)

    async def test_MUST_accept_semver_with_prerelease(
        self, agent_registry: InMemoryAgentRegistry
    ) -> None:
        """Semver with pre-release tag MUST be accepted."""
        mgr = AIDManager(agent_registry)
        aid = make_aid(AgentURI("nl://acme.com/agent/1.0.0-beta.1"))
        await mgr.register_agent(aid)
        result = await mgr.get_agent(AgentURI("nl://acme.com/agent/1.0.0-beta.1"))
        assert result is not None


# ===================================================================
# Section 4 -- AID structure
# ===================================================================

class TestAIDValidation:
    """Spec Section 4: AID MUST pass structural validation."""

    async def test_MUST_reject_expires_before_created(
        self, agent_registry: InMemoryAgentRegistry
    ) -> None:
        """expires_at MUST be strictly after created_at."""
        mgr = AIDManager(agent_registry)
        now = datetime.now(UTC)
        aid = make_aid(expires_at=now - timedelta(hours=2))
        # The AID factory sets created_at to now - 1h, expires_at to now - 2h
        with pytest.raises(InvalidAgent):
            await mgr.register_agent(aid)

    async def test_MUST_reject_invalid_scope_pattern(
        self, agent_registry: InMemoryAgentRegistry
    ) -> None:
        """Scope patterns with invalid characters MUST be rejected."""
        mgr = AIDManager(agent_registry)
        aid = make_aid(scope=["api/$EVIL"])
        with pytest.raises(InvalidAgent):
            await mgr.register_agent(aid)


# ===================================================================
# Section 5 -- TrustLevel ordering
# ===================================================================

class TestTrustLevelOrdering:
    """Spec Section 5: TrustLevel MUST support L0 < L1 < L2 < L3."""

    def test_MUST_order_L0_less_than_L1(self) -> None:
        assert TrustLevel.L0 < TrustLevel.L1

    def test_MUST_order_L1_less_than_L2(self) -> None:
        assert TrustLevel.L1 < TrustLevel.L2

    def test_MUST_order_L2_less_than_L3(self) -> None:
        assert TrustLevel.L2 < TrustLevel.L3

    def test_MUST_provide_numeric_property(self) -> None:
        """Each TrustLevel MUST expose a .numeric property (0-3)."""
        assert TrustLevel.L0.numeric == 0
        assert TrustLevel.L1.numeric == 1
        assert TrustLevel.L2.numeric == 2
        assert TrustLevel.L3.numeric == 3

    def test_MUST_support_comparison_operators(self) -> None:
        """All comparison operators MUST work correctly."""
        assert TrustLevel.L3 >= TrustLevel.L2
        assert TrustLevel.L1 <= TrustLevel.L3
        assert not (TrustLevel.L0 > TrustLevel.L1)


# ===================================================================
# Section 6 -- Lifecycle state machine
# ===================================================================

class TestLifecycleStateMachine:
    """Spec Section 6: lifecycle transitions MUST follow the state machine."""

    async def test_MUST_allow_pending_to_active(
        self, agent_registry: InMemoryAgentRegistry
    ) -> None:
        """PENDING -> ACTIVE MUST be allowed."""
        aid = make_aid(lifecycle_state=LifecycleState.PENDING)
        await agent_registry.register(aid)
        mgr = LifecycleManager(agent_registry)
        result = await mgr.activate(AGENT_URI)
        assert result is None or result == LifecycleState.ACTIVE
        updated = await agent_registry.get_aid(AGENT_URI)
        assert updated is not None
        assert updated.lifecycle_state == LifecycleState.ACTIVE

    async def test_MUST_allow_active_to_suspended(
        self, agent_registry: InMemoryAgentRegistry
    ) -> None:
        """ACTIVE -> SUSPENDED MUST be allowed."""
        aid = make_aid(lifecycle_state=LifecycleState.ACTIVE)
        await agent_registry.register(aid)
        mgr = LifecycleManager(agent_registry)
        await mgr.suspend(AGENT_URI)
        updated = await agent_registry.get_aid(AGENT_URI)
        assert updated is not None
        assert updated.lifecycle_state == LifecycleState.SUSPENDED

    async def test_MUST_allow_suspended_to_active(
        self, agent_registry: InMemoryAgentRegistry
    ) -> None:
        """SUSPENDED -> ACTIVE (reactivation) MUST be allowed."""
        aid = make_aid(lifecycle_state=LifecycleState.SUSPENDED)
        await agent_registry.register(aid)
        mgr = LifecycleManager(agent_registry)
        await mgr.reactivate(AGENT_URI)
        updated = await agent_registry.get_aid(AGENT_URI)
        assert updated is not None
        assert updated.lifecycle_state == LifecycleState.ACTIVE

    async def test_MUST_allow_active_to_revoked(
        self, agent_registry: InMemoryAgentRegistry
    ) -> None:
        """ACTIVE -> REVOKED MUST be allowed."""
        aid = make_aid(lifecycle_state=LifecycleState.ACTIVE)
        await agent_registry.register(aid)
        mgr = LifecycleManager(agent_registry)
        await mgr.revoke(AGENT_URI)
        updated = await agent_registry.get_aid(AGENT_URI)
        assert updated is not None
        assert updated.lifecycle_state == LifecycleState.REVOKED

    async def test_MUST_allow_suspended_to_revoked(
        self, agent_registry: InMemoryAgentRegistry
    ) -> None:
        """SUSPENDED -> REVOKED MUST be allowed."""
        aid = make_aid(lifecycle_state=LifecycleState.SUSPENDED)
        await agent_registry.register(aid)
        mgr = LifecycleManager(agent_registry)
        await mgr.revoke(AGENT_URI)
        updated = await agent_registry.get_aid(AGENT_URI)
        assert updated is not None
        assert updated.lifecycle_state == LifecycleState.REVOKED

    async def test_MUST_NOT_allow_revoked_to_active(
        self, agent_registry: InMemoryAgentRegistry
    ) -> None:
        """REVOKED is terminal -- MUST NOT transition to ACTIVE."""
        aid = make_aid(lifecycle_state=LifecycleState.REVOKED)
        await agent_registry.register(aid)
        mgr = LifecycleManager(agent_registry)
        with pytest.raises(InvalidLifecycleTransition):
            await mgr.transition(AGENT_URI, LifecycleState.ACTIVE)

    async def test_MUST_NOT_allow_revoked_to_suspended(
        self, agent_registry: InMemoryAgentRegistry
    ) -> None:
        """REVOKED is terminal -- MUST NOT transition to SUSPENDED."""
        aid = make_aid(lifecycle_state=LifecycleState.REVOKED)
        await agent_registry.register(aid)
        mgr = LifecycleManager(agent_registry)
        with pytest.raises(InvalidLifecycleTransition):
            await mgr.transition(AGENT_URI, LifecycleState.SUSPENDED)

    async def test_MUST_NOT_allow_pending_to_suspended(
        self, agent_registry: InMemoryAgentRegistry
    ) -> None:
        """PENDING -> SUSPENDED MUST NOT be allowed."""
        aid = make_aid(lifecycle_state=LifecycleState.PENDING)
        await agent_registry.register(aid)
        mgr = LifecycleManager(agent_registry)
        with pytest.raises(InvalidLifecycleTransition):
            await mgr.transition(AGENT_URI, LifecycleState.SUSPENDED)


# ===================================================================
# Section 7 -- Trust level capabilities
# ===================================================================

class TestTrustLevelCapabilities:
    """Spec Section 7: each trust level permits specific action types."""

    def test_MUST_deny_all_capabilities_at_L0(self) -> None:
        """L0 (self-attested) MUST NOT permit any action type."""
        mgr = TrustLevelManager()
        for action in ActionType:
            assert not mgr.can_perform_action(TrustLevel.L0, action)

    def test_MUST_allow_read_at_L1(self) -> None:
        """L1 MUST permit READ."""
        mgr = TrustLevelManager()
        assert mgr.can_perform_action(TrustLevel.L1, ActionType.READ)

    def test_MUST_NOT_allow_exec_at_L1(self) -> None:
        """L1 MUST NOT permit EXEC."""
        mgr = TrustLevelManager()
        assert not mgr.can_perform_action(TrustLevel.L1, ActionType.EXEC)

    def test_MUST_reject_overclaimed_capabilities(self) -> None:
        """AID claiming EXEC at L1 MUST be rejected."""
        mgr = TrustLevelManager()
        aid = make_aid(
            trust_level=TrustLevel.L1,
            capabilities=[ActionType.EXEC],
        )
        with pytest.raises(TrustLevelInsufficient):
            mgr.validate_capabilities(aid)


# ===================================================================
# Section 10 -- Agent verification (expiry detection)
# ===================================================================

class TestAIDExpiry:
    """Spec Section 10.2: expired agents MUST be rejected."""

    async def test_MUST_reject_expired_aid(
        self, agent_registry: InMemoryAgentRegistry
    ) -> None:
        """An agent whose expires_at is in the past MUST be rejected."""
        expired_aid = make_aid(
            expires_at=datetime.now(UTC) - timedelta(seconds=1),
        )
        # Override created_at to be before expires_at so registration works
        expired_aid.created_at = datetime.now(UTC) - timedelta(days=1)
        await agent_registry.register(expired_aid)
        mgr = AIDManager(agent_registry)
        with pytest.raises(AIDExpired):
            await mgr.verify_agent(AGENT_URI)

    async def test_MUST_reject_suspended_agent(
        self, agent_registry: InMemoryAgentRegistry
    ) -> None:
        """A SUSPENDED agent MUST NOT pass verification."""
        aid = make_aid(lifecycle_state=LifecycleState.SUSPENDED)
        await agent_registry.register(aid)
        mgr = AIDManager(agent_registry)
        with pytest.raises(AgentSuspended):
            await mgr.verify_agent(AGENT_URI)

    async def test_MUST_reject_revoked_agent(
        self, agent_registry: InMemoryAgentRegistry
    ) -> None:
        """A REVOKED agent MUST NOT pass verification."""
        aid = make_aid(lifecycle_state=LifecycleState.REVOKED)
        await agent_registry.register(aid)
        mgr = AIDManager(agent_registry)
        with pytest.raises(AgentRevoked):
            await mgr.verify_agent(AGENT_URI)

    async def test_MUST_reject_pending_agent(
        self, agent_registry: InMemoryAgentRegistry
    ) -> None:
        """A PENDING agent MUST NOT pass verification."""
        aid = make_aid(lifecycle_state=LifecycleState.PENDING)
        await agent_registry.register(aid)
        mgr = AIDManager(agent_registry)
        with pytest.raises(AuthenticationError):
            await mgr.verify_agent(AGENT_URI)
