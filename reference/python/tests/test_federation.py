"""Tests for NL Protocol Level 7 -- Cross-Agent Trust & Federation.

This module covers the federation subpackage:

1. **Delegation token creation** -- valid creation, subset rule enforcement,
   depth limits, time bounding, re-delegation.
2. **8-step verification** -- each step passing, each step failing
   independently.
3. **Nonce management** -- generation, freshness, replay prevention, cleanup.
4. **Revocation cascading** -- single token, chain, agent-level, transitive.
5. **Token binding** -- HMAC creation, verification, timestamp tolerance,
   wrong agent, tampered proof.
6. **Delegation chains** -- A -> B -> C end-to-end scenarios.
"""
from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta

import pytest

from nl_protocol.core.errors import (
    DelegationDepthExceeded,
    DelegationSubsetViolation,
    DelegationTokenExpired,
    InvalidAgent,
    InvalidDelegationToken,
    ReplayDetectedAuth,
)
from nl_protocol.core.interfaces import (
    InMemoryAgentRegistry,
    InMemoryDelegationStore,
    InMemoryNonceStore,
    InMemoryScopeGrantStore,
)
from nl_protocol.core.types import (
    AID,
    ActionType,
    AgentURI,
    DelegationScope,
    DelegationToken,
    LifecycleState,
    ScopeConditions,
    ScopeGrant,
)
from nl_protocol.federation.cascade import CascadeEngine
from nl_protocol.federation.delegation import DelegationManager
from nl_protocol.federation.nonce import NonceManager
from nl_protocol.federation.token_binding import TokenBinding
from nl_protocol.federation.verification import DelegationVerifier

# ---------------------------------------------------------------------------
# Constants & helpers
# ---------------------------------------------------------------------------

AGENT_A = AgentURI("nl://org-a.com/orchestrator/1.0.0")
AGENT_B = AgentURI("nl://org-b.com/deploy-agent/1.0.0")
AGENT_C = AgentURI("nl://org-c.com/sub-agent/1.0.0")
AGENT_D = AgentURI("nl://org-d.com/deep-agent/1.0.0")

NOW = datetime.now(UTC)
FUTURE = NOW + timedelta(hours=8)
PAST = NOW - timedelta(hours=8)


def _make_grant(
    *,
    agent_uri: AgentURI = AGENT_A,
    grant_id: str = "grant-001",
    secret: str = "api/*",
    actions: list[ActionType] | None = None,
    valid_from: datetime | None = None,
    valid_until: datetime | None = None,
    max_uses: int | None = None,
    current_uses: int = 0,
    revoked: bool = False,
) -> ScopeGrant:
    """Helper to create a ScopeGrant with sensible defaults."""
    return ScopeGrant(
        grant_id=grant_id,
        agent_uri=agent_uri,
        secret=secret,
        actions=actions or [ActionType.EXEC, ActionType.TEMPLATE],
        conditions=ScopeConditions(
            valid_from=valid_from or (NOW - timedelta(hours=1)),
            valid_until=valid_until or FUTURE,
            max_uses=max_uses,
            current_uses=current_uses,
        ),
        revoked=revoked,
    )


def _make_aid(
    agent_uri: AgentURI,
    *,
    state: LifecycleState = LifecycleState.ACTIVE,
) -> AID:
    """Helper to create an AID with sensible defaults."""
    return AID(
        agent_uri=agent_uri,
        display_name="Test Agent",
        vendor="test.com",
        version="1.0.0",
        scope=["api/*"],
        expires_at=FUTURE,
        lifecycle_state=state,
    )


def _make_scope(
    *,
    secrets: list[str] | None = None,
    actions: list[ActionType] | None = None,
) -> DelegationScope:
    """Helper to create a DelegationScope."""
    return DelegationScope(
        secrets=secrets or ["api/DEPLOY_KEY"],
        actions=actions or [ActionType.EXEC],
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def delegation_store() -> InMemoryDelegationStore:
    return InMemoryDelegationStore()


@pytest.fixture
def grant_store() -> InMemoryScopeGrantStore:
    return InMemoryScopeGrantStore()


@pytest.fixture
def nonce_store() -> InMemoryNonceStore:
    return InMemoryNonceStore()


@pytest.fixture
def agent_registry() -> InMemoryAgentRegistry:
    return InMemoryAgentRegistry()


@pytest.fixture
def nonce_manager(nonce_store: InMemoryNonceStore) -> NonceManager:
    return NonceManager(nonce_store)


@pytest.fixture
def token_binding() -> TokenBinding:
    return TokenBinding()


@pytest.fixture
def delegation_manager(
    delegation_store: InMemoryDelegationStore,
    grant_store: InMemoryScopeGrantStore,
) -> DelegationManager:
    from nl_protocol.access.scope_grants import ScopeEvaluator

    evaluator = ScopeEvaluator(grant_store)
    return DelegationManager(delegation_store, evaluator)


@pytest.fixture
def cascade_engine(delegation_store: InMemoryDelegationStore) -> CascadeEngine:
    return CascadeEngine(delegation_store)


@pytest.fixture
async def verifier(
    delegation_store: InMemoryDelegationStore,
    agent_registry: InMemoryAgentRegistry,
    grant_store: InMemoryScopeGrantStore,
    nonce_manager: NonceManager,
    token_binding: TokenBinding,
) -> DelegationVerifier:
    return DelegationVerifier(
        delegation_store=delegation_store,
        agent_registry=agent_registry,
        scope_grant_store=grant_store,
        nonce_manager=nonce_manager,
        token_binding=token_binding,
    )


# ===================================================================
# 1. Delegation Token Creation Tests
# ===================================================================


class TestDelegationCreation:
    """Tests for DelegationManager.create_token."""

    @pytest.mark.asyncio
    async def test_create_valid_token(
        self, delegation_manager: DelegationManager
    ) -> None:
        """A delegation token is created when scope is a valid subset."""
        parent_grant = _make_grant()
        scope = _make_scope()

        token = await delegation_manager.create_token(
            parent_grant, AGENT_B, scope
        )

        assert token.token_id is not None
        assert token.issuer == AGENT_A
        assert token.subject == AGENT_B
        assert token.scope.secrets == ["api/DEPLOY_KEY"]
        assert token.scope.actions == [ActionType.EXEC]
        assert token.current_depth == 0
        assert token.expires_at > datetime.now(UTC)

    @pytest.mark.asyncio
    async def test_create_token_stored(
        self,
        delegation_manager: DelegationManager,
        delegation_store: InMemoryDelegationStore,
    ) -> None:
        """A created token is persisted in the delegation store."""
        parent_grant = _make_grant()
        scope = _make_scope()

        token = await delegation_manager.create_token(
            parent_grant, AGENT_B, scope
        )

        stored = await delegation_store.get_token(token.token_id)
        assert stored is not None
        assert stored.token_id == token.token_id

    @pytest.mark.asyncio
    async def test_subset_rule_secret_violation(
        self, delegation_manager: DelegationManager
    ) -> None:
        """DelegationSubsetViolation raised for out-of-scope secrets."""
        parent_grant = _make_grant(secret="api/*")
        scope = DelegationScope(
            secrets=["database/DB_PASSWORD"],
            actions=[ActionType.EXEC],
        )

        with pytest.raises(DelegationSubsetViolation):
            await delegation_manager.create_token(
                parent_grant, AGENT_B, scope
            )

    @pytest.mark.asyncio
    async def test_subset_rule_action_violation(
        self, delegation_manager: DelegationManager
    ) -> None:
        """DelegationSubsetViolation raised for escalated actions."""
        parent_grant = _make_grant(actions=[ActionType.EXEC])
        scope = DelegationScope(
            secrets=["api/TOKEN"],
            actions=[ActionType.EXEC, ActionType.DELEGATE],
        )

        with pytest.raises(DelegationSubsetViolation):
            await delegation_manager.create_token(
                parent_grant, AGENT_B, scope
            )

    @pytest.mark.asyncio
    async def test_subset_rule_exact_match(
        self, delegation_manager: DelegationManager
    ) -> None:
        """Equal scope (not escalated) is allowed."""
        parent_grant = _make_grant(
            secret="api/*", actions=[ActionType.EXEC, ActionType.TEMPLATE]
        )
        scope = DelegationScope(
            secrets=["api/TOKEN"],
            actions=[ActionType.EXEC, ActionType.TEMPLATE],
        )

        token = await delegation_manager.create_token(
            parent_grant, AGENT_B, scope
        )
        assert token is not None

    @pytest.mark.asyncio
    async def test_depth_limit_exceeded(
        self,
        delegation_store: InMemoryDelegationStore,
        grant_store: InMemoryScopeGrantStore,
    ) -> None:
        """DelegationDepthExceeded raised when max depth is reached."""
        from nl_protocol.access.scope_grants import ScopeEvaluator

        evaluator = ScopeEvaluator(grant_store)
        manager = DelegationManager(
            delegation_store, evaluator, max_delegation_depth=1
        )

        parent_grant = _make_grant()
        scope = _make_scope()

        # First delegation: depth 0 -> OK
        token_ab = await manager.create_token(parent_grant, AGENT_B, scope)
        assert token_ab.current_depth == 0

        # Second delegation from token_ab: depth 1 >= max_depth=1 -> FAIL
        grant_b = _make_grant(agent_uri=AGENT_B, grant_id="grant-b")
        with pytest.raises(DelegationDepthExceeded):
            await manager.create_token(
                grant_b, AGENT_C, scope, parent_token=token_ab
            )

    @pytest.mark.asyncio
    async def test_depth_limit_default_three(
        self, delegation_manager: DelegationManager
    ) -> None:
        """Default max_delegation_depth is 3."""
        parent_grant = _make_grant()
        scope = _make_scope()

        # Depth 0
        t1 = await delegation_manager.create_token(parent_grant, AGENT_B, scope)
        assert t1.current_depth == 0

        # Depth 1
        grant_b = _make_grant(agent_uri=AGENT_B, grant_id="grant-b")
        t2 = await delegation_manager.create_token(
            grant_b, AGENT_C, scope, parent_token=t1
        )
        assert t2.current_depth == 1

        # Depth 2
        grant_c = _make_grant(agent_uri=AGENT_C, grant_id="grant-c")
        t3 = await delegation_manager.create_token(
            grant_c, AGENT_D, scope, parent_token=t2
        )
        assert t3.current_depth == 2

    @pytest.mark.asyncio
    async def test_depth_three_blocks_fourth(
        self,
        delegation_store: InMemoryDelegationStore,
        grant_store: InMemoryScopeGrantStore,
    ) -> None:
        """Depth 3 (default max) blocks a fourth delegation."""
        from nl_protocol.access.scope_grants import ScopeEvaluator

        evaluator = ScopeEvaluator(grant_store)
        manager = DelegationManager(
            delegation_store, evaluator, max_delegation_depth=3
        )

        parent_grant = _make_grant()
        scope = _make_scope()

        t1 = await manager.create_token(parent_grant, AGENT_B, scope)
        grant_b = _make_grant(agent_uri=AGENT_B, grant_id="grant-b")
        t2 = await manager.create_token(grant_b, AGENT_C, scope, parent_token=t1)
        grant_c = _make_grant(agent_uri=AGENT_C, grant_id="grant-c")
        t3 = await manager.create_token(grant_c, AGENT_D, scope, parent_token=t2)

        grant_d = _make_grant(
            agent_uri=AGENT_D,
            grant_id="grant-d",
        )
        agent_e = AgentURI("nl://org-e.com/leaf-agent/1.0.0")
        with pytest.raises(DelegationDepthExceeded):
            await manager.create_token(
                grant_d, agent_e, scope, parent_token=t3
            )

    @pytest.mark.asyncio
    async def test_custom_ttl(
        self, delegation_manager: DelegationManager
    ) -> None:
        """Custom TTL is applied to the token."""
        parent_grant = _make_grant()
        scope = _make_scope()

        token = await delegation_manager.create_token(
            parent_grant, AGENT_B, scope, ttl=timedelta(minutes=10)
        )

        expected = datetime.now(UTC) + timedelta(minutes=10)
        # Allow 2 seconds of tolerance
        assert abs((token.expires_at - expected).total_seconds()) < 2

    @pytest.mark.asyncio
    async def test_ttl_capped_by_parent_grant(
        self, delegation_manager: DelegationManager
    ) -> None:
        """Token expiry is capped by the parent grant's valid_until."""
        short_future = NOW + timedelta(minutes=2)
        parent_grant = _make_grant(valid_until=short_future)
        scope = _make_scope()

        token = await delegation_manager.create_token(
            parent_grant, AGENT_B, scope, ttl=timedelta(hours=1)
        )

        # Token should expire at the parent grant's valid_until, not 1 hour later
        assert token.expires_at <= short_future

    @pytest.mark.asyncio
    async def test_ttl_capped_by_parent_token(
        self, delegation_manager: DelegationManager
    ) -> None:
        """Re-delegation expiry is capped by parent token's expires_at."""
        parent_grant = _make_grant()
        scope = _make_scope()

        # Create first token with 3 min TTL
        t1 = await delegation_manager.create_token(
            parent_grant, AGENT_B, scope, ttl=timedelta(minutes=3)
        )

        # Re-delegate with a 1 hour TTL -- should be capped by t1's expires_at
        grant_b = _make_grant(agent_uri=AGENT_B, grant_id="grant-b")
        t2 = await delegation_manager.create_token(
            grant_b, AGENT_C, scope, ttl=timedelta(hours=1), parent_token=t1
        )

        assert t2.expires_at <= t1.expires_at

    @pytest.mark.asyncio
    async def test_default_ttl_five_minutes(
        self, delegation_manager: DelegationManager
    ) -> None:
        """Default TTL is 5 minutes per spec recommendation."""
        parent_grant = _make_grant()
        scope = _make_scope()

        token = await delegation_manager.create_token(
            parent_grant, AGENT_B, scope
        )

        expected = datetime.now(UTC) + timedelta(minutes=5)
        assert abs((token.expires_at - expected).total_seconds()) < 2

    @pytest.mark.asyncio
    async def test_token_has_unique_id(
        self, delegation_manager: DelegationManager
    ) -> None:
        """Each created token has a unique UUID."""
        parent_grant = _make_grant()
        scope = _make_scope()

        t1 = await delegation_manager.create_token(parent_grant, AGENT_B, scope)
        t2 = await delegation_manager.create_token(parent_grant, AGENT_B, scope)

        assert t1.token_id != t2.token_id


# ===================================================================
# 2. 8-Step Delegation Verification Tests
# ===================================================================


class TestDelegationVerification:
    """Tests for DelegationVerifier.verify -- 8-step verification."""

    async def _setup_valid_context(
        self,
        delegation_store: InMemoryDelegationStore,
        agent_registry: InMemoryAgentRegistry,
        grant_store: InMemoryScopeGrantStore,
    ) -> DelegationToken:
        """Create a valid token and all supporting data."""
        # Register agents
        await agent_registry.register(_make_aid(AGENT_A))
        await agent_registry.register(_make_aid(AGENT_B))

        # Create scope grant for issuer
        grant = _make_grant()
        await grant_store.create_grant(grant)

        # Create and store delegation token
        token = DelegationToken(
            token_id="test-token-001",
            issuer=AGENT_A,
            subject=AGENT_B,
            scope=_make_scope(),
            issued_at=NOW,
            expires_at=FUTURE,
            max_delegation_depth=3,
            current_depth=0,
        )
        await delegation_store.store_token(token)
        return token

    @pytest.mark.asyncio
    async def test_full_verification_passes(
        self,
        delegation_store: InMemoryDelegationStore,
        agent_registry: InMemoryAgentRegistry,
        grant_store: InMemoryScopeGrantStore,
        nonce_manager: NonceManager,
    ) -> None:
        """All 8 steps pass for a valid token."""
        token = await self._setup_valid_context(
            delegation_store, agent_registry, grant_store
        )
        verifier = DelegationVerifier(
            delegation_store, agent_registry, grant_store, nonce_manager
        )

        nonce = nonce_manager.generate_nonce()
        result = await verifier.verify(
            token.token_id, AGENT_B, nonce=nonce
        )

        assert result.token_id == token.token_id
        assert result.subject == AGENT_B

    @pytest.mark.asyncio
    async def test_step1_token_not_found(
        self,
        delegation_store: InMemoryDelegationStore,
        agent_registry: InMemoryAgentRegistry,
        grant_store: InMemoryScopeGrantStore,
        nonce_manager: NonceManager,
    ) -> None:
        """Step 1 fails: token does not exist in store."""
        verifier = DelegationVerifier(
            delegation_store, agent_registry, grant_store, nonce_manager
        )

        with pytest.raises(InvalidDelegationToken, match="not found"):
            await verifier.verify("nonexistent-token", AGENT_B)

    @pytest.mark.asyncio
    async def test_step2_token_revoked(
        self,
        delegation_store: InMemoryDelegationStore,
        agent_registry: InMemoryAgentRegistry,
        grant_store: InMemoryScopeGrantStore,
        nonce_manager: NonceManager,
    ) -> None:
        """Step 1/2 fails: token has been revoked (returns None from store)."""
        token = await self._setup_valid_context(
            delegation_store, agent_registry, grant_store
        )
        verifier = DelegationVerifier(
            delegation_store, agent_registry, grant_store, nonce_manager
        )

        # Revoke the token
        await delegation_store.revoke_token(token.token_id)

        with pytest.raises(InvalidDelegationToken, match="not found or revoked"):
            await verifier.verify(token.token_id, AGENT_B)

    @pytest.mark.asyncio
    async def test_step3_token_expired(
        self,
        delegation_store: InMemoryDelegationStore,
        agent_registry: InMemoryAgentRegistry,
        grant_store: InMemoryScopeGrantStore,
        nonce_manager: NonceManager,
    ) -> None:
        """Step 3 fails: token has expired."""
        await agent_registry.register(_make_aid(AGENT_A))
        await agent_registry.register(_make_aid(AGENT_B))
        await grant_store.create_grant(_make_grant())

        expired_token = DelegationToken(
            token_id="expired-token",
            issuer=AGENT_A,
            subject=AGENT_B,
            scope=_make_scope(),
            issued_at=PAST - timedelta(hours=1),
            expires_at=PAST,
            max_delegation_depth=3,
            current_depth=0,
        )
        await delegation_store.store_token(expired_token)

        verifier = DelegationVerifier(
            delegation_store, agent_registry, grant_store, nonce_manager
        )

        with pytest.raises(DelegationTokenExpired):
            await verifier.verify(expired_token.token_id, AGENT_B)

    @pytest.mark.asyncio
    async def test_step3_strict_less_than(
        self,
        delegation_store: InMemoryDelegationStore,
        agent_registry: InMemoryAgentRegistry,
        grant_store: InMemoryScopeGrantStore,
        nonce_manager: NonceManager,
    ) -> None:
        """Step 3: token at exactly expires_at is rejected (strict <)."""
        await agent_registry.register(_make_aid(AGENT_A))
        await agent_registry.register(_make_aid(AGENT_B))
        await grant_store.create_grant(_make_grant())

        # Token expires "now" (or just before by the time verification runs)
        now = datetime.now(UTC)
        token = DelegationToken(
            token_id="edge-token",
            issuer=AGENT_A,
            subject=AGENT_B,
            scope=_make_scope(),
            issued_at=PAST,
            expires_at=now - timedelta(milliseconds=1),
            max_delegation_depth=3,
            current_depth=0,
        )
        await delegation_store.store_token(token)

        verifier = DelegationVerifier(
            delegation_store, agent_registry, grant_store, nonce_manager
        )

        with pytest.raises(DelegationTokenExpired):
            await verifier.verify(token.token_id, AGENT_B)

    @pytest.mark.asyncio
    async def test_step4_subject_mismatch(
        self,
        delegation_store: InMemoryDelegationStore,
        agent_registry: InMemoryAgentRegistry,
        grant_store: InMemoryScopeGrantStore,
        nonce_manager: NonceManager,
    ) -> None:
        """Step 4 fails: presenting agent does not match subject."""
        token = await self._setup_valid_context(
            delegation_store, agent_registry, grant_store
        )
        verifier = DelegationVerifier(
            delegation_store, agent_registry, grant_store, nonce_manager
        )

        wrong_agent = AgentURI("nl://evil.com/attacker/1.0.0")
        with pytest.raises(InvalidDelegationToken, match="does not match"):
            await verifier.verify(token.token_id, wrong_agent)

    @pytest.mark.asyncio
    async def test_step5_issuer_not_found(
        self,
        delegation_store: InMemoryDelegationStore,
        agent_registry: InMemoryAgentRegistry,
        grant_store: InMemoryScopeGrantStore,
        nonce_manager: NonceManager,
    ) -> None:
        """Step 5 fails: issuer agent not in registry."""
        # Register only agent B, not agent A (the issuer)
        await agent_registry.register(_make_aid(AGENT_B))
        await grant_store.create_grant(_make_grant())

        token = DelegationToken(
            token_id="orphan-token",
            issuer=AGENT_A,
            subject=AGENT_B,
            scope=_make_scope(),
            issued_at=NOW,
            expires_at=FUTURE,
            max_delegation_depth=3,
            current_depth=0,
        )
        await delegation_store.store_token(token)

        verifier = DelegationVerifier(
            delegation_store, agent_registry, grant_store, nonce_manager
        )

        with pytest.raises(InvalidAgent, match="not found"):
            await verifier.verify(token.token_id, AGENT_B)

    @pytest.mark.asyncio
    async def test_step5_issuer_revoked(
        self,
        delegation_store: InMemoryDelegationStore,
        agent_registry: InMemoryAgentRegistry,
        grant_store: InMemoryScopeGrantStore,
        nonce_manager: NonceManager,
    ) -> None:
        """Step 5 fails: issuer agent has been revoked."""
        await agent_registry.register(
            _make_aid(AGENT_A, state=LifecycleState.REVOKED)
        )
        await agent_registry.register(_make_aid(AGENT_B))
        await grant_store.create_grant(_make_grant())

        token = DelegationToken(
            token_id="revoked-issuer-token",
            issuer=AGENT_A,
            subject=AGENT_B,
            scope=_make_scope(),
            issued_at=NOW,
            expires_at=FUTURE,
            max_delegation_depth=3,
            current_depth=0,
        )
        await delegation_store.store_token(token)

        verifier = DelegationVerifier(
            delegation_store, agent_registry, grant_store, nonce_manager
        )

        with pytest.raises(InvalidAgent, match="not active"):
            await verifier.verify(token.token_id, AGENT_B)

    @pytest.mark.asyncio
    async def test_step5_issuer_suspended(
        self,
        delegation_store: InMemoryDelegationStore,
        agent_registry: InMemoryAgentRegistry,
        grant_store: InMemoryScopeGrantStore,
        nonce_manager: NonceManager,
    ) -> None:
        """Step 5 fails: issuer agent is suspended."""
        await agent_registry.register(
            _make_aid(AGENT_A, state=LifecycleState.SUSPENDED)
        )
        await agent_registry.register(_make_aid(AGENT_B))
        await grant_store.create_grant(_make_grant())

        token = DelegationToken(
            token_id="suspended-issuer-token",
            issuer=AGENT_A,
            subject=AGENT_B,
            scope=_make_scope(),
            issued_at=NOW,
            expires_at=FUTURE,
            max_delegation_depth=3,
            current_depth=0,
        )
        await delegation_store.store_token(token)

        verifier = DelegationVerifier(
            delegation_store, agent_registry, grant_store, nonce_manager
        )

        with pytest.raises(InvalidAgent, match="not active"):
            await verifier.verify(token.token_id, AGENT_B)

    @pytest.mark.asyncio
    async def test_step6_scope_revoked(
        self,
        delegation_store: InMemoryDelegationStore,
        agent_registry: InMemoryAgentRegistry,
        grant_store: InMemoryScopeGrantStore,
        nonce_manager: NonceManager,
    ) -> None:
        """Step 6 fails: issuer has no active scope grants."""
        await agent_registry.register(_make_aid(AGENT_A))
        await agent_registry.register(_make_aid(AGENT_B))

        # Create a revoked grant (no active grants)
        revoked_grant = _make_grant(revoked=True)
        await grant_store.create_grant(revoked_grant)

        token = DelegationToken(
            token_id="no-scope-token",
            issuer=AGENT_A,
            subject=AGENT_B,
            scope=_make_scope(),
            issued_at=NOW,
            expires_at=FUTURE,
            max_delegation_depth=3,
            current_depth=0,
        )
        await delegation_store.store_token(token)

        verifier = DelegationVerifier(
            delegation_store, agent_registry, grant_store, nonce_manager
        )

        with pytest.raises(InvalidDelegationToken, match="no active scope"):
            await verifier.verify(token.token_id, AGENT_B)

    @pytest.mark.asyncio
    async def test_step7_replay_detected(
        self,
        delegation_store: InMemoryDelegationStore,
        agent_registry: InMemoryAgentRegistry,
        grant_store: InMemoryScopeGrantStore,
        nonce_manager: NonceManager,
    ) -> None:
        """Step 7 fails: nonce has already been used (replay)."""
        token = await self._setup_valid_context(
            delegation_store, agent_registry, grant_store
        )
        verifier = DelegationVerifier(
            delegation_store, agent_registry, grant_store, nonce_manager
        )

        nonce = nonce_manager.generate_nonce()

        # First use: OK
        await verifier.verify(token.token_id, AGENT_B, nonce=nonce)

        # Second use: replay detected
        with pytest.raises(ReplayDetectedAuth):
            await verifier.verify(token.token_id, AGENT_B, nonce=nonce)

    @pytest.mark.asyncio
    async def test_step8_binding_valid(
        self,
        delegation_store: InMemoryDelegationStore,
        agent_registry: InMemoryAgentRegistry,
        grant_store: InMemoryScopeGrantStore,
        nonce_manager: NonceManager,
        token_binding: TokenBinding,
    ) -> None:
        """Step 8 passes: valid HMAC binding proof."""
        token = await self._setup_valid_context(
            delegation_store, agent_registry, grant_store
        )
        verifier = DelegationVerifier(
            delegation_store,
            agent_registry,
            grant_store,
            nonce_manager,
            token_binding=token_binding,
        )

        secret_key = "test-binding-key-256bit"
        proof = token_binding.create_proof(
            token.token_id, str(AGENT_B), secret_key
        )

        result = await verifier.verify(
            token.token_id,
            AGENT_B,
            binding_proof=proof,
            binding_secret=secret_key,
        )
        assert result.token_id == token.token_id

    @pytest.mark.asyncio
    async def test_step8_binding_invalid(
        self,
        delegation_store: InMemoryDelegationStore,
        agent_registry: InMemoryAgentRegistry,
        grant_store: InMemoryScopeGrantStore,
        nonce_manager: NonceManager,
        token_binding: TokenBinding,
    ) -> None:
        """Step 8 fails: invalid HMAC binding proof."""
        token = await self._setup_valid_context(
            delegation_store, agent_registry, grant_store
        )
        verifier = DelegationVerifier(
            delegation_store,
            agent_registry,
            grant_store,
            nonce_manager,
            token_binding=token_binding,
        )

        with pytest.raises(InvalidDelegationToken, match="binding proof"):
            await verifier.verify(
                token.token_id,
                AGENT_B,
                binding_proof="fake.proof",
                binding_secret="wrong-key",
            )

    @pytest.mark.asyncio
    async def test_verification_without_nonce_skips_step7(
        self,
        delegation_store: InMemoryDelegationStore,
        agent_registry: InMemoryAgentRegistry,
        grant_store: InMemoryScopeGrantStore,
        nonce_manager: NonceManager,
    ) -> None:
        """When no nonce is provided, step 7 is skipped."""
        token = await self._setup_valid_context(
            delegation_store, agent_registry, grant_store
        )
        verifier = DelegationVerifier(
            delegation_store, agent_registry, grant_store, nonce_manager
        )

        # No nonce passed -- should still succeed
        result = await verifier.verify(token.token_id, AGENT_B)
        assert result.token_id == token.token_id

    @pytest.mark.asyncio
    async def test_verification_without_binding_skips_step8(
        self,
        delegation_store: InMemoryDelegationStore,
        agent_registry: InMemoryAgentRegistry,
        grant_store: InMemoryScopeGrantStore,
        nonce_manager: NonceManager,
    ) -> None:
        """When no token_binding is configured, step 8 is skipped."""
        token = await self._setup_valid_context(
            delegation_store, agent_registry, grant_store
        )
        # No token_binding parameter
        verifier = DelegationVerifier(
            delegation_store, agent_registry, grant_store, nonce_manager
        )

        result = await verifier.verify(token.token_id, AGENT_B)
        assert result.token_id == token.token_id


# ===================================================================
# 3. Nonce Management Tests
# ===================================================================


class TestNonceManagement:
    """Tests for NonceManager."""

    def test_generate_nonce_length(self, nonce_manager: NonceManager) -> None:
        """Generated nonces have sufficient length (256 bits = 43 chars base64)."""
        nonce = nonce_manager.generate_nonce()
        # 32 bytes -> ~43 chars in URL-safe base64
        assert len(nonce) >= 40

    def test_generate_nonce_unique(self, nonce_manager: NonceManager) -> None:
        """Each generated nonce is unique."""
        nonces = {nonce_manager.generate_nonce() for _ in range(100)}
        assert len(nonces) == 100

    @pytest.mark.asyncio
    async def test_check_and_consume_fresh(
        self, nonce_manager: NonceManager
    ) -> None:
        """A fresh nonce is accepted."""
        nonce = nonce_manager.generate_nonce()
        result = await nonce_manager.check_and_consume(nonce, FUTURE)
        assert result is True

    @pytest.mark.asyncio
    async def test_check_and_consume_replay(
        self, nonce_manager: NonceManager
    ) -> None:
        """A replayed nonce is rejected."""
        nonce = nonce_manager.generate_nonce()
        await nonce_manager.check_and_consume(nonce, FUTURE)

        # Replay
        result = await nonce_manager.check_and_consume(nonce, FUTURE)
        assert result is False

    @pytest.mark.asyncio
    async def test_different_nonces_both_accepted(
        self, nonce_manager: NonceManager
    ) -> None:
        """Two different nonces are both accepted."""
        nonce1 = nonce_manager.generate_nonce()
        nonce2 = nonce_manager.generate_nonce()

        assert await nonce_manager.check_and_consume(nonce1, FUTURE) is True
        assert await nonce_manager.check_and_consume(nonce2, FUTURE) is True

    @pytest.mark.asyncio
    async def test_cleanup_expired(
        self,
        nonce_store: InMemoryNonceStore,
        nonce_manager: NonceManager,
    ) -> None:
        """Expired nonces are cleaned up."""
        past_time = datetime.now(UTC) - timedelta(hours=1)
        await nonce_store.check_and_store("old-nonce", past_time)

        removed = await nonce_manager.cleanup_expired()
        assert removed == 1

    @pytest.mark.asyncio
    async def test_cleanup_does_not_remove_active(
        self,
        nonce_manager: NonceManager,
    ) -> None:
        """Active (unexpired) nonces are not cleaned up."""
        nonce = nonce_manager.generate_nonce()
        await nonce_manager.check_and_consume(nonce, FUTURE)

        removed = await nonce_manager.cleanup_expired()
        assert removed == 0

        # The nonce should still be seen as a replay
        result = await nonce_manager.check_and_consume(nonce, FUTURE)
        assert result is False


# ===================================================================
# 4. Revocation Cascading Tests
# ===================================================================


class TestCascadeEngine:
    """Tests for CascadeEngine -- transitive revocation."""

    @pytest.mark.asyncio
    async def test_revoke_single_token(
        self,
        cascade_engine: CascadeEngine,
        delegation_store: InMemoryDelegationStore,
    ) -> None:
        """Revoking a single token with no children."""
        token = DelegationToken(
            token_id="token-1",
            issuer=AGENT_A,
            subject=AGENT_B,
            scope=_make_scope(),
            issued_at=NOW,
            expires_at=FUTURE,
        )
        await delegation_store.store_token(token)

        revoked = await cascade_engine.revoke_token("token-1")
        assert revoked == ["token-1"]

        # Token should no longer be retrievable
        assert await delegation_store.get_token("token-1") is None

    @pytest.mark.asyncio
    async def test_revoke_cascades_to_children(
        self,
        cascade_engine: CascadeEngine,
        delegation_store: InMemoryDelegationStore,
    ) -> None:
        """Revoking a parent cascades to all children."""
        parent = DelegationToken(
            token_id="parent",
            issuer=AGENT_A,
            subject=AGENT_B,
            scope=_make_scope(),
            issued_at=NOW,
            expires_at=FUTURE,
        )
        child = DelegationToken(
            token_id="child",
            issuer=AGENT_B,
            subject=AGENT_C,
            scope=_make_scope(),
            issued_at=NOW,
            expires_at=FUTURE,
        )

        await delegation_store.store_token(parent)
        await delegation_store.store_token(child)
        delegation_store.register_child("parent", "child")

        revoked = await cascade_engine.revoke_token("parent")
        assert "parent" in revoked
        assert "child" in revoked
        assert len(revoked) == 2

    @pytest.mark.asyncio
    async def test_revoke_cascades_deeply(
        self,
        cascade_engine: CascadeEngine,
        delegation_store: InMemoryDelegationStore,
    ) -> None:
        """Revocation cascades through A -> B -> C chain."""
        token_a = DelegationToken(
            token_id="t-a",
            issuer=AGENT_A,
            subject=AGENT_B,
            scope=_make_scope(),
            issued_at=NOW,
            expires_at=FUTURE,
        )
        token_b = DelegationToken(
            token_id="t-b",
            issuer=AGENT_B,
            subject=AGENT_C,
            scope=_make_scope(),
            issued_at=NOW,
            expires_at=FUTURE,
        )
        token_c = DelegationToken(
            token_id="t-c",
            issuer=AGENT_C,
            subject=AGENT_D,
            scope=_make_scope(),
            issued_at=NOW,
            expires_at=FUTURE,
        )

        await delegation_store.store_token(token_a)
        await delegation_store.store_token(token_b)
        await delegation_store.store_token(token_c)
        delegation_store.register_child("t-a", "t-b")
        delegation_store.register_child("t-b", "t-c")

        revoked = await cascade_engine.revoke_token("t-a")
        assert set(revoked) == {"t-a", "t-b", "t-c"}

    @pytest.mark.asyncio
    async def test_revoke_multiple_children(
        self,
        cascade_engine: CascadeEngine,
        delegation_store: InMemoryDelegationStore,
    ) -> None:
        """Revocation cascades to multiple children of same parent."""
        parent = DelegationToken(
            token_id="parent",
            issuer=AGENT_A,
            subject=AGENT_B,
            scope=_make_scope(),
            issued_at=NOW,
            expires_at=FUTURE,
        )
        child1 = DelegationToken(
            token_id="child1",
            issuer=AGENT_B,
            subject=AGENT_C,
            scope=_make_scope(),
            issued_at=NOW,
            expires_at=FUTURE,
        )
        child2 = DelegationToken(
            token_id="child2",
            issuer=AGENT_B,
            subject=AGENT_D,
            scope=_make_scope(),
            issued_at=NOW,
            expires_at=FUTURE,
        )

        await delegation_store.store_token(parent)
        await delegation_store.store_token(child1)
        await delegation_store.store_token(child2)
        delegation_store.register_child("parent", "child1")
        delegation_store.register_child("parent", "child2")

        revoked = await cascade_engine.revoke_token("parent")
        assert set(revoked) == {"parent", "child1", "child2"}

    @pytest.mark.asyncio
    async def test_revoke_nonexistent_token(
        self,
        cascade_engine: CascadeEngine,
    ) -> None:
        """Revoking a nonexistent token still returns a list (with the id)."""
        revoked = await cascade_engine.revoke_token("nonexistent")
        # The store's revoke_token is a no-op for missing tokens,
        # but we still track the id in revoked_ids
        assert revoked == ["nonexistent"]

    @pytest.mark.asyncio
    async def test_revoke_agent_all_tokens(
        self,
        cascade_engine: CascadeEngine,
        delegation_store: InMemoryDelegationStore,
    ) -> None:
        """Revoking an agent revokes all tokens where agent is issuer or subject."""
        # Agent B is issuer of one token and subject of another
        token_to_b = DelegationToken(
            token_id="to-b",
            issuer=AGENT_A,
            subject=AGENT_B,
            scope=_make_scope(),
            issued_at=NOW,
            expires_at=FUTURE,
        )
        token_from_b = DelegationToken(
            token_id="from-b",
            issuer=AGENT_B,
            subject=AGENT_C,
            scope=_make_scope(),
            issued_at=NOW,
            expires_at=FUTURE,
        )
        token_unrelated = DelegationToken(
            token_id="unrelated",
            issuer=AGENT_A,
            subject=AGENT_C,
            scope=_make_scope(),
            issued_at=NOW,
            expires_at=FUTURE,
        )

        await delegation_store.store_token(token_to_b)
        await delegation_store.store_token(token_from_b)
        await delegation_store.store_token(token_unrelated)

        revoked = await cascade_engine.revoke_agent(str(AGENT_B))
        assert "to-b" in revoked
        assert "from-b" in revoked
        assert "unrelated" not in revoked

    @pytest.mark.asyncio
    async def test_revoke_agent_cascades_children(
        self,
        cascade_engine: CascadeEngine,
        delegation_store: InMemoryDelegationStore,
    ) -> None:
        """Agent revocation cascades to child tokens."""
        token_to_b = DelegationToken(
            token_id="to-b",
            issuer=AGENT_A,
            subject=AGENT_B,
            scope=_make_scope(),
            issued_at=NOW,
            expires_at=FUTURE,
        )
        token_b_child = DelegationToken(
            token_id="b-child",
            issuer=AGENT_B,
            subject=AGENT_C,
            scope=_make_scope(),
            issued_at=NOW,
            expires_at=FUTURE,
        )

        await delegation_store.store_token(token_to_b)
        await delegation_store.store_token(token_b_child)
        delegation_store.register_child("to-b", "b-child")

        revoked = await cascade_engine.revoke_agent(str(AGENT_B))
        assert "to-b" in revoked
        assert "b-child" in revoked

    @pytest.mark.asyncio
    async def test_revoke_agent_no_tokens(
        self,
        cascade_engine: CascadeEngine,
    ) -> None:
        """Revoking an agent with no tokens returns empty list."""
        revoked = await cascade_engine.revoke_agent(str(AGENT_A))
        assert revoked == []

    @pytest.mark.asyncio
    async def test_revoke_idempotent(
        self,
        cascade_engine: CascadeEngine,
        delegation_store: InMemoryDelegationStore,
    ) -> None:
        """Revoking an already-revoked token is idempotent."""
        token = DelegationToken(
            token_id="token-1",
            issuer=AGENT_A,
            subject=AGENT_B,
            scope=_make_scope(),
            issued_at=NOW,
            expires_at=FUTURE,
        )
        await delegation_store.store_token(token)

        r1 = await cascade_engine.revoke_token("token-1")
        r2 = await cascade_engine.revoke_token("token-1")
        assert "token-1" in r1
        assert "token-1" in r2


# ===================================================================
# 5. Token Binding Tests
# ===================================================================


class TestTokenBinding:
    """Tests for TokenBinding -- HMAC-SHA256 proof creation and verification."""

    def test_create_proof_format(self, token_binding: TokenBinding) -> None:
        """Proof has the format '<timestamp>.<hex_hmac>'."""
        proof = token_binding.create_proof("token-1", str(AGENT_B), "secret")
        parts = proof.split(".", 1)
        assert len(parts) == 2
        assert parts[0].isdigit()
        assert len(parts[1]) == 64  # SHA-256 hex = 64 chars

    def test_create_and_verify_round_trip(
        self, token_binding: TokenBinding
    ) -> None:
        """A proof created can be immediately verified."""
        ts = int(time.time())
        proof = token_binding.create_proof(
            "token-1", str(AGENT_B), "secret", timestamp=ts
        )
        result = token_binding.verify_proof(
            "token-1", str(AGENT_B), proof, "secret", current_time=ts
        )
        assert result is True

    def test_verify_wrong_agent(self, token_binding: TokenBinding) -> None:
        """Proof fails when verified with a different agent URI."""
        ts = int(time.time())
        proof = token_binding.create_proof(
            "token-1", str(AGENT_B), "secret", timestamp=ts
        )
        result = token_binding.verify_proof(
            "token-1", str(AGENT_C), proof, "secret", current_time=ts
        )
        assert result is False

    def test_verify_wrong_token(self, token_binding: TokenBinding) -> None:
        """Proof fails when verified with a different token ID."""
        ts = int(time.time())
        proof = token_binding.create_proof(
            "token-1", str(AGENT_B), "secret", timestamp=ts
        )
        result = token_binding.verify_proof(
            "token-2", str(AGENT_B), proof, "secret", current_time=ts
        )
        assert result is False

    def test_verify_wrong_secret(self, token_binding: TokenBinding) -> None:
        """Proof fails when verified with a different secret key."""
        ts = int(time.time())
        proof = token_binding.create_proof(
            "token-1", str(AGENT_B), "correct-secret", timestamp=ts
        )
        result = token_binding.verify_proof(
            "token-1", str(AGENT_B), proof, "wrong-secret", current_time=ts
        )
        assert result is False

    def test_verify_expired_timestamp(self, token_binding: TokenBinding) -> None:
        """Proof fails when timestamp is outside tolerance window."""
        old_ts = int(time.time()) - 60  # 60 seconds ago (> 30s tolerance)
        proof = token_binding.create_proof(
            "token-1", str(AGENT_B), "secret", timestamp=old_ts
        )
        result = token_binding.verify_proof(
            "token-1", str(AGENT_B), proof, "secret"
        )
        assert result is False

    def test_verify_within_tolerance(self, token_binding: TokenBinding) -> None:
        """Proof succeeds when timestamp is within tolerance window."""
        ts = int(time.time()) - 10  # 10 seconds ago (< 30s tolerance)
        proof = token_binding.create_proof(
            "token-1", str(AGENT_B), "secret", timestamp=ts
        )
        result = token_binding.verify_proof(
            "token-1", str(AGENT_B), proof, "secret"
        )
        assert result is True

    def test_verify_tampered_proof(self, token_binding: TokenBinding) -> None:
        """A tampered proof is rejected."""
        ts = int(time.time())
        proof = token_binding.create_proof(
            "token-1", str(AGENT_B), "secret", timestamp=ts
        )
        # Tamper with the HMAC part
        parts = proof.split(".", 1)
        tampered = parts[0] + "." + "0" * 64
        result = token_binding.verify_proof(
            "token-1", str(AGENT_B), tampered, "secret", current_time=ts
        )
        assert result is False

    def test_verify_malformed_proof(self, token_binding: TokenBinding) -> None:
        """A malformed proof string is rejected."""
        assert token_binding.verify_proof(
            "token-1", str(AGENT_B), "not-a-valid-proof", "secret"
        ) is False

    def test_verify_empty_proof(self, token_binding: TokenBinding) -> None:
        """An empty proof string is rejected."""
        assert token_binding.verify_proof(
            "token-1", str(AGENT_B), "", "secret"
        ) is False

    def test_verify_non_numeric_timestamp(
        self, token_binding: TokenBinding
    ) -> None:
        """A proof with a non-numeric timestamp is rejected."""
        assert token_binding.verify_proof(
            "token-1", str(AGENT_B), "abc.def", "secret"
        ) is False

    def test_custom_tolerance(self) -> None:
        """Custom timestamp tolerance is respected."""
        binding = TokenBinding(timestamp_tolerance=5)
        ts = int(time.time()) - 10  # 10 seconds ago
        proof = binding.create_proof(
            "token-1", str(AGENT_B), "secret", timestamp=ts
        )
        # 10s > 5s tolerance => fail
        result = binding.verify_proof(
            "token-1", str(AGENT_B), proof, "secret"
        )
        assert result is False

    def test_deterministic_hmac(self, token_binding: TokenBinding) -> None:
        """Same inputs produce the same HMAC (deterministic)."""
        ts = int(time.time())
        proof1 = token_binding.create_proof(
            "token-1", str(AGENT_B), "secret", timestamp=ts
        )
        proof2 = token_binding.create_proof(
            "token-1", str(AGENT_B), "secret", timestamp=ts
        )
        assert proof1 == proof2


# ===================================================================
# 6. Delegation Chain Tests (End-to-End)
# ===================================================================


class TestDelegationChains:
    """End-to-end tests for delegation chains A -> B -> C."""

    @pytest.mark.asyncio
    async def test_chain_a_to_b_to_c(
        self,
        delegation_store: InMemoryDelegationStore,
        grant_store: InMemoryScopeGrantStore,
        agent_registry: InMemoryAgentRegistry,
        nonce_manager: NonceManager,
    ) -> None:
        """Full chain: A delegates to B, B re-delegates to C."""
        from nl_protocol.access.scope_grants import ScopeEvaluator

        evaluator = ScopeEvaluator(grant_store)
        manager = DelegationManager(delegation_store, evaluator)

        # Setup agents
        await agent_registry.register(_make_aid(AGENT_A))
        await agent_registry.register(_make_aid(AGENT_B))
        await agent_registry.register(_make_aid(AGENT_C))

        # Setup grants
        grant_a = _make_grant(agent_uri=AGENT_A, grant_id="grant-a")
        grant_b = _make_grant(agent_uri=AGENT_B, grant_id="grant-b")
        await grant_store.create_grant(grant_a)
        await grant_store.create_grant(grant_b)

        scope = _make_scope()

        # A delegates to B
        token_ab = await manager.create_token(grant_a, AGENT_B, scope)
        assert token_ab.current_depth == 0
        assert token_ab.issuer == AGENT_A
        assert token_ab.subject == AGENT_B

        # B re-delegates to C
        token_bc = await manager.create_token(
            grant_b, AGENT_C, scope, parent_token=token_ab
        )
        assert token_bc.current_depth == 1
        assert token_bc.issuer == AGENT_B
        assert token_bc.subject == AGENT_C

        # Verify token_bc
        verifier = DelegationVerifier(
            delegation_store, agent_registry, grant_store, nonce_manager
        )
        result = await verifier.verify(token_bc.token_id, AGENT_C)
        assert result.token_id == token_bc.token_id

    @pytest.mark.asyncio
    async def test_chain_revocation_propagates(
        self,
        delegation_store: InMemoryDelegationStore,
        grant_store: InMemoryScopeGrantStore,
        agent_registry: InMemoryAgentRegistry,
        nonce_manager: NonceManager,
    ) -> None:
        """Revoking A->B token also invalidates B->C token."""
        from nl_protocol.access.scope_grants import ScopeEvaluator

        evaluator = ScopeEvaluator(grant_store)
        manager = DelegationManager(delegation_store, evaluator)
        cascade = CascadeEngine(delegation_store)

        # Setup
        await agent_registry.register(_make_aid(AGENT_A))
        await agent_registry.register(_make_aid(AGENT_B))
        await agent_registry.register(_make_aid(AGENT_C))

        grant_a = _make_grant(agent_uri=AGENT_A, grant_id="grant-a")
        grant_b = _make_grant(agent_uri=AGENT_B, grant_id="grant-b")
        await grant_store.create_grant(grant_a)
        await grant_store.create_grant(grant_b)

        scope = _make_scope()
        token_ab = await manager.create_token(grant_a, AGENT_B, scope)
        token_bc = await manager.create_token(
            grant_b, AGENT_C, scope, parent_token=token_ab
        )

        # Revoke the root token
        revoked = await cascade.revoke_token(token_ab.token_id)
        assert token_ab.token_id in revoked
        assert token_bc.token_id in revoked

        # Both tokens should now be inaccessible
        assert await delegation_store.get_token(token_ab.token_id) is None
        assert await delegation_store.get_token(token_bc.token_id) is None

    @pytest.mark.asyncio
    async def test_chain_scope_narrowing(
        self,
        delegation_store: InMemoryDelegationStore,
        grant_store: InMemoryScopeGrantStore,
    ) -> None:
        """Each delegation in the chain narrows the scope."""
        from nl_protocol.access.scope_grants import ScopeEvaluator

        evaluator = ScopeEvaluator(grant_store)
        manager = DelegationManager(delegation_store, evaluator)

        # A has wide scope
        grant_a = _make_grant(
            agent_uri=AGENT_A,
            grant_id="grant-a",
            secret="*",
            actions=[ActionType.EXEC, ActionType.TEMPLATE, ActionType.READ],
        )

        # A delegates to B with narrower scope
        scope_ab = DelegationScope(
            secrets=["api/DEPLOY_KEY", "api/TOKEN"],
            actions=[ActionType.EXEC, ActionType.TEMPLATE],
        )
        token_ab = await manager.create_token(grant_a, AGENT_B, scope_ab)
        assert len(token_ab.scope.secrets) == 2

        # B delegates to C with even narrower scope
        grant_b = _make_grant(
            agent_uri=AGENT_B,
            grant_id="grant-b",
            secret="api/*",
            actions=[ActionType.EXEC, ActionType.TEMPLATE],
        )
        scope_bc = DelegationScope(
            secrets=["api/DEPLOY_KEY"],
            actions=[ActionType.EXEC],
        )
        token_bc = await manager.create_token(
            grant_b, AGENT_C, scope_bc, parent_token=token_ab
        )
        assert token_bc.scope.secrets == ["api/DEPLOY_KEY"]
        assert token_bc.scope.actions == [ActionType.EXEC]

    @pytest.mark.asyncio
    async def test_chain_escalation_blocked(
        self,
        delegation_store: InMemoryDelegationStore,
        grant_store: InMemoryScopeGrantStore,
    ) -> None:
        """Privilege escalation in a delegation chain is blocked."""
        from nl_protocol.access.scope_grants import ScopeEvaluator

        evaluator = ScopeEvaluator(grant_store)
        manager = DelegationManager(delegation_store, evaluator)

        # B has only exec on api/*
        grant_b = _make_grant(
            agent_uri=AGENT_B,
            grant_id="grant-b",
            secret="api/*",
            actions=[ActionType.EXEC],
        )

        # B tries to delegate database access to C -- should fail
        escalated_scope = DelegationScope(
            secrets=["database/DB_PASSWORD"],
            actions=[ActionType.EXEC],
        )

        with pytest.raises(DelegationSubsetViolation):
            await manager.create_token(
                grant_b, AGENT_C, escalated_scope
            )

    @pytest.mark.asyncio
    async def test_chain_time_bounded(
        self,
        delegation_store: InMemoryDelegationStore,
        grant_store: InMemoryScopeGrantStore,
    ) -> None:
        """Re-delegated tokens cannot outlive their parent."""
        from nl_protocol.access.scope_grants import ScopeEvaluator

        evaluator = ScopeEvaluator(grant_store)
        manager = DelegationManager(delegation_store, evaluator)

        grant_a = _make_grant(agent_uri=AGENT_A, grant_id="grant-a")
        scope = _make_scope()

        # A creates token with 2 min TTL
        token_ab = await manager.create_token(
            grant_a, AGENT_B, scope, ttl=timedelta(minutes=2)
        )

        # B tries to re-delegate with 1 hour TTL
        grant_b = _make_grant(agent_uri=AGENT_B, grant_id="grant-b")
        token_bc = await manager.create_token(
            grant_b, AGENT_C, scope, ttl=timedelta(hours=1),
            parent_token=token_ab,
        )

        # token_bc must not exceed token_ab's expiry
        assert token_bc.expires_at <= token_ab.expires_at


# ===================================================================
# 7. Integration / Edge Case Tests
# ===================================================================


class TestEdgeCases:
    """Edge cases and integration scenarios."""

    @pytest.mark.asyncio
    async def test_empty_scope_secrets(
        self, delegation_manager: DelegationManager
    ) -> None:
        """A delegation with empty secrets list is valid (narrowest possible)."""
        parent_grant = _make_grant()
        scope = DelegationScope(
            secrets=[],
            actions=[ActionType.EXEC],
        )

        token = await delegation_manager.create_token(
            parent_grant, AGENT_B, scope
        )
        assert token.scope.secrets == []

    @pytest.mark.asyncio
    async def test_empty_scope_actions(
        self, delegation_manager: DelegationManager
    ) -> None:
        """A delegation with empty actions list is valid (no actions)."""
        parent_grant = _make_grant()
        scope = DelegationScope(
            secrets=["api/TOKEN"],
            actions=[],
        )

        token = await delegation_manager.create_token(
            parent_grant, AGENT_B, scope
        )
        assert token.scope.actions == []

    @pytest.mark.asyncio
    async def test_cascade_no_duplicate_in_diamond(
        self,
        delegation_store: InMemoryDelegationStore,
    ) -> None:
        """Cascade engine handles diamond-shaped delegation graphs."""
        cascade = CascadeEngine(delegation_store)

        # Diamond: parent -> child1, parent -> child2, child1 -> leaf, child2 -> leaf
        parent = DelegationToken(
            token_id="parent",
            issuer=AGENT_A,
            subject=AGENT_B,
            scope=_make_scope(),
            issued_at=NOW,
            expires_at=FUTURE,
        )
        child1 = DelegationToken(
            token_id="child1",
            issuer=AGENT_B,
            subject=AGENT_C,
            scope=_make_scope(),
            issued_at=NOW,
            expires_at=FUTURE,
        )
        child2 = DelegationToken(
            token_id="child2",
            issuer=AGENT_B,
            subject=AGENT_D,
            scope=_make_scope(),
            issued_at=NOW,
            expires_at=FUTURE,
        )
        leaf = DelegationToken(
            token_id="leaf",
            issuer=AGENT_C,
            subject=AGENT_D,
            scope=_make_scope(),
            issued_at=NOW,
            expires_at=FUTURE,
        )

        await delegation_store.store_token(parent)
        await delegation_store.store_token(child1)
        await delegation_store.store_token(child2)
        await delegation_store.store_token(leaf)
        delegation_store.register_child("parent", "child1")
        delegation_store.register_child("parent", "child2")
        delegation_store.register_child("child1", "leaf")
        delegation_store.register_child("child2", "leaf")

        revoked = await cascade.revoke_token("parent")
        # Leaf should appear exactly once despite being reachable via two paths
        assert revoked.count("leaf") == 1
        assert set(revoked) == {"parent", "child1", "child2", "leaf"}

    def test_nonce_is_url_safe(self, nonce_manager: NonceManager) -> None:
        """Generated nonces are URL-safe (no +, /, = characters)."""
        for _ in range(50):
            nonce = nonce_manager.generate_nonce()
            assert "+" not in nonce
            assert "/" not in nonce

    @pytest.mark.asyncio
    async def test_multiple_nonces_all_unique(
        self, nonce_manager: NonceManager
    ) -> None:
        """Generating many nonces produces no collisions."""
        nonces = set()
        for _ in range(1000):
            n = nonce_manager.generate_nonce()
            assert n not in nonces
            nonces.add(n)

    @pytest.mark.asyncio
    async def test_verification_after_cascade_revocation(
        self,
        delegation_store: InMemoryDelegationStore,
        agent_registry: InMemoryAgentRegistry,
        grant_store: InMemoryScopeGrantStore,
        nonce_manager: NonceManager,
    ) -> None:
        """A token revoked via cascade fails verification."""
        await agent_registry.register(_make_aid(AGENT_A))
        await agent_registry.register(_make_aid(AGENT_B))
        await agent_registry.register(_make_aid(AGENT_C))

        grant = _make_grant()
        await grant_store.create_grant(grant)

        parent = DelegationToken(
            token_id="parent",
            issuer=AGENT_A,
            subject=AGENT_B,
            scope=_make_scope(),
            issued_at=NOW,
            expires_at=FUTURE,
        )
        child = DelegationToken(
            token_id="child",
            issuer=AGENT_B,
            subject=AGENT_C,
            scope=_make_scope(),
            issued_at=NOW,
            expires_at=FUTURE,
        )

        await delegation_store.store_token(parent)
        await delegation_store.store_token(child)
        delegation_store.register_child("parent", "child")

        # Revoke parent (cascades to child)
        cascade = CascadeEngine(delegation_store)
        await cascade.revoke_token("parent")

        # Verify child -- should fail
        verifier = DelegationVerifier(
            delegation_store, agent_registry, grant_store, nonce_manager
        )
        with pytest.raises(InvalidDelegationToken):
            await verifier.verify("child", AGENT_C)

    @pytest.mark.asyncio
    async def test_token_binding_end_to_end(
        self,
        delegation_store: InMemoryDelegationStore,
        agent_registry: InMemoryAgentRegistry,
        grant_store: InMemoryScopeGrantStore,
        nonce_manager: NonceManager,
        token_binding: TokenBinding,
    ) -> None:
        """End-to-end: create token, create proof, verify with binding."""
        from nl_protocol.access.scope_grants import ScopeEvaluator

        evaluator = ScopeEvaluator(grant_store)
        manager = DelegationManager(delegation_store, evaluator)

        await agent_registry.register(_make_aid(AGENT_A))
        await agent_registry.register(_make_aid(AGENT_B))

        grant = _make_grant()
        await grant_store.create_grant(grant)

        scope = _make_scope()
        token = await manager.create_token(grant, AGENT_B, scope)

        # Create binding proof
        binding_key = "agent-b-binding-key-for-token"
        proof = token_binding.create_proof(
            token.token_id, str(AGENT_B), binding_key
        )

        # Verify with binding
        verifier = DelegationVerifier(
            delegation_store,
            agent_registry,
            grant_store,
            nonce_manager,
            token_binding=token_binding,
        )
        result = await verifier.verify(
            token.token_id,
            AGENT_B,
            binding_proof=proof,
            binding_secret=binding_key,
        )
        assert result.token_id == token.token_id
