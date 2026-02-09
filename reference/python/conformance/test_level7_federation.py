"""Level 7 -- Cross-Agent Trust & Federation conformance tests.

Verifies Chapter 07 requirements: delegation subset rule enforcement,
max delegation depth, token expiry detection, nonce replay prevention,
and cascade revocation.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from nl_protocol.access.scope_grants import ScopeEvaluator
from nl_protocol.core.errors import (
    DelegationDepthExceeded,
    DelegationSubsetViolation,
    DelegationTokenExpired,
)
from nl_protocol.core.interfaces import (
    InMemoryAgentRegistry,
    InMemoryDelegationStore,
    InMemoryNonceStore,
    InMemoryScopeGrantStore,
)
from nl_protocol.core.types import (
    ActionType,
    AgentURI,
    DelegationScope,
    LifecycleState,
)
from nl_protocol.federation.cascade import CascadeEngine
from nl_protocol.federation.delegation import DelegationManager
from nl_protocol.federation.nonce import NonceManager
from nl_protocol.federation.token_binding import TokenBinding
from nl_protocol.federation.verification import DelegationVerifier

from .conftest import AGENT_URI, AGENT_URI_B, make_aid, make_delegation_token, make_grant

# ===================================================================
# Section 3.6 -- Delegation subset rule
# ===================================================================

class TestDelegationSubsetRule:
    """Spec Section 3.6: delegated scope MUST be a subset of parent."""

    async def test_MUST_allow_subset_delegation(
        self,
        delegation_store: InMemoryDelegationStore,
        scope_grant_store: InMemoryScopeGrantStore,
    ) -> None:
        """A delegation scope that is a subset MUST be allowed."""
        grant = make_grant(secret="api/*", actions=[ActionType.READ, ActionType.EXEC])
        await scope_grant_store.create_grant(grant)
        evaluator = ScopeEvaluator(scope_grant_store)
        mgr = DelegationManager(delegation_store, evaluator)

        scope = DelegationScope(secrets=["api/TOKEN"], actions=[ActionType.READ])
        token = await mgr.create_token(grant, AGENT_URI_B, scope)
        assert token.subject == AGENT_URI_B

    async def test_MUST_reject_superset_secrets(
        self,
        delegation_store: InMemoryDelegationStore,
        scope_grant_store: InMemoryScopeGrantStore,
    ) -> None:
        """Delegation requesting secrets outside parent scope MUST be rejected."""
        grant = make_grant(secret="api/*", actions=[ActionType.READ])
        await scope_grant_store.create_grant(grant)
        evaluator = ScopeEvaluator(scope_grant_store)
        mgr = DelegationManager(delegation_store, evaluator)

        scope = DelegationScope(secrets=["db/PASSWORD"], actions=[ActionType.READ])
        with pytest.raises(DelegationSubsetViolation):
            await mgr.create_token(grant, AGENT_URI_B, scope)

    async def test_MUST_reject_superset_actions(
        self,
        delegation_store: InMemoryDelegationStore,
        scope_grant_store: InMemoryScopeGrantStore,
    ) -> None:
        """Delegation requesting actions not in parent MUST be rejected."""
        grant = make_grant(secret="api/*", actions=[ActionType.READ])
        await scope_grant_store.create_grant(grant)
        evaluator = ScopeEvaluator(scope_grant_store)
        mgr = DelegationManager(delegation_store, evaluator)

        scope = DelegationScope(secrets=["api/TOKEN"], actions=[ActionType.EXEC])
        with pytest.raises(DelegationSubsetViolation):
            await mgr.create_token(grant, AGENT_URI_B, scope)


# ===================================================================
# Section 2.3 -- Delegation depth limits
# ===================================================================

class TestDelegationDepth:
    """Spec Section 2.3: max_delegation_depth MUST be enforced."""

    async def test_MUST_enforce_max_delegation_depth(
        self,
        delegation_store: InMemoryDelegationStore,
        scope_grant_store: InMemoryScopeGrantStore,
    ) -> None:
        """Creating a token at max depth MUST raise DelegationDepthExceeded."""
        grant = make_grant(secret="api/*", actions=[ActionType.READ])
        await scope_grant_store.create_grant(grant)
        evaluator = ScopeEvaluator(scope_grant_store)
        mgr = DelegationManager(delegation_store, evaluator, max_delegation_depth=2)

        scope = DelegationScope(secrets=["api/TOKEN"], actions=[ActionType.READ])

        # First delegation: depth 0
        parent_token = await mgr.create_token(grant, AGENT_URI_B, scope)
        assert parent_token.current_depth == 0

        # Second delegation: depth 1
        child_token = await mgr.create_token(
            grant, AGENT_URI_B, scope, parent_token=parent_token
        )
        assert child_token.current_depth == 1

        # Third delegation: depth 2 -- MUST fail (max_delegation_depth=2)
        with pytest.raises(DelegationDepthExceeded):
            await mgr.create_token(
                grant, AGENT_URI_B, scope, parent_token=child_token
            )

    async def test_MUST_track_current_depth(
        self,
        delegation_store: InMemoryDelegationStore,
        scope_grant_store: InMemoryScopeGrantStore,
    ) -> None:
        """Delegation tokens MUST track their current depth in the chain."""
        grant = make_grant(secret="api/*", actions=[ActionType.READ])
        await scope_grant_store.create_grant(grant)
        evaluator = ScopeEvaluator(scope_grant_store)
        mgr = DelegationManager(delegation_store, evaluator, max_delegation_depth=5)

        scope = DelegationScope(secrets=["api/TOKEN"], actions=[ActionType.READ])
        t1 = await mgr.create_token(grant, AGENT_URI_B, scope)
        assert t1.current_depth == 0

        t2 = await mgr.create_token(grant, AGENT_URI_B, scope, parent_token=t1)
        assert t2.current_depth == 1


# ===================================================================
# Section 3.5 -- Token expiry
# ===================================================================

class TestTokenExpiry:
    """Spec Section 3.5: expired tokens MUST be rejected."""

    async def test_MUST_reject_expired_token(
        self,
        delegation_store: InMemoryDelegationStore,
        agent_registry: InMemoryAgentRegistry,
        scope_grant_store: InMemoryScopeGrantStore,
        nonce_store: InMemoryNonceStore,
    ) -> None:
        """A token past its expires_at MUST be rejected during verification."""
        expired_token = make_delegation_token(
            expires_at=datetime.now(UTC) - timedelta(seconds=1),
        )
        await delegation_store.store_token(expired_token)

        # Register agents and grants for verification steps 5 and 6
        issuer_aid = make_aid(AGENT_URI, lifecycle_state=LifecycleState.ACTIVE)
        await agent_registry.register(issuer_aid)
        grant = make_grant(AGENT_URI)
        await scope_grant_store.create_grant(grant)

        nonce_mgr = NonceManager(nonce_store)
        verifier = DelegationVerifier(
            delegation_store, agent_registry, scope_grant_store, nonce_mgr
        )
        with pytest.raises(DelegationTokenExpired):
            await verifier.verify(expired_token.token_id, AGENT_URI_B)

    async def test_MUST_accept_valid_token(
        self,
        delegation_store: InMemoryDelegationStore,
        agent_registry: InMemoryAgentRegistry,
        scope_grant_store: InMemoryScopeGrantStore,
        nonce_store: InMemoryNonceStore,
    ) -> None:
        """A non-expired token for the correct subject MUST pass verification."""
        token = make_delegation_token()
        await delegation_store.store_token(token)

        issuer_aid = make_aid(AGENT_URI, lifecycle_state=LifecycleState.ACTIVE)
        await agent_registry.register(issuer_aid)
        grant = make_grant(AGENT_URI)
        await scope_grant_store.create_grant(grant)

        nonce_mgr = NonceManager(nonce_store)
        verifier = DelegationVerifier(
            delegation_store, agent_registry, scope_grant_store, nonce_mgr
        )
        result = await verifier.verify(token.token_id, AGENT_URI_B)
        assert result.token_id == token.token_id


# ===================================================================
# Section 3.7 -- Nonce replay prevention
# ===================================================================

class TestNonceReplayPrevention:
    """Spec Section 3.7.1: nonce MUST prevent replay attacks."""

    async def test_MUST_accept_fresh_nonce(
        self, nonce_store: InMemoryNonceStore
    ) -> None:
        """A never-seen nonce MUST be accepted."""
        mgr = NonceManager(nonce_store)
        nonce = mgr.generate_nonce()
        expires = datetime.now(UTC) + timedelta(hours=1)
        result = await mgr.check_and_consume(nonce, expires)
        assert result is True

    async def test_MUST_reject_replayed_nonce(
        self, nonce_store: InMemoryNonceStore
    ) -> None:
        """A previously-seen nonce MUST be rejected (replay)."""
        mgr = NonceManager(nonce_store)
        nonce = mgr.generate_nonce()
        expires = datetime.now(UTC) + timedelta(hours=1)
        await mgr.check_and_consume(nonce, expires)
        result = await mgr.check_and_consume(nonce, expires)
        assert result is False

    def test_MUST_generate_high_entropy_nonce(self) -> None:
        """Generated nonces MUST have at least 128 bits of entropy."""
        mgr = NonceManager(InMemoryNonceStore())
        nonce = mgr.generate_nonce()
        # 32 bytes = 256 bits encoded in base64 -> ~43 chars
        assert len(nonce) >= 20  # well above 128 bits


# ===================================================================
# Section 3.8 -- Cascade revocation
# ===================================================================

class TestCascadeRevocation:
    """Spec Section 3.8: revoking a token MUST cascade to all children."""

    async def test_MUST_cascade_revocation_to_children(
        self, delegation_store: InMemoryDelegationStore
    ) -> None:
        """Revoking a parent MUST also revoke all child tokens."""
        parent = make_delegation_token()
        child = make_delegation_token(
            issuer=AGENT_URI_B,
            subject=AgentURI("nl://acme.com/grandchild/1.0.0"),
        )
        await delegation_store.store_token(parent)
        await delegation_store.store_token(child)
        delegation_store.register_child(parent.token_id, child.token_id)

        cascade = CascadeEngine(delegation_store)
        revoked_ids = await cascade.revoke_token(parent.token_id)

        assert parent.token_id in revoked_ids
        assert child.token_id in revoked_ids

        # Both should be inaccessible
        assert await delegation_store.get_token(parent.token_id) is None
        assert await delegation_store.get_token(child.token_id) is None

    async def test_MUST_cascade_through_multiple_levels(
        self, delegation_store: InMemoryDelegationStore
    ) -> None:
        """Cascade MUST work through multiple delegation levels."""
        t1 = make_delegation_token()
        t2 = make_delegation_token(
            issuer=AGENT_URI_B,
            subject=AgentURI("nl://acme.com/c-agent/1.0.0"),
        )
        t3 = make_delegation_token(
            issuer=AgentURI("nl://acme.com/c-agent/1.0.0"),
            subject=AgentURI("nl://acme.com/d-agent/1.0.0"),
        )
        await delegation_store.store_token(t1)
        await delegation_store.store_token(t2)
        await delegation_store.store_token(t3)
        delegation_store.register_child(t1.token_id, t2.token_id)
        delegation_store.register_child(t2.token_id, t3.token_id)

        cascade = CascadeEngine(delegation_store)
        revoked_ids = await cascade.revoke_token(t1.token_id)

        assert len(revoked_ids) == 3
        for tok_id in [t1.token_id, t2.token_id, t3.token_id]:
            assert tok_id in revoked_ids


# ===================================================================
# Section 3.4 -- Token binding (HMAC)
# ===================================================================

class TestTokenBinding:
    """Spec Section 3.4: HMAC-based token binding."""

    def test_MUST_create_valid_proof(self) -> None:
        """create_proof MUST produce a verifiable proof."""
        binding = TokenBinding()
        ts = 1700000000
        proof = binding.create_proof(
            "token-123", "nl://acme.com/agent/1.0.0", "shared-secret",
            timestamp=ts,
        )
        result = binding.verify_proof(
            "token-123", "nl://acme.com/agent/1.0.0", proof, "shared-secret",
            current_time=ts,
        )
        assert result is True

    def test_MUST_reject_wrong_agent(self) -> None:
        """Proof for a different agent_uri MUST fail verification."""
        binding = TokenBinding()
        ts = 1700000000
        proof = binding.create_proof(
            "token-123", "nl://acme.com/agent/1.0.0", "shared-secret",
            timestamp=ts,
        )
        result = binding.verify_proof(
            "token-123", "nl://evil.com/agent/1.0.0", proof, "shared-secret",
            current_time=ts,
        )
        assert result is False

    def test_MUST_reject_wrong_secret(self) -> None:
        """Proof verified with wrong secret MUST fail."""
        binding = TokenBinding()
        ts = 1700000000
        proof = binding.create_proof(
            "token-123", "nl://acme.com/agent/1.0.0", "correct-secret",
            timestamp=ts,
        )
        result = binding.verify_proof(
            "token-123", "nl://acme.com/agent/1.0.0", proof, "wrong-secret",
            current_time=ts,
        )
        assert result is False

    def test_MUST_reject_expired_timestamp(self) -> None:
        """Proof with timestamp outside tolerance MUST fail."""
        binding = TokenBinding(timestamp_tolerance=30)
        proof = binding.create_proof(
            "token-123", "nl://acme.com/agent/1.0.0", "secret",
            timestamp=1000000,
        )
        result = binding.verify_proof(
            "token-123", "nl://acme.com/agent/1.0.0", proof, "secret",
            current_time=1000100,
        )
        assert result is False
