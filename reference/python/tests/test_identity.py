"""Tests for the NL Protocol Level 1 -- Agent Identity module.

Covers:
1. AID creation and validation (valid/invalid URIs, expired agents, scope checking).
2. Attestation JWT creation and verification (ES256).
3. Trust level capabilities (each level allows correct action types).
4. Lifecycle transitions (valid and invalid).
5. Agent verification (exists, active, not expired).

Run with::

    pytest tests/test_identity.py -v
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from nl_protocol.core.errors import (
    AgentRevoked,
    AgentSuspended,
    AIDExpired,
    AttestationSignatureInvalid,
    AuthenticationError,
    ExpiredAttestation,
    InvalidAgent,
    TrustLevelInsufficient,
)
from nl_protocol.core.interfaces import InMemoryAgentRegistry
from nl_protocol.core.types import (
    AID,
    ActionType,
    AgentURI,
    LifecycleState,
    TrustLevel,
)
from nl_protocol.identity.aid import AIDManager
from nl_protocol.identity.attestation import AttestationService
from nl_protocol.identity.lifecycle import (
    InvalidLifecycleTransition,
    LifecycleManager,
)
from nl_protocol.identity.trust_levels import TrustLevelManager

# ======================================================================
# Fixtures
# ======================================================================


@pytest.fixture()
def registry() -> InMemoryAgentRegistry:
    """A fresh in-memory agent registry for each test."""
    return InMemoryAgentRegistry()


@pytest.fixture()
def aid_manager(registry: InMemoryAgentRegistry) -> AIDManager:
    """An AIDManager backed by the in-memory registry."""
    return AIDManager(registry)


@pytest.fixture()
def lifecycle_manager(registry: InMemoryAgentRegistry) -> LifecycleManager:
    """A LifecycleManager backed by the in-memory registry."""
    return LifecycleManager(registry)


@pytest.fixture()
def trust_manager() -> TrustLevelManager:
    """A TrustLevelManager instance (stateless)."""
    return TrustLevelManager()


@pytest.fixture()
def attestation_service() -> AttestationService:
    """An AttestationService instance (stateless)."""
    return AttestationService()


@pytest.fixture()
def es256_keypair() -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """Generate a fresh ES256 (P-256 ECDSA) key pair for testing."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


def _make_agent_uri(
    vendor: str = "anthropic.com",
    agent_type: str = "claude-code",
    version: str = "1.5.2",
) -> AgentURI:
    """Helper to construct a valid AgentURI string."""
    return AgentURI(f"nl://{vendor}/{agent_type}/{version}")


_SENTINEL_SCOPE: list[str] = []


def _make_aid(
    agent_uri: AgentURI | None = None,
    display_name: str = "Claude Code",
    vendor: str = "anthropic.com",
    version: str = "1.5.2",
    scope: list[str] | None = _SENTINEL_SCOPE,
    trust_level: TrustLevel = TrustLevel.L2,
    capabilities: list[ActionType] | None = None,
    public_key: str | None = None,
    created_at: datetime | None = None,
    expires_at: datetime | None = None,
    lifecycle_state: LifecycleState = LifecycleState.ACTIVE,
    metadata: dict[str, Any] | None = None,
) -> AID:
    """Helper to build an AID with sensible defaults for testing."""
    now = datetime.now(UTC)
    # Use sentinel to distinguish "not provided" from "explicitly empty/None"
    if scope is _SENTINEL_SCOPE:
        resolved_scope = ["api/*", "database/DB_*"]
    elif scope is None:
        resolved_scope = []
    else:
        resolved_scope = scope
    return AID(
        agent_uri=agent_uri if agent_uri is not None else _make_agent_uri(vendor=vendor),
        display_name=display_name,
        vendor=vendor,
        version=version,
        scope=resolved_scope,
        trust_level=trust_level,
        capabilities=capabilities or [ActionType.READ, ActionType.TEMPLATE],
        public_key=public_key or "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...",
        created_at=created_at or now - timedelta(hours=1),
        expires_at=expires_at or now + timedelta(hours=11),
        lifecycle_state=lifecycle_state,
        metadata=metadata or {},
    )


# ======================================================================
# 1. AID Creation and Validation
# ======================================================================


class TestAIDValidation:
    """Tests for AIDManager._validate_aid and register_agent."""

    async def test_register_valid_aid(
        self, aid_manager: AIDManager, registry: InMemoryAgentRegistry
    ) -> None:
        """A well-formed AID should be accepted and stored."""
        aid = _make_aid()
        await aid_manager.register_agent(aid)
        stored = await registry.get_aid(aid.agent_uri)
        assert stored is not None
        assert stored.agent_uri == aid.agent_uri

    @pytest.mark.parametrize(
        "uri,reason",
        [
            ("http://anthropic.com/claude/1.0.0", "wrong scheme"),
            ("nl://ANTHROPIC.COM/claude/1.0.0", "uppercase vendor"),
            ("nl://anthropic.com/Claude/1.0.0", "uppercase agent type"),
            ("nl://anthropic.com/claude-/1.0.0", "trailing hyphen in agent type"),
            ("nl://anthropic.com/claude/1.0", "incomplete version"),
            ("nl://anthropic.com//1.0.0", "empty agent type"),
            ("nl:///claude/1.0.0", "empty vendor"),
            ("nl://anthropic.com/claude/", "empty version"),
            ("", "empty string"),
            ("nl://anthropic.com/claude-code/1.0.0/extra", "extra path segment"),
        ],
        ids=lambda v: v if isinstance(v, str) and len(v) < 40 else None,
    )
    async def test_register_invalid_uri_rejected(
        self, aid_manager: AIDManager, uri: str, reason: str
    ) -> None:
        """Malformed agent URIs must be rejected with InvalidAgent."""
        aid = _make_aid(agent_uri=AgentURI(uri))
        with pytest.raises(InvalidAgent):
            await aid_manager.register_agent(aid)

    @pytest.mark.parametrize(
        "valid_uri",
        [
            "nl://anthropic.com/claude-code/1.5.2",
            "nl://acme.corp/deploy-bot/2.1.0",
            "nl://github.com/copilot/1.200.0",
            "nl://openai.com/codex-cli/1.0.0-beta.1",
            "nl://codeium.com/windsurf/1.2.0+build.42",
            "nl://a/b/0.0.0",
        ],
    )
    async def test_register_valid_uris_accepted(
        self, aid_manager: AIDManager, valid_uri: str
    ) -> None:
        """Various valid URI formats per the spec ABNF should be accepted."""
        aid = _make_aid(agent_uri=AgentURI(valid_uri), vendor="anthropic.com")
        await aid_manager.register_agent(aid)

    async def test_register_expired_before_created_rejected(
        self, aid_manager: AIDManager
    ) -> None:
        """expires_at <= created_at must be rejected."""
        now = datetime.now(UTC)
        aid = _make_aid(
            created_at=now,
            expires_at=now - timedelta(seconds=1),
        )
        with pytest.raises(InvalidAgent):
            await aid_manager.register_agent(aid)

    async def test_register_expires_equals_created_rejected(
        self, aid_manager: AIDManager
    ) -> None:
        """expires_at == created_at (zero TTL) must be rejected."""
        now = datetime.now(UTC)
        aid = _make_aid(created_at=now, expires_at=now)
        with pytest.raises(InvalidAgent):
            await aid_manager.register_agent(aid)

    async def test_register_invalid_scope_pattern_rejected(
        self, aid_manager: AIDManager
    ) -> None:
        """Scope patterns with disallowed characters must be rejected."""
        aid = _make_aid(scope=["api/*", "bad pattern; rm -rf /"])
        with pytest.raises(InvalidAgent):
            await aid_manager.register_agent(aid)


# ======================================================================
# 2. Scope Checking
# ======================================================================


class TestScopeChecking:
    """Tests for AIDManager.check_scope (glob pattern matching)."""

    def test_scope_match_simple_glob(self, aid_manager: AIDManager) -> None:
        """``api/*`` should match ``api/KEY`` but not ``api/v2/KEY``."""
        aid = _make_aid(scope=["api/*"])
        assert aid_manager.check_scope(aid, "api/KEY") is True
        assert aid_manager.check_scope(aid, "api/v2/KEY") is False

    def test_scope_match_prefix_pattern(self, aid_manager: AIDManager) -> None:
        """``database/DB_*`` should match ``database/DB_PASSWORD``."""
        aid = _make_aid(scope=["database/DB_*"])
        assert aid_manager.check_scope(aid, "database/DB_PASSWORD") is True
        assert aid_manager.check_scope(aid, "database/API_KEY") is False

    def test_scope_multiple_patterns_any_match(self, aid_manager: AIDManager) -> None:
        """If any pattern matches, the result should be True."""
        aid = _make_aid(scope=["api/*", "database/DB_*"])
        assert aid_manager.check_scope(aid, "api/KEY") is True
        assert aid_manager.check_scope(aid, "database/DB_PASS") is True
        assert aid_manager.check_scope(aid, "cache/REDIS") is False

    def test_scope_no_patterns_allows_all(self, aid_manager: AIDManager) -> None:
        """Empty or None scope should allow everything (no AID-level restriction)."""
        aid_empty = _make_aid(scope=[])
        aid_none = _make_aid(scope=None)
        assert aid_manager.check_scope(aid_empty, "anything/here") is True
        assert aid_manager.check_scope(aid_none, "anything/here") is True

    def test_scope_question_mark_wildcard(self, aid_manager: AIDManager) -> None:
        """``DB_?`` should match exactly one character."""
        aid = _make_aid(scope=["DB_?"])
        assert aid_manager.check_scope(aid, "DB_A") is True
        assert aid_manager.check_scope(aid, "DB_AB") is False

    def test_scope_no_match(self, aid_manager: AIDManager) -> None:
        """Secret refs outside all scope patterns should return False."""
        aid = _make_aid(scope=["production/*"])
        assert aid_manager.check_scope(aid, "staging/KEY") is False


# ======================================================================
# 3. Attestation JWT Creation and Verification (ES256)
# ======================================================================


class TestAttestation:
    """Tests for AttestationService create/verify cycle."""

    def test_create_and_verify_es256(
        self,
        attestation_service: AttestationService,
        es256_keypair: tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey],
    ) -> None:
        """A token created with ES256 should verify successfully."""
        private_key, public_key = es256_keypair
        aid = _make_aid()

        token = attestation_service.create_attestation(aid, private_key, algorithm="ES256")
        assert isinstance(token, str)
        assert len(token) > 0

        payload = attestation_service.verify_attestation(token, public_key)
        assert payload["sub"] == str(aid.agent_uri)
        assert payload["iss"] == aid.vendor
        assert payload["nl_version"] == "1.0"
        assert payload["trust_level"] == aid.trust_level.value

    def test_verify_with_expected_agent_uri(
        self,
        attestation_service: AttestationService,
        es256_keypair: tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey],
    ) -> None:
        """Verification should succeed when expected_agent_uri matches sub."""
        private_key, public_key = es256_keypair
        aid = _make_aid()

        token = attestation_service.create_attestation(aid, private_key)
        payload = attestation_service.verify_attestation(
            token, public_key, expected_agent_uri=aid.agent_uri
        )
        assert payload["sub"] == str(aid.agent_uri)

    def test_verify_agent_uri_mismatch(
        self,
        attestation_service: AttestationService,
        es256_keypair: tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey],
    ) -> None:
        """Verification should fail when expected_agent_uri does not match sub."""
        private_key, public_key = es256_keypair
        aid = _make_aid()
        wrong_uri = _make_agent_uri(agent_type="wrong-agent")

        token = attestation_service.create_attestation(aid, private_key)
        with pytest.raises(AttestationSignatureInvalid):
            attestation_service.verify_attestation(
                token, public_key, expected_agent_uri=wrong_uri
            )

    def test_verify_with_wrong_key_fails(
        self,
        attestation_service: AttestationService,
        es256_keypair: tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey],
    ) -> None:
        """Verification with a different public key must fail."""
        private_key, _public_key = es256_keypair
        # Generate a second, unrelated key pair
        other_private = ec.generate_private_key(ec.SECP256R1())
        other_public = other_private.public_key()

        aid = _make_aid()
        token = attestation_service.create_attestation(aid, private_key)

        with pytest.raises(AttestationSignatureInvalid):
            attestation_service.verify_attestation(token, other_public)

    def test_verify_expired_token(
        self,
        attestation_service: AttestationService,
        es256_keypair: tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey],
    ) -> None:
        """A token whose exp is in the past must raise ExpiredAttestation."""
        private_key, public_key = es256_keypair
        now = datetime.now(UTC)
        aid = _make_aid(
            created_at=now - timedelta(hours=24),
            expires_at=now - timedelta(hours=1),
        )

        token = attestation_service.create_attestation(aid, private_key)
        with pytest.raises(ExpiredAttestation):
            attestation_service.verify_attestation(token, public_key)

    def test_unsupported_algorithm_rejected(
        self,
        attestation_service: AttestationService,
        es256_keypair: tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey],
    ) -> None:
        """Unsupported algorithms must raise AttestationSignatureInvalid."""
        private_key, _public_key = es256_keypair
        aid = _make_aid()

        with pytest.raises(AttestationSignatureInvalid):
            attestation_service.create_attestation(aid, private_key, algorithm="HS256")

    def test_payload_contains_capabilities(
        self,
        attestation_service: AttestationService,
        es256_keypair: tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey],
    ) -> None:
        """The JWT payload should include capabilities and scope."""
        private_key, public_key = es256_keypair
        aid = _make_aid(
            capabilities=[ActionType.READ, ActionType.TEMPLATE],
            scope=["api/*"],
        )

        token = attestation_service.create_attestation(aid, private_key)
        payload = attestation_service.verify_attestation(token, public_key)

        assert "capabilities" in payload
        assert ActionType.READ.value in payload["capabilities"]
        assert ActionType.TEMPLATE.value in payload["capabilities"]
        assert payload["scope"] == ["api/*"]


# ======================================================================
# 4. Trust Level Capabilities
# ======================================================================


class TestTrustLevels:
    """Tests for TrustLevelManager capability mapping."""

    def test_l0_no_capabilities(self, trust_manager: TrustLevelManager) -> None:
        """L0 (Self-Attested) should have NO allowed actions."""
        for action_type in ActionType:
            assert trust_manager.can_perform_action(TrustLevel.L0, action_type) is False

    def test_l1_read_only(self, trust_manager: TrustLevelManager) -> None:
        """L1 (Org-Verified) should allow only READ."""
        assert trust_manager.can_perform_action(TrustLevel.L1, ActionType.READ) is True
        assert trust_manager.can_perform_action(TrustLevel.L1, ActionType.TEMPLATE) is False
        assert trust_manager.can_perform_action(TrustLevel.L1, ActionType.EXEC) is False
        assert trust_manager.can_perform_action(TrustLevel.L1, ActionType.HTTP) is False

    def test_l2_read_and_template(self, trust_manager: TrustLevelManager) -> None:
        """L2 (Vendor-Attested) should allow READ and TEMPLATE."""
        assert trust_manager.can_perform_action(TrustLevel.L2, ActionType.READ) is True
        assert trust_manager.can_perform_action(TrustLevel.L2, ActionType.TEMPLATE) is True
        assert trust_manager.can_perform_action(TrustLevel.L2, ActionType.EXEC) is False
        assert trust_manager.can_perform_action(TrustLevel.L2, ActionType.HTTP) is False

    def test_l3_all_actions(self, trust_manager: TrustLevelManager) -> None:
        """L3 (Third-Party-Certified) should allow ALL action types."""
        assert trust_manager.can_perform_action(TrustLevel.L3, ActionType.READ) is True
        assert trust_manager.can_perform_action(TrustLevel.L3, ActionType.TEMPLATE) is True
        assert trust_manager.can_perform_action(TrustLevel.L3, ActionType.EXEC) is True
        assert trust_manager.can_perform_action(TrustLevel.L3, ActionType.HTTP) is True

    def test_validate_capabilities_within_trust_level(
        self, trust_manager: TrustLevelManager
    ) -> None:
        """An AID whose capabilities are within its trust level should pass."""
        aid = _make_aid(
            trust_level=TrustLevel.L2,
            capabilities=[ActionType.READ, ActionType.TEMPLATE],
        )
        # Should not raise
        trust_manager.validate_capabilities(aid)

    def test_validate_capabilities_exceeding_trust_level(
        self, trust_manager: TrustLevelManager
    ) -> None:
        """An AID declaring EXEC at L1 should fail validation."""
        aid = _make_aid(
            trust_level=TrustLevel.L1,
            capabilities=[ActionType.READ, ActionType.EXEC],
        )
        with pytest.raises(TrustLevelInsufficient):
            trust_manager.validate_capabilities(aid)

    def test_validate_capabilities_l0_any_capability_fails(
        self, trust_manager: TrustLevelManager
    ) -> None:
        """L0 should reject any capability."""
        aid = _make_aid(
            trust_level=TrustLevel.L0,
            capabilities=[ActionType.READ],
        )
        with pytest.raises(TrustLevelInsufficient):
            trust_manager.validate_capabilities(aid)

    def test_can_promote(self, trust_manager: TrustLevelManager) -> None:
        """Promotion is valid when target > current."""
        assert trust_manager.can_promote(TrustLevel.L0, TrustLevel.L1) is True
        assert trust_manager.can_promote(TrustLevel.L1, TrustLevel.L2) is True
        assert trust_manager.can_promote(TrustLevel.L2, TrustLevel.L3) is True
        assert trust_manager.can_promote(TrustLevel.L0, TrustLevel.L3) is True

    def test_cannot_promote_same_or_lower(
        self, trust_manager: TrustLevelManager
    ) -> None:
        """Promotion to same or lower level is invalid."""
        assert trust_manager.can_promote(TrustLevel.L2, TrustLevel.L2) is False
        assert trust_manager.can_promote(TrustLevel.L3, TrustLevel.L1) is False

    def test_can_demote(self, trust_manager: TrustLevelManager) -> None:
        """Demotion check returns True when target < current."""
        assert trust_manager.can_demote(TrustLevel.L3, TrustLevel.L0) is True
        assert trust_manager.can_demote(TrustLevel.L2, TrustLevel.L1) is True

    def test_cannot_demote_same_or_higher(
        self, trust_manager: TrustLevelManager
    ) -> None:
        """Demotion to same or higher level is not a demotion."""
        assert trust_manager.can_demote(TrustLevel.L1, TrustLevel.L1) is False
        assert trust_manager.can_demote(TrustLevel.L1, TrustLevel.L3) is False


# ======================================================================
# 5. Lifecycle Transitions
# ======================================================================


class TestLifecycleTransitions:
    """Tests for LifecycleManager state transitions."""

    async def test_activate_from_pending(
        self, lifecycle_manager: LifecycleManager, registry: InMemoryAgentRegistry
    ) -> None:
        """PENDING -> ACTIVE should succeed."""
        aid = _make_aid(lifecycle_state=LifecycleState.PENDING)
        await registry.register(aid)

        result = await lifecycle_manager.transition(
            aid.agent_uri, LifecycleState.ACTIVE
        )
        assert result == LifecycleState.ACTIVE

    async def test_suspend_from_active(
        self, lifecycle_manager: LifecycleManager, registry: InMemoryAgentRegistry
    ) -> None:
        """ACTIVE -> SUSPENDED should succeed."""
        aid = _make_aid(lifecycle_state=LifecycleState.ACTIVE)
        await registry.register(aid)

        await lifecycle_manager.suspend(aid.agent_uri)
        updated = await registry.get_aid(aid.agent_uri)
        assert updated is not None
        assert updated.lifecycle_state == LifecycleState.SUSPENDED

    async def test_revoke_from_active(
        self, lifecycle_manager: LifecycleManager, registry: InMemoryAgentRegistry
    ) -> None:
        """ACTIVE -> REVOKED should succeed."""
        aid = _make_aid(lifecycle_state=LifecycleState.ACTIVE)
        await registry.register(aid)

        await lifecycle_manager.revoke(aid.agent_uri)
        updated = await registry.get_aid(aid.agent_uri)
        assert updated is not None
        assert updated.lifecycle_state == LifecycleState.REVOKED

    async def test_reactivate_from_suspended(
        self, lifecycle_manager: LifecycleManager, registry: InMemoryAgentRegistry
    ) -> None:
        """SUSPENDED -> ACTIVE should succeed."""
        aid = _make_aid(lifecycle_state=LifecycleState.SUSPENDED)
        await registry.register(aid)

        await lifecycle_manager.reactivate(aid.agent_uri)
        updated = await registry.get_aid(aid.agent_uri)
        assert updated is not None
        assert updated.lifecycle_state == LifecycleState.ACTIVE

    async def test_revoke_from_suspended(
        self, lifecycle_manager: LifecycleManager, registry: InMemoryAgentRegistry
    ) -> None:
        """SUSPENDED -> REVOKED should succeed."""
        aid = _make_aid(lifecycle_state=LifecycleState.SUSPENDED)
        await registry.register(aid)

        await lifecycle_manager.revoke(aid.agent_uri)
        updated = await registry.get_aid(aid.agent_uri)
        assert updated is not None
        assert updated.lifecycle_state == LifecycleState.REVOKED

    async def test_revoked_is_terminal(
        self, lifecycle_manager: LifecycleManager, registry: InMemoryAgentRegistry
    ) -> None:
        """REVOKED -> any state should fail (terminal state)."""
        aid = _make_aid(lifecycle_state=LifecycleState.REVOKED)
        await registry.register(aid)

        with pytest.raises(InvalidLifecycleTransition):
            await lifecycle_manager.transition(
                aid.agent_uri, LifecycleState.ACTIVE
            )

        with pytest.raises(InvalidLifecycleTransition):
            await lifecycle_manager.transition(
                aid.agent_uri, LifecycleState.SUSPENDED
            )

    async def test_pending_to_suspended_invalid(
        self, lifecycle_manager: LifecycleManager, registry: InMemoryAgentRegistry
    ) -> None:
        """PENDING -> SUSPENDED is not a valid transition."""
        aid = _make_aid(lifecycle_state=LifecycleState.PENDING)
        await registry.register(aid)

        with pytest.raises(InvalidLifecycleTransition):
            await lifecycle_manager.suspend(aid.agent_uri)

    async def test_pending_to_revoked_invalid(
        self, lifecycle_manager: LifecycleManager, registry: InMemoryAgentRegistry
    ) -> None:
        """PENDING -> REVOKED is not a valid transition."""
        aid = _make_aid(lifecycle_state=LifecycleState.PENDING)
        await registry.register(aid)

        with pytest.raises(InvalidLifecycleTransition):
            await lifecycle_manager.revoke(aid.agent_uri)

    async def test_active_to_pending_invalid(
        self, lifecycle_manager: LifecycleManager, registry: InMemoryAgentRegistry
    ) -> None:
        """ACTIVE -> PENDING is not a valid transition."""
        aid = _make_aid(lifecycle_state=LifecycleState.ACTIVE)
        await registry.register(aid)

        with pytest.raises(InvalidLifecycleTransition):
            await lifecycle_manager.transition(
                aid.agent_uri, LifecycleState.PENDING
            )

    async def test_transition_unknown_agent(
        self, lifecycle_manager: LifecycleManager
    ) -> None:
        """Transitioning a non-existent agent should raise InvalidAgent."""
        fake_uri = _make_agent_uri(agent_type="nonexistent")
        with pytest.raises(InvalidAgent):
            await lifecycle_manager.transition(fake_uri, LifecycleState.ACTIVE)

    async def test_activate_convenience_method(
        self, lifecycle_manager: LifecycleManager, registry: InMemoryAgentRegistry
    ) -> None:
        """The activate() convenience method should work for PENDING -> ACTIVE."""
        aid = _make_aid(lifecycle_state=LifecycleState.PENDING)
        await registry.register(aid)

        await lifecycle_manager.activate(aid.agent_uri)
        updated = await registry.get_aid(aid.agent_uri)
        assert updated is not None
        assert updated.lifecycle_state == LifecycleState.ACTIVE


# ======================================================================
# 6. Agent Verification (exists + active + not expired)
# ======================================================================


class TestAgentVerification:
    """Tests for AIDManager.verify_agent end-to-end checks."""

    async def test_verify_active_agent(
        self, aid_manager: AIDManager, registry: InMemoryAgentRegistry
    ) -> None:
        """An active, non-expired agent should verify successfully."""
        aid = _make_aid(lifecycle_state=LifecycleState.ACTIVE)
        await registry.register(aid)

        verified = await aid_manager.verify_agent(aid.agent_uri)
        assert verified.agent_uri == aid.agent_uri

    async def test_verify_nonexistent_agent_raises(
        self, aid_manager: AIDManager
    ) -> None:
        """Verifying a non-existent agent must raise InvalidAgent."""
        fake_uri = _make_agent_uri(agent_type="ghost")
        with pytest.raises(InvalidAgent):
            await aid_manager.verify_agent(fake_uri)

    async def test_verify_suspended_agent_raises(
        self, aid_manager: AIDManager, registry: InMemoryAgentRegistry
    ) -> None:
        """Verifying a suspended agent must raise AgentSuspended."""
        aid = _make_aid(lifecycle_state=LifecycleState.SUSPENDED)
        await registry.register(aid)

        with pytest.raises(AgentSuspended):
            await aid_manager.verify_agent(aid.agent_uri)

    async def test_verify_revoked_agent_raises(
        self, aid_manager: AIDManager, registry: InMemoryAgentRegistry
    ) -> None:
        """Verifying a revoked agent must raise AgentRevoked."""
        aid = _make_aid(lifecycle_state=LifecycleState.REVOKED)
        await registry.register(aid)

        with pytest.raises(AgentRevoked):
            await aid_manager.verify_agent(aid.agent_uri)

    async def test_verify_pending_agent_raises(
        self, aid_manager: AIDManager, registry: InMemoryAgentRegistry
    ) -> None:
        """Verifying a pending (not yet activated) agent must raise AuthenticationError."""
        aid = _make_aid(lifecycle_state=LifecycleState.PENDING)
        await registry.register(aid)

        with pytest.raises(AuthenticationError):
            await aid_manager.verify_agent(aid.agent_uri)

    async def test_verify_expired_agent_raises(
        self, aid_manager: AIDManager, registry: InMemoryAgentRegistry
    ) -> None:
        """Verifying an expired agent must raise AIDExpired."""
        now = datetime.now(UTC)
        aid = _make_aid(
            lifecycle_state=LifecycleState.ACTIVE,
            created_at=now - timedelta(hours=24),
            expires_at=now - timedelta(seconds=1),
        )
        await registry.register(aid)

        with pytest.raises(AIDExpired):
            await aid_manager.verify_agent(aid.agent_uri)

    async def test_get_agent_not_found(self, aid_manager: AIDManager) -> None:
        """get_agent must raise InvalidAgent for unknown URIs."""
        with pytest.raises(InvalidAgent):
            await aid_manager.get_agent(_make_agent_uri(agent_type="missing"))

    async def test_get_agent_success(
        self, aid_manager: AIDManager, registry: InMemoryAgentRegistry
    ) -> None:
        """get_agent must return the stored AID for a registered agent."""
        aid = _make_aid()
        await registry.register(aid)

        result = await aid_manager.get_agent(aid.agent_uri)
        assert result.agent_uri == aid.agent_uri
        assert result.vendor == aid.vendor


# ======================================================================
# 7. Integration: Full registration + verification flow
# ======================================================================


class TestIntegrationFlow:
    """End-to-end flow tests combining multiple identity components."""

    async def test_register_activate_verify(
        self,
        aid_manager: AIDManager,
        lifecycle_manager: LifecycleManager,
        trust_manager: TrustLevelManager,
    ) -> None:
        """Full flow: register -> activate -> verify -> scope check."""
        # 1. Create and register a PENDING agent
        aid = _make_aid(
            lifecycle_state=LifecycleState.PENDING,
            trust_level=TrustLevel.L2,
            capabilities=[ActionType.READ, ActionType.TEMPLATE],
            scope=["api/*", "database/DB_*"],
        )
        await aid_manager.register_agent(aid)

        # 2. Validate capabilities match trust level
        trust_manager.validate_capabilities(aid)

        # 3. Activate the agent
        await lifecycle_manager.activate(aid.agent_uri)

        # 4. Verify the agent (should now be ACTIVE and not expired)
        verified = await aid_manager.verify_agent(aid.agent_uri)
        assert verified.lifecycle_state == LifecycleState.ACTIVE

        # 5. Check scope
        assert aid_manager.check_scope(verified, "api/MY_KEY") is True
        assert aid_manager.check_scope(verified, "database/DB_PASSWORD") is True
        assert aid_manager.check_scope(verified, "cache/REDIS_URL") is False

    async def test_register_activate_suspend_reactivate(
        self,
        aid_manager: AIDManager,
        lifecycle_manager: LifecycleManager,
    ) -> None:
        """Full lifecycle: PENDING -> ACTIVE -> SUSPENDED -> ACTIVE."""
        aid = _make_aid(lifecycle_state=LifecycleState.PENDING)
        await aid_manager.register_agent(aid)

        # Activate
        await lifecycle_manager.activate(aid.agent_uri)
        verified = await aid_manager.verify_agent(aid.agent_uri)
        assert verified.lifecycle_state == LifecycleState.ACTIVE

        # Suspend
        await lifecycle_manager.suspend(aid.agent_uri)
        with pytest.raises(AgentSuspended):
            await aid_manager.verify_agent(aid.agent_uri)

        # Reactivate
        await lifecycle_manager.reactivate(aid.agent_uri)
        verified = await aid_manager.verify_agent(aid.agent_uri)
        assert verified.lifecycle_state == LifecycleState.ACTIVE

    async def test_register_activate_revoke_is_terminal(
        self,
        aid_manager: AIDManager,
        lifecycle_manager: LifecycleManager,
    ) -> None:
        """Once revoked, agent cannot be reactivated."""
        aid = _make_aid(lifecycle_state=LifecycleState.PENDING)
        await aid_manager.register_agent(aid)

        await lifecycle_manager.activate(aid.agent_uri)
        await lifecycle_manager.revoke(aid.agent_uri)

        with pytest.raises(AgentRevoked):
            await aid_manager.verify_agent(aid.agent_uri)

        with pytest.raises(InvalidLifecycleTransition):
            await lifecycle_manager.reactivate(aid.agent_uri)

    async def test_attest_and_verify_full_flow(
        self,
        aid_manager: AIDManager,
        lifecycle_manager: LifecycleManager,
        attestation_service: AttestationService,
        es256_keypair: tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey],
    ) -> None:
        """Register, activate, create attestation, verify attestation."""
        private_key, public_key = es256_keypair
        aid = _make_aid(lifecycle_state=LifecycleState.PENDING)
        await aid_manager.register_agent(aid)
        await lifecycle_manager.activate(aid.agent_uri)

        # Create attestation
        token = attestation_service.create_attestation(aid, private_key)
        assert isinstance(token, str)

        # Verify attestation
        payload = attestation_service.verify_attestation(
            token, public_key, expected_agent_uri=aid.agent_uri
        )
        assert payload["sub"] == str(aid.agent_uri)
        assert payload["iss"] == aid.vendor

        # Verify agent identity
        verified = await aid_manager.verify_agent(aid.agent_uri)
        assert verified.lifecycle_state == LifecycleState.ACTIVE
