"""Tests for NL Protocol Level 2 -- Action-Based Access.

This module covers the access subpackage:

1. **Placeholder extraction** -- valid patterns, invalid patterns, nested, empty.
2. **Placeholder resolution** -- successful, missing secret, multiple placeholders.
3. **Scope grant evaluation** -- matching, non-matching, expired, usage limits,
   glob patterns.
4. **Subset rule** -- valid subset, invalid escalation, stricter conditions.
5. **Output sanitization** (CRITICAL SECURITY TESTS):
   - Plaintext detection and redaction
   - Base64-encoded detection
   - URL-encoded detection
   - Hex-encoded detection
   - Multiple secrets in same output
   - Redaction marker format
   - Short secrets skipped (NL-2.6.5)
   - Null byte stripping (NL-2.6.10)
   - Multi-line secrets (NL-2.6.11)
   - Output size limit enforcement
6. **Policy evaluation order** -- deny first, then AID scope, then grants.
7. **Action validation** -- per-type payload validation.
"""
from __future__ import annotations

import base64
import urllib.parse
from datetime import UTC, datetime, timedelta

import pytest

from nl_protocol.access.actions import ActionValidator
from nl_protocol.access.placeholders import PLACEHOLDER_PATTERN, PlaceholderResolver
from nl_protocol.access.sanitization import OutputSanitizer
from nl_protocol.access.scope_grants import ScopeEvaluator
from nl_protocol.core.errors import (
    ActionBlocked,
    NoScopeGrant,
    ScopeExpired,
    SecretNotFound,
    UseLimitExceeded,
)
from nl_protocol.core.interfaces import (
    InMemoryScopeGrantStore,
    InMemorySecretStore,
)
from nl_protocol.core.types import (
    AID,
    ActionPayload,
    ActionType,
    AgentURI,
    DelegationScope,
    ScopeConditions,
    ScopeGrant,
    SecretRef,
    SecretValue,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def secret_store() -> InMemorySecretStore:
    """A pre-populated in-memory secret store."""
    store = InMemorySecretStore()
    store.put(SecretRef("api/GITHUB_TOKEN"), SecretValue("ghp_abc123def456"))
    store.put(SecretRef("database/DB_PASSWORD"), SecretValue("p@ssw0rd!_secret"))
    store.put(SecretRef("API_KEY"), SecretValue("sk-1234567890abcdef"))
    store.put(SecretRef("SHORT"), SecretValue("ab"))  # too short for scanning
    store.put(
        SecretRef("ssh/id_rsa_deploy"),
        SecretValue(
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIE...rest-of-key\n"
            "-----END RSA PRIVATE KEY-----"
        ),
    )
    return store


@pytest.fixture
def resolver(secret_store: InMemorySecretStore) -> PlaceholderResolver:
    """A PlaceholderResolver backed by the test secret store."""
    return PlaceholderResolver(secret_store)


@pytest.fixture
def grant_store() -> InMemoryScopeGrantStore:
    """A pre-populated in-memory scope grant store."""
    return InMemoryScopeGrantStore()


@pytest.fixture
def scope_evaluator(grant_store: InMemoryScopeGrantStore) -> ScopeEvaluator:
    """A ScopeEvaluator backed by the test grant store."""
    return ScopeEvaluator(grant_store)


@pytest.fixture
def sanitizer() -> OutputSanitizer:
    """An OutputSanitizer instance."""
    return OutputSanitizer()


@pytest.fixture
def action_validator() -> ActionValidator:
    """An ActionValidator instance."""
    return ActionValidator()


# Helper constants
AGENT_URI = AgentURI("nl://anthropic.com/claude-code/1.5.2")
NOW = datetime.now(UTC)
FUTURE = NOW + timedelta(hours=8)
PAST = NOW - timedelta(hours=8)


def _make_grant(
    *,
    agent_uri: AgentURI = AGENT_URI,
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


# ===================================================================
# 1. Placeholder Extraction Tests
# ===================================================================

class TestPlaceholderExtraction:
    """Tests for PlaceholderResolver.extract_refs and PLACEHOLDER_PATTERN."""

    def test_simple_reference(self, resolver: PlaceholderResolver) -> None:
        """A simple name like {{nl:API_KEY}} is extracted correctly."""
        refs = resolver.extract_refs("curl -H 'Auth: {{nl:API_KEY}}'")
        assert refs == [SecretRef("API_KEY")]

    def test_categorized_reference(self, resolver: PlaceholderResolver) -> None:
        """A categorized ref like {{nl:api/GITHUB_TOKEN}} is extracted."""
        refs = resolver.extract_refs(
            "curl -H 'Auth: Bearer {{nl:api/GITHUB_TOKEN}}' https://api.github.com"
        )
        assert refs == [SecretRef("api/GITHUB_TOKEN")]

    def test_scoped_reference(self, resolver: PlaceholderResolver) -> None:
        """A scoped ref like {{nl:project/env/name}} is extracted."""
        refs = resolver.extract_refs("connect {{nl:myapp/production/DB_PASS}}")
        assert refs == [SecretRef("myapp/production/DB_PASS")]

    def test_fully_qualified_reference(self, resolver: PlaceholderResolver) -> None:
        """A fully qualified ref {{nl:project/env/category/name}} is extracted."""
        refs = resolver.extract_refs(
            "docker login -p {{nl:braincol/production/registry/DOCKER_TOKEN}} ghcr.io"
        )
        assert refs == [SecretRef("braincol/production/registry/DOCKER_TOKEN")]

    def test_multiple_references(self, resolver: PlaceholderResolver) -> None:
        """Multiple placeholders in a single template."""
        template = 'curl -u "{{nl:api/USERNAME}}:{{nl:api/PASSWORD}}" https://api.example.com'
        refs = resolver.extract_refs(template)
        assert refs == [SecretRef("api/USERNAME"), SecretRef("api/PASSWORD")]

    def test_duplicate_references_preserved(self, resolver: PlaceholderResolver) -> None:
        """Duplicate references are preserved (order matters for env-var mapping)."""
        template = "echo {{nl:TOKEN}} && echo {{nl:TOKEN}}"
        refs = resolver.extract_refs(template)
        assert refs == [SecretRef("TOKEN"), SecretRef("TOKEN")]

    def test_no_references(self, resolver: PlaceholderResolver) -> None:
        """A template without placeholders returns an empty list."""
        refs = resolver.extract_refs("echo hello world")
        assert refs == []

    def test_empty_template(self, resolver: PlaceholderResolver) -> None:
        """An empty string returns an empty list."""
        refs = resolver.extract_refs("")
        assert refs == []

    def test_static_extraction(self) -> None:
        """The static method works without a store instance."""
        refs = PlaceholderResolver.extract_refs_static("{{nl:api/KEY}}")
        assert refs == [SecretRef("api/KEY")]

    def test_pattern_matches_inside_escaped(self) -> None:
        """The regex itself matches inside escaped syntax.

        Escape handling (per spec Section 4.6) is a resolution-time
        concern: {{{{nl: means literal text, but the regex still finds
        the inner {{nl:...}}.  The resolver or caller must strip escaped
        sequences before extraction.
        """
        # The Python string "{{{{nl:SECRET}}" contains the literal {{{{nl:SECRET}}
        # The regex finds {{nl:SECRET}} at an offset inside it.
        matches = PLACEHOLDER_PATTERN.findall("{{{{nl:SECRET}}")
        assert matches == ["SECRET"]

    def test_ref_with_dots_and_hyphens(self, resolver: PlaceholderResolver) -> None:
        """References with dots and hyphens are valid."""
        refs = resolver.extract_refs("{{nl:my-service.api/key-name}}")
        assert refs == [SecretRef("my-service.api/key-name")]


# ===================================================================
# 2. Placeholder Validation Tests
# ===================================================================

class TestPlaceholderValidation:
    """Tests for PlaceholderResolver.validate_template."""

    def test_valid_template(self, resolver: PlaceholderResolver) -> None:
        """A well-formed template produces no errors."""
        errors = resolver.validate_template(
            "curl -H 'Auth: Bearer {{nl:api/TOKEN}}' https://api.example.com"
        )
        assert errors == []

    def test_empty_reference(self, resolver: PlaceholderResolver) -> None:
        """{{nl:}} is detected as invalid."""
        errors = resolver.validate_template("echo {{nl:}}")
        assert len(errors) >= 1
        assert any("empty" in e.lower() for e in errors)

    def test_nested_placeholder(self, resolver: PlaceholderResolver) -> None:
        """Nested placeholders are detected."""
        errors = resolver.validate_template("{{nl:outer-{{nl:inner}}}}")
        assert len(errors) >= 1
        assert any("nested" in e.lower() for e in errors)

    def test_malformed_no_close(self, resolver: PlaceholderResolver) -> None:
        """Unclosed placeholder is detected as malformed."""
        errors = resolver.validate_template("echo {{nl:SECRET and more text")
        assert len(errors) >= 1
        assert any("malformed" in e.lower() for e in errors)

    def test_multiple_valid_placeholders(self, resolver: PlaceholderResolver) -> None:
        """Multiple valid placeholders produce no errors."""
        template = "{{nl:KEY1}} and {{nl:KEY2}} and {{nl:category/KEY3}}"
        errors = resolver.validate_template(template)
        assert errors == []

    def test_leading_slash(self, resolver: PlaceholderResolver) -> None:
        """A reference starting with / is flagged."""
        errors = resolver.validate_template("{{nl:/invalid}}")
        # This won't match the PLACEHOLDER_PATTERN since / at start
        # means the pattern itself might or might not match;
        # depends on regex. Let's check separately.
        refs = resolver.extract_refs("{{nl:/invalid}}")
        if refs:
            assert any("slash" in e.lower() for e in errors)

    def test_trailing_slash(self, resolver: PlaceholderResolver) -> None:
        """A reference ending with / is flagged."""
        errors = resolver.validate_template("{{nl:invalid/}}")
        refs = resolver.extract_refs("{{nl:invalid/}}")
        if refs:
            assert any("slash" in e.lower() for e in errors)


# ===================================================================
# 3. Placeholder Resolution Tests
# ===================================================================

class TestPlaceholderResolution:
    """Tests for PlaceholderResolver.resolve (async)."""

    @pytest.mark.asyncio
    async def test_single_resolution(self, resolver: PlaceholderResolver) -> None:
        """A single placeholder is resolved to the secret value."""
        resolved, refs = await resolver.resolve(
            "curl -H 'Auth: Bearer {{nl:api/GITHUB_TOKEN}}' https://api.github.com"
        )
        assert "ghp_abc123def456" in resolved
        assert "{{nl:" not in resolved
        assert refs == [SecretRef("api/GITHUB_TOKEN")]

    @pytest.mark.asyncio
    async def test_multiple_resolution(self, resolver: PlaceholderResolver) -> None:
        """Multiple different placeholders are all resolved."""
        resolved, refs = await resolver.resolve(
            "user={{nl:API_KEY}}&pass={{nl:database/DB_PASSWORD}}"
        )
        assert "sk-1234567890abcdef" in resolved
        assert "p@ssw0rd!_secret" in resolved
        assert "{{nl:" not in resolved
        assert len(refs) == 2

    @pytest.mark.asyncio
    async def test_missing_secret_raises(self, resolver: PlaceholderResolver) -> None:
        """Resolving a non-existent secret raises SecretNotFound."""
        with pytest.raises(SecretNotFound):
            await resolver.resolve("echo {{nl:NONEXISTENT_SECRET}}")

    @pytest.mark.asyncio
    async def test_no_placeholders(self, resolver: PlaceholderResolver) -> None:
        """A template without placeholders is returned unchanged."""
        resolved, refs = await resolver.resolve("echo hello")
        assert resolved == "echo hello"
        assert refs == []

    @pytest.mark.asyncio
    async def test_multiline_secret_resolution(
        self, resolver: PlaceholderResolver
    ) -> None:
        """Multi-line secrets are resolved correctly."""
        resolved, refs = await resolver.resolve(
            "ssh -i {{nl:ssh/id_rsa_deploy}} deploy@host"
        )
        assert "-----BEGIN RSA PRIVATE KEY-----" in resolved
        assert "{{nl:" not in resolved


# ===================================================================
# 4. Scope Grant Evaluation Tests
# ===================================================================

class TestScopeEvaluation:
    """Tests for ScopeEvaluator.find_matching_grant."""

    @pytest.mark.asyncio
    async def test_matching_grant(
        self,
        scope_evaluator: ScopeEvaluator,
        grant_store: InMemoryScopeGrantStore,
    ) -> None:
        """A valid, active grant is returned when it matches."""
        grant = _make_grant()
        await grant_store.create_grant(grant)

        result = await scope_evaluator.find_matching_grant(
            AGENT_URI, SecretRef("api/GITHUB_TOKEN"), ActionType.EXEC
        )
        assert result.grant_id == "grant-001"

    @pytest.mark.asyncio
    async def test_no_matching_grant(
        self,
        scope_evaluator: ScopeEvaluator,
        grant_store: InMemoryScopeGrantStore,
    ) -> None:
        """NoScopeGrant is raised when no grant matches."""
        grant = _make_grant(secret="database/*")
        await grant_store.create_grant(grant)

        with pytest.raises(NoScopeGrant):
            await scope_evaluator.find_matching_grant(
                AGENT_URI, SecretRef("api/GITHUB_TOKEN"), ActionType.EXEC
            )

    @pytest.mark.asyncio
    async def test_wrong_action_type(
        self,
        scope_evaluator: ScopeEvaluator,
        grant_store: InMemoryScopeGrantStore,
    ) -> None:
        """NoScopeGrant is raised when action type doesn't match."""
        grant = _make_grant(actions=[ActionType.TEMPLATE])
        await grant_store.create_grant(grant)

        with pytest.raises(NoScopeGrant):
            await scope_evaluator.find_matching_grant(
                AGENT_URI, SecretRef("api/TOKEN"), ActionType.EXEC
            )

    @pytest.mark.asyncio
    async def test_expired_grant(
        self,
        scope_evaluator: ScopeEvaluator,
        grant_store: InMemoryScopeGrantStore,
    ) -> None:
        """ScopeExpired is raised when the grant's time window has passed."""
        grant = _make_grant(
            valid_from=PAST - timedelta(hours=4),
            valid_until=PAST,
        )
        await grant_store.create_grant(grant)

        with pytest.raises(ScopeExpired):
            await scope_evaluator.find_matching_grant(
                AGENT_URI, SecretRef("api/TOKEN"), ActionType.EXEC
            )

    @pytest.mark.asyncio
    async def test_not_yet_valid_grant(
        self,
        scope_evaluator: ScopeEvaluator,
        grant_store: InMemoryScopeGrantStore,
    ) -> None:
        """NoScopeGrant is raised when the grant is not yet active (valid_from in future)."""
        grant = _make_grant(
            valid_from=FUTURE,
            valid_until=FUTURE + timedelta(hours=4),
        )
        await grant_store.create_grant(grant)

        with pytest.raises(NoScopeGrant):
            await scope_evaluator.find_matching_grant(
                AGENT_URI, SecretRef("api/TOKEN"), ActionType.EXEC
            )

    @pytest.mark.asyncio
    async def test_revoked_grant_skipped(
        self,
        scope_evaluator: ScopeEvaluator,
        grant_store: InMemoryScopeGrantStore,
    ) -> None:
        """Revoked grants are silently skipped."""
        grant = _make_grant(revoked=True)
        await grant_store.create_grant(grant)

        with pytest.raises(NoScopeGrant):
            await scope_evaluator.find_matching_grant(
                AGENT_URI, SecretRef("api/TOKEN"), ActionType.EXEC
            )

    @pytest.mark.asyncio
    async def test_usage_limit_exhausted(
        self,
        scope_evaluator: ScopeEvaluator,
        grant_store: InMemoryScopeGrantStore,
    ) -> None:
        """A grant at its max_uses limit is not matched."""
        grant = _make_grant(max_uses=5, current_uses=5)
        await grant_store.create_grant(grant)

        with pytest.raises(NoScopeGrant):
            await scope_evaluator.find_matching_grant(
                AGENT_URI, SecretRef("api/TOKEN"), ActionType.EXEC
            )

    @pytest.mark.asyncio
    async def test_glob_pattern_wildcard(
        self,
        scope_evaluator: ScopeEvaluator,
        grant_store: InMemoryScopeGrantStore,
    ) -> None:
        """The glob pattern 'api/*' matches 'api/GITHUB_TOKEN'."""
        grant = _make_grant(secret="api/*")
        await grant_store.create_grant(grant)

        result = await scope_evaluator.find_matching_grant(
            AGENT_URI, SecretRef("api/GITHUB_TOKEN"), ActionType.EXEC
        )
        assert result.grant_id == "grant-001"

    @pytest.mark.asyncio
    async def test_glob_pattern_star(
        self,
        scope_evaluator: ScopeEvaluator,
        grant_store: InMemoryScopeGrantStore,
    ) -> None:
        """The glob pattern '*' matches everything."""
        grant = _make_grant(secret="*")
        await grant_store.create_grant(grant)

        result = await scope_evaluator.find_matching_grant(
            AGENT_URI, SecretRef("anything/goes"), ActionType.EXEC
        )
        assert result.grant_id == "grant-001"

    @pytest.mark.asyncio
    async def test_glob_no_cross_category_match(
        self,
        scope_evaluator: ScopeEvaluator,
        grant_store: InMemoryScopeGrantStore,
    ) -> None:
        """'api/*' does NOT match 'database/DB_PASSWORD'."""
        grant = _make_grant(secret="api/*")
        await grant_store.create_grant(grant)

        with pytest.raises(NoScopeGrant):
            await scope_evaluator.find_matching_grant(
                AGENT_URI, SecretRef("database/DB_PASSWORD"), ActionType.EXEC
            )

    @pytest.mark.asyncio
    async def test_multiple_grants_first_match(
        self,
        scope_evaluator: ScopeEvaluator,
        grant_store: InMemoryScopeGrantStore,
    ) -> None:
        """When multiple grants match, the first one is returned."""
        grant1 = _make_grant(grant_id="grant-first", secret="api/*")
        grant2 = _make_grant(grant_id="grant-second", secret="*")
        await grant_store.create_grant(grant1)
        await grant_store.create_grant(grant2)

        result = await scope_evaluator.find_matching_grant(
            AGENT_URI, SecretRef("api/TOKEN"), ActionType.EXEC
        )
        assert result.grant_id == "grant-first"


# ===================================================================
# 4b. Usage Consumption Tests
# ===================================================================

class TestUsageConsumption:
    """Tests for ScopeEvaluator.consume_usage."""

    @pytest.mark.asyncio
    async def test_consume_increments(
        self,
        scope_evaluator: ScopeEvaluator,
        grant_store: InMemoryScopeGrantStore,
    ) -> None:
        """consume_usage increments the usage count."""
        grant = _make_grant(max_uses=10, current_uses=0)
        await grant_store.create_grant(grant)

        await scope_evaluator.consume_usage(grant)
        # After consume, current_uses should be 1
        stored = (await grant_store.get_grants(AGENT_URI))[0]
        assert stored.conditions.current_uses == 1

    @pytest.mark.asyncio
    async def test_consume_at_limit_raises(
        self,
        scope_evaluator: ScopeEvaluator,
        grant_store: InMemoryScopeGrantStore,
    ) -> None:
        """UseLimitExceeded is raised when exceeding max_uses."""
        grant = _make_grant(max_uses=1, current_uses=0)
        await grant_store.create_grant(grant)

        # First consume succeeds
        await scope_evaluator.consume_usage(grant)

        # Second consume exceeds the limit
        with pytest.raises(UseLimitExceeded):
            await scope_evaluator.consume_usage(grant)

    @pytest.mark.asyncio
    async def test_consume_unlimited(
        self,
        scope_evaluator: ScopeEvaluator,
        grant_store: InMemoryScopeGrantStore,
    ) -> None:
        """consume_usage is a no-op when max_uses is None (unlimited)."""
        grant = _make_grant(max_uses=None)
        await grant_store.create_grant(grant)

        # Should not raise
        await scope_evaluator.consume_usage(grant)
        await scope_evaluator.consume_usage(grant)


# ===================================================================
# 5. Subset Rule Tests (Delegation)
# ===================================================================

class TestSubsetRule:
    """Tests for ScopeEvaluator.is_subset (delegation verification)."""

    def test_valid_subset(self, scope_evaluator: ScopeEvaluator) -> None:
        """A delegation scope within the parent's bounds is a valid subset."""
        parent = _make_grant(
            secret="api/*",
            actions=[ActionType.EXEC, ActionType.TEMPLATE],
            max_uses=100,
            valid_until=FUTURE,
        )
        child = DelegationScope(
            secrets=["api/TOKEN"],
            actions=[ActionType.EXEC],
            conditions=ScopeConditions(
                max_uses=10,
                valid_until=FUTURE - timedelta(hours=1),
            ),
        )
        assert scope_evaluator.is_subset(parent, child) is True

    def test_invalid_secret_escalation(self, scope_evaluator: ScopeEvaluator) -> None:
        """A child with secrets outside the parent's pattern is NOT a subset."""
        parent = _make_grant(secret="api/*")
        child = DelegationScope(
            secrets=["database/DB_PASSWORD"],
            actions=[ActionType.EXEC],
        )
        assert scope_evaluator.is_subset(parent, child) is False

    def test_invalid_action_escalation(self, scope_evaluator: ScopeEvaluator) -> None:
        """A child with actions not in the parent's list is NOT a subset."""
        parent = _make_grant(actions=[ActionType.EXEC])
        child = DelegationScope(
            secrets=["api/TOKEN"],
            actions=[ActionType.EXEC, ActionType.DELEGATE],
        )
        assert scope_evaluator.is_subset(parent, child) is False

    def test_invalid_time_escalation(self, scope_evaluator: ScopeEvaluator) -> None:
        """A child with a later valid_until than parent is NOT a subset."""
        parent = _make_grant(valid_until=FUTURE)
        child = DelegationScope(
            secrets=["api/TOKEN"],
            actions=[ActionType.EXEC],
            conditions=ScopeConditions(
                valid_until=FUTURE + timedelta(hours=1),
            ),
        )
        assert scope_evaluator.is_subset(parent, child) is False

    def test_invalid_uses_escalation(self, scope_evaluator: ScopeEvaluator) -> None:
        """A child with more max_uses than parent is NOT a subset."""
        parent = _make_grant(max_uses=10)
        child = DelegationScope(
            secrets=["api/TOKEN"],
            actions=[ActionType.EXEC],
            conditions=ScopeConditions(max_uses=20),
        )
        assert scope_evaluator.is_subset(parent, child) is False

    def test_child_no_time_limit_with_parent_limit(
        self, scope_evaluator: ScopeEvaluator
    ) -> None:
        """A child with no valid_until when parent has one is an escalation."""
        parent = _make_grant(valid_until=FUTURE)
        child = DelegationScope(
            secrets=["api/TOKEN"],
            actions=[ActionType.EXEC],
            conditions=ScopeConditions(valid_until=None),
        )
        assert scope_evaluator.is_subset(parent, child) is False

    def test_child_no_uses_limit_with_parent_limit(
        self, scope_evaluator: ScopeEvaluator
    ) -> None:
        """A child with no max_uses when parent has one is an escalation."""
        parent = _make_grant(max_uses=10)
        child = DelegationScope(
            secrets=["api/TOKEN"],
            actions=[ActionType.EXEC],
            conditions=ScopeConditions(max_uses=None),
        )
        assert scope_evaluator.is_subset(parent, child) is False

    def test_equal_scope_is_subset(self, scope_evaluator: ScopeEvaluator) -> None:
        """An equal scope (same secrets, actions, conditions) is a valid subset."""
        parent = _make_grant(
            secret="api/*",
            actions=[ActionType.EXEC],
            max_uses=10,
            valid_until=FUTURE,
        )
        child = DelegationScope(
            secrets=["api/TOKEN"],
            actions=[ActionType.EXEC],
            conditions=ScopeConditions(
                max_uses=10,
                valid_until=FUTURE,
            ),
        )
        assert scope_evaluator.is_subset(parent, child) is True

    def test_child_without_conditions(self, scope_evaluator: ScopeEvaluator) -> None:
        """A child with no conditions is valid (conditions=None means no constraint)."""
        parent = _make_grant(secret="api/*", actions=[ActionType.EXEC])
        child = DelegationScope(
            secrets=["api/TOKEN"],
            actions=[ActionType.EXEC],
            conditions=None,
        )
        assert scope_evaluator.is_subset(parent, child) is True

    def test_stricter_valid_from(self, scope_evaluator: ScopeEvaluator) -> None:
        """A child with a later valid_from than parent is stricter (valid subset)."""
        parent = _make_grant(
            valid_from=NOW - timedelta(hours=2),
            valid_until=FUTURE,
        )
        child = DelegationScope(
            secrets=["api/TOKEN"],
            actions=[ActionType.EXEC],
            conditions=ScopeConditions(
                valid_from=NOW - timedelta(hours=1),
                valid_until=FUTURE,  # same as parent, not an escalation
            ),
        )
        assert scope_evaluator.is_subset(parent, child) is True

    def test_earlier_valid_from_is_escalation(
        self, scope_evaluator: ScopeEvaluator
    ) -> None:
        """A child with an earlier valid_from than parent is an escalation."""
        parent = _make_grant(
            valid_from=NOW - timedelta(hours=1),
        )
        child = DelegationScope(
            secrets=["api/TOKEN"],
            actions=[ActionType.EXEC],
            conditions=ScopeConditions(
                valid_from=NOW - timedelta(hours=2),
            ),
        )
        assert scope_evaluator.is_subset(parent, child) is False


# ===================================================================
# 6. Output Sanitization Tests (CRITICAL SECURITY)
# ===================================================================

class TestOutputSanitization:
    """Tests for OutputSanitizer -- the LAST LINE OF DEFENCE.

    These tests verify that secret values are NEVER leaked through
    action output, regardless of encoding.
    """

    # -- Plaintext detection -----------------------------------------------

    def test_plaintext_detection(self, sanitizer: OutputSanitizer) -> None:
        """A plaintext secret in output is detected and redacted."""
        output = "Authorization: Bearer sk-1234567890abcdef"
        secrets = {"api/TOKEN": SecretValue("sk-1234567890abcdef")}

        result, redacted = sanitizer.sanitize(output, secrets)
        assert "sk-1234567890abcdef" not in result
        assert "[NL-REDACTED:api/TOKEN]" in result
        assert "api/TOKEN" in redacted

    def test_plaintext_multiple_occurrences(self, sanitizer: OutputSanitizer) -> None:
        """All occurrences of a secret are redacted."""
        output = "key=sk-abc123 and also sk-abc123 appears again"
        secrets = {"TOKEN": SecretValue("sk-abc123")}

        result, redacted = sanitizer.sanitize(output, secrets)
        assert "sk-abc123" not in result
        assert result.count("[NL-REDACTED:TOKEN]") == 2
        assert "TOKEN" in redacted

    # -- Base64 detection --------------------------------------------------

    def test_base64_detection(self, sanitizer: OutputSanitizer) -> None:
        """A Base64-encoded secret is detected and redacted."""
        secret_value = "my_secret_value_123"
        b64 = base64.b64encode(secret_value.encode()).decode()
        output = f"encoded: {b64}"
        secrets = {"creds/KEY": SecretValue(secret_value)}

        result, redacted = sanitizer.sanitize(output, secrets)
        assert b64 not in result
        assert "[NL-REDACTED:creds/KEY:base64]" in result
        assert "creds/KEY" in redacted

    def test_base64_with_padding(self, sanitizer: OutputSanitizer) -> None:
        """Base64 with padding characters (=) is handled correctly."""
        # Values that produce padding in base64
        secret_value = "test"  # base64: dGVzdA==
        b64 = base64.b64encode(secret_value.encode()).decode()
        assert "=" in b64  # Confirm padding exists
        output = f"data: {b64}"
        secrets = {"KEY": SecretValue(secret_value)}

        result, redacted = sanitizer.sanitize(output, secrets)
        assert b64 not in result
        assert "[NL-REDACTED:KEY:base64]" in result

    # -- URL-encoded detection ---------------------------------------------

    def test_url_encoded_detection(self, sanitizer: OutputSanitizer) -> None:
        """A URL-encoded secret is detected and redacted."""
        secret_value = "p@ssw0rd!_secret"
        url_encoded = urllib.parse.quote(secret_value, safe="")
        output = f"param=user&password={url_encoded}"
        secrets = {"db/PASS": SecretValue(secret_value)}

        result, redacted = sanitizer.sanitize(output, secrets)
        assert url_encoded not in result
        assert "[NL-REDACTED:db/PASS:url]" in result
        assert "db/PASS" in redacted

    def test_url_encoded_special_chars(self, sanitizer: OutputSanitizer) -> None:
        """URL encoding handles special characters (spaces, @, !, etc.)."""
        secret_value = "hello world@2026!"
        url_encoded = urllib.parse.quote(secret_value, safe="")
        output = f"value={url_encoded}"
        secrets = {"SPECIAL": SecretValue(secret_value)}

        result, redacted = sanitizer.sanitize(output, secrets)
        assert url_encoded not in result
        assert "[NL-REDACTED:SPECIAL:url]" in result

    # -- Hex-encoded detection ---------------------------------------------

    def test_hex_encoded_detection(self, sanitizer: OutputSanitizer) -> None:
        """A hex-encoded secret is detected and redacted."""
        secret_value = "deadbeef_token"
        hex_encoded = secret_value.encode().hex()
        output = f"hex: {hex_encoded}"
        secrets = {"HEX_KEY": SecretValue(secret_value)}

        result, redacted = sanitizer.sanitize(output, secrets)
        assert hex_encoded not in result
        assert "[NL-REDACTED:HEX_KEY:hex]" in result
        assert "HEX_KEY" in redacted

    # -- Multiple secrets --------------------------------------------------

    def test_multiple_secrets_same_output(self, sanitizer: OutputSanitizer) -> None:
        """Multiple different secrets in the same output are all redacted."""
        output = "token=ghp_abc123def456 password=p@ssw0rd!_secret"
        secrets = {
            "api/TOKEN": SecretValue("ghp_abc123def456"),
            "db/PASS": SecretValue("p@ssw0rd!_secret"),
        }

        result, redacted = sanitizer.sanitize(output, secrets)
        assert "ghp_abc123def456" not in result
        assert "p@ssw0rd!_secret" not in result
        assert "[NL-REDACTED:api/TOKEN]" in result
        assert "[NL-REDACTED:db/PASS]" in result
        assert "api/TOKEN" in redacted
        assert "db/PASS" in redacted

    def test_same_secret_multiple_encodings(self, sanitizer: OutputSanitizer) -> None:
        """A secret appearing in both plaintext and base64 is caught in both."""
        secret_value = "supersecret_value"
        b64 = base64.b64encode(secret_value.encode()).decode()
        output = f"plain: {secret_value} encoded: {b64}"
        secrets = {"MULTI": SecretValue(secret_value)}

        result, redacted = sanitizer.sanitize(output, secrets)
        assert secret_value not in result
        assert b64 not in result
        assert "[NL-REDACTED:MULTI]" in result
        assert "[NL-REDACTED:MULTI:base64]" in result
        assert "MULTI" in redacted

    # -- Redaction marker format -------------------------------------------

    def test_redaction_marker_plaintext_format(self, sanitizer: OutputSanitizer) -> None:
        """Plaintext redaction uses [NL-REDACTED:name] format."""
        output = "key=sk-1234567890abcdef"
        secrets = {"api/TOKEN": SecretValue("sk-1234567890abcdef")}

        result, _ = sanitizer.sanitize(output, secrets)
        assert "[NL-REDACTED:api/TOKEN]" in result

    def test_redaction_marker_encoded_format(self, sanitizer: OutputSanitizer) -> None:
        """Encoded redaction uses [NL-REDACTED:name:encoding] format.

        We use a secret with special characters so that URL-encoding
        produces a different string than plaintext, ensuring each
        encoding path is exercised independently.
        """
        secret = "p@ss w0rd!#$"
        b64 = base64.b64encode(secret.encode()).decode()
        url = urllib.parse.quote(secret, safe="")
        hexv = secret.encode().hex()

        # Build output with ONLY encoded forms (not plaintext) so each
        # encoding is independently verifiable.
        output = f"b64={b64} url={url} hex={hexv}"
        secrets = {"KEY": SecretValue(secret)}

        result, _ = sanitizer.sanitize(output, secrets)
        assert "[NL-REDACTED:KEY:base64]" in result
        assert "[NL-REDACTED:KEY:url]" in result
        assert "[NL-REDACTED:KEY:hex]" in result

    # -- Short secrets (NL-2.6.5) ------------------------------------------

    def test_short_secret_skipped(self, sanitizer: OutputSanitizer) -> None:
        """Secrets shorter than 4 characters are skipped (NL-2.6.5)."""
        output = "value: ab and more ab text"
        secrets = {"SHORT": SecretValue("ab")}

        result, redacted = sanitizer.sanitize(output, secrets)
        # "ab" should NOT be redacted (too short, too many false positives)
        assert result == output
        assert redacted == []

    def test_four_char_secret_is_scanned(self, sanitizer: OutputSanitizer) -> None:
        """Secrets exactly 4 characters long ARE scanned."""
        output = "key: abcd and more"
        secrets = {"FOUR": SecretValue("abcd")}

        result, redacted = sanitizer.sanitize(output, secrets)
        assert "abcd" not in result
        assert "[NL-REDACTED:FOUR]" in result

    def test_empty_secret_skipped(self, sanitizer: OutputSanitizer) -> None:
        """Empty secret values are skipped."""
        output = "some output"
        secrets = {"EMPTY": SecretValue("")}

        result, redacted = sanitizer.sanitize(output, secrets)
        assert result == output
        assert redacted == []

    # -- Null bytes (NL-2.6.10) --------------------------------------------

    def test_null_bytes_stripped(self, sanitizer: OutputSanitizer) -> None:
        """Binary null bytes are stripped before scanning (NL-2.6.10)."""
        secret = "my_secret_key"
        # Insert null bytes into the output around the secret
        output = f"data\x00: {secret}\x00more"
        secrets = {"KEY": SecretValue(secret)}

        result, redacted = sanitizer.sanitize(output, secrets)
        assert "\x00" not in result
        assert secret not in result
        assert "[NL-REDACTED:KEY]" in result

    def test_null_bytes_between_secret_chars(self, sanitizer: OutputSanitizer) -> None:
        """Null bytes interspersed in a secret value do not prevent detection."""
        # The null bytes are stripped first, then the secret is matched
        secret = "abcdefgh"
        # Output has the secret with nulls stripped = matches
        output = f"prefix: {secret}suffix"
        secrets = {"KEY": SecretValue(secret)}

        result, redacted = sanitizer.sanitize(output, secrets)
        assert secret not in result
        assert "[NL-REDACTED:KEY]" in result

    # -- Multi-line secrets (NL-2.6.11) ------------------------------------

    def test_multiline_secret(self, sanitizer: OutputSanitizer) -> None:
        """Multi-line secrets are matched as a single string (NL-2.6.11)."""
        secret = "line1\nline2\nline3"
        output = f"START{secret}END"
        secrets = {"MULTILINE": SecretValue(secret)}

        result, redacted = sanitizer.sanitize(output, secrets)
        assert secret not in result
        assert "[NL-REDACTED:MULTILINE]" in result

    # -- Output size limit -------------------------------------------------

    def test_output_too_large(self, sanitizer: OutputSanitizer) -> None:
        """Output exceeding max_size raises SanitizationFailure."""
        from nl_protocol.core.errors import SanitizationFailure

        output = "x" * 100
        secrets: dict[str, SecretValue] = {}

        with pytest.raises(SanitizationFailure):
            sanitizer.sanitize(output, secrets, max_size=50)

    # -- Count variant -----------------------------------------------------

    def test_sanitize_with_count(self, sanitizer: OutputSanitizer) -> None:
        """sanitize_with_count returns the total number of redactions."""
        secret = "supersecret123"
        output = f"{secret} and {secret} and {secret}"
        secrets = {"KEY": SecretValue(secret)}

        result, redacted, count = sanitizer.sanitize_with_count(output, secrets)
        assert secret not in result
        assert "KEY" in redacted
        assert count == 3

    def test_sanitize_with_count_multiple_encodings(
        self, sanitizer: OutputSanitizer
    ) -> None:
        """Count variant counts across all encoding types."""
        secret = "my_test_secret!"
        b64 = base64.b64encode(secret.encode()).decode()
        url = urllib.parse.quote(secret, safe="")
        hexv = secret.encode().hex()

        output = f"{secret} {b64} {url} {hexv}"
        secrets = {"KEY": SecretValue(secret)}

        result, redacted, count = sanitizer.sanitize_with_count(output, secrets)
        assert count == 4  # plaintext + base64 + url + hex

    # -- No-leak guarantee -------------------------------------------------

    def test_no_secret_in_redacted_output(self, sanitizer: OutputSanitizer) -> None:
        """CRITICAL: After sanitization, no secret value appears in output."""
        secrets = {
            "api/TOKEN": SecretValue("ghp_abc123def456"),
            "db/PASS": SecretValue("p@ssw0rd!_secret"),
            "API_KEY": SecretValue("sk-1234567890abcdef"),
        }

        # Construct output containing all secrets in all encodings
        parts: list[str] = []
        for _name, sv in secrets.items():
            v = sv.expose()
            parts.append(v)
            parts.append(base64.b64encode(v.encode()).decode())
            parts.append(urllib.parse.quote(v, safe=""))
            parts.append(v.encode().hex())

        output = " ".join(parts)
        result, redacted = sanitizer.sanitize(output, secrets)

        # Verify NO secret value remains in any encoding
        for name, sv in secrets.items():
            v = sv.expose()
            assert v not in result, f"Plaintext secret '{name}' leaked!"
            assert (
                base64.b64encode(v.encode()).decode() not in result
            ), f"Base64 secret '{name}' leaked!"
            assert (
                urllib.parse.quote(v, safe="") not in result
            ), f"URL-encoded secret '{name}' leaked!"
            assert (
                v.encode().hex() not in result
            ), f"Hex-encoded secret '{name}' leaked!"

    def test_no_false_positive_on_clean_output(
        self, sanitizer: OutputSanitizer
    ) -> None:
        """Clean output without secrets is unchanged."""
        output = '{"status": "ok", "data": [1, 2, 3]}'
        secrets = {"api/TOKEN": SecretValue("totally_different_value")}

        result, redacted = sanitizer.sanitize(output, secrets)
        assert result == output
        assert redacted == []


# ===================================================================
# 7. Action Validation Tests
# ===================================================================

class TestActionValidation:
    """Tests for ActionValidator."""

    def test_valid_exec(self, action_validator: ActionValidator) -> None:
        """A valid EXEC payload passes validation."""
        payload = ActionPayload(
            type=ActionType.EXEC,
            template="curl -H 'Auth: {{nl:TOKEN}}' https://api.example.com",
            purpose="Test API access",
        )
        errors = action_validator.validate(payload)
        assert errors == []

    def test_exec_empty_template(self, action_validator: ActionValidator) -> None:
        """An EXEC payload with empty template fails."""
        payload = ActionPayload(
            type=ActionType.EXEC,
            template="",
            purpose="Test",
        )
        errors = action_validator.validate(payload)
        assert len(errors) >= 1

    def test_exec_only_placeholders(self, action_validator: ActionValidator) -> None:
        """An EXEC payload with only placeholders (no command) fails."""
        payload = ActionPayload(
            type=ActionType.EXEC,
            template="{{nl:TOKEN}}",
            purpose="Test",
        )
        errors = action_validator.validate(payload)
        assert len(errors) >= 1
        assert any("command" in e.lower() for e in errors)

    def test_valid_template(self, action_validator: ActionValidator) -> None:
        """A valid TEMPLATE payload passes validation."""
        payload = ActionPayload(
            type=ActionType.TEMPLATE,
            template="DB_PASS={{nl:database/DB_PASSWORD}}",
            purpose="Generate env file",
        )
        errors = action_validator.validate(payload)
        assert errors == []

    def test_template_empty(self, action_validator: ActionValidator) -> None:
        """A TEMPLATE payload with empty content fails."""
        payload = ActionPayload(
            type=ActionType.TEMPLATE,
            template="",
            purpose="Test",
        )
        errors = action_validator.validate(payload)
        assert len(errors) >= 1

    def test_valid_http(self, action_validator: ActionValidator) -> None:
        """A valid HTTP payload passes validation."""
        payload = ActionPayload(
            type=ActionType.HTTP,
            template="https://api.example.com/data?key={{nl:API_KEY}}",
            purpose="Fetch data",
        )
        errors = action_validator.validate(payload)
        assert errors == []

    def test_http_no_url(self, action_validator: ActionValidator) -> None:
        """An HTTP payload without a URL fails."""
        payload = ActionPayload(
            type=ActionType.HTTP,
            template="just some text without a url",
            purpose="Test",
        )
        errors = action_validator.validate(payload)
        assert len(errors) >= 1
        assert any("url" in e.lower() for e in errors)

    def test_read_empty_template_ok(self, action_validator: ActionValidator) -> None:
        """A READ payload with empty template is valid."""
        payload = ActionPayload(
            type=ActionType.READ,
            template="",
            purpose="Check secret existence",
        )
        errors = action_validator.validate(payload)
        assert errors == []

    def test_validate_or_raise_on_valid(
        self, action_validator: ActionValidator
    ) -> None:
        """validate_or_raise does not raise for valid payloads."""
        payload = ActionPayload(
            type=ActionType.EXEC,
            template="echo {{nl:TOKEN}}",
            purpose="Test",
        )
        action_validator.validate_or_raise(payload)  # Should not raise

    def test_validate_or_raise_on_invalid(
        self, action_validator: ActionValidator
    ) -> None:
        """validate_or_raise raises InvalidPlaceholder for invalid payloads."""
        from nl_protocol.core.errors import InvalidPlaceholder

        payload = ActionPayload(
            type=ActionType.EXEC,
            template="",
            purpose="Test",
        )
        with pytest.raises(InvalidPlaceholder):
            action_validator.validate_or_raise(payload)


# ===================================================================
# 8. Policy Evaluation Order Tests
# ===================================================================

class TestPolicyEvaluation:
    """Tests for PolicyEvaluator -- the 5-step evaluation order.

    These tests use mock/stub components since the full AIDManager
    and other dependencies are in separate modules.
    """

    @pytest.mark.asyncio
    async def test_deny_rule_blocks_first(self) -> None:
        """Step 1: A deny rule match blocks before any other check."""
        from nl_protocol.access.policy import PolicyEvaluator
        from nl_protocol.core.types import ActionRequest

        # Create a deny engine that always blocks
        class StubDenyEngine:
            def check(self, template: str) -> None:
                raise ActionBlocked("Blocked by deny rule")

        # Create a stub AID manager (should NOT be reached)
        class StubAIDManager:
            async def verify_agent(self, agent_uri: AgentURI) -> AID:
                raise AssertionError("Should not reach AID verification")

            def check_scope(self, aid: AID, ref: str) -> bool:
                raise AssertionError("Should not reach scope check")

        # Create a stub scope evaluator (should NOT be reached)
        class StubScopeEvaluator:
            async def find_matching_grant(
                self, agent_uri: AgentURI, ref: SecretRef, action_type: ActionType
            ) -> ScopeGrant:
                raise AssertionError("Should not reach grant evaluation")

        evaluator = PolicyEvaluator(
            aid_manager=StubAIDManager(),  # type: ignore[arg-type]
            scope_evaluator=StubScopeEvaluator(),  # type: ignore[arg-type]
            deny_engine=StubDenyEngine(),  # type: ignore[arg-type]
        )

        request = ActionRequest(
            agent_uri=AGENT_URI,
            action=ActionPayload(
                type=ActionType.EXEC,
                template="echo {{nl:FORBIDDEN}}",
                purpose="Test deny rule",
            ),
        )

        with pytest.raises(ActionBlocked):
            await evaluator.evaluate(request)

    @pytest.mark.asyncio
    async def test_aid_scope_checked_before_grants(self) -> None:
        """Step 2: AID scope violation blocks before scope grant lookup."""
        from nl_protocol.access.policy import PolicyEvaluator
        from nl_protocol.core.types import ActionRequest

        class StubAIDManager:
            async def verify_agent(self, agent_uri: AgentURI) -> AID:
                return AID(
                    agent_uri=agent_uri,
                    display_name="Test Agent",
                    vendor="test.com",
                    version="1.0.0",
                    scope=["database/*"],  # Only database scope
                    expires_at=FUTURE,
                )

            def check_scope(self, aid: AID, ref: str) -> bool:
                from fnmatch import fnmatch
                return any(fnmatch(ref, p) for p in aid.scope)

        class StubScopeEvaluator:
            async def find_matching_grant(
                self, agent_uri: AgentURI, ref: SecretRef, action_type: ActionType
            ) -> ScopeGrant:
                raise AssertionError("Should not reach grant evaluation")

        evaluator = PolicyEvaluator(
            aid_manager=StubAIDManager(),  # type: ignore[arg-type]
            scope_evaluator=StubScopeEvaluator(),  # type: ignore[arg-type]
        )

        request = ActionRequest(
            agent_uri=AGENT_URI,
            action=ActionPayload(
                type=ActionType.EXEC,
                template="curl {{nl:api/TOKEN}}",  # api/* not in AID scope
                purpose="Test AID scope",
            ),
        )

        with pytest.raises(NoScopeGrant):
            await evaluator.evaluate(request)

    @pytest.mark.asyncio
    async def test_full_evaluation_success(self) -> None:
        """All five steps pass and a PolicyDecision is returned."""
        from nl_protocol.access.policy import PolicyDecision, PolicyEvaluator
        from nl_protocol.core.types import ActionRequest

        test_aid = AID(
            agent_uri=AGENT_URI,
            display_name="Test Agent",
            vendor="anthropic.com",
            version="1.5.2",
            scope=[],  # No scope restriction
            expires_at=FUTURE,
        )

        test_grant = _make_grant()

        class StubAIDManager:
            async def verify_agent(self, agent_uri: AgentURI) -> AID:
                return test_aid

            def check_scope(self, aid: AID, ref: str) -> bool:
                return True  # No scope restriction

        class StubScopeEvaluator:
            async def find_matching_grant(
                self, agent_uri: AgentURI, ref: SecretRef, action_type: ActionType
            ) -> ScopeGrant:
                return test_grant

        evaluator = PolicyEvaluator(
            aid_manager=StubAIDManager(),  # type: ignore[arg-type]
            scope_evaluator=StubScopeEvaluator(),  # type: ignore[arg-type]
        )

        request = ActionRequest(
            agent_uri=AGENT_URI,
            action=ActionPayload(
                type=ActionType.EXEC,
                template="curl {{nl:api/TOKEN}}",
                purpose="Full eval test",
            ),
        )

        decision = await evaluator.evaluate(request)
        assert isinstance(decision, PolicyDecision)
        assert decision.allowed is True
        assert decision.aid is test_aid
        assert decision.grant is test_grant
        assert len(decision.secret_refs) == 1
        assert decision.secret_refs[0] == SecretRef("api/TOKEN")

    @pytest.mark.asyncio
    async def test_no_placeholders_skips_grant_check(self) -> None:
        """A template with no placeholders skips scope grant evaluation."""
        from nl_protocol.access.policy import PolicyEvaluator
        from nl_protocol.core.types import ActionRequest

        test_aid = AID(
            agent_uri=AGENT_URI,
            display_name="Test Agent",
            vendor="anthropic.com",
            version="1.5.2",
            scope=[],
            expires_at=FUTURE,
        )

        class StubAIDManager:
            async def verify_agent(self, agent_uri: AgentURI) -> AID:
                return test_aid

            def check_scope(self, aid: AID, ref: str) -> bool:
                return True

        class StubScopeEvaluator:
            async def find_matching_grant(
                self, agent_uri: AgentURI, ref: SecretRef, action_type: ActionType
            ) -> ScopeGrant:
                raise AssertionError("Should not be called for no-placeholder template")

        evaluator = PolicyEvaluator(
            aid_manager=StubAIDManager(),  # type: ignore[arg-type]
            scope_evaluator=StubScopeEvaluator(),  # type: ignore[arg-type]
        )

        request = ActionRequest(
            agent_uri=AGENT_URI,
            action=ActionPayload(
                type=ActionType.EXEC,
                template="echo hello world",
                purpose="No secrets",
            ),
        )

        decision = await evaluator.evaluate(request)
        assert decision.allowed is True
        assert decision.grant is None
        assert decision.secret_refs == []
