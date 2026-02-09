"""Level 2 -- Action-Based Access conformance tests.

Verifies Chapter 02 requirements: placeholder extraction, scope grant
matching with glob patterns, condition checking, usage consumption,
policy evaluation order, and output sanitization.
"""
from __future__ import annotations

import base64
import urllib.parse
from datetime import UTC, datetime, timedelta

import pytest

from nl_protocol.access.placeholders import PlaceholderResolver
from nl_protocol.access.sanitization import OutputSanitizer
from nl_protocol.access.scope_grants import ScopeEvaluator
from nl_protocol.core.errors import NoScopeGrant, ScopeExpired, UseLimitExceeded
from nl_protocol.core.interfaces import (
    InMemoryScopeGrantStore,
    InMemorySecretStore,
)
from nl_protocol.core.types import (
    ActionType,
    SecretRef,
    SecretValue,
)

from .conftest import AGENT_URI, SECRET_VALUE, make_grant

# ===================================================================
# Section 4 -- Placeholder extraction and resolution
# ===================================================================

class TestPlaceholderExtraction:
    """Spec Section 4: {{nl:...}} placeholder parsing."""

    def test_MUST_extract_single_placeholder(
        self, secret_store: InMemorySecretStore
    ) -> None:
        """A single {{nl:ref}} MUST be extracted correctly."""
        resolver = PlaceholderResolver(secret_store)
        refs = resolver.extract_refs("echo {{nl:api/TOKEN}}")
        assert refs == [SecretRef("api/TOKEN")]

    def test_MUST_extract_multiple_placeholders(
        self, secret_store: InMemorySecretStore
    ) -> None:
        """Multiple placeholders MUST all be extracted in order."""
        resolver = PlaceholderResolver(secret_store)
        refs = resolver.extract_refs("{{nl:api/TOKEN}} and {{nl:db/PASSWORD}}")
        assert refs == [SecretRef("api/TOKEN"), SecretRef("db/PASSWORD")]

    def test_MUST_return_empty_for_no_placeholders(
        self, secret_store: InMemorySecretStore
    ) -> None:
        """A template without placeholders MUST return an empty list."""
        resolver = PlaceholderResolver(secret_store)
        refs = resolver.extract_refs("echo hello world")
        assert refs == []

    async def test_MUST_resolve_placeholder_to_value(
        self, secret_store: InMemorySecretStore
    ) -> None:
        """Resolution MUST replace placeholder with the actual secret value."""
        resolver = PlaceholderResolver(secret_store)
        resolved, refs = await resolver.resolve("echo {{nl:api/TOKEN}}")
        assert SECRET_VALUE in resolved
        assert refs == [SecretRef("api/TOKEN")]

    def test_MUST_validate_malformed_placeholder(
        self, secret_store: InMemorySecretStore
    ) -> None:
        """Malformed placeholder (opening without close) MUST produce errors."""
        resolver = PlaceholderResolver(secret_store)
        errors = resolver.validate_template("echo {{nl:bad")
        assert len(errors) > 0


# ===================================================================
# Section 8 -- Scope grant matching
# ===================================================================

class TestScopeGrantMatching:
    """Spec Section 8: scope grant evaluation with glob patterns."""

    async def test_MUST_match_exact_secret(
        self, scope_grant_store: InMemoryScopeGrantStore
    ) -> None:
        """An exact secret ref MUST match an exact grant pattern."""
        grant = make_grant(secret="api/TOKEN")
        await scope_grant_store.create_grant(grant)
        evaluator = ScopeEvaluator(scope_grant_store)
        matched = await evaluator.find_matching_grant(
            AGENT_URI, SecretRef("api/TOKEN"), ActionType.EXEC
        )
        assert matched.grant_id == grant.grant_id

    async def test_MUST_match_glob_pattern(
        self, scope_grant_store: InMemoryScopeGrantStore
    ) -> None:
        """Glob pattern api/* MUST match api/TOKEN."""
        grant = make_grant(secret="api/*")
        await scope_grant_store.create_grant(grant)
        evaluator = ScopeEvaluator(scope_grant_store)
        matched = await evaluator.find_matching_grant(
            AGENT_URI, SecretRef("api/TOKEN"), ActionType.EXEC
        )
        assert matched.grant_id == grant.grant_id

    async def test_MUST_NOT_match_unrelated_secret(
        self, scope_grant_store: InMemoryScopeGrantStore
    ) -> None:
        """A grant for api/* MUST NOT match db/PASSWORD."""
        grant = make_grant(secret="api/*")
        await scope_grant_store.create_grant(grant)
        evaluator = ScopeEvaluator(scope_grant_store)
        with pytest.raises(NoScopeGrant):
            await evaluator.find_matching_grant(
                AGENT_URI, SecretRef("db/PASSWORD"), ActionType.EXEC
            )

    async def test_MUST_skip_revoked_grant(
        self, scope_grant_store: InMemoryScopeGrantStore
    ) -> None:
        """Revoked grants MUST NOT be returned as matches."""
        grant = make_grant(secret="api/*", revoked=True)
        await scope_grant_store.create_grant(grant)
        evaluator = ScopeEvaluator(scope_grant_store)
        with pytest.raises(NoScopeGrant):
            await evaluator.find_matching_grant(
                AGENT_URI, SecretRef("api/TOKEN"), ActionType.EXEC
            )

    async def test_MUST_reject_wrong_action_type(
        self, scope_grant_store: InMemoryScopeGrantStore
    ) -> None:
        """A grant not including the requested action type MUST NOT match."""
        grant = make_grant(secret="api/*", actions=[ActionType.READ])
        await scope_grant_store.create_grant(grant)
        evaluator = ScopeEvaluator(scope_grant_store)
        with pytest.raises(NoScopeGrant):
            await evaluator.find_matching_grant(
                AGENT_URI, SecretRef("api/TOKEN"), ActionType.EXEC
            )


# ===================================================================
# Section 8.4 -- Condition checking
# ===================================================================

class TestScopeConditions:
    """Spec Section 8.4: time bounds and usage limits."""

    async def test_MUST_reject_expired_grant(
        self, scope_grant_store: InMemoryScopeGrantStore
    ) -> None:
        """A grant whose valid_until is in the past MUST raise ScopeExpired."""
        grant = make_grant(
            secret="api/*",
            valid_until=datetime.now(UTC) - timedelta(hours=1),
        )
        await scope_grant_store.create_grant(grant)
        evaluator = ScopeEvaluator(scope_grant_store)
        with pytest.raises(ScopeExpired):
            await evaluator.find_matching_grant(
                AGENT_URI, SecretRef("api/TOKEN"), ActionType.EXEC
            )

    async def test_MUST_reject_exhausted_usage(
        self, scope_grant_store: InMemoryScopeGrantStore
    ) -> None:
        """A grant that has reached max_uses MUST raise UseLimitExceeded."""
        grant = make_grant(secret="api/*", max_uses=1)
        await scope_grant_store.create_grant(grant)
        evaluator = ScopeEvaluator(scope_grant_store)
        matched = await evaluator.find_matching_grant(
            AGENT_URI, SecretRef("api/TOKEN"), ActionType.EXEC
        )
        await evaluator.consume_usage(matched)
        # Grant is now fully consumed -- next consume MUST fail
        with pytest.raises(UseLimitExceeded):
            await evaluator.consume_usage(matched)

    async def test_MUST_allow_within_usage_limit(
        self, scope_grant_store: InMemoryScopeGrantStore
    ) -> None:
        """A grant with remaining uses MUST allow consumption."""
        grant = make_grant(secret="api/*", max_uses=5)
        await scope_grant_store.create_grant(grant)
        evaluator = ScopeEvaluator(scope_grant_store)
        matched = await evaluator.find_matching_grant(
            AGENT_URI, SecretRef("api/TOKEN"), ActionType.EXEC
        )
        # First use should succeed
        await evaluator.consume_usage(matched)
        assert grant.conditions.current_uses == 1


# ===================================================================
# Section 9 -- Output sanitization
# ===================================================================

class TestOutputSanitization:
    """Spec Section 9: output MUST be scanned for secret leakage."""

    def test_MUST_redact_plaintext_secret(self) -> None:
        """Plaintext secret in output MUST be replaced with [NL-REDACTED:name]."""
        sanitizer = OutputSanitizer()
        output = f"Result: {SECRET_VALUE}"
        cleaned, names = sanitizer.sanitize(
            output, {"api/TOKEN": SecretValue(SECRET_VALUE)}
        )
        assert SECRET_VALUE not in cleaned
        assert "[NL-REDACTED:api/TOKEN]" in cleaned
        assert "api/TOKEN" in names

    def test_MUST_redact_base64_encoded_secret(self) -> None:
        """Base64-encoded secret in output MUST be redacted."""
        sanitizer = OutputSanitizer()
        b64 = base64.b64encode(SECRET_VALUE.encode()).decode()
        output = f"Encoded: {b64}"
        cleaned, names = sanitizer.sanitize(
            output, {"api/TOKEN": SecretValue(SECRET_VALUE)}
        )
        assert b64 not in cleaned
        assert "[NL-REDACTED:api/TOKEN:base64]" in cleaned

    def test_MUST_redact_url_encoded_secret(self) -> None:
        """URL-encoded secret in output MUST be redacted."""
        sanitizer = OutputSanitizer()
        # Use a secret with special chars that differ when URL-encoded
        special_secret = "p@ss=w0rd&key!"
        url_encoded = urllib.parse.quote(special_secret, safe="")
        output = f"URL: {url_encoded}"
        cleaned, names = sanitizer.sanitize(
            output, {"api/TOKEN": SecretValue(special_secret)}
        )
        assert url_encoded not in cleaned
        assert "[NL-REDACTED:api/TOKEN:url]" in cleaned

    def test_MUST_redact_hex_encoded_secret(self) -> None:
        """Hex-encoded secret in output MUST be redacted."""
        sanitizer = OutputSanitizer()
        hex_val = SECRET_VALUE.encode().hex()
        output = f"Hex: {hex_val}"
        cleaned, names = sanitizer.sanitize(
            output, {"api/TOKEN": SecretValue(SECRET_VALUE)}
        )
        assert hex_val not in cleaned
        assert "[NL-REDACTED:api/TOKEN:hex]" in cleaned

    def test_MUST_NOT_redact_short_secrets(self) -> None:
        """Secrets shorter than 4 chars MUST NOT be redacted (NL-2.6.5)."""
        sanitizer = OutputSanitizer()
        output = "Value: abc"
        cleaned, names = sanitizer.sanitize(
            output, {"short/key": SecretValue("abc")}
        )
        assert cleaned == output
        assert names == []

    def test_MUST_strip_null_bytes(self) -> None:
        """Binary null bytes in output MUST be stripped (NL-2.6.10)."""
        sanitizer = OutputSanitizer()
        output = "hello\x00world"
        cleaned, _ = sanitizer.sanitize(output, {})
        assert "\x00" not in cleaned
        assert "helloworld" in cleaned

    def test_MUST_handle_clean_output(self) -> None:
        """Output without secrets MUST pass through unchanged."""
        sanitizer = OutputSanitizer()
        output = "Clean output with no secrets"
        cleaned, names = sanitizer.sanitize(
            output, {"api/TOKEN": SecretValue(SECRET_VALUE)}
        )
        assert cleaned == output
        assert names == []


# ===================================================================
# SecretValue redaction safety
# ===================================================================

class TestSecretValueRedaction:
    """Spec Section 9 / Core types: SecretValue MUST prevent accidental exposure."""

    def test_MUST_redact_str(self) -> None:
        """str(SecretValue) MUST return [NL-REDACTED]."""
        sv = SecretValue("my-secret")
        assert str(sv) == "[NL-REDACTED]"

    def test_MUST_redact_repr(self) -> None:
        """repr(SecretValue) MUST NOT contain the actual value."""
        sv = SecretValue("my-secret")
        assert "my-secret" not in repr(sv)

    def test_MUST_redact_format(self) -> None:
        """format(SecretValue) MUST return [NL-REDACTED]."""
        sv = SecretValue("my-secret")
        assert f"{sv}" == "[NL-REDACTED]"

    def test_MUST_expose_via_explicit_method(self) -> None:
        """.expose() MUST return the actual value."""
        sv = SecretValue("my-secret")
        assert sv.expose() == "my-secret"
