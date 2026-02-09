"""Level 4 -- Pre-Execution Defense conformance tests.

Verifies Chapter 04 requirements: deny rules blocking dangerous patterns,
Unicode evasion detection, and command validation.
"""
from __future__ import annotations

import pytest

from nl_protocol.core.errors import ActionBlocked, EvasionDetected
from nl_protocol.defense.deny_rules import DenyRule, DenyRuleEngine
from nl_protocol.defense.validation import CommandValidator

# ===================================================================
# Section 3 -- Deny rule matching
# ===================================================================

class TestDenyRuleBlocking:
    """Spec Section 3: deny rules MUST block dangerous patterns."""

    def test_MUST_block_env_command(self) -> None:
        """The 'env' command MUST be blocked (environment dump)."""
        engine = DenyRuleEngine()
        with pytest.raises(ActionBlocked):
            engine.check("env")

    def test_MUST_block_printenv_command(self) -> None:
        """The 'printenv' command MUST be blocked."""
        engine = DenyRuleEngine()
        with pytest.raises(ActionBlocked):
            engine.check("printenv")

    def test_MUST_block_cat_env_file(self) -> None:
        """Reading .env files MUST be blocked."""
        engine = DenyRuleEngine()
        with pytest.raises(ActionBlocked):
            engine.check("cat .env")

    def test_MUST_block_vault_get(self) -> None:
        """Direct vault get commands MUST be blocked."""
        engine = DenyRuleEngine()
        with pytest.raises(ActionBlocked):
            engine.check("vault get secret/key")

    def test_MUST_block_aws_secretsmanager(self) -> None:
        """AWS Secrets Manager retrieval MUST be blocked."""
        engine = DenyRuleEngine()
        with pytest.raises(ActionBlocked):
            engine.check("aws secretsmanager get-secret-value --secret-id prod")

    def test_MUST_block_proc_environ(self) -> None:
        """Reading /proc/self/environ MUST be blocked."""
        engine = DenyRuleEngine()
        with pytest.raises(ActionBlocked):
            engine.check("cat /proc/self/environ")

    def test_MUST_block_base64_decode_to_shell(self) -> None:
        """base64 decode piped to shell MUST be blocked."""
        engine = DenyRuleEngine()
        with pytest.raises(ActionBlocked):
            engine.check("base64 -d payload.txt | bash")

    def test_MUST_allow_safe_commands(self) -> None:
        """Safe commands like 'echo hello' MUST NOT be blocked."""
        engine = DenyRuleEngine()
        # Should not raise
        engine.check("echo hello world")

    def test_MUST_provide_alternative_in_error(self) -> None:
        """ActionBlocked error MUST include an alternative suggestion."""
        engine = DenyRuleEngine()
        with pytest.raises(ActionBlocked) as exc_info:
            engine.check("cat .env")
        assert exc_info.value.details.get("alternative")

    def test_MUST_include_rule_id_in_error(self) -> None:
        """ActionBlocked error MUST include the matching rule_id."""
        engine = DenyRuleEngine()
        with pytest.raises(ActionBlocked) as exc_info:
            engine.check("vault get secret/key")
        assert "rule_id" in exc_info.value.details


# ===================================================================
# Section 3.3 -- Custom rules
# ===================================================================

class TestCustomDenyRules:
    """Spec Section 3.3: custom deny rules MUST be supported."""

    def test_MUST_add_custom_rule(self) -> None:
        """Adding a custom deny rule MUST make it enforced."""
        engine = DenyRuleEngine()
        custom = DenyRule(
            rule_id="CUSTOM-001",
            category="custom",
            pattern=r"my-dangerous-command",
            severity="high",
            description="Block custom command",
            alternative="Use safe alternative.",
        )
        engine.add_rule(custom)
        with pytest.raises(ActionBlocked):
            engine.check("my-dangerous-command")

    def test_MUST_NOT_allow_duplicate_rule_id(self) -> None:
        """Duplicate rule_id MUST be rejected."""
        engine = DenyRuleEngine()
        custom = DenyRule(
            rule_id="CUSTOM-002",
            category="custom",
            pattern=r"test",
            severity="low",
            description="Test rule",
            alternative="N/A",
        )
        engine.add_rule(custom)
        with pytest.raises(ValueError):
            engine.add_rule(custom)

    def test_MUST_NOT_remove_standard_rules(self) -> None:
        """Standard rules MUST NOT be removable."""
        engine = DenyRuleEngine()
        with pytest.raises(ValueError):
            engine.remove_rule("NL-4-DENY-001")

    def test_MUST_allow_removing_custom_rules(self) -> None:
        """Custom rules MUST be removable by ID."""
        engine = DenyRuleEngine()
        custom = DenyRule(
            rule_id="CUSTOM-003",
            category="custom",
            pattern=r"removable",
            severity="low",
            description="Removable rule",
            alternative="N/A",
        )
        engine.add_rule(custom)
        removed = engine.remove_rule("CUSTOM-003")
        assert removed.rule_id == "CUSTOM-003"


# ===================================================================
# Section 6 -- Evasion detection
# ===================================================================

class TestUnicodeEvasionDetection:
    """Spec Section 6.2.1: Unicode evasion MUST be detected."""

    def test_MUST_detect_zero_width_characters(self) -> None:
        """Zero-width characters MUST be detected as evasion."""
        validator = CommandValidator()
        assert validator.has_zero_width_chars("v\u200bault get secret")

    def test_MUST_detect_bidi_control_characters(self) -> None:
        """Bidirectional control characters MUST be detected."""
        validator = CommandValidator()
        assert validator.has_bidi_controls("get \u202esecret")

    def test_MUST_detect_homoglyph_characters(self) -> None:
        """Cyrillic/confusable characters MUST be detected."""
        validator = CommandValidator()
        # Cyrillic 'а' (U+0430) looks like Latin 'a'
        assert validator.has_confusable_chars("\u0430bc")

    def test_MUST_raise_on_null_byte(self) -> None:
        """Null bytes MUST trigger EvasionDetected."""
        validator = CommandValidator()
        with pytest.raises(EvasionDetected):
            validator.validate_or_raise("cmd\x00arg")

    def test_MUST_raise_on_bidi_override(self) -> None:
        """Bidi override characters MUST trigger EvasionDetected."""
        validator = CommandValidator()
        with pytest.raises(EvasionDetected):
            validator.validate_or_raise("echo \u202ehello")

    def test_MUST_normalize_for_deny_matching(self) -> None:
        """Normalization MUST strip zero-width and bidi chars."""
        validator = CommandValidator()
        normalized = validator.normalize("v\u200bault\u200c get secret")
        assert "vault get secret" in normalized


# ===================================================================
# Section 6.2.2 -- Whitespace and template injection
# ===================================================================

class TestWhitespaceAndTemplateValidation:
    """Spec Section 6.2.2: whitespace manipulation detection."""

    def test_MUST_collapse_whitespace(self) -> None:
        """Excessive whitespace MUST be collapsed during normalization."""
        validator = CommandValidator()
        normalized = validator.normalize("echo    hello     world")
        assert normalized == "echo hello world"

    def test_MUST_detect_template_injection(self) -> None:
        """Non-NL template expressions {{ }} MUST be detected."""
        validator = CommandValidator()
        assert validator.has_template_injection("{{ config.secret }}")

    def test_MUST_NOT_flag_nl_placeholders_as_injection(self) -> None:
        """{{nl:...}} placeholders MUST NOT be flagged as template injection."""
        validator = CommandValidator()
        assert not validator.has_template_injection("{{nl:api/TOKEN}}")
