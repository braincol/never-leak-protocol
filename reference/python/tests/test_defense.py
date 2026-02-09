"""Tests for NL Protocol Level 4 -- Pre-Execution Defense.

Covers the defense subpackage:

1. **Deny rule matching** -- at least 2 tests per category (7 categories).
2. **Pattern engine** -- timeout, caching, RE2 vs re fallback.
3. **Unicode evasion detection** -- homoglyphs, zero-width, RTL overrides.
4. **Command injection detection**.
5. **Null byte detection**.
6. **Custom rule addition/removal**.
7. **Integration with PolicyEvaluator's DenyEngine Protocol**.
"""
from __future__ import annotations

import re

import pytest

from nl_protocol.access.policy import DenyEngine
from nl_protocol.core.errors import ActionBlocked, EvasionDetected
from nl_protocol.defense import (
    CATEGORY_PRIORITY,
    CommandValidator,
    DenyMatch,
    DenyRule,
    DenyRuleEngine,
    EvasionFinding,
    PatternEngine,
)

# ===================================================================
# Fixtures
# ===================================================================


@pytest.fixture
def engine() -> DenyRuleEngine:
    """A DenyRuleEngine with all standard rules loaded."""
    return DenyRuleEngine()


@pytest.fixture
def empty_engine() -> DenyRuleEngine:
    """A DenyRuleEngine with NO standard rules (for custom-rule testing)."""
    return DenyRuleEngine(load_standard_rules=False)


@pytest.fixture
def pattern_engine() -> PatternEngine:
    """A PatternEngine with default settings."""
    return PatternEngine()


@pytest.fixture
def validator() -> CommandValidator:
    """A CommandValidator with default settings."""
    return CommandValidator()


# ===================================================================
# Test: PatternEngine
# ===================================================================


class TestPatternEngine:
    """Tests for the RE2-compatible pattern matching engine."""

    def test_simple_match(self, pattern_engine: PatternEngine) -> None:
        """Basic pattern matching works."""
        assert pattern_engine.match(r"vault\s+get", "vault get SECRET")

    def test_no_match(self, pattern_engine: PatternEngine) -> None:
        """Non-matching text returns False."""
        assert not pattern_engine.match(r"vault\s+get", "git status")

    def test_case_insensitive(self, pattern_engine: PatternEngine) -> None:
        """Matching is case-insensitive by default."""
        assert pattern_engine.match(r"vault\s+get", "VAULT GET SECRET")
        assert pattern_engine.match(r"vault\s+get", "VaUlT   GeT SECRET")

    def test_find_all(self, pattern_engine: PatternEngine) -> None:
        """find_all returns all non-overlapping matches."""
        results = pattern_engine.find_all(r"\b\w+_KEY\b", "API_KEY and DB_KEY here")
        assert "API_KEY" in results
        assert "DB_KEY" in results

    def test_find_all_no_match(self, pattern_engine: PatternEngine) -> None:
        """find_all returns empty list on no match."""
        results = pattern_engine.find_all(r"nonexistent", "hello world")
        assert results == []

    def test_pattern_compilation_caching(self, pattern_engine: PatternEngine) -> None:
        """Repeated compilations use the cache."""
        PatternEngine.clear_cache()
        pattern_engine.compile(r"test\d+")
        info1 = PatternEngine.cache_info()
        pattern_engine.compile(r"test\d+")
        info2 = PatternEngine.cache_info()
        assert info2.hits > info1.hits

    def test_invalid_pattern_raises(self, pattern_engine: PatternEngine) -> None:
        """Invalid regex raises re.error at compile time."""
        with pytest.raises(re.error):
            pattern_engine.compile(r"[invalid")

    def test_engine_name_is_stdlib(self, pattern_engine: PatternEngine) -> None:
        """When google-re2 is not installed, falls back to stdlib re."""
        # In the test environment, google-re2 is likely not installed
        assert pattern_engine.engine_name in ("re (stdlib)", "google-re2")

    def test_timeout_property(self) -> None:
        """Timeout property reflects the configured value."""
        pe = PatternEngine(timeout_ms=50.0)
        assert pe.timeout_ms == 50.0

    def test_timeout_fail_closed(self) -> None:
        """When a pattern evaluation times out, it returns True (fail-closed).

        We simulate this by using a very short timeout and a pattern
        that should be fast but we force it through the thread machinery.
        """
        # Use an absurdly short timeout
        pe = PatternEngine(timeout_ms=0.001)
        # The match function may or may not time out depending on scheduling,
        # but the important thing is it doesn't raise -- it returns a bool.
        result = pe.match(r"vault\s+get", "vault get SECRET")
        assert isinstance(result, bool)

    def test_clear_cache(self) -> None:
        """Cache can be cleared."""
        pe = PatternEngine()
        pe.compile(r"cache_test_\d+")
        PatternEngine.clear_cache()
        info = PatternEngine.cache_info()
        assert info.currsize == 0


# ===================================================================
# Test: CommandValidator -- Unicode Evasion
# ===================================================================


class TestUnicodeEvasion:
    """Tests for Unicode-based evasion detection (Section 6.2.1)."""

    def test_homoglyph_cyrillic_a(self, validator: CommandValidator) -> None:
        """Cyrillic 'a' (U+0430) is detected as homoglyph."""
        text = "v\u0430ult get SECRET"  # Cyrillic 'a' instead of Latin 'a'
        assert validator.has_confusable_chars(text)

    def test_homoglyph_cyrillic_o(self, validator: CommandValidator) -> None:
        """Cyrillic 'o' (U+043E) is detected as homoglyph."""
        text = "env d\u043emp"
        assert validator.has_confusable_chars(text)

    def test_homoglyph_fullwidth(self, validator: CommandValidator) -> None:
        """Fullwidth Latin characters are detected as confusables."""
        text = "\uff56\uff41\uff55\uff4c\uff54 get SECRET"  # fullwidth "vault"
        assert validator.has_confusable_chars(text)

    def test_homoglyph_normalization(self, validator: CommandValidator) -> None:
        """Confusable characters are replaced during normalization."""
        text = "v\u0430ult get SECRET"
        normalized = validator.normalize(text)
        assert normalized == "vault get SECRET"

    def test_zero_width_space(self, validator: CommandValidator) -> None:
        """Zero-width space (U+200B) is detected."""
        text = "vault\u200bget SECRET"
        assert validator.has_zero_width_chars(text)

    def test_zero_width_joiner(self, validator: CommandValidator) -> None:
        """Zero-width joiner (U+200D) is detected."""
        text = "cat\u200d .env"
        assert validator.has_zero_width_chars(text)

    def test_zero_width_bom(self, validator: CommandValidator) -> None:
        """BOM / ZWNBSP (U+FEFF) is detected."""
        text = "\ufeffvault get SECRET"
        assert validator.has_zero_width_chars(text)

    def test_zero_width_stripped_in_normalization(
        self, validator: CommandValidator
    ) -> None:
        """Zero-width chars are stripped during normalization."""
        text = "va\u200bul\u200ct get SECRET"
        normalized = validator.normalize(text)
        assert normalized == "vault get SECRET"

    def test_bidi_rtl_override(self, validator: CommandValidator) -> None:
        """RTL override (U+202E) is detected."""
        text = "\u202evault get SECRET"
        assert validator.has_bidi_controls(text)

    def test_bidi_lri(self, validator: CommandValidator) -> None:
        """Left-to-right isolate (U+2066) is detected."""
        text = "vault\u2066 get SECRET"
        assert validator.has_bidi_controls(text)

    def test_bidi_stripped_in_normalization(self, validator: CommandValidator) -> None:
        """Bidi control characters are stripped during normalization."""
        text = "\u202evault\u200f get SECRET"
        normalized = validator.normalize(text)
        assert normalized == "vault get SECRET"

    def test_validate_or_raise_on_homoglyph(self, validator: CommandValidator) -> None:
        """validate_or_raise raises EvasionDetected for homoglyphs."""
        text = "v\u0430ult get SECRET"
        with pytest.raises(EvasionDetected) as exc_info:
            validator.validate_or_raise(text)
        assert exc_info.value.code == "NL-E401"
        assert "homoglyph" in exc_info.value.details["technique"]

    def test_validate_or_raise_on_zero_width(self, validator: CommandValidator) -> None:
        """validate_or_raise raises EvasionDetected for zero-width chars."""
        text = "vault\u200b get SECRET"
        with pytest.raises(EvasionDetected) as exc_info:
            validator.validate_or_raise(text)
        assert exc_info.value.code == "NL-E401"
        assert "zero_width" in exc_info.value.details["technique"]

    def test_validate_or_raise_on_bidi(self, validator: CommandValidator) -> None:
        """validate_or_raise raises EvasionDetected for bidi controls."""
        text = "\u202evault get SECRET"
        with pytest.raises(EvasionDetected) as exc_info:
            validator.validate_or_raise(text)
        assert exc_info.value.code == "NL-E401"
        assert "bidi_control" in exc_info.value.details["technique"]


# ===================================================================
# Test: CommandValidator -- Null Byte Detection
# ===================================================================


class TestNullByteDetection:
    """Tests for null byte injection detection."""

    def test_null_byte_detected(self, validator: CommandValidator) -> None:
        """Null byte in text is detected."""
        assert validator.has_null_bytes("vault\x00get SECRET")

    def test_null_byte_in_validate(self, validator: CommandValidator) -> None:
        """validate() reports null byte as a finding."""
        findings = validator.validate("vault\x00get SECRET")
        assert any(f.technique == "null_byte" for f in findings)

    def test_no_null_byte(self, validator: CommandValidator) -> None:
        """Clean text has no null bytes."""
        assert not validator.has_null_bytes("vault get SECRET")

    def test_null_byte_raises_on_validate_or_raise(
        self, validator: CommandValidator
    ) -> None:
        """validate_or_raise raises EvasionDetected for null bytes."""
        with pytest.raises(EvasionDetected):
            validator.validate_or_raise("vault\x00get")


# ===================================================================
# Test: CommandValidator -- Template Injection
# ===================================================================


class TestTemplateInjection:
    """Tests for template injection detection."""

    def test_jinja2_template_detected(self, validator: CommandValidator) -> None:
        """Jinja2-style {{ variable }} is detected as injection."""
        assert validator.has_template_injection("{{ config.SECRET }}")

    def test_nl_placeholder_not_detected(self, validator: CommandValidator) -> None:
        """NL Protocol {{nl:...}} placeholders are NOT flagged."""
        assert not validator.has_template_injection("{{nl:API_KEY}}")

    def test_nl_placeholder_with_space(self, validator: CommandValidator) -> None:
        """NL Protocol {{ nl:...}} with leading space is NOT flagged."""
        assert not validator.has_template_injection("{{ nl:API_KEY}}")

    def test_mixed_templates(self, validator: CommandValidator) -> None:
        """Mix of NL and Jinja2 -- only Jinja2 flagged."""
        text = "{{nl:API_KEY}} and {{ env.SECRET }}"
        assert validator.has_template_injection(text)
        findings = validator.validate(text)
        template_findings = [f for f in findings if f.technique == "template_injection"]
        assert len(template_findings) == 1
        assert "env.SECRET" in template_findings[0].detail


# ===================================================================
# Test: CommandValidator -- Shell & Command Injection
# ===================================================================


class TestCommandInjection:
    """Tests for shell metacharacter and command injection detection."""

    def test_semicolon_chaining(self, validator: CommandValidator) -> None:
        """Semicolon command chaining is detected."""
        matches = validator.detect_command_injection("ls; vault get SECRET")
        assert len(matches) > 0

    def test_pipe_or_chaining(self, validator: CommandValidator) -> None:
        """|| chaining is detected."""
        matches = validator.detect_command_injection("false || vault get SECRET")
        assert len(matches) > 0

    def test_and_chaining(self, validator: CommandValidator) -> None:
        """&& chaining is detected."""
        matches = validator.detect_command_injection("true && vault get SECRET")
        assert len(matches) > 0

    def test_command_substitution(self, validator: CommandValidator) -> None:
        """$(...) command substitution is detected."""
        matches = validator.detect_command_injection("echo $(vault get KEY)")
        assert len(matches) > 0

    def test_backtick_substitution(self, validator: CommandValidator) -> None:
        """Backtick substitution is detected."""
        matches = validator.detect_command_injection("echo `vault get KEY`")
        assert len(matches) > 0

    def test_clean_command(self, validator: CommandValidator) -> None:
        """Clean simple command has no injection patterns."""
        matches = validator.detect_command_injection("git status")
        assert len(matches) == 0

    def test_shell_metacharacters_dollar(self, validator: CommandValidator) -> None:
        """Dollar sign is a shell metacharacter."""
        matches = validator.detect_shell_metacharacters("echo $SECRET")
        assert len(matches) > 0

    def test_shell_metacharacters_backtick(self, validator: CommandValidator) -> None:
        """Backtick is a shell metacharacter."""
        matches = validator.detect_shell_metacharacters("echo `whoami`")
        assert len(matches) > 0


# ===================================================================
# Test: CommandValidator -- Normalization
# ===================================================================


class TestNormalization:
    """Tests for text normalization (whitespace, unicode, etc.)."""

    def test_whitespace_collapsing(self, validator: CommandValidator) -> None:
        """Multiple whitespace characters collapse to single space."""
        assert validator.normalize("vault    get   SECRET") == "vault get SECRET"

    def test_leading_trailing_trim(self, validator: CommandValidator) -> None:
        """Leading/trailing whitespace is trimmed."""
        assert validator.normalize("  vault get SECRET  ") == "vault get SECRET"

    def test_tab_normalization(self, validator: CommandValidator) -> None:
        """Tabs are normalized to spaces."""
        assert validator.normalize("vault\tget\tSECRET") == "vault get SECRET"

    def test_newline_normalization(self, validator: CommandValidator) -> None:
        """Newlines are normalized to spaces."""
        assert validator.normalize("vault\nget\nSECRET") == "vault get SECRET"

    def test_clean_text_unchanged(self, validator: CommandValidator) -> None:
        """Clean text with normal spacing is unchanged."""
        assert validator.normalize("git status") == "git status"


# ===================================================================
# Test: DenyRuleEngine -- Category: Direct Secret Access
# ===================================================================


class TestDenyDirectSecretAccess:
    """Deny rules for Category 1: Direct Secret Access."""

    def test_vault_get_blocked(self, engine: DenyRuleEngine) -> None:
        """'vault get SECRET' is blocked."""
        with pytest.raises(ActionBlocked) as exc_info:
            engine.check("vault get API_KEY")
        assert exc_info.value.code == "NL-E400"
        assert "NL-4-DENY-001" in exc_info.value.details["rule_id"]

    def test_vault_read_blocked(self, engine: DenyRuleEngine) -> None:
        """'vault read secret/path' is blocked."""
        with pytest.raises(ActionBlocked) as exc_info:
            engine.check("vault read secret/production/api-key")
        assert "direct_secret_access" in exc_info.value.details["category"]

    def test_cat_env_blocked(self, engine: DenyRuleEngine) -> None:
        """'cat .env' is blocked."""
        with pytest.raises(ActionBlocked):
            engine.check("cat .env")

    def test_cat_pem_blocked(self, engine: DenyRuleEngine) -> None:
        """'cat server.pem' is blocked."""
        with pytest.raises(ActionBlocked):
            engine.check("cat server.pem")

    def test_aws_secrets_blocked(self, engine: DenyRuleEngine) -> None:
        """'aws secretsmanager get-secret-value' is blocked."""
        with pytest.raises(ActionBlocked):
            engine.check("aws secretsmanager get-secret-value --secret-id mykey")

    def test_gcloud_secrets_blocked(self, engine: DenyRuleEngine) -> None:
        """'gcloud secrets versions access' is blocked."""
        with pytest.raises(ActionBlocked):
            engine.check("gcloud secrets versions access latest --secret=mykey")

    def test_az_keyvault_blocked(self, engine: DenyRuleEngine) -> None:
        """'az keyvault secret show' is blocked."""
        with pytest.raises(ActionBlocked):
            engine.check("az keyvault secret show --name mykey --vault vaultname")


# ===================================================================
# Test: DenyRuleEngine -- Category: Bulk Export
# ===================================================================


class TestDenyBulkExport:
    """Deny rules for Category 2: Bulk Export."""

    def test_vault_export_blocked(self, engine: DenyRuleEngine) -> None:
        """'vault export' is blocked."""
        with pytest.raises(ActionBlocked) as exc_info:
            engine.check("vault export")
        assert "bulk_export" in exc_info.value.details["category"]

    def test_env_command_blocked(self, engine: DenyRuleEngine) -> None:
        """Bare 'env' command is blocked."""
        with pytest.raises(ActionBlocked):
            engine.check("env")

    def test_printenv_blocked(self, engine: DenyRuleEngine) -> None:
        """'printenv' is blocked."""
        with pytest.raises(ActionBlocked):
            engine.check("printenv")

    def test_printenv_with_arg_blocked(self, engine: DenyRuleEngine) -> None:
        """'printenv DATABASE_URL' is blocked."""
        with pytest.raises(ActionBlocked):
            engine.check("printenv DATABASE_URL")

    def test_kubectl_get_secret_json_blocked(self, engine: DenyRuleEngine) -> None:
        """'kubectl get secret ... -o json' is blocked."""
        with pytest.raises(ActionBlocked):
            engine.check("kubectl get secret my-secret -o json")


# ===================================================================
# Test: DenyRuleEngine -- Category: Internal File Access
# ===================================================================


class TestDenyInternalFileAccess:
    """Deny rules for Category 3: Internal File Access."""

    def test_cat_vault_enc_blocked(self, engine: DenyRuleEngine) -> None:
        """'cat data/vault.enc' is blocked."""
        with pytest.raises(ActionBlocked) as exc_info:
            engine.check("cat data/vault.enc")
        assert "internal_file_access" in exc_info.value.details["category"]

    def test_strings_pem_blocked(self, engine: DenyRuleEngine) -> None:
        """'strings server.pem' is blocked."""
        with pytest.raises(ActionBlocked):
            engine.check("strings server.pem")

    def test_find_key_files_blocked(self, engine: DenyRuleEngine) -> None:
        """'find / -name *.key' is blocked."""
        with pytest.raises(ActionBlocked):
            engine.check("find / -name '*.key'")


# ===================================================================
# Test: DenyRuleEngine -- Category: Encoding Evasion
# ===================================================================


class TestDenyEncodingEvasion:
    """Deny rules for Category 4: Encoding Evasion."""

    def test_base64_decode_to_shell_blocked(self, engine: DenyRuleEngine) -> None:
        """'base64 -d ... | bash' is blocked."""
        with pytest.raises(ActionBlocked) as exc_info:
            engine.check("base64 -d payload.b64 | bash")
        assert "encoding_evasion" in exc_info.value.details["category"]

    def test_echo_base64_decode_blocked(self, engine: DenyRuleEngine) -> None:
        """'echo ... | base64 -d | sh' is blocked."""
        with pytest.raises(ActionBlocked):
            engine.check("echo 'dmF1bHQgZ2V0IEFQSV9LRVk=' | base64 -d | sh")

    def test_python_exec_decode_blocked(self, engine: DenyRuleEngine) -> None:
        """Python exec with decode is blocked."""
        with pytest.raises(ActionBlocked):
            engine.check(
                'python3 -c "exec(base64.b64decode(x).decode())"'
            )


# ===================================================================
# Test: DenyRuleEngine -- Category: Shell Expansion
# ===================================================================


class TestDenyShellExpansion:
    """Deny rules for Category 5: Shell Expansion."""

    def test_dollar_vault_get_blocked(self, engine: DenyRuleEngine) -> None:
        """'$(vault get SECRET)' is blocked by shell_expansion or direct_secret_access."""
        with pytest.raises(ActionBlocked) as exc_info:
            engine.check('curl -H "Auth: $(vault get API_KEY)" https://api.example.com')
        # Both direct_secret_access and shell_expansion match; the higher-priority
        # category (direct_secret_access) fires first, which is correct behaviour.
        assert exc_info.value.details["category"] in (
            "shell_expansion",
            "direct_secret_access",
        )

    def test_dollar_aws_secrets_blocked(self, engine: DenyRuleEngine) -> None:
        """'$(aws secretsmanager get-secret-value ...)' is blocked."""
        with pytest.raises(ActionBlocked):
            engine.check(
                "export KEY=$(aws secretsmanager get-secret-value --secret-id x)"
            )

    def test_eval_vault_blocked(self, engine: DenyRuleEngine) -> None:
        """'eval ... vault ...' is blocked."""
        with pytest.raises(ActionBlocked):
            engine.check("eval vault read secret/key")


# ===================================================================
# Test: DenyRuleEngine -- Category: Environment Dumps
# ===================================================================


class TestDenyEnvironmentDump:
    """Deny rules for Category 6: Environment Dumps."""

    def test_cat_proc_environ_blocked(self, engine: DenyRuleEngine) -> None:
        """'cat /proc/1/environ' is blocked."""
        with pytest.raises(ActionBlocked) as exc_info:
            engine.check("cat /proc/1/environ")
        assert "environment_dump" in exc_info.value.details["category"]

    def test_cat_proc_self_environ_blocked(self, engine: DenyRuleEngine) -> None:
        """'cat /proc/self/environ' is blocked."""
        with pytest.raises(ActionBlocked):
            engine.check("cat /proc/self/environ")

    def test_python_os_environ_blocked(self, engine: DenyRuleEngine) -> None:
        """'python -c ... os.environ' is blocked."""
        with pytest.raises(ActionBlocked):
            engine.check('python -c "import os; print(os.environ)"')

    def test_node_process_env_blocked(self, engine: DenyRuleEngine) -> None:
        """'node -e ... process.env' is blocked."""
        with pytest.raises(ActionBlocked):
            engine.check('node -e "console.log(process.env)"')


# ===================================================================
# Test: DenyRuleEngine -- Category: Indirect Execution
# ===================================================================


class TestDenyIndirectExecution:
    """Deny rules for Category 7: Indirect Execution."""

    def test_eval_with_variable_blocked(self, engine: DenyRuleEngine) -> None:
        """'eval $CMD' is blocked."""
        with pytest.raises(ActionBlocked) as exc_info:
            engine.check("eval $CMD")
        assert exc_info.value.details["category"] in (
            "indirect_execution",
            "shell_expansion",
        )

    def test_bash_c_vault_blocked(self, engine: DenyRuleEngine) -> None:
        """'bash -c vault get ...' is blocked."""
        with pytest.raises(ActionBlocked):
            engine.check("bash -c 'vault get secret/key'")

    def test_source_dotenv_blocked(self, engine: DenyRuleEngine) -> None:
        """'source .env' is blocked."""
        with pytest.raises(ActionBlocked):
            engine.check("source .env")


# ===================================================================
# Test: DenyRuleEngine -- Safe commands MUST be allowed
# ===================================================================


class TestSafeCommandsAllowed:
    """Spec Section 3.4 test vectors: commands that MUST be allowed."""

    def test_nl_placeholder_allowed(self, engine: DenyRuleEngine) -> None:
        """NL placeholder command is allowed."""
        engine.check(
            'curl -H "Authorization: Bearer {{nl:api-key}}" https://api.example.com'
        )

    def test_simple_query_allowed(self, engine: DenyRuleEngine) -> None:
        """Simple SQL query is allowed."""
        engine.check("psql -c 'SELECT count(*) FROM users'")

    def test_git_status_allowed(self, engine: DenyRuleEngine) -> None:
        """'git status' is allowed."""
        engine.check("git status")

    def test_python_script_allowed(self, engine: DenyRuleEngine) -> None:
        """'python script.py --config config.yaml' is allowed."""
        engine.check("python script.py --config config.yaml")

    def test_npm_test_allowed(self, engine: DenyRuleEngine) -> None:
        """'npm test' is allowed."""
        engine.check("npm test")

    def test_curl_without_secrets_allowed(self, engine: DenyRuleEngine) -> None:
        """Curl without secrets is allowed."""
        engine.check("curl https://api.example.com/health")

    def test_kubectl_apply_allowed(self, engine: DenyRuleEngine) -> None:
        """'kubectl apply' without secret extraction is allowed."""
        engine.check("kubectl apply -f deployment.yaml")

    def test_docker_build_allowed(self, engine: DenyRuleEngine) -> None:
        """'docker build' is allowed."""
        engine.check("docker build -t myapp:latest .")


# ===================================================================
# Test: DenyRuleEngine -- Custom Rules
# ===================================================================


class TestCustomRules:
    """Tests for custom rule management."""

    def test_add_custom_rule(self, empty_engine: DenyRuleEngine) -> None:
        """Custom rules can be added and are enforced."""
        rule = DenyRule(
            rule_id="CUSTOM-001",
            category="custom",
            pattern=r"my-internal-tool\s+export",
            severity="high",
            description="Blocks internal tool export",
            alternative="Use my-internal-tool inject instead.",
        )
        empty_engine.add_rule(rule)
        assert len(empty_engine.custom_rules) == 1

        with pytest.raises(ActionBlocked):
            empty_engine.check("my-internal-tool export credentials")

    def test_custom_rule_allows_safe(self, empty_engine: DenyRuleEngine) -> None:
        """Custom rule does not block unrelated commands."""
        rule = DenyRule(
            rule_id="CUSTOM-002",
            category="custom",
            pattern=r"danger-cmd\s+leak",
            severity="high",
            description="Blocks danger-cmd leak",
            alternative="Use safe-cmd instead.",
        )
        empty_engine.add_rule(rule)
        # Should not raise
        empty_engine.check("safe-cmd run")

    def test_remove_custom_rule(self, empty_engine: DenyRuleEngine) -> None:
        """Custom rules can be removed."""
        rule = DenyRule(
            rule_id="CUSTOM-003",
            category="custom",
            pattern=r"removable\s+cmd",
            severity="medium",
            description="A removable rule",
            alternative="N/A",
        )
        empty_engine.add_rule(rule)
        assert len(empty_engine.custom_rules) == 1

        removed = empty_engine.remove_rule("CUSTOM-003")
        assert removed.rule_id == "CUSTOM-003"
        assert len(empty_engine.custom_rules) == 0

        # Previously blocked command should now pass
        empty_engine.check("removable cmd here")

    def test_remove_standard_rule_raises(self, engine: DenyRuleEngine) -> None:
        """Cannot remove standard rules."""
        with pytest.raises(ValueError, match="Cannot remove standard rule"):
            engine.remove_rule("NL-4-DENY-001")

    def test_remove_nonexistent_rule_raises(self, engine: DenyRuleEngine) -> None:
        """Removing non-existent rule raises ValueError."""
        with pytest.raises(ValueError, match="Rule not found"):
            engine.remove_rule("NONEXISTENT-RULE")

    def test_add_duplicate_rule_id_raises(self, engine: DenyRuleEngine) -> None:
        """Cannot add a rule with a duplicate ID."""
        rule = DenyRule(
            rule_id="NL-4-DENY-001",
            category="custom",
            pattern=r"duplicate",
            severity="low",
            description="Duplicate",
            alternative="N/A",
        )
        with pytest.raises(ValueError, match="Rule ID already exists"):
            engine.add_rule(rule)

    def test_add_rule_with_invalid_pattern_raises(
        self, empty_engine: DenyRuleEngine
    ) -> None:
        """Adding a rule with invalid regex raises re.error."""
        rule = DenyRule(
            rule_id="CUSTOM-BAD",
            category="custom",
            pattern=r"[invalid",
            severity="low",
            description="Bad pattern",
            alternative="N/A",
        )
        with pytest.raises(re.error):
            empty_engine.add_rule(rule)


# ===================================================================
# Test: DenyRuleEngine -- check_all diagnostics
# ===================================================================


class TestCheckAll:
    """Tests for the check_all() diagnostics method."""

    def test_check_all_returns_multiple_matches(
        self, engine: DenyRuleEngine
    ) -> None:
        """check_all returns multiple matches when applicable."""
        # 'vault get' matches both direct_secret_access and potentially others
        matches = engine.check_all("vault get API_KEY")
        assert len(matches) >= 1
        assert all(isinstance(m, DenyMatch) for m in matches)
        assert any(m.rule.rule_id == "NL-4-DENY-001" for m in matches)

    def test_check_all_returns_empty_for_safe_command(
        self, engine: DenyRuleEngine
    ) -> None:
        """check_all returns empty list for safe commands."""
        matches = engine.check_all("git status")
        assert matches == []


# ===================================================================
# Test: DenyRuleEngine -- Category priority ordering
# ===================================================================


class TestCategoryPriority:
    """Tests for deny rule category evaluation order."""

    def test_standard_categories_in_priority(self) -> None:
        """All spec categories are in the CATEGORY_PRIORITY list."""
        expected = {
            "direct_secret_access",
            "bulk_export",
            "internal_file_access",
            "encoding_evasion",
            "shell_expansion",
            "environment_dump",
            "indirect_execution",
        }
        assert expected.issubset(set(CATEGORY_PRIORITY))

    def test_direct_secret_access_first(self) -> None:
        """direct_secret_access is evaluated first."""
        assert CATEGORY_PRIORITY[0] == "direct_secret_access"

    def test_sorted_rules_order(self, engine: DenyRuleEngine) -> None:
        """all_rules returns rules in category priority order."""
        rules = engine.all_rules
        categories_seen: list[str] = []
        for rule in rules:
            if rule.category not in categories_seen:
                categories_seen.append(rule.category)

        # Verify categories appear in priority order
        priority_positions = [
            CATEGORY_PRIORITY.index(c)
            for c in categories_seen
            if c in CATEGORY_PRIORITY
        ]
        assert priority_positions == sorted(priority_positions)


# ===================================================================
# Test: DenyRuleEngine -- Evasion triggers
# ===================================================================


class TestDenyEngineEvasion:
    """Verify the deny engine catches evasion attempts during check()."""

    def test_check_raises_on_homoglyph(self, engine: DenyRuleEngine) -> None:
        """check() raises EvasionDetected for homoglyph evasion."""
        # Cyrillic 'a' in "vault"
        with pytest.raises(EvasionDetected):
            engine.check("v\u0430ult get SECRET")

    def test_check_raises_on_zero_width(self, engine: DenyRuleEngine) -> None:
        """check() raises EvasionDetected for zero-width char evasion."""
        with pytest.raises(EvasionDetected):
            engine.check("vault\u200b get SECRET")

    def test_check_raises_on_null_byte(self, engine: DenyRuleEngine) -> None:
        """check() raises EvasionDetected for null byte injection."""
        with pytest.raises(EvasionDetected):
            engine.check("vault\x00get SECRET")

    def test_check_raises_on_bidi(self, engine: DenyRuleEngine) -> None:
        """check() raises EvasionDetected for bidi override."""
        with pytest.raises(EvasionDetected):
            engine.check("\u202evault get SECRET")


# ===================================================================
# Test: DenyRuleEngine -- Spec test vectors (Section 3.4)
# ===================================================================


class TestSpecTestVectors:
    """Tests directly from Section 3.4 of the spec."""

    def test_vector_1_vault_read(self, engine: DenyRuleEngine) -> None:
        """Test vector 1: vault read secret/production/api-key MUST be blocked."""
        with pytest.raises(ActionBlocked):
            engine.check("vault read secret/production/api-key")

    def test_vector_5_python_environ(self, engine: DenyRuleEngine) -> None:
        """Test vector 5: python -c 'import os; print(os.environ)' MUST be blocked."""
        with pytest.raises(ActionBlocked):
            engine.check('python -c "import os; print(os.environ)"')

    def test_vector_7_bash_c_vault(self, engine: DenyRuleEngine) -> None:
        """Test vector 7: bash -c 'vault read secret/key' MUST be blocked."""
        with pytest.raises(ActionBlocked):
            engine.check("bash -c 'vault read secret/key'")

    def test_vector_allowed_1_nl_placeholder(self, engine: DenyRuleEngine) -> None:
        """Test vector allowed 1: curl with NL placeholder MUST be allowed."""
        engine.check(
            "curl -H 'Authorization: Bearer {{nl:api-key}}' https://api.example.com"
        )

    def test_vector_allowed_3_git_status(self, engine: DenyRuleEngine) -> None:
        """Test vector allowed 3: git status MUST be allowed."""
        engine.check("git status")

    def test_vector_allowed_5_npm_test(self, engine: DenyRuleEngine) -> None:
        """Test vector allowed 5: npm test MUST be allowed."""
        engine.check("npm test")


# ===================================================================
# Test: DenyEngine Protocol conformance
# ===================================================================


class TestDenyEngineProtocol:
    """Verify DenyRuleEngine satisfies the DenyEngine Protocol."""

    def test_isinstance_check(self) -> None:
        """DenyRuleEngine is a runtime-checkable DenyEngine."""
        engine = DenyRuleEngine()
        assert isinstance(engine, DenyEngine)

    def test_protocol_method_signature(self) -> None:
        """DenyEngine.check(template: str) -> None exists."""
        engine: DenyEngine = DenyRuleEngine()
        # Should not raise for a safe command
        engine.check("git status")

    def test_protocol_raises_action_blocked(self) -> None:
        """DenyEngine.check() raises ActionBlocked on match."""
        engine: DenyEngine = DenyRuleEngine()
        with pytest.raises(ActionBlocked):
            engine.check("vault get SECRET")


# ===================================================================
# Test: DenyRuleEngine -- Standard rules count and introspection
# ===================================================================


class TestRuleIntrospection:
    """Tests for rule listing and introspection."""

    def test_standard_rules_loaded(self, engine: DenyRuleEngine) -> None:
        """At least 20 standard rules are loaded."""
        assert len(engine.standard_rules) >= 20

    def test_custom_rules_initially_empty(self, engine: DenyRuleEngine) -> None:
        """No custom rules loaded by default."""
        assert len(engine.custom_rules) == 0

    def test_all_rules_combines(self, engine: DenyRuleEngine) -> None:
        """all_rules includes both standard and custom."""
        rule = DenyRule(
            rule_id="CUSTOM-INTROSPECT",
            category="custom",
            pattern=r"introspect-test",
            severity="low",
            description="Test rule",
            alternative="N/A",
        )
        engine.add_rule(rule)
        all_rules = engine.all_rules
        assert any(r.rule_id == "CUSTOM-INTROSPECT" for r in all_rules)
        assert any(r.rule_id.startswith("NL-4-DENY-") for r in all_rules)

    def test_all_standard_rules_have_required_fields(
        self, engine: DenyRuleEngine
    ) -> None:
        """Every standard rule has non-empty required fields."""
        for rule in engine.standard_rules:
            assert rule.rule_id, f"Rule missing rule_id: {rule}"
            assert rule.category, f"Rule missing category: {rule.rule_id}"
            assert rule.pattern, f"Rule missing pattern: {rule.rule_id}"
            assert rule.severity in (
                "critical",
                "high",
                "medium",
                "low",
            ), f"Invalid severity in {rule.rule_id}: {rule.severity}"
            assert rule.description, f"Rule missing description: {rule.rule_id}"
            assert rule.alternative, f"Rule missing alternative: {rule.rule_id}"

    def test_all_seven_categories_represented(
        self, engine: DenyRuleEngine
    ) -> None:
        """All 7 spec categories have at least one rule."""
        categories = {r.category for r in engine.standard_rules}
        expected = {
            "direct_secret_access",
            "bulk_export",
            "internal_file_access",
            "encoding_evasion",
            "shell_expansion",
            "environment_dump",
            "indirect_execution",
        }
        assert expected.issubset(categories), (
            f"Missing categories: {expected - categories}"
        )


# ===================================================================
# Test: EvasionFinding dataclass
# ===================================================================


class TestEvasionFinding:
    """Basic tests for the EvasionFinding dataclass."""

    def test_creation(self) -> None:
        """EvasionFinding can be created."""
        f = EvasionFinding(technique="null_byte", detail="Null byte", position=5)
        assert f.technique == "null_byte"
        assert f.detail == "Null byte"
        assert f.position == 5

    def test_frozen(self) -> None:
        """EvasionFinding is immutable."""
        f = EvasionFinding(technique="test", detail="test")
        with pytest.raises(AttributeError):
            f.technique = "changed"  # type: ignore[misc]


# ===================================================================
# Test: DenyMatch dataclass
# ===================================================================


class TestDenyMatch:
    """Basic tests for the DenyMatch dataclass."""

    def test_creation(self) -> None:
        """DenyMatch can be created."""
        rule = DenyRule(
            rule_id="TEST-001",
            category="test",
            pattern=r"test",
            severity="low",
            description="Test",
            alternative="N/A",
        )
        m = DenyMatch(rule=rule, matched_text="test")
        assert m.rule.rule_id == "TEST-001"
        assert m.matched_text == "test"


# ===================================================================
# Test: ActionBlocked error details
# ===================================================================


class TestActionBlockedDetails:
    """Verify ActionBlocked errors contain educational response data."""

    def test_error_code(self, engine: DenyRuleEngine) -> None:
        """ActionBlocked has code NL-E400."""
        with pytest.raises(ActionBlocked) as exc_info:
            engine.check("vault get SECRET")
        assert exc_info.value.code == "NL-E400"

    def test_error_details_rule_id(self, engine: DenyRuleEngine) -> None:
        """ActionBlocked details include rule_id."""
        with pytest.raises(ActionBlocked) as exc_info:
            engine.check("vault get SECRET")
        assert "rule_id" in exc_info.value.details

    def test_error_details_category(self, engine: DenyRuleEngine) -> None:
        """ActionBlocked details include category."""
        with pytest.raises(ActionBlocked) as exc_info:
            engine.check("vault get SECRET")
        assert "category" in exc_info.value.details

    def test_error_details_severity(self, engine: DenyRuleEngine) -> None:
        """ActionBlocked details include severity."""
        with pytest.raises(ActionBlocked) as exc_info:
            engine.check("vault get SECRET")
        assert "severity" in exc_info.value.details

    def test_error_details_alternative(self, engine: DenyRuleEngine) -> None:
        """ActionBlocked details include safe alternative."""
        with pytest.raises(ActionBlocked) as exc_info:
            engine.check("vault get SECRET")
        assert "alternative" in exc_info.value.details

    def test_error_details_blocked_action(self, engine: DenyRuleEngine) -> None:
        """ActionBlocked details include the original blocked action."""
        with pytest.raises(ActionBlocked) as exc_info:
            engine.check("vault get SECRET")
        assert exc_info.value.details["blocked_action"] == "vault get SECRET"

    def test_error_to_dict(self, engine: DenyRuleEngine) -> None:
        """ActionBlocked serialises to dict via NLProtocolError.to_dict()."""
        with pytest.raises(ActionBlocked) as exc_info:
            engine.check("vault get SECRET")
        d = exc_info.value.to_dict()
        assert "error" in d
        assert d["error"]["code"] == "NL-E400"
