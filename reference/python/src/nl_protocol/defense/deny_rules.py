"""NL Protocol Level 4 -- Deny rule engine.

Implements the deny rule matching engine defined in Section 3 of Chapter 04.
Loads standard deny rules from the 69 patterns defined in the spec and
supports custom rule addition/removal.

The engine implements the :class:`~nl_protocol.access.policy.DenyEngine`
protocol so that it can be plugged into the :class:`PolicyEvaluator`
five-step evaluation pipeline.
"""
from __future__ import annotations

from dataclasses import dataclass

from nl_protocol.core.errors import ActionBlocked
from nl_protocol.defense.pattern_engine import PatternEngine
from nl_protocol.defense.validation import CommandValidator

# ---------------------------------------------------------------------------
# Deny rule data structure
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DenyRule:
    """A single deny rule as defined in Section 3.1.

    Attributes
    ----------
    rule_id:
        Unique identifier (``NL-4-DENY-XXX`` for standard rules).
    category:
        One of the categories defined in Section 3.3.
    pattern:
        RE2-compatible regex pattern to match against actions.
    severity:
        ``"critical"``, ``"high"``, ``"medium"``, or ``"low"``.
    description:
        Human-readable description of what the rule blocks.
    alternative:
        The safe, NL Protocol-compliant alternative.
    """

    rule_id: str
    category: str
    pattern: str
    severity: str
    description: str
    alternative: str


@dataclass(frozen=True, slots=True)
class DenyMatch:
    """Result of a deny rule match (used by :meth:`DenyRuleEngine.check_all`)."""

    rule: DenyRule
    matched_text: str


# ---------------------------------------------------------------------------
# Category priority order (Section 2.3 -- standard rules first, in order)
# ---------------------------------------------------------------------------

CATEGORY_PRIORITY: list[str] = [
    "direct_secret_access",
    "bulk_export",
    "internal_file_access",
    "encoding_evasion",
    "shell_expansion",
    "environment_dump",
    "indirect_execution",
    "custom",
]

# ---------------------------------------------------------------------------
# Standard deny rules (representative subset from each category)
# ---------------------------------------------------------------------------


def _build_standard_rules() -> list[DenyRule]:
    """Build the standard deny rules from the spec (Section 3.3).

    Includes the most critical rules from each of the 7 categories.
    """
    rules: list[DenyRule] = []

    # -- Category 1: Direct Secret Access -----------------------------------
    rules.extend([
        DenyRule(
            rule_id="NL-4-DENY-001",
            category="direct_secret_access",
            pattern=r"vault\s+(get|read|show|reveal|decrypt|fetch)\s+",
            severity="critical",
            description="Direct retrieval of secret values via vault CLI",
            alternative=(
                "Use action-based access with {{nl:<reference>}} placeholder "
                "syntax (NL Protocol Level 2)."
            ),
        ),
        DenyRule(
            rule_id="NL-4-DENY-002",
            category="direct_secret_access",
            pattern=r"cat\s+\.env",
            severity="critical",
            description="Reading .env files containing secrets",
            alternative="Reference secrets via {{nl:<reference>}} placeholders.",
        ),
        DenyRule(
            rule_id="NL-4-DENY-003",
            category="direct_secret_access",
            pattern=r"cat\s+.*\.(key|pem|p12|pfx|jks|keystore|crt)",
            severity="critical",
            description="Reading key and certificate files directly",
            alternative="Reference keys via {{nl:<reference>}} placeholders.",
        ),
        DenyRule(
            rule_id="NL-4-DENY-005",
            category="direct_secret_access",
            pattern=r"aws\s+secretsmanager\s+get-secret-value",
            severity="critical",
            description="AWS Secrets Manager retrieval",
            alternative="Use {{nl:aws/secret-name}} placeholder syntax.",
        ),
        DenyRule(
            rule_id="NL-4-DENY-006",
            category="direct_secret_access",
            pattern=r"gcloud\s+secrets\s+versions\s+access",
            severity="critical",
            description="GCP Secret Manager retrieval",
            alternative="Use {{nl:gcp/secret-name}} placeholder syntax.",
        ),
        DenyRule(
            rule_id="NL-4-DENY-007",
            category="direct_secret_access",
            pattern=r"az\s+keyvault\s+secret\s+show",
            severity="critical",
            description="Azure Key Vault retrieval",
            alternative="Use {{nl:azure/secret-name}} placeholder syntax.",
        ),
    ])

    # -- Category 2: Bulk Export --------------------------------------------
    rules.extend([
        DenyRule(
            rule_id="NL-4-DENY-010",
            category="bulk_export",
            pattern=r"vault\s+export",
            severity="critical",
            description="Vault bulk export",
            alternative="List secret names without values, then reference individually.",
        ),
        DenyRule(
            rule_id="NL-4-DENY-011",
            category="bulk_export",
            pattern=r"^env$|^env\s",
            severity="critical",
            description="Shell environment variable dump",
            alternative="Use the implementation's secret listing to enumerate names only.",
        ),
        DenyRule(
            rule_id="NL-4-DENY-012",
            category="bulk_export",
            pattern=r"^printenv$|^printenv\s",
            severity="critical",
            description="Print all environment variables",
            alternative="Use the implementation's secret listing to enumerate names only.",
        ),
        DenyRule(
            rule_id="NL-4-DENY-017",
            category="bulk_export",
            pattern=r"kubectl\s+get\s+secret.*-o\s+(json|yaml|jsonpath)",
            severity="critical",
            description="Kubernetes secret value extraction",
            alternative="Use {{nl:k8s/SECRET_NAME}} in your manifests.",
        ),
    ])

    # -- Category 3: Internal File Access -----------------------------------
    rules.extend([
        DenyRule(
            rule_id="NL-4-DENY-020",
            category="internal_file_access",
            pattern=r"cat\s+.*vault\.(age|enc|gpg|sealed|db)",
            severity="high",
            description="Reading encrypted vault files",
            alternative="Interact with the vault exclusively through its CLI or API.",
        ),
        DenyRule(
            rule_id="NL-4-DENY-021",
            category="internal_file_access",
            pattern=r"strings\s+.*\.(key|age|enc|pem|db)",
            severity="high",
            description="Extracting strings from encrypted files",
            alternative="Use the vault API for authorized access.",
        ),
        DenyRule(
            rule_id="NL-4-DENY-025",
            category="internal_file_access",
            pattern=r"find\s+.*-name\s+[\"']?\*?\.(key|pem|p12|age)",
            severity="medium",
            description="Searching for key files on disk",
            alternative="Use the vault API to discover available secrets.",
        ),
    ])

    # -- Category 4: Encoding Evasion ---------------------------------------
    rules.extend([
        DenyRule(
            rule_id="NL-4-DENY-030",
            category="encoding_evasion",
            pattern=r"base64\s+(-d|--decode).*\|\s*(sh|bash|zsh|dash)",
            severity="critical",
            description="Base64 decode piped to shell",
            alternative="Submit all commands in plaintext.",
        ),
        DenyRule(
            rule_id="NL-4-DENY-031",
            category="encoding_evasion",
            pattern=r"echo\s+.*\|\s*base64\s+(-d|--decode)\s*\|\s*(sh|bash)",
            severity="critical",
            description="Echo encoded payload to decode to shell",
            alternative="Submit all commands in plaintext.",
        ),
        DenyRule(
            rule_id="NL-4-DENY-032",
            category="encoding_evasion",
            pattern=r"python[23]?\s+-c\s+.*exec\(.*decode",
            severity="critical",
            description="Python exec with base64/hex decode",
            alternative="Submit all commands in plaintext.",
        ),
    ])

    # -- Category 5: Shell Expansion ----------------------------------------
    rules.extend([
        DenyRule(
            rule_id="NL-4-DENY-040",
            category="shell_expansion",
            pattern=r"\$\(\s*vault\s+(get|read|show|reveal)\s+",
            severity="critical",
            description="Command substitution with vault get",
            alternative="Use {{nl:<reference>}} placeholder syntax.",
        ),
        DenyRule(
            rule_id="NL-4-DENY-043",
            category="shell_expansion",
            pattern=r"\$\(\s*aws\s+secretsmanager\s+get-secret-value",
            severity="critical",
            description="Command substitution with AWS Secrets Manager",
            alternative="Use {{nl:aws/secret-name}} placeholder syntax.",
        ),
        DenyRule(
            rule_id="NL-4-DENY-045",
            category="shell_expansion",
            pattern=r"eval\s+.*vault",
            severity="critical",
            description="Eval wrapping vault commands",
            alternative="Submit commands directly without eval wrapping.",
        ),
    ])

    # -- Category 6: Environment Dumps --------------------------------------
    rules.extend([
        DenyRule(
            rule_id="NL-4-DENY-050",
            category="environment_dump",
            pattern=r"cat\s+/proc/.*/environ",
            severity="critical",
            description="Linux process environment file",
            alternative="Secrets are available only within the isolated execution environment.",
        ),
        DenyRule(
            rule_id="NL-4-DENY-053",
            category="environment_dump",
            pattern=r"cat\s+/proc/self/environ",
            severity="critical",
            description="Self process environment",
            alternative="Secrets are available only within the isolated execution environment.",
        ),
        DenyRule(
            rule_id="NL-4-DENY-056",
            category="environment_dump",
            pattern=r"python[23]?\s+-c\s+.*os\.environ",
            severity="critical",
            description="Python os.environ access",
            alternative="Use {{nl:<reference>}} placeholder syntax.",
        ),
        DenyRule(
            rule_id="NL-4-DENY-057",
            category="environment_dump",
            pattern=r"node\s+-e\s+.*process\.env",
            severity="high",
            description="Node.js process.env access",
            alternative="Use {{nl:<reference>}} placeholder syntax.",
        ),
    ])

    # -- Category 7: Indirect Execution -------------------------------------
    rules.extend([
        DenyRule(
            rule_id="NL-4-DENY-060",
            category="indirect_execution",
            pattern=r"eval\s+.*\$",
            severity="high",
            description="Eval with variable expansion",
            alternative="Submit all commands directly without eval wrapping.",
        ),
        DenyRule(
            rule_id="NL-4-DENY-061",
            category="indirect_execution",
            pattern=r"bash\s+-c\s+.*vault\s+(get|read|export)",
            severity="critical",
            description="Subshell wrapping vault retrieval",
            alternative="Submit vault commands directly; use {{nl:}} placeholders.",
        ),
        DenyRule(
            rule_id="NL-4-DENY-063",
            category="indirect_execution",
            pattern=r"source\s+.*\.env",
            severity="high",
            description="Sourcing .env files into shell context",
            alternative="Use {{nl:<reference>}} placeholder syntax.",
        ),
    ])

    return rules


# ---------------------------------------------------------------------------
# DenyRuleEngine
# ---------------------------------------------------------------------------


class DenyRuleEngine:
    """Pre-execution deny rule matching engine.

    Implements the :class:`~nl_protocol.access.policy.DenyEngine` protocol.

    Evaluates action templates against the standard deny rules (Section 3)
    and any custom rules, raising :class:`ActionBlocked` on match.

    Parameters
    ----------
    pattern_engine:
        Optional :class:`PatternEngine` instance.  Defaults to a new engine
        with 100 ms timeout.
    validator:
        Optional :class:`CommandValidator` for pre-match normalization
        and evasion detection.
    load_standard_rules:
        If ``True`` (default), loads the standard deny rules from the spec.
    """

    def __init__(
        self,
        pattern_engine: PatternEngine | None = None,
        validator: CommandValidator | None = None,
        *,
        load_standard_rules: bool = True,
    ) -> None:
        self._engine = pattern_engine or PatternEngine()
        self._validator = validator or CommandValidator()
        self._standard_rules: list[DenyRule] = []
        self._custom_rules: list[DenyRule] = []

        if load_standard_rules:
            self._standard_rules = _build_standard_rules()

        # Validate all patterns compile at load time (Section 3.2 requirement 6)
        for rule in self._standard_rules + self._custom_rules:
            self._engine.compile(rule.pattern)

    # -- DenyEngine protocol ------------------------------------------------

    def check(self, template: str) -> None:
        """Check *template* against all deny rules.

        Raises :class:`ActionBlocked` if any rule matches.

        The evaluation order is:
        1. Evasion detection (validate + normalize).
        2. Standard deny rules (in category priority order).
        3. Custom deny rules.
        """
        # Step 0: Evasion detection
        self._validator.validate_or_raise(template)

        # Step 1: Normalize for pattern matching
        normalized = self._validator.normalize(template)

        # Step 2: Check standard rules (in category priority order)
        for rule in self._sorted_rules(self._standard_rules):
            if self._engine.match(rule.pattern, normalized):
                self._raise_blocked(rule, template)

        # Step 3: Check custom rules
        for rule in self._sorted_rules(self._custom_rules):
            if self._engine.match(rule.pattern, normalized):
                self._raise_blocked(rule, template)

    def check_all(self, template: str) -> list[DenyMatch]:
        """Return all matching rules for *template* (diagnostics mode).

        Unlike :meth:`check`, this does NOT raise and does NOT stop
        at the first match.  Evasion detection is still performed and
        may raise :class:`EvasionDetected`.
        """
        # Step 0: Evasion detection (still raises)
        self._validator.validate_or_raise(template)

        normalized = self._validator.normalize(template)
        matches: list[DenyMatch] = []

        all_rules = self._sorted_rules(self._standard_rules) + self._sorted_rules(
            self._custom_rules
        )

        for rule in all_rules:
            found = self._engine.find_all(rule.pattern, normalized)
            if found:
                matches.append(DenyMatch(rule=rule, matched_text=found[0]))

        return matches

    # -- Custom rule management ---------------------------------------------

    def add_rule(self, rule: DenyRule) -> None:
        """Add a custom deny rule.

        Validates the pattern compiles at addition time.

        Raises
        ------
        re.error
            If the pattern is syntactically invalid.
        ValueError
            If a rule with the same ``rule_id`` already exists.
        """
        # Check for duplicates
        all_ids = {r.rule_id for r in self._standard_rules + self._custom_rules}
        if rule.rule_id in all_ids:
            msg = f"Rule ID already exists: {rule.rule_id}"
            raise ValueError(msg)

        # Validate pattern compiles
        self._engine.compile(rule.pattern)

        self._custom_rules.append(rule)

    def remove_rule(self, rule_id: str) -> DenyRule:
        """Remove a custom deny rule by ID.

        Standard rules cannot be removed.

        Returns
        -------
        DenyRule
            The removed rule.

        Raises
        ------
        ValueError
            If the rule is a standard rule or does not exist.
        """
        # Check if it's a standard rule
        for rule in self._standard_rules:
            if rule.rule_id == rule_id:
                msg = f"Cannot remove standard rule: {rule_id}"
                raise ValueError(msg)

        # Find and remove from custom rules
        for i, rule in enumerate(self._custom_rules):
            if rule.rule_id == rule_id:
                return self._custom_rules.pop(i)

        msg = f"Rule not found: {rule_id}"
        raise ValueError(msg)

    # -- Introspection ------------------------------------------------------

    @property
    def standard_rules(self) -> list[DenyRule]:
        """Return a copy of the standard rules."""
        return list(self._standard_rules)

    @property
    def custom_rules(self) -> list[DenyRule]:
        """Return a copy of the custom rules."""
        return list(self._custom_rules)

    @property
    def all_rules(self) -> list[DenyRule]:
        """Return all rules (standard + custom) in evaluation order."""
        return self._sorted_rules(self._standard_rules) + self._sorted_rules(
            self._custom_rules
        )

    # -- Internal helpers ---------------------------------------------------

    @staticmethod
    def _sorted_rules(rules: list[DenyRule]) -> list[DenyRule]:
        """Sort rules by category priority order."""
        priority_map = {cat: i for i, cat in enumerate(CATEGORY_PRIORITY)}
        return sorted(
            rules,
            key=lambda r: priority_map.get(r.category, len(CATEGORY_PRIORITY)),
        )

    @staticmethod
    def _raise_blocked(rule: DenyRule, original_template: str) -> None:
        """Raise :class:`ActionBlocked` with the educational response."""
        raise ActionBlocked(
            f"Action blocked by deny rule {rule.rule_id}: {rule.description}",
            details={
                "rule_id": rule.rule_id,
                "category": rule.category,
                "severity": rule.severity,
                "blocked_action": original_template,
                "alternative": rule.alternative,
            },
            resolution=rule.alternative,
        )
