"""NL Protocol Level 4 -- Pre-Execution Defense.

This subpackage implements the Pre-Execution Defense layer defined in
Chapter 04 of the NL Protocol Specification v1.0.  It provides:

* **DenyRuleEngine** -- the deny rule matching engine that evaluates
  action templates against standard and custom deny rules (Section 3).
* **DenyRule** / **DenyMatch** -- data structures for deny rules and
  match results.
* **PatternEngine** -- RE2-compatible pattern matching with timeout
  support and compilation caching (Section 3.2).
* **CommandValidator** -- evasion detection covering Unicode homoglyphs,
  zero-width characters, bidirectional overrides, null bytes, template
  injection, and shell metacharacter analysis (Section 6).
* **EvasionFinding** -- data structure for evasion detection results.
"""
from __future__ import annotations

from nl_protocol.defense.deny_rules import (
    CATEGORY_PRIORITY,
    DenyMatch,
    DenyRule,
    DenyRuleEngine,
)
from nl_protocol.defense.pattern_engine import PatternEngine
from nl_protocol.defense.validation import CommandValidator, EvasionFinding

__all__ = [
    "CATEGORY_PRIORITY",
    "CommandValidator",
    "DenyMatch",
    "DenyRule",
    "DenyRuleEngine",
    "EvasionFinding",
    "PatternEngine",
]
