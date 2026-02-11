"""NL Protocol Level 2 -- Action-Based Access.

This subpackage implements the action-based access layer as defined in the
NL Protocol Specification v1.0, Chapter 02.  It provides:

* **PlaceholderResolver** -- parsing and resolution of ``{{nl:...}}``
  placeholders in action templates (Section 4).
* **ScopeEvaluator** -- evaluation of scope grants against action requests
  (Section 8).
* **OutputSanitizer** -- output sanitization to prevent secret leakage in
  action results (Section 9).  This is the *last line of defence*.
* **PolicyEvaluator** -- five-step policy evaluation order from the spec
  overview (deny, AID scope, scope grant, conditions, delegation).
* **ActionValidator** -- action type definitions and payload validation
  (Section 5).
* **PolicyDecision** -- dataclass holding the result of a policy evaluation.
"""
from __future__ import annotations

from nl_protocol.access.actions import ActionValidator
from nl_protocol.access.placeholders import PLACEHOLDER_PATTERN, PlaceholderResolver
from nl_protocol.access.policy import PolicyDecision, PolicyEvaluator
from nl_protocol.access.sanitization import OutputSanitizer
from nl_protocol.access.scope_grants import ScopeEvaluator

__all__ = [
    "PLACEHOLDER_PATTERN",
    "PlaceholderResolver",
    "ScopeEvaluator",
    "OutputSanitizer",
    "PolicyEvaluator",
    "PolicyDecision",
    "ActionValidator",
]
