"""NL Protocol Level 2 -- Placeholder parsing and resolution.

This module implements the ``{{nl:...}}`` placeholder syntax defined in
Chapter 02, Section 4 of the NL Protocol specification.

Key responsibilities:

* **Extract** all secret references from a template string.
* **Resolve** placeholders by looking up secret values from a
  :class:`~nl_protocol.core.interfaces.SecretStore` -- the resolved string
  MUST only be used inside the isolation boundary (Level 3).
* **Validate** placeholder syntax for malformed, nested, or empty references.

Security invariant: the resolved template (containing real secret values)
MUST NEVER be returned to the agent.  It exists only within the execution
isolation boundary.
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

from nl_protocol.core.types import SecretRef

if TYPE_CHECKING:
    from nl_protocol.core.interfaces import SecretStore

# ---------------------------------------------------------------------------
# Regex for NL placeholder syntax
# ---------------------------------------------------------------------------
# Matches: {{nl:reference}}
# where reference = 1+ chars from [a-zA-Z0-9_\-/.:]
# Supports simple (NAME), categorized (category/name), scoped
# (project/env/name), fully qualified (project/env/category/name),
# and cross-provider (provider://path) references per Section 4.1.
PLACEHOLDER_PATTERN: re.Pattern[str] = re.compile(
    r"\{\{nl:([a-zA-Z0-9_\-/.:#]+)\}\}"
)

# Pattern for escaped placeholders: {{{{nl: should NOT be resolved.
_ESCAPED_PATTERN: re.Pattern[str] = re.compile(r"\{\{\{\{nl:")

# Pattern for detecting malformed/incomplete placeholders.
_MALFORMED_PATTERN: re.Pattern[str] = re.compile(
    r"\{\{nl:"        # opening
    r"(?!"            # negative lookahead: NOT followed by valid ref + }}
    r"[a-zA-Z0-9_\-/.:#]+\}\}"
    r")"
)

# Pattern for nested placeholders: {{nl:...{{nl:...}}...}}
_NESTED_PATTERN: re.Pattern[str] = re.compile(
    r"\{\{nl:[^}]*\{\{nl:"
)


class PlaceholderResolver:
    """Parses and resolves ``{{nl:...}}`` placeholders in action templates.

    This class is the bridge between the agent's opaque handle syntax and
    the secret store.  It performs three operations:

    1. **extract_refs** -- stateless extraction of :class:`SecretRef` values
       from a template string.
    2. **resolve** -- asynchronous resolution that replaces each placeholder
       with the actual secret value (to be used *only* inside the isolation
       boundary).
    3. **validate_template** -- static validation of placeholder syntax.

    Parameters
    ----------
    secret_store:
        A :class:`~nl_protocol.core.interfaces.SecretStore` used to look up
        secret values during resolution.
    """

    def __init__(self, secret_store: SecretStore) -> None:
        self._store = secret_store

    # -- Public API ---------------------------------------------------------

    def extract_refs(self, template: str) -> list[SecretRef]:
        """Extract all secret references from a template string.

        Parameters
        ----------
        template:
            A command or content template potentially containing
            ``{{nl:...}}`` placeholders.

        Returns
        -------
        list[SecretRef]
            Ordered list of secret references found in the template.
            Duplicates are preserved (order matters for env-var mapping).
        """
        return self._extract_refs_impl(template)

    @staticmethod
    def extract_refs_static(template: str) -> list[SecretRef]:
        """Extract secret references without needing a store instance.

        This is a convenience class-method for use in policy evaluation
        and validation paths that do not require resolution.
        """
        return PlaceholderResolver._extract_refs_impl(template)

    async def resolve(self, template: str) -> tuple[str, list[SecretRef]]:
        """Resolve all placeholders, returning the resolved string and refs used.

        The resolved string contains actual secret values and MUST only be
        used inside the isolation boundary (Level 3).  It MUST be securely
        wiped from memory after execution completes.

        Parameters
        ----------
        template:
            A template string containing ``{{nl:...}}`` placeholders.

        Returns
        -------
        tuple[str, list[SecretRef]]
            A 2-tuple of (resolved_template, list_of_refs_used).

        Raises
        ------
        nl_protocol.core.errors.SecretNotFound
            If a referenced secret does not exist in the store.
        """
        refs = self.extract_refs(template)
        resolved = template
        for ref in refs:
            value = await self._store.get(ref)
            # Replace the specific placeholder with the exposed secret value.
            # We use exact string replacement rather than regex to avoid
            # issues with special characters in secret values.
            placeholder = f"{{{{nl:{ref}}}}}"
            resolved = resolved.replace(placeholder, value.expose())
        return resolved, refs

    def validate_template(self, template: str) -> list[str]:
        """Validate placeholder syntax in a template.

        Returns a list of human-readable error strings.  An empty list
        means the template is syntactically valid.

        Checks performed:
        1. Malformed placeholders (opening ``{{nl:`` without valid close).
        2. Nested placeholders (``{{nl:...{{nl:...}}...}}``).
        3. Empty references (``{{nl:}}``).
        4. Invalid reference characters.
        5. Escaped placeholder awareness (``{{{{nl:`` is not a placeholder).
        """
        errors: list[str] = []

        # Check for empty references: {{nl:}}
        if "{{nl:}}" in template:
            errors.append(
                "Empty placeholder reference found: '{{nl:}}'. "
                "A reference name is required."
            )

        # Check for nested placeholders
        if _NESTED_PATTERN.search(template):
            errors.append(
                "Nested placeholders detected. Placeholders cannot "
                "contain other placeholders."
            )

        # Check for malformed placeholders (opening without proper close)
        # First, strip out all valid placeholders and escaped ones
        stripped = PLACEHOLDER_PATTERN.sub("", template)
        stripped = _ESCAPED_PATTERN.sub("", stripped)
        # After removing valid placeholders, any remaining {{nl: is malformed
        remaining_opens = re.findall(r"\{\{nl:", stripped)
        if remaining_opens:
            errors.append(
                f"Found {len(remaining_opens)} malformed placeholder(s). "
                "Each '{{nl:' must be followed by a valid reference and '}}'."
            )

        # Validate each extracted reference for character constraints
        matches = PLACEHOLDER_PATTERN.findall(template)
        for match in matches:
            if not match:
                errors.append("Empty reference in placeholder.")
                continue
            # Check for double slashes
            if "//" in match and "://" not in match:
                errors.append(
                    f"Invalid reference '{match}': double slashes are not "
                    "permitted outside cross-provider syntax."
                )
            # Check for leading/trailing slashes
            if match.startswith("/") or match.endswith("/"):
                errors.append(
                    f"Invalid reference '{match}': must not start or end "
                    "with a slash."
                )

        return errors

    # -- Internal helpers ---------------------------------------------------

    @staticmethod
    def _extract_refs_impl(template: str) -> list[SecretRef]:
        """Internal implementation of reference extraction."""
        matches = PLACEHOLDER_PATTERN.findall(template)
        return [SecretRef(m) for m in matches]
