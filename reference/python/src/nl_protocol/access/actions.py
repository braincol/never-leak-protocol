"""NL Protocol Level 2 -- Action type definitions and validation.

This module validates action payloads per their type, as defined in
Chapter 02, Section 5 of the NL Protocol specification.

Supported action types and their validation rules:

* **EXEC** -- template MUST contain a command (non-empty after
  placeholder extraction).
* **TEMPLATE** -- template produces text output; MUST contain at least
  one placeholder or literal content.
* **READ** -- no template needed; represents a direct secret existence
  check (dry-run style).  Template may be empty.
* **HTTP** -- template MUST contain a URL (http:// or https://).
* **INJECT_STDIN** -- command field is validated; template contains
  the secret reference to pipe via stdin.
* **INJECT_TEMPFILE** -- command field is validated; template contains
  file reference mappings.
* **SDK_PROXY** -- provider, service, and operation must be specified
  (validated at a higher layer; this module checks template syntax).
* **DELEGATE** -- delegate target and delegated action must be specified
  (validated at a higher layer).
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

from nl_protocol.access.placeholders import PLACEHOLDER_PATTERN
from nl_protocol.core.errors import InvalidPlaceholder, UnknownActionType
from nl_protocol.core.types import ActionType

if TYPE_CHECKING:
    from nl_protocol.core.types import ActionPayload

# URL pattern for HTTP action validation (simplified).
_URL_PATTERN: re.Pattern[str] = re.compile(
    r"https?://[^\s]+"
)


class ActionValidator:
    """Validates action payloads by type.

    Ensures that action templates meet the syntactic and semantic
    requirements for their declared action type.  This validator runs
    *before* scope evaluation and placeholder resolution.

    Usage
    -----
    ::

        validator = ActionValidator()
        errors = validator.validate(action_payload)
        if errors:
            raise InvalidPlaceholder("; ".join(errors))
    """

    def validate(self, payload: ActionPayload) -> list[str]:
        """Validate an action payload.

        Parameters
        ----------
        payload:
            The action payload to validate.

        Returns
        -------
        list[str]
            A list of human-readable validation error messages.
            An empty list means the payload is valid.
        """
        try:
            handler = self._VALIDATORS[payload.type]
        except KeyError:
            return [f"Unknown action type: '{payload.type}'."]

        return handler(self, payload)

    def validate_or_raise(self, payload: ActionPayload) -> None:
        """Validate a payload and raise on failure.

        Parameters
        ----------
        payload:
            The action payload to validate.

        Raises
        ------
        UnknownActionType
            If the action type is not recognized.
        InvalidPlaceholder
            If the payload fails validation.
        """
        errors = self.validate(payload)
        if errors:
            # Determine which error class to use
            if errors[0].startswith("Unknown action type"):
                raise UnknownActionType(payload.type)
            raise InvalidPlaceholder("; ".join(errors))

    # -- Per-type validators -----------------------------------------------

    def _validate_exec(self, payload: ActionPayload) -> list[str]:
        """Validate an EXEC action payload.

        The template MUST contain a command.  After removing all
        ``{{nl:...}}`` placeholders, the remaining text must be
        non-whitespace (i.e., there must be an actual command).
        """
        errors: list[str] = []
        template = payload.template.strip()

        if not template:
            errors.append("EXEC action requires a non-empty template.")
            return errors

        # After removing placeholders, there must be a command remaining
        stripped = PLACEHOLDER_PATTERN.sub("", template).strip()
        if not stripped:
            errors.append(
                "EXEC action template contains only placeholders; "
                "a command is required."
            )

        return errors

    def _validate_template(self, payload: ActionPayload) -> list[str]:
        """Validate a TEMPLATE action payload.

        The template MUST contain content (either literal text or
        at least one placeholder).
        """
        errors: list[str] = []

        if not payload.template.strip():
            errors.append(
                "TEMPLATE action requires non-empty template content."
            )

        return errors

    def _validate_read(self, payload: ActionPayload) -> list[str]:
        """Validate a READ action payload.

        READ actions check secret existence/permissions.  The template
        may contain a secret reference or be empty (for dry-run checks).
        """
        # READ is the most permissive -- no strict template requirements.
        return []

    def _validate_http(self, payload: ActionPayload) -> list[str]:
        """Validate an HTTP action payload.

        The template MUST contain a URL (http:// or https://).
        """
        errors: list[str] = []
        template = payload.template.strip()

        if not template:
            errors.append("HTTP action requires a non-empty template.")
            return errors

        # After removing placeholders, check for URL presence.
        # Note: the URL might be partially inside a placeholder
        # (e.g., "https://{{nl:HOST}}/api"), so we check the raw template.
        if not _URL_PATTERN.search(template):
            # Also check if a URL could be formed after placeholder resolution
            # (e.g., "{{nl:BASE_URL}}/path" -- starts with a placeholder)
            has_leading_placeholder = template.startswith("{{nl:")
            if not has_leading_placeholder:
                errors.append(
                    "HTTP action template must contain a URL "
                    "(http:// or https://)."
                )

        return errors

    def _validate_inject_stdin(self, payload: ActionPayload) -> list[str]:
        """Validate an INJECT_STDIN action payload.

        The template should contain the command to execute.  The secret
        reference to pipe via stdin is specified separately, but for
        basic validation we just check the template is non-empty.
        """
        errors: list[str] = []
        if not payload.template.strip():
            errors.append(
                "INJECT_STDIN action requires a non-empty template "
                "containing the command to execute."
            )
        return errors

    def _validate_inject_tempfile(self, payload: ActionPayload) -> list[str]:
        """Validate an INJECT_TEMPFILE action payload.

        The template should contain the command with file reference
        placeholders.
        """
        errors: list[str] = []
        if not payload.template.strip():
            errors.append(
                "INJECT_TEMPFILE action requires a non-empty template "
                "containing the command to execute."
            )
        return errors

    def _validate_sdk_proxy(self, payload: ActionPayload) -> list[str]:
        """Validate an SDK_PROXY action payload.

        Detailed provider/service/operation validation is deferred to a
        higher layer; here we ensure the template is reasonable.
        """
        # SDK_PROXY may use the template to carry JSON parameters
        return []

    def _validate_delegate(self, payload: ActionPayload) -> list[str]:
        """Validate a DELEGATE action payload.

        Delegation details are validated at the federation layer (Level 7).
        """
        return []

    # -- Validator dispatch table -------------------------------------------

    _VALIDATORS: dict[ActionType, ActionValidatorMethod] = {
        ActionType.EXEC: _validate_exec,
        ActionType.TEMPLATE: _validate_template,
        ActionType.READ: _validate_read,
        ActionType.HTTP: _validate_http,
        ActionType.INJECT_STDIN: _validate_inject_stdin,
        ActionType.INJECT_TEMPFILE: _validate_inject_tempfile,
        ActionType.SDK_PROXY: _validate_sdk_proxy,
        ActionType.DELEGATE: _validate_delegate,
    }


# Type alias for the validator method signature (used in the dispatch table)
from collections.abc import Callable  # noqa: E402

ActionValidatorMethod = Callable[["ActionValidator", "ActionPayload"], list[str]]
