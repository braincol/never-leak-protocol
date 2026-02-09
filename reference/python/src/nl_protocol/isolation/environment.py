"""NL Protocol Level 3 -- Environment variable management.

This module implements the :class:`EnvironmentManager` which constructs
the isolated child process environment according to:

* Chapter 03, Section 4   -- Environment Variable Injection
* Chapter 03, Section 4.2 -- Variable Naming Convention
* Chapter 03, Section 4.4 -- Inherited Environment

Key rules:
1. Secrets are passed as ``NL_SECRET_<INDEX>`` environment variables.
2. The child environment MUST be constructed explicitly -- never inherit
   the full parent environment.
3. ``NL_SECRET_*`` variables MUST NOT exist in the parent environment.
4. Only a minimal set of safe system variables are inherited.
"""
from __future__ import annotations

import os
import re

from nl_protocol.core.errors import IsolationFailure
from nl_protocol.core.types import SecretRef

# Environment variables that SHOULD be inherited from the parent (spec Section 4.4).
_INHERITED_VARS: tuple[str, ...] = (
    "PATH",
    "HOME",
    "LANG",
    "TERM",
    "TMPDIR",
    "TZ",
)

# Regex for LC_* locale variables that should be inherited.
_LC_VAR_RE = re.compile(r"^LC_[A-Z_]+$")

# Pattern for NL_SECRET_* variables.
_NL_SECRET_RE = re.compile(r"^NL_SECRET_")


def sanitize_env_name(name: str) -> str:
    """Sanitize a secret name into a valid environment variable suffix.

    Conversion rules:
    * Convert to uppercase.
    * Replace any non-alphanumeric character with ``_``.
    * Collapse consecutive underscores.
    * Strip leading/trailing underscores.

    Parameters
    ----------
    name:
        A raw secret name or ref, e.g. ``"api/my-key"``.

    Returns
    -------
    str
        A sanitised uppercase string suitable for env var naming,
        e.g. ``"API_MY_KEY"``.
    """
    upper = name.upper()
    replaced = re.sub(r"[^A-Z0-9]", "_", upper)
    collapsed = re.sub(r"_+", "_", replaced)
    return collapsed.strip("_")


class EnvironmentManager:
    """Build isolated environment mappings for subprocess execution.

    The manager tracks NL_SECRET_* assignments and detects collisions.

    Typical usage::

        mgr = EnvironmentManager()
        env = mgr.build_child_env(
            secrets={"api/API_KEY": "actual-value", "db/PASSWORD": "pw"},
        )
        # env == {
        #     "PATH": "/usr/bin:/bin",
        #     "HOME": "/Users/...",
        #     ...
        #     "NL_SECRET_0": "actual-value",
        #     "NL_SECRET_1": "pw",
        # }
    """

    def build_child_env(
        self,
        secrets: dict[SecretRef | str, str],
        *,
        extra_inherit: list[str] | None = None,
        extra_vars: dict[str, str] | None = None,
    ) -> dict[str, str]:
        """Construct the child process environment.

        Parameters
        ----------
        secrets:
            Mapping of ``SecretRef`` (or plain string) to plaintext
            secret value.  Each secret is assigned ``NL_SECRET_<i>``
            in iteration order.
        extra_inherit:
            Additional environment variable names to inherit from the
            parent, beyond the spec defaults.
        extra_vars:
            Additional literal environment variables to set in the child
            (e.g. ``{"MY_FLAG": "1"}``).  These MUST NOT start with
            ``NL_SECRET_``.

        Returns
        -------
        dict[str, str]
            The complete environment mapping for the child process.

        Raises
        ------
        IsolationFailure
            If collision detection fails or invalid variable names are
            provided.
        """
        env: dict[str, str] = {}

        # 1. Inherit safe system variables from parent.
        for var in _INHERITED_VARS:
            val = os.environ.get(var)
            if val is not None:
                env[var] = val

        # Also inherit LC_* locale variables.
        for key, val in os.environ.items():
            if _LC_VAR_RE.match(key):
                env[key] = val

        # Extra inherited variables (from sandbox config or caller).
        if extra_inherit:
            for var in extra_inherit:
                val = os.environ.get(var)
                if val is not None:
                    env[var] = val

        # 2. Inject extra literal variables (non-secret).
        if extra_vars:
            for key, val in extra_vars.items():
                if _NL_SECRET_RE.match(key):
                    raise IsolationFailure(
                        f"extra_vars key {key!r} must not start with NL_SECRET_",
                        details={"key": key},
                    )
                env[key] = val

        # 3. Map secrets to NL_SECRET_<index>.
        secret_names: list[str] = []
        for idx, (ref, value) in enumerate(secrets.items()):
            var_name = f"NL_SECRET_{idx}"
            if var_name in env:
                raise IsolationFailure(
                    f"Environment variable collision: {var_name} already set",
                    details={"var": var_name},
                )
            env[var_name] = value
            secret_names.append(str(ref))

        return env

    @staticmethod
    def map_secret_refs(
        refs: list[SecretRef | str],
        values: list[str],
    ) -> tuple[dict[str, str], dict[str, str]]:
        """Map a list of secret refs and values to NL_SECRET_* variables.

        Parameters
        ----------
        refs:
            Secret references, in order.
        values:
            Corresponding plaintext values, in the same order.

        Returns
        -------
        tuple[dict[str, str], dict[str, str]]
            A 2-tuple of (env_mapping, ref_to_var).  ``env_mapping`` maps
            ``NL_SECRET_<i>`` to the secret value.  ``ref_to_var`` maps
            the original ref string to the variable name.

        Raises
        ------
        IsolationFailure
            If *refs* and *values* have different lengths.
        """
        if len(refs) != len(values):
            raise IsolationFailure(
                f"refs ({len(refs)}) and values ({len(values)}) length mismatch",
            )
        env_mapping: dict[str, str] = {}
        ref_to_var: dict[str, str] = {}
        for idx, (ref, val) in enumerate(zip(refs, values, strict=True)):
            var = f"NL_SECRET_{idx}"
            env_mapping[var] = val
            ref_to_var[str(ref)] = var
        return env_mapping, ref_to_var

    @staticmethod
    def detect_collisions(env: dict[str, str]) -> list[str]:
        """Check an environment mapping for NL_SECRET_* collisions.

        Returns a list of variable names that appear more than once or
        share the same index.  An empty list means no collisions.
        """
        seen: dict[str, int] = {}
        collisions: list[str] = []
        for key in env:
            if _NL_SECRET_RE.match(key):
                if key in seen:
                    collisions.append(key)
                seen[key] = seen.get(key, 0) + 1
        return collisions

    @staticmethod
    def strip_nl_secrets_from_parent() -> list[str]:
        """Remove any NL_SECRET_* variables from the current process environment.

        This is a safety measure -- NL_SECRET_* MUST NOT exist in the
        parent.  Returns the list of variable names that were removed.
        """
        removed: list[str] = []
        for key in list(os.environ.keys()):
            if _NL_SECRET_RE.match(key):
                del os.environ[key]
                removed.append(key)
        return removed
