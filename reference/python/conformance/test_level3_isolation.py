"""Level 3 -- Execution Isolation conformance tests.

Verifies Chapter 03 requirements: secrets injected via NL_SECRET_*
environment variables, NEVER as command-line arguments, timeout
enforcement, and environment construction safety.
"""
from __future__ import annotations

import os

import pytest

from nl_protocol.core.errors import IsolationFailure
from nl_protocol.core.types import SecretRef
from nl_protocol.isolation.environment import EnvironmentManager, sanitize_env_name

# ===================================================================
# Section 4 -- Environment variable injection
# ===================================================================

class TestSecretInjection:
    """Spec Section 4: secrets MUST be injected via NL_SECRET_* env vars."""

    def test_MUST_inject_secrets_as_NL_SECRET_vars(self) -> None:
        """Secrets MUST be mapped to NL_SECRET_0, NL_SECRET_1, etc."""
        mgr = EnvironmentManager()
        env = mgr.build_child_env(
            secrets={"api/TOKEN": "secret-val-1", "db/PASS": "secret-val-2"}
        )
        assert env["NL_SECRET_0"] == "secret-val-1"
        assert env["NL_SECRET_1"] == "secret-val-2"

    def test_MUST_NOT_pass_secrets_as_command_args(self) -> None:
        """Secrets MUST NEVER appear in command-line arguments.

        This verifies the environment-only injection model: the child env
        contains NL_SECRET_* vars, not arguments.
        """
        mgr = EnvironmentManager()
        env = mgr.build_child_env(secrets={"api/KEY": "val123"})
        # The env dict keys should only use the NL_SECRET_ prefix for secrets
        secret_vars = [k for k in env if k.startswith("NL_SECRET_")]
        assert len(secret_vars) == 1
        assert env[secret_vars[0]] == "val123"

    def test_MUST_NOT_inherit_full_parent_environment(self) -> None:
        """Child environment MUST be explicitly constructed, not inherited in full."""
        mgr = EnvironmentManager()
        env = mgr.build_child_env(secrets={})
        # The child env should NOT contain every parent variable
        parent_keys = set(os.environ.keys())
        child_keys = set(env.keys())
        # Child must have fewer keys than parent (only safe subset inherited)
        assert len(child_keys) < len(parent_keys) or len(parent_keys) == 0

    def test_MUST_include_safe_system_vars(self) -> None:
        """PATH and HOME SHOULD be inherited from the parent environment."""
        mgr = EnvironmentManager()
        env = mgr.build_child_env(secrets={})
        if "PATH" in os.environ:
            assert "PATH" in env
        if "HOME" in os.environ:
            assert "HOME" in env


# ===================================================================
# Section 4.2 -- Variable naming convention
# ===================================================================

class TestVariableNaming:
    """Spec Section 4.2: NL_SECRET_<index> naming convention."""

    def test_MUST_use_sequential_indices(self) -> None:
        """Secret vars MUST use sequential indices starting at 0."""
        mgr = EnvironmentManager()
        secrets = {f"ref{i}": f"val{i}" for i in range(5)}
        env = mgr.build_child_env(secrets=secrets)
        for i in range(5):
            assert f"NL_SECRET_{i}" in env

    def test_MUST_sanitize_env_name_uppercase(self) -> None:
        """sanitize_env_name MUST convert to uppercase."""
        assert sanitize_env_name("api/my-key") == "API_MY_KEY"

    def test_MUST_sanitize_env_name_replace_specials(self) -> None:
        """Non-alphanumeric characters MUST be replaced with underscore."""
        assert sanitize_env_name("my.secret/name-here") == "MY_SECRET_NAME_HERE"

    def test_MUST_collapse_consecutive_underscores(self) -> None:
        """Consecutive underscores MUST be collapsed to one."""
        assert sanitize_env_name("a///b") == "A_B"


# ===================================================================
# Section 4.3 -- Collision detection
# ===================================================================

class TestCollisionDetection:
    """Spec Section 4.3: NL_SECRET_* collisions MUST be detected."""

    def test_MUST_detect_NL_SECRET_collision(self) -> None:
        """If extra_vars contain NL_SECRET_*, it MUST be rejected."""
        mgr = EnvironmentManager()
        with pytest.raises(IsolationFailure):
            mgr.build_child_env(
                secrets={},
                extra_vars={"NL_SECRET_0": "malicious"},
            )

    def test_MUST_map_refs_and_values_correctly(self) -> None:
        """map_secret_refs MUST return (env_mapping, ref_to_var)."""
        refs = [SecretRef("api/A"), SecretRef("db/B")]
        values = ["val-a", "val-b"]
        env_map, ref_map = EnvironmentManager.map_secret_refs(refs, values)
        assert env_map["NL_SECRET_0"] == "val-a"
        assert env_map["NL_SECRET_1"] == "val-b"
        assert ref_map["api/A"] == "NL_SECRET_0"
        assert ref_map["db/B"] == "NL_SECRET_1"

    def test_MUST_reject_mismatched_lengths(self) -> None:
        """map_secret_refs MUST raise on length mismatch."""
        with pytest.raises(IsolationFailure):
            EnvironmentManager.map_secret_refs(
                [SecretRef("a")], ["v1", "v2"]
            )


# ===================================================================
# Section 4.4 -- NL_SECRET_* not in parent
# ===================================================================

class TestParentEnvironmentSafety:
    """Spec Section 4.4: NL_SECRET_* MUST NOT exist in the parent."""

    def test_MUST_strip_NL_SECRET_from_parent(self) -> None:
        """strip_nl_secrets_from_parent MUST remove any NL_SECRET_* vars."""
        # Set a test variable then strip it
        os.environ["NL_SECRET_TEST"] = "should-be-removed"
        removed = EnvironmentManager.strip_nl_secrets_from_parent()
        assert "NL_SECRET_TEST" in removed
        assert "NL_SECRET_TEST" not in os.environ

    def test_MUST_detect_no_collisions_in_clean_env(self) -> None:
        """detect_collisions on a clean env MUST return empty list."""
        env = {"PATH": "/usr/bin", "HOME": "/home/test", "NL_SECRET_0": "val"}
        collisions = EnvironmentManager.detect_collisions(env)
        assert collisions == []


# ===================================================================
# General isolation invariants
# ===================================================================

class TestIsolationInvariants:
    """General isolation invariants from Chapter 03."""

    def test_MUST_NOT_leak_secret_values_in_env_keys(self) -> None:
        """Secret values MUST NOT appear in environment variable names."""
        mgr = EnvironmentManager()
        env = mgr.build_child_env(
            secrets={"api/TOKEN": "super-secret-abc123"}
        )
        for key in env:
            assert "super-secret-abc123" not in key

    def test_MUST_support_empty_secret_set(self) -> None:
        """Building a child env with no secrets MUST succeed."""
        mgr = EnvironmentManager()
        env = mgr.build_child_env(secrets={})
        # Should at least have some inherited system vars
        assert isinstance(env, dict)

    def test_MUST_support_extra_inherit_vars(self) -> None:
        """Extra inherited variables MUST be included if present in parent."""
        os.environ["_NL_TEST_VAR"] = "test-value"
        try:
            mgr = EnvironmentManager()
            env = mgr.build_child_env(
                secrets={}, extra_inherit=["_NL_TEST_VAR"]
            )
            assert env.get("_NL_TEST_VAR") == "test-value"
        finally:
            del os.environ["_NL_TEST_VAR"]
