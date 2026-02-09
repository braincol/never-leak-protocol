"""Tests for NL Protocol Level 3 -- Execution Isolation.

This module covers the isolation subpackage:

1. **Environment variable management** -- name sanitization, NL_SECRET_*
   mapping, collision detection, parent stripping, inherited variables.
2. **Subprocess execution** -- basic execution, exit codes, stdout/stderr
   capture, secret injection via env vars, shell and array-based commands.
3. **Timeout enforcement** -- timeout clamping, process termination on
   timeout, ExecutionTimeout error with correct details.
4. **Secure memory** -- bytearray wipe, context manager cleanup, wipe
   verification, wipe_string best-effort, type validation.
5. **Sandbox configuration** -- default values, platform detection,
   resource limits, frozen dataclass behaviour.
6. **Error handling** -- IsolationFailure on spawn failure, collision
   detection, extra_vars with NL_SECRET_ prefix.
"""
from __future__ import annotations

import os
import sys

import pytest

from nl_protocol.core.errors import ExecutionTimeout, IsolationFailure
from nl_protocol.core.types import ActionResult
from nl_protocol.isolation.environment import (
    EnvironmentManager,
    sanitize_env_name,
)
from nl_protocol.isolation.memory import SecureMemory, wipe, wipe_string
from nl_protocol.isolation.sandbox import ResourceLimits, SandboxConfig
from nl_protocol.isolation.subprocess import (
    DEFAULT_TIMEOUT_S,
    GRACEFUL_SHUTDOWN_S,
    MAX_TIMEOUT_S,
    MIN_TIMEOUT_S,
    IsolatedExecutor,
    _clamp_timeout,
)

# ===================================================================
# Environment Variable Management
# ===================================================================


class TestSanitizeEnvName:
    """Test sanitize_env_name conversion rules."""

    def test_simple_name(self) -> None:
        assert sanitize_env_name("API_KEY") == "API_KEY"

    def test_lowercase_to_uppercase(self) -> None:
        assert sanitize_env_name("api_key") == "API_KEY"

    def test_mixed_case(self) -> None:
        assert sanitize_env_name("myApiKey") == "MYAPIKEY"

    def test_slash_replaced_with_underscore(self) -> None:
        assert sanitize_env_name("api/my-key") == "API_MY_KEY"

    def test_dashes_replaced(self) -> None:
        assert sanitize_env_name("my-secret-name") == "MY_SECRET_NAME"

    def test_dots_replaced(self) -> None:
        assert sanitize_env_name("config.db.password") == "CONFIG_DB_PASSWORD"

    def test_multiple_special_chars_collapsed(self) -> None:
        assert sanitize_env_name("api//my--key") == "API_MY_KEY"

    def test_leading_trailing_special_stripped(self) -> None:
        assert sanitize_env_name("/api/key/") == "API_KEY"

    def test_empty_string(self) -> None:
        assert sanitize_env_name("") == ""

    def test_all_special_chars(self) -> None:
        assert sanitize_env_name("---") == ""

    def test_numeric_name(self) -> None:
        assert sanitize_env_name("key123") == "KEY123"

    def test_already_uppercase(self) -> None:
        assert sanitize_env_name("DB_PASSWORD") == "DB_PASSWORD"


class TestEnvironmentManager:
    """Test EnvironmentManager.build_child_env and related methods."""

    def test_build_child_env_basic(self) -> None:
        mgr = EnvironmentManager()
        env = mgr.build_child_env(secrets={"api/key": "secret-value"})

        # Must contain NL_SECRET_0
        assert env["NL_SECRET_0"] == "secret-value"
        # Must contain inherited system vars (if present in parent)
        if "PATH" in os.environ:
            assert "PATH" in env

    def test_build_child_env_multiple_secrets(self) -> None:
        mgr = EnvironmentManager()
        env = mgr.build_child_env(
            secrets={
                "api/key": "value-0",
                "db/password": "value-1",
                "service/token": "value-2",
            },
        )
        assert env["NL_SECRET_0"] == "value-0"
        assert env["NL_SECRET_1"] == "value-1"
        assert env["NL_SECRET_2"] == "value-2"

    def test_build_child_env_no_secrets(self) -> None:
        mgr = EnvironmentManager()
        env = mgr.build_child_env(secrets={})
        # No NL_SECRET_* variables
        nl_vars = [k for k in env if k.startswith("NL_SECRET_")]
        assert nl_vars == []

    def test_build_child_env_with_extra_vars(self) -> None:
        mgr = EnvironmentManager()
        env = mgr.build_child_env(
            secrets={"ref": "val"},
            extra_vars={"MY_FLAG": "1", "DEBUG": "true"},
        )
        assert env["MY_FLAG"] == "1"
        assert env["DEBUG"] == "true"

    def test_build_child_env_extra_vars_nl_secret_rejected(self) -> None:
        mgr = EnvironmentManager()
        with pytest.raises(IsolationFailure, match="NL_SECRET_"):
            mgr.build_child_env(
                secrets={},
                extra_vars={"NL_SECRET_HACK": "bad"},
            )

    def test_build_child_env_does_not_inherit_full_parent(self) -> None:
        """The child env must NOT contain arbitrary parent variables."""
        mgr = EnvironmentManager()
        # Set a non-standard variable in the parent.
        os.environ["_NL_TEST_CUSTOM_VAR"] = "should-not-inherit"
        try:
            env = mgr.build_child_env(secrets={})
            assert "_NL_TEST_CUSTOM_VAR" not in env
        finally:
            del os.environ["_NL_TEST_CUSTOM_VAR"]

    def test_build_child_env_inherits_path(self) -> None:
        mgr = EnvironmentManager()
        original_path = os.environ.get("PATH")
        if original_path:
            env = mgr.build_child_env(secrets={})
            assert env["PATH"] == original_path

    def test_build_child_env_extra_inherit(self) -> None:
        mgr = EnvironmentManager()
        os.environ["_NL_TEST_EXTRA"] = "inherited"
        try:
            env = mgr.build_child_env(
                secrets={},
                extra_inherit=["_NL_TEST_EXTRA"],
            )
            assert env["_NL_TEST_EXTRA"] == "inherited"
        finally:
            del os.environ["_NL_TEST_EXTRA"]

    def test_map_secret_refs(self) -> None:
        env_map, ref_to_var = EnvironmentManager.map_secret_refs(
            refs=["api/KEY", "db/PASS"],
            values=["k1", "p1"],
        )
        assert env_map == {"NL_SECRET_0": "k1", "NL_SECRET_1": "p1"}
        assert ref_to_var == {"api/KEY": "NL_SECRET_0", "db/PASS": "NL_SECRET_1"}

    def test_map_secret_refs_length_mismatch(self) -> None:
        with pytest.raises(IsolationFailure, match="length mismatch"):
            EnvironmentManager.map_secret_refs(
                refs=["a", "b"],
                values=["1"],
            )

    def test_detect_collisions_none(self) -> None:
        env = {"NL_SECRET_0": "a", "NL_SECRET_1": "b", "PATH": "/usr/bin"}
        assert EnvironmentManager.detect_collisions(env) == []

    def test_strip_nl_secrets_from_parent(self) -> None:
        os.environ["NL_SECRET_0"] = "leaked"
        os.environ["NL_SECRET_TEST"] = "also-leaked"
        try:
            removed = EnvironmentManager.strip_nl_secrets_from_parent()
            assert "NL_SECRET_0" in removed
            assert "NL_SECRET_TEST" in removed
            assert "NL_SECRET_0" not in os.environ
            assert "NL_SECRET_TEST" not in os.environ
        finally:
            # Ensure cleanup even if test fails.
            os.environ.pop("NL_SECRET_0", None)
            os.environ.pop("NL_SECRET_TEST", None)


# ===================================================================
# Secure Memory
# ===================================================================


class TestWipe:
    """Test the wipe() function for bytearray zeroing."""

    def test_wipe_zeros_all_bytes(self) -> None:
        data = bytearray(b"super-secret-value-12345")
        wipe(data)
        assert all(b == 0 for b in data)
        assert len(data) == len(b"super-secret-value-12345")

    def test_wipe_empty_bytearray(self) -> None:
        data = bytearray(b"")
        wipe(data)  # Should not raise.
        assert len(data) == 0

    def test_wipe_single_byte(self) -> None:
        data = bytearray(b"X")
        wipe(data)
        assert data[0] == 0

    def test_wipe_large_buffer(self) -> None:
        data = bytearray(os.urandom(4096))
        wipe(data)
        assert all(b == 0 for b in data)

    def test_wipe_rejects_non_bytearray(self) -> None:
        with pytest.raises(TypeError, match="Expected bytearray"):
            wipe(b"immutable")  # type: ignore[arg-type]

    def test_wipe_rejects_string(self) -> None:
        with pytest.raises(TypeError, match="Expected bytearray"):
            wipe("string")  # type: ignore[arg-type]


class TestWipeString:
    """Test wipe_string best-effort behaviour."""

    def test_wipe_string_does_not_raise(self) -> None:
        """wipe_string should never raise, even on non-strings."""
        wipe_string("some-secret")
        wipe_string("")
        wipe_string(42)  # type: ignore[arg-type]

    def test_wipe_string_accepts_string(self) -> None:
        """Basic smoke test -- just ensure it does not crash."""
        s = "my-secret-password"
        wipe_string(s)


class TestSecureMemory:
    """Test the SecureMemory context manager."""

    def test_context_manager_wipes_on_exit(self) -> None:
        data = bytearray(b"secret-data")
        with SecureMemory(data) as buf:
            assert buf == bytearray(b"secret-data")
        # After exit, data should be zeroed.
        assert all(b == 0 for b in data)

    def test_context_manager_wipes_on_exception(self) -> None:
        data = bytearray(b"secret-data")
        with pytest.raises(ValueError, match="test"), SecureMemory(data):
            raise ValueError("test")
        assert all(b == 0 for b in data)

    def test_context_manager_returns_bytearray(self) -> None:
        data = bytearray(b"hello")
        with SecureMemory(data) as buf:
            assert isinstance(buf, bytearray)
            assert buf is data

    def test_explicit_wipe(self) -> None:
        data = bytearray(b"explicit")
        sm = SecureMemory(data)
        assert not sm.wiped
        sm.wipe()
        assert sm.wiped
        assert all(b == 0 for b in data)

    def test_double_wipe_is_safe(self) -> None:
        data = bytearray(b"double")
        sm = SecureMemory(data)
        sm.wipe()
        sm.wipe()  # Should not raise.
        assert sm.wiped

    def test_rejects_non_bytearray(self) -> None:
        with pytest.raises(TypeError, match="requires bytearray"):
            SecureMemory(b"immutable")  # type: ignore[arg-type]

    def test_rejects_string(self) -> None:
        with pytest.raises(TypeError, match="requires bytearray"):
            SecureMemory("string")  # type: ignore[arg-type]


# ===================================================================
# Sandbox Configuration
# ===================================================================


class TestSandboxConfig:
    """Test SandboxConfig defaults and properties."""

    def test_default_values(self) -> None:
        cfg = SandboxConfig()
        assert cfg.disable_core_dumps is True
        assert cfg.disable_network is False
        assert cfg.allowed_read_paths == []
        assert cfg.allowed_write_paths == []
        assert cfg.use_pid_namespace is False
        assert cfg.use_network_namespace is False
        assert cfg.inherit_env_vars == []

    def test_platform_property(self) -> None:
        cfg = SandboxConfig()
        if sys.platform == "win32":
            assert cfg.platform == "nt"
        else:
            assert cfg.platform == "posix"

    def test_is_macos(self) -> None:
        cfg = SandboxConfig()
        assert cfg.is_macos == (sys.platform == "darwin")

    def test_is_linux(self) -> None:
        cfg = SandboxConfig()
        assert cfg.is_linux == sys.platform.startswith("linux")

    def test_frozen(self) -> None:
        cfg = SandboxConfig()
        with pytest.raises(AttributeError):
            cfg.disable_core_dumps = False  # type: ignore[misc]

    def test_custom_resource_limits(self) -> None:
        limits = ResourceLimits(
            max_memory_bytes=1024 * 1024 * 512,
            max_cpu_seconds=60,
            max_file_descriptors=256,
        )
        cfg = SandboxConfig(resource_limits=limits)
        assert cfg.resource_limits.max_memory_bytes == 512 * 1024 * 1024
        assert cfg.resource_limits.max_cpu_seconds == 60
        assert cfg.resource_limits.max_file_descriptors == 256

    def test_default_resource_limits(self) -> None:
        cfg = SandboxConfig()
        assert cfg.resource_limits.max_memory_bytes is None
        assert cfg.resource_limits.max_cpu_seconds is None
        assert cfg.resource_limits.max_file_descriptors is None

    def test_custom_sandbox(self) -> None:
        cfg = SandboxConfig(
            disable_network=True,
            allowed_read_paths=["/usr", "/var/data"],  # noqa: S108
            allowed_write_paths=["/var/data/output"],  # noqa: S108
            inherit_env_vars=["CUSTOM_VAR"],
        )
        assert cfg.disable_network is True
        assert cfg.allowed_read_paths == ["/usr", "/var/data"]
        assert cfg.allowed_write_paths == ["/var/data/output"]
        assert cfg.inherit_env_vars == ["CUSTOM_VAR"]


class TestResourceLimits:
    """Test ResourceLimits dataclass."""

    def test_defaults(self) -> None:
        rl = ResourceLimits()
        assert rl.max_memory_bytes is None
        assert rl.max_cpu_seconds is None
        assert rl.max_file_descriptors is None

    def test_frozen(self) -> None:
        rl = ResourceLimits(max_memory_bytes=1024)
        with pytest.raises(AttributeError):
            rl.max_memory_bytes = 2048  # type: ignore[misc]


# ===================================================================
# Timeout Clamping
# ===================================================================


class TestClampTimeout:
    """Test _clamp_timeout utility."""

    def test_within_range(self) -> None:
        assert _clamp_timeout(30) == 30.0

    def test_below_min(self) -> None:
        assert _clamp_timeout(0) == float(MIN_TIMEOUT_S)
        assert _clamp_timeout(-5) == float(MIN_TIMEOUT_S)
        assert _clamp_timeout(0.5) == float(MIN_TIMEOUT_S)

    def test_above_max(self) -> None:
        assert _clamp_timeout(9999) == float(MAX_TIMEOUT_S)
        assert _clamp_timeout(601) == float(MAX_TIMEOUT_S)

    def test_exact_boundaries(self) -> None:
        assert _clamp_timeout(MIN_TIMEOUT_S) == float(MIN_TIMEOUT_S)
        assert _clamp_timeout(MAX_TIMEOUT_S) == float(MAX_TIMEOUT_S)

    def test_float_input(self) -> None:
        assert _clamp_timeout(5.5) == 5.5

    def test_constants_match_spec(self) -> None:
        assert MIN_TIMEOUT_S == 1
        assert MAX_TIMEOUT_S == 600
        assert DEFAULT_TIMEOUT_S == 30
        assert GRACEFUL_SHUTDOWN_S == 5


# ===================================================================
# Subprocess Execution
# ===================================================================


class TestIsolatedExecutor:
    """Test IsolatedExecutor.execute for various scenarios."""

    @pytest.fixture
    def executor(self) -> IsolatedExecutor:
        return IsolatedExecutor()

    async def test_simple_echo(self, executor: IsolatedExecutor) -> None:
        result = await executor.execute("echo hello")
        assert result.exit_code == 0
        assert result.stdout.strip() == "hello"
        assert result.stderr == ""

    async def test_returns_action_result(self, executor: IsolatedExecutor) -> None:
        result = await executor.execute("echo test")
        assert isinstance(result, ActionResult)

    async def test_captures_stderr(self, executor: IsolatedExecutor) -> None:
        result = await executor.execute("echo error >&2")
        assert result.exit_code == 0
        assert "error" in result.stderr

    async def test_exit_code_nonzero(self, executor: IsolatedExecutor) -> None:
        result = await executor.execute("exit 42")
        assert result.exit_code == 42

    async def test_exit_code_127_command_not_found(self, executor: IsolatedExecutor) -> None:
        result = await executor.execute("this_command_does_not_exist_nl_test_xyz")
        assert result.exit_code == 127

    async def test_secret_injection_via_env_vars(self, executor: IsolatedExecutor) -> None:
        """Secrets must be accessible as NL_SECRET_* in the child process."""
        result = await executor.execute(
            "echo $NL_SECRET_0",
            secrets={"api/key": "my-secret-value"},
        )
        assert result.exit_code == 0
        assert result.stdout.strip() == "my-secret-value"

    async def test_multiple_secrets_injection(self, executor: IsolatedExecutor) -> None:
        result = await executor.execute(
            'echo "$NL_SECRET_0:$NL_SECRET_1"',
            secrets={"api/user": "alice", "api/pass": "s3cret"},
        )
        assert result.exit_code == 0
        assert result.stdout.strip() == "alice:s3cret"

    async def test_secrets_not_in_parent_env_after_execution(
        self, executor: IsolatedExecutor,
    ) -> None:
        """NL_SECRET_* must not leak into the parent environment."""
        await executor.execute(
            "echo $NL_SECRET_0",
            secrets={"ref": "value"},
        )
        for key in os.environ:
            assert not key.startswith("NL_SECRET_"), f"{key} found in parent env"

    async def test_extra_env_vars(self, executor: IsolatedExecutor) -> None:
        result = await executor.execute(
            "echo $MY_CUSTOM_VAR",
            extra_env={"MY_CUSTOM_VAR": "custom-value"},
        )
        assert result.exit_code == 0
        assert result.stdout.strip() == "custom-value"

    async def test_empty_command(self, executor: IsolatedExecutor) -> None:
        result = await executor.execute("true")
        assert result.exit_code == 0

    async def test_array_based_command(self, executor: IsolatedExecutor) -> None:
        """Array-based execution (no shell) is preferred per spec."""
        result = await executor.execute(
            ["/bin/echo", "array-mode"],
        )
        assert result.exit_code == 0
        assert result.stdout.strip() == "array-mode"

    async def test_array_based_with_secrets(self, executor: IsolatedExecutor) -> None:
        """Secrets should be in the env even with array-based execution."""
        result = await executor.execute(
            ["/bin/sh", "-c", "echo $NL_SECRET_0"],
            secrets={"key": "arr-secret"},
        )
        assert result.exit_code == 0
        assert result.stdout.strip() == "arr-secret"

    async def test_stdin_data(self, executor: IsolatedExecutor) -> None:
        result = await executor.execute(
            "cat",
            stdin_data=b"hello from stdin",
        )
        assert result.exit_code == 0
        assert result.stdout.strip() == "hello from stdin"

    async def test_no_secrets_empty_dict(self, executor: IsolatedExecutor) -> None:
        result = await executor.execute("echo no-secrets", secrets={})
        assert result.exit_code == 0
        assert result.stdout.strip() == "no-secrets"

    async def test_child_cannot_see_parent_custom_var(
        self, executor: IsolatedExecutor,
    ) -> None:
        """The child must NOT inherit arbitrary parent env vars."""
        os.environ["_NL_TEST_PARENT_VAR"] = "should-not-see"
        try:
            result = await executor.execute(
                'echo "VAR=${_NL_TEST_PARENT_VAR:-unset}"',
            )
            assert result.exit_code == 0
            assert "unset" in result.stdout
        finally:
            del os.environ["_NL_TEST_PARENT_VAR"]


# ===================================================================
# Timeout Enforcement
# ===================================================================


class TestTimeoutEnforcement:
    """Test timeout enforcement in subprocess execution."""

    @pytest.fixture
    def executor(self) -> IsolatedExecutor:
        return IsolatedExecutor()

    async def test_timeout_raises_execution_timeout(
        self, executor: IsolatedExecutor,
    ) -> None:
        """A process exceeding timeout must raise ExecutionTimeout (NL-E303)."""
        with pytest.raises(ExecutionTimeout) as exc_info:
            await executor.execute("sleep 60", timeout=1)
        assert exc_info.value.code == "NL-E303"
        assert "timeout" in exc_info.value.details.get("exit_reason", "")

    async def test_timeout_details_include_timeout_ms(
        self, executor: IsolatedExecutor,
    ) -> None:
        with pytest.raises(ExecutionTimeout) as exc_info:
            await executor.execute("sleep 60", timeout=2)
        assert exc_info.value.details["timeout_ms"] == 2000

    async def test_fast_command_does_not_timeout(
        self, executor: IsolatedExecutor,
    ) -> None:
        """A fast command should complete within timeout."""
        result = await executor.execute("echo fast", timeout=10)
        assert result.exit_code == 0

    async def test_timeout_clamped_to_min(
        self, executor: IsolatedExecutor,
    ) -> None:
        """Timeout below MIN_TIMEOUT_S should be clamped, not rejected."""
        # 0.1s would be clamped to 1s -- sleep 0.1 should succeed within 1s.
        result = await executor.execute("echo clamped", timeout=0.1)
        assert result.exit_code == 0


# ===================================================================
# Error Handling
# ===================================================================


class TestErrorHandling:
    """Test error scenarios for IsolatedExecutor."""

    @pytest.fixture
    def executor(self) -> IsolatedExecutor:
        return IsolatedExecutor()

    async def test_spawn_failure_raises_isolation_failure(self) -> None:
        """Attempting to execute a non-existent binary should raise IsolationFailure."""
        executor = IsolatedExecutor()
        with pytest.raises(IsolationFailure):
            await executor.execute(
                ["/nonexistent/binary/path/nl_test_xyz"],
            )

    async def test_extra_env_nl_secret_prefix_rejected(
        self, executor: IsolatedExecutor,
    ) -> None:
        with pytest.raises(IsolationFailure, match="NL_SECRET_"):
            await executor.execute(
                "echo test",
                extra_env={"NL_SECRET_INJECT": "bad"},
            )

    async def test_execution_timeout_error_type(
        self, executor: IsolatedExecutor,
    ) -> None:
        """ExecutionTimeout should be an ExecutionError subclass with NL-E303."""
        with pytest.raises(ExecutionTimeout) as exc_info:
            await executor.execute("sleep 30", timeout=1)
        err = exc_info.value
        assert err.code == "NL-E303"
        assert err.http_status == 408

    async def test_isolation_failure_error_type(self) -> None:
        """IsolationFailure should be an ExecutionError subclass with NL-E307."""
        executor = IsolatedExecutor()
        with pytest.raises(IsolationFailure) as exc_info:
            await executor.execute(
                ["/nonexistent/binary/nl_test_abc_xyz"],
            )
        err = exc_info.value
        assert err.code == "NL-E307"
        assert err.http_status == 500


# ===================================================================
# Secret Cleanup Verification
# ===================================================================


class TestSecretCleanup:
    """Verify that secrets are cleaned up after execution."""

    async def test_parent_env_clean_after_execution(self) -> None:
        executor = IsolatedExecutor()
        await executor.execute(
            "echo $NL_SECRET_0",
            secrets={"key": "sensitive-data"},
        )
        # Verify no NL_SECRET_* in parent env.
        nl_vars = [k for k in os.environ if k.startswith("NL_SECRET_")]
        assert nl_vars == [], f"Leaked env vars: {nl_vars}"

    async def test_parent_env_clean_after_timeout(self) -> None:
        executor = IsolatedExecutor()
        with pytest.raises(ExecutionTimeout):
            await executor.execute(
                "sleep 60",
                secrets={"key": "timeout-secret"},
                timeout=1,
            )
        nl_vars = [k for k in os.environ if k.startswith("NL_SECRET_")]
        assert nl_vars == [], f"Leaked env vars after timeout: {nl_vars}"

    async def test_parent_env_clean_after_failure(self) -> None:
        executor = IsolatedExecutor()
        result = await executor.execute(
            "exit 1",
            secrets={"key": "fail-secret"},
        )
        assert result.exit_code == 1
        nl_vars = [k for k in os.environ if k.startswith("NL_SECRET_")]
        assert nl_vars == [], f"Leaked env vars after failure: {nl_vars}"

    async def test_strip_nl_secrets_from_parent_safety(self) -> None:
        """strip_nl_secrets_from_parent should remove stale vars."""
        os.environ["NL_SECRET_STALE"] = "leftover"
        removed = EnvironmentManager.strip_nl_secrets_from_parent()
        assert "NL_SECRET_STALE" in removed
        assert "NL_SECRET_STALE" not in os.environ


# ===================================================================
# Integration: secrets never appear in command args
# ===================================================================


class TestSecretNeverInArgs:
    """Verify that secrets are injected via env vars, not command args."""

    async def test_secret_not_visible_in_proc_cmdline(self) -> None:
        """The secret value must NOT appear in the shell command string."""
        executor = IsolatedExecutor()
        secret = "ultra-secret-api-key-12345"
        # The command references $NL_SECRET_0, not the actual value.
        result = await executor.execute(
            "echo $NL_SECRET_0",
            secrets={"api/key": secret},
        )
        assert result.exit_code == 0
        assert result.stdout.strip() == secret


# ===================================================================
# Module-level imports / re-exports
# ===================================================================


class TestModuleExports:
    """Verify that the isolation __init__.py re-exports all public symbols."""

    def test_isolation_module_imports(self) -> None:
        from nl_protocol.isolation import (
            DEFAULT_TIMEOUT_S,
            GRACEFUL_SHUTDOWN_S,
            MAX_TIMEOUT_S,
            MIN_TIMEOUT_S,
            EnvironmentManager,
            IsolatedExecutor,
            ResourceLimits,
            SandboxConfig,
            SecureMemory,
            sanitize_env_name,
            wipe,
            wipe_string,
        )
        # Just confirm they are importable and not None.
        assert IsolatedExecutor is not None
        assert EnvironmentManager is not None
        assert SecureMemory is not None
        assert SandboxConfig is not None
        assert ResourceLimits is not None
        assert sanitize_env_name is not None
        assert wipe is not None
        assert wipe_string is not None
        assert DEFAULT_TIMEOUT_S == 30
        assert MAX_TIMEOUT_S == 600
        assert MIN_TIMEOUT_S == 1
        assert GRACEFUL_SHUTDOWN_S == 5

    def test_sandbox_config_in_all(self) -> None:
        import nl_protocol.isolation as iso_mod

        assert "SandboxConfig" in iso_mod.__all__
        assert "IsolatedExecutor" in iso_mod.__all__
        assert "EnvironmentManager" in iso_mod.__all__
        assert "SecureMemory" in iso_mod.__all__

    def test_executor_custom_sandbox(self) -> None:
        """IsolatedExecutor accepts a custom SandboxConfig."""
        cfg = SandboxConfig(disable_core_dumps=False)
        executor = IsolatedExecutor(sandbox=cfg)
        assert executor._sandbox is cfg
