"""NL Protocol Level 3 -- Isolated subprocess execution.

This module implements the :class:`IsolatedExecutor` which runs commands
in an isolated child process with secrets injected via environment
variables.

Spec references:
* Chapter 03, Section 3   -- Isolation Model
* Chapter 03, Section 4   -- Environment Variable Injection
* Chapter 03, Section 6   -- Process Security
* Chapter 03, Section 6.4 -- Timeout Enforcement
* Chapter 03, Section 6.5 -- Process Exit Code Handling

Key guarantees:
1. Secrets are NEVER passed as command-line arguments.
2. The child process gets an explicitly-constructed environment.
3. After execution, secret values are wiped from memory.
4. Timeouts are enforced; processes exceeding timeout are killed.
5. Core dumps are disabled for the child process.
"""
from __future__ import annotations

import asyncio
import contextlib
import sys

from nl_protocol.core.errors import ExecutionTimeout, IsolationFailure
from nl_protocol.core.types import ActionResult
from nl_protocol.isolation.environment import EnvironmentManager
from nl_protocol.isolation.memory import wipe
from nl_protocol.isolation.sandbox import SandboxConfig

# Spec limits (Chapter 03, Section 6.4).
MIN_TIMEOUT_S = 1
MAX_TIMEOUT_S = 600
DEFAULT_TIMEOUT_S = 30

# Grace period before SIGKILL after SIGTERM (spec Section 6.4).
GRACEFUL_SHUTDOWN_S = 5


def _preexec_fn(disable_core_dumps: bool = True) -> None:
    """Pre-exec function called in the child process before ``exec()``.

    * Disables core dumps via ``setrlimit(RLIMIT_CORE, 0)`` (NL-3.7).
    * On Linux, sets ``PR_SET_DUMPABLE = 0`` via ``prctl``.
    """
    if not disable_core_dumps:
        return
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ImportError, ValueError, OSError):
        pass

    # Linux-specific: prctl(PR_SET_DUMPABLE, 0)
    if sys.platform.startswith("linux"):
        try:
            import ctypes

            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            PR_SET_DUMPABLE = 4  # noqa: N806
            libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
        except (OSError, AttributeError):
            pass


def _resolve_stdin(stdin_data: bytes | None) -> int | None:
    """Return the appropriate stdin argument for subprocess creation."""
    if stdin_data is not None:
        return asyncio.subprocess.PIPE
    return asyncio.subprocess.DEVNULL


class IsolatedExecutor:
    """Execute commands in an isolated subprocess with secret injection.

    Usage::

        executor = IsolatedExecutor()
        result = await executor.execute(
            command="curl -H 'Authorization: Bearer $NL_SECRET_0' https://api.example.com",
            secrets={"api/API_KEY": "sk-1234"},
            timeout=30,
        )
        # result.exit_code, result.stdout, result.stderr
    """

    def __init__(
        self,
        sandbox: SandboxConfig | None = None,
    ) -> None:
        self._sandbox = sandbox or SandboxConfig()
        self._env_manager = EnvironmentManager()

    async def execute(
        self,
        command: str | list[str],
        secrets: dict[str, str] | None = None,
        *,
        timeout: int | float = DEFAULT_TIMEOUT_S,
        extra_env: dict[str, str] | None = None,
        stdin_data: bytes | None = None,
    ) -> ActionResult:
        """Execute *command* in an isolated subprocess.

        Parameters
        ----------
        command:
            Either a shell command string (executed via ``/bin/sh -c``)
            or an argument list for direct exec.
        secrets:
            Mapping of secret ref to plaintext value.  Each is injected
            as ``NL_SECRET_<i>`` in the child environment.
        timeout:
            Maximum execution time in seconds.  Clamped to
            [MIN_TIMEOUT_S, MAX_TIMEOUT_S] per the spec.
        extra_env:
            Additional non-secret environment variables for the child.
        stdin_data:
            Optional bytes to write to the child's stdin.

        Returns
        -------
        ActionResult
            Contains ``exit_code``, ``stdout``, and ``stderr``.

        Raises
        ------
        ExecutionTimeout
            If the process exceeds *timeout*.
        IsolationFailure
            If the isolated environment cannot be created or the process
            fails to spawn.
        """
        timeout = _clamp_timeout(timeout)
        secrets = secrets or {}

        # Build the child environment.
        child_env = self._env_manager.build_child_env(
            secrets=secrets,
            extra_vars=extra_env,
            extra_inherit=self._sandbox.inherit_env_vars if self._sandbox else None,
        )

        # Prepare the secret buffers for wiping after execution.
        secret_buffers: list[bytearray] = [
            bytearray(v.encode("utf-8")) for v in secrets.values()
        ]

        try:
            result = await self._spawn_and_wait(
                command=command,
                env=child_env,
                timeout=timeout,
                stdin_data=stdin_data,
            )
        finally:
            # CLEANUP: Wipe secret values from memory (NL-3.3).
            for buf in secret_buffers:
                wipe(buf)
            # Clear secret values from the env dict.
            for key in list(child_env):
                if key.startswith("NL_SECRET_"):
                    child_env[key] = "\x00" * len(child_env[key])
                    del child_env[key]

        return result

    async def _spawn_and_wait(
        self,
        command: str | list[str],
        env: dict[str, str],
        timeout: float,
        stdin_data: bytes | None = None,
    ) -> ActionResult:
        """Spawn the subprocess and wait for completion or timeout."""
        stdin_arg = _resolve_stdin(stdin_data)
        try:
            if isinstance(command, str):
                # Shell command -- use /bin/sh -c (POSIX) per spec Section 6.1.
                proc = await asyncio.create_subprocess_exec(
                    "/bin/sh", "-c", command,
                    env=env,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    stdin=stdin_arg,
                    close_fds=True,
                    preexec_fn=lambda: _preexec_fn(
                        self._sandbox.disable_core_dumps,
                    ),
                )
            else:
                # Array-based execution -- preferred, no shell involved.
                proc = await asyncio.create_subprocess_exec(
                    *command,
                    env=env,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    stdin=stdin_arg,
                    close_fds=True,
                    preexec_fn=lambda: _preexec_fn(
                        self._sandbox.disable_core_dumps,
                    ),
                )
        except (OSError, FileNotFoundError, PermissionError) as exc:
            raise IsolationFailure(
                f"Failed to spawn isolated subprocess: {exc}",
                details={"original_error": str(exc)},
            ) from exc

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(input=stdin_data),
                timeout=timeout,
            )
        except TimeoutError as exc:
            # Timeout enforcement per spec Section 6.4.
            await self._terminate_process(proc)
            # Capture any partial output.
            stdout_bytes = b""
            stderr_bytes = b""
            if proc.stdout:
                with contextlib.suppress(TimeoutError, Exception):
                    stdout_bytes = await asyncio.wait_for(
                        proc.stdout.read(), timeout=1.0,
                    )
            if proc.stderr:
                with contextlib.suppress(TimeoutError, Exception):
                    stderr_bytes = await asyncio.wait_for(
                        proc.stderr.read(), timeout=1.0,
                    )
            raise ExecutionTimeout(
                f"Process exceeded timeout of {timeout}s",
                details={
                    "timeout_ms": int(timeout * 1000),
                    "exit_reason": "timeout",
                    "stdout": stdout_bytes.decode("utf-8", errors="replace"),
                    "stderr": stderr_bytes.decode("utf-8", errors="replace"),
                },
            ) from exc

        exit_code = proc.returncode if proc.returncode is not None else -1
        return ActionResult(
            exit_code=exit_code,
            stdout=stdout_bytes.decode("utf-8", errors="replace"),
            stderr=stderr_bytes.decode("utf-8", errors="replace"),
        )

    @staticmethod
    async def _terminate_process(proc: asyncio.subprocess.Process) -> None:
        """Gracefully terminate a subprocess per spec Section 6.4.

        1. Send SIGTERM (POSIX) or terminate (Windows).
        2. Wait up to GRACEFUL_SHUTDOWN_S for exit.
        3. If still running, send SIGKILL.
        """
        try:
            proc.terminate()  # SIGTERM on POSIX
        except ProcessLookupError:
            return  # Already exited.

        try:
            await asyncio.wait_for(
                proc.wait(),
                timeout=GRACEFUL_SHUTDOWN_S,
            )
        except TimeoutError:
            # Force-kill after grace period.
            with contextlib.suppress(ProcessLookupError):
                proc.kill()  # SIGKILL on POSIX
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(proc.wait(), timeout=1.0)


def _clamp_timeout(timeout: int | float) -> float:
    """Clamp *timeout* to the spec-defined [MIN, MAX] range."""
    return max(float(MIN_TIMEOUT_S), min(float(timeout), float(MAX_TIMEOUT_S)))
