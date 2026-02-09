"""NL Protocol Level 3 -- Sandbox configuration.

This module defines the :class:`SandboxConfig` dataclass for platform-specific
sandbox configuration.  It is a *config/model* layer only -- actual
OS-level sandboxing (namespaces, seccomp, App Sandbox) is platform-specific
and would be applied by the :class:`IsolatedExecutor` at spawn time.

Spec references:
* Chapter 03, Section 8   -- Cross-platform considerations
* Chapter 03, Section 9   -- Advanced isolation (OPTIONAL)
* Chapter 03, Section 6.3 -- No core dumps
"""
from __future__ import annotations

import sys
from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class ResourceLimits:
    """Process resource limits applied to the isolated child.

    These map to POSIX ``setrlimit`` / Windows job-object limits.

    Attributes
    ----------
    max_memory_bytes:
        Maximum resident set size in bytes.  ``None`` means no limit.
    max_cpu_seconds:
        Maximum CPU time in seconds.  ``None`` means no limit.
    max_file_descriptors:
        Maximum number of open file descriptors.  ``None`` means no limit.
    """

    max_memory_bytes: int | None = None
    max_cpu_seconds: int | None = None
    max_file_descriptors: int | None = None


@dataclass(frozen=True, slots=True)
class SandboxConfig:
    """Platform-specific sandbox configuration for isolated execution.

    This is a declarative configuration object.  It does **not** perform
    sandboxing itself -- the :class:`IsolatedExecutor` reads these
    settings when preparing the child process.

    Attributes
    ----------
    disable_core_dumps:
        MUST be ``True`` for NL-compliant execution (NL-3.7).
    disable_network:
        If ``True``, the child process should have no network access
        (requires Linux network namespace or equivalent).
    allowed_read_paths:
        Filesystem paths the child is allowed to read.  An empty list
        means "unrestricted" (default).  This is only enforced on
        platforms with filesystem sandboxing (e.g. macOS sandbox
        profiles, Linux Landlock).
    allowed_write_paths:
        Filesystem paths the child is allowed to write.
    resource_limits:
        CPU, memory, and file descriptor limits for the child.
    use_pid_namespace:
        Linux-only: isolate the child in its own PID namespace
        (``CLONE_NEWPID``).
    use_network_namespace:
        Linux-only: isolate the child in its own network namespace
        (``CLONE_NEWNET``).
    inherit_env_vars:
        Additional environment variable names to inherit from the parent
        (beyond the spec-defined defaults: PATH, HOME, LANG, LC_*,
        TERM, TMPDIR, TZ).
    """

    disable_core_dumps: bool = True
    disable_network: bool = False
    allowed_read_paths: list[str] = field(default_factory=list)
    allowed_write_paths: list[str] = field(default_factory=list)
    resource_limits: ResourceLimits = field(default_factory=ResourceLimits)
    use_pid_namespace: bool = False
    use_network_namespace: bool = False
    inherit_env_vars: list[str] = field(default_factory=list)

    @property
    def platform(self) -> str:
        """Return the current platform identifier (``posix`` or ``nt``)."""
        return "nt" if sys.platform == "win32" else "posix"

    @property
    def is_linux(self) -> bool:
        """Return ``True`` when running on Linux."""
        return sys.platform.startswith("linux")

    @property
    def is_macos(self) -> bool:
        """Return ``True`` when running on macOS."""
        return sys.platform == "darwin"
