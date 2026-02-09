"""NL Protocol Level 3 -- Execution Isolation.

This subpackage implements the execution isolation layer as defined in the
NL Protocol Specification v1.0, Chapter 03.  It provides:

* **IsolatedExecutor** -- async subprocess execution with secret injection
  via environment variables, timeout enforcement, and memory cleanup
  (Sections 3-6).
* **EnvironmentManager** -- explicit child environment construction with
  ``NL_SECRET_*`` mapping, collision detection, and parent sanitisation
  (Section 4).
* **SecureMemory** -- secure memory wipe for secret values after use,
  with context-manager support (Section 5).
* **SandboxConfig** -- platform-specific sandbox configuration for
  resource limits, namespace isolation, and core-dump prevention
  (Sections 6, 8, 9).

The core guarantee of Level 3 is:

    Secrets exist ONLY inside an isolated child process.  They never
    exist in the agent's process, the agent's memory, or any state
    observable by the agent.
"""
from __future__ import annotations

from nl_protocol.isolation.environment import EnvironmentManager, sanitize_env_name
from nl_protocol.isolation.memory import SecureMemory, wipe, wipe_string
from nl_protocol.isolation.sandbox import ResourceLimits, SandboxConfig
from nl_protocol.isolation.subprocess import (
    DEFAULT_TIMEOUT_S,
    GRACEFUL_SHUTDOWN_S,
    MAX_TIMEOUT_S,
    MIN_TIMEOUT_S,
    IsolatedExecutor,
)

__all__ = [
    # Subprocess execution
    "IsolatedExecutor",
    "DEFAULT_TIMEOUT_S",
    "MAX_TIMEOUT_S",
    "MIN_TIMEOUT_S",
    "GRACEFUL_SHUTDOWN_S",
    # Environment management
    "EnvironmentManager",
    "sanitize_env_name",
    # Secure memory
    "SecureMemory",
    "wipe",
    "wipe_string",
    # Sandbox configuration
    "SandboxConfig",
    "ResourceLimits",
]
