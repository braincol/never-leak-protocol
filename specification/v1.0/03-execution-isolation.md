# NL Protocol Specification v1.0 -- Level 3: Execution Isolation

**Status:** 1.0
**Version:** 1.0.0
**Date:** 2026-02-08
**Level:** 3 (Enforcement)
**Conformance:** Required for all tiers (Basic, Standard, Advanced)

> **Note:** This document is a SPECIFICATION. It defines required behaviors,
> data formats, and protocols — not specific products or CLI commands.
> For implementations of this specification, see [IMPLEMENTATIONS.md](../../IMPLEMENTATIONS.md).

---

## 1. Purpose

Levels 1 and 2 define identity and the action-based access model. Level 3
defines **how** secrets are physically isolated during action execution.

The core guarantee of Level 3 is:

> **Secrets exist ONLY inside an isolated child process. They never
> exist in the agent's process, the agent's memory, or any state
> observable by the agent.**

Level 2 defines the *what* (actions, not secrets); Level 3 defines the
*how* (isolation boundary, environment variable injection, memory
lifecycle, secure temporary files, timeout enforcement).

This specification defines:

- The isolation model and security boundary
- Environment variable injection in subprocesses
- Memory protection and secret wiping
- Process security (no shell expansion, no core dumps, timeouts)
- Temporary file security (permissions, lifecycle, secure deletion)
- Cross-platform considerations (macOS, Linux, Windows)
- What is in scope and out of scope for isolation

---

## 2. Requirements Summary

| ID | Requirement | Priority | Description |
|----|-------------|----------|-------------|
| NL-3.1 | Process Isolation | MUST | Secrets MUST be injected into an isolated child process, never into the agent's own process. |
| NL-3.2 | Environment Variable Injection | MUST | Secrets MUST be passed to the child process as environment variables, not as command-line arguments. |
| NL-3.3 | Memory Wipe | MUST | After execution completes, the parent process MUST overwrite the secret values in memory with zeros or random data before releasing the memory. |
| NL-3.4 | No Shell Expansion in Parent | MUST | Secret values MUST NOT be subject to shell expansion (`$VAR`, backticks, `$(...)`) in the parent process. |
| NL-3.5 | Tempfile Security | MUST | Temporary files containing secrets MUST have permissions `0o400` or more restrictive, and MUST be securely deleted after use. |
| NL-3.6 | Timeout Enforcement | MUST | Every action execution MUST have a configurable timeout. Processes that exceed the timeout MUST be terminated. |
| NL-3.7 | No Core Dumps | MUST | Core dumps MUST be disabled for processes that handle secret values. |
| NL-3.8 | Output Capture | MUST | stdout and stderr of the child process MUST be captured by the parent for sanitization (Level 2, Section 9). |
| NL-3.9 | Process Termination Cleanup | MUST | When the child process terminates (normally or abnormally), all secret material MUST be cleaned up. |
| NL-3.10 | Namespace Isolation | MAY | On Linux, implementations MAY use PID and network namespaces for additional isolation. |
| NL-3.11 | Secure Memory | MAY | Implementations MAY use `mlock()` to prevent secret memory pages from being written to swap. |
| NL-3.12 | Sandbox Integration | MAY | On macOS, implementations MAY use the sandbox facility (`sandbox-exec` or App Sandbox) for additional isolation. |

---

## 3. Isolation Model

### 3.1 Security Boundary

The isolation boundary separates two domains:

```
+---------------------------------------------------------------+
|                     AGENT DOMAIN                               |
|                                                                |
|  The agent's process, memory, context window, and any state    |
|  accessible to the LLM. Secrets MUST NEVER exist here.        |
|                                                                |
|  What the agent sees:                                          |
|    - Opaque handles: {{nl:API_KEY}}                            |
|    - Action results: {"stdout": "...", "exit_code": 0}         |
|    - Secret names (for reference): ["api/API_KEY"]             |
|                                                                |
|  What the agent NEVER sees:                                    |
|    - Secret values: "sk-1234567890abcdef"                      |
|    - Decrypted material of any kind                            |
|    - Environment variables containing secrets                  |
|    - Temporary files containing secrets                        |
+-------------------------------+-------------------------------+
                                |
                     ISOLATION BOUNDARY
              (process boundary, env var scope)
                                |
+-------------------------------+-------------------------------+
|                   ISOLATION DOMAIN                             |
|                                                                |
|  An isolated child process where secrets exist temporarily     |
|  for the duration of action execution.                         |
|                                                                |
|  What exists here:                                             |
|    - Secret values as environment variables (NL_SECRET_0, etc) |
|    - The actual command execution                              |
|    - Temporary files with secret content (if inject_tempfile)  |
|                                                                |
|  Lifecycle: created -> secrets injected -> executed ->          |
|             output captured -> secrets wiped -> destroyed       |
+---------------------------------------------------------------+
```

### 3.2 Isolation Guarantees

The isolation boundary provides the following guarantees:

1. **Process separation:** The child process is a separate OS process.
   The agent's process cannot read the child's environment variables or
   memory (absent root/admin privileges on the host, which is out of
   scope).

2. **Environment scoping:** Environment variables set for the child
   process do NOT propagate to the parent process or to any other
   process.

3. **Unidirectional data flow:** Data flows from the parent to the child
   (env vars, stdin) and from the child to the parent (stdout, stderr,
   exit code). The child cannot write to the parent's memory.

4. **Temporal limitation:** Secrets exist in the isolation domain only
   for the duration of execution. Before and after execution, secrets
   do not exist in any accessible memory.

### 3.3 Execution Flow

```
Parent Process (NL-Compliant System)
  |
  |  1. RESOLVE: Look up secret values from secure storage
  |     - Decrypt secrets (AEAD, key wrapping, etc.)
  |     - Store in secure memory (mlock if available)
  |
  |  2. PREPARE: Create child process configuration
  |     - Build env var map: {NL_SECRET_0: value, NL_SECRET_1: value, ...}
  |     - Rewrite command template: {{nl:X}} -> $NL_SECRET_0
  |     - Set process attributes (no core dumps, timeout)
  |
  |  3. SPAWN: Create isolated child process
  |     - fork() + exec() (POSIX) or CreateProcess (Windows)
  |     - Pass env vars to child ONLY (not to parent's env)
  |     - Redirect stdout/stderr to pipes
  |
  |  4. EXECUTE: Child process runs the command
  |     |
  |     |  [CHILD PROCESS - ISOLATION DOMAIN]
  |     |  - Command executes with secrets as env vars
  |     |  - Output written to stdout/stderr pipes
  |     |  - Process exits with exit code
  |     |
  |
  |  5. CAPTURE: Parent reads stdout/stderr from pipes
  |     - Read until EOF or timeout
  |     - Collect exit code via waitpid() / WaitForSingleObject()
  |
  |  6. SANITIZE: Scan output for leaked secrets (Level 2, Section 9)
  |     - Replace any detected secret values with [NL-REDACTED:name]
  |
  |  7. CLEANUP: Wipe all secret material
  |     - Overwrite secret values in memory with zeros
  |     - Delete temporary files (overwrite then unlink)
  |     - Release secure memory (munlock if used)
  |
  |  8. RESPOND: Return sanitized result to agent
  |     - stdout, stderr, exit_code
  |     - List of secrets used (names only)
  |     - Redaction status
  |
```

---

## 4. Environment Variable Injection

### 4.1 Rationale

Secrets MUST be passed to child processes as environment variables, not
as command-line arguments. This is because:

1. **Command-line arguments are visible in process listings.** On POSIX
   systems, `ps aux` and `/proc/PID/cmdline` expose command arguments to
   all users. Environment variables are only visible to the process
   owner and root.

2. **Command-line arguments may be logged.** Shell history, audit logs
   (auditd, osquery), and process accounting systems often record
   command-line arguments but not environment variables.

3. **Shell expansion risks.** Command arguments undergo shell expansion,
   which could transform or expose secret values. Environment variables
   referenced as `$VAR` are expanded by the child's shell, not the
   parent's.

### 4.2 Variable Naming Convention

When injecting secrets into a child process, the NL-compliant system
MUST use the following naming convention:

```
NL_SECRET_<INDEX>
```

Where `<INDEX>` is a zero-based integer corresponding to the order in
which placeholders appear in the action template.

**Example:**

Template:
```
curl -u "{{nl:api/USERNAME}}:{{nl:api/PASSWORD}}" https://api.example.com
```

Environment variables:
```
NL_SECRET_0=actual_username_value
NL_SECRET_1=actual_password_value
```

Rewritten command:
```
curl -u "$NL_SECRET_0:$NL_SECRET_1" https://api.example.com
```

### 4.3 Implementation Requirements

1. The parent process MUST create a new environment for the child process.
   This environment MUST include the `NL_SECRET_*` variables and MAY
   include a minimal set of standard system variables (`PATH`, `HOME`,
   `LANG`, `TERM`) but MUST NOT include the parent's full environment
   unless explicitly configured.

2. The `NL_SECRET_*` variables MUST NOT be set in the parent's own
   environment. They MUST exist only in the child process's environment
   block.

3. Implementations MUST ensure that the environment variable values are
   not written to any persistent storage (log files, audit records,
   configuration files) by the NL-compliant system itself.

4. The child process MUST NOT be able to modify the parent's environment.
   This is guaranteed by the OS process model on all supported platforms.

5. If the isolated subprocess forks child processes, those children MUST
   NOT inherit the `NL_SECRET_*` environment variables.

6. Implementations SHOULD set `NL_SECRET_*` variables with the subprocess
   API rather than the system environment to prevent inheritance.

7. On POSIX, implementations SHOULD use `PR_SET_NO_NEW_PRIVS` (Linux) or
   equivalent to prevent child privilege escalation.

### 4.4 Inherited Environment

The child process's environment MUST be constructed explicitly. The
system MUST NOT blindly inherit the parent's full environment, as it
may contain other sensitive data.

The following variables SHOULD be inherited from the parent (if present):

| Variable | Reason |
|----------|--------|
| `PATH` | Required for command resolution. |
| `HOME` | Required by many tools for configuration lookup. |
| `LANG`, `LC_*` | Locale settings for consistent output encoding. |
| `TERM` | Terminal type (relevant for interactive commands). |
| `TMPDIR` | Temporary directory location. |
| `TZ` | Timezone (for timestamp consistency). |

All other environment variables MUST be excluded unless the action
request explicitly specifies additional variables to inherit.

---

## 5. Memory Protection

### 5.1 Secret Memory Lifecycle

A secret value passes through five stages in memory:

```
STAGE 1: RETRIEVAL
  Secret decrypted from secure storage.
  Stored in a dedicated buffer.
  Duration: as short as possible.

       |
       v

STAGE 2: PREPARATION
  Secret value copied into child process
  environment block (fork/exec model) or
  passed via CreateProcess (Windows).
  Original buffer: marked for wipe.

       |
       v

STAGE 3: EXECUTION
  Secret exists in child process's address
  space as environment variable value.
  Parent has secret in its preparation buffer.

       |
       v

STAGE 4: CLEANUP
  Child process terminated.
  Parent overwrites buffer with zeros: memset(ptr, 0, len)
  If mlock was used: munlock().
  Pointer set to null. Buffer deallocated.

       |
       v

STAGE 5: VERIFICATION
  Output scanned for leaked secrets.
  If found: redact and log security event.
  All secret references cleared.
```

### 5.2 Memory Wipe Requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| NL-3.3.1 | After execution, secret values in the parent process MUST be overwritten with zeros or cryptographically random data before the memory is freed. | MUST |
| NL-3.3.2 | Implementations MUST use explicit overwrite functions that are not subject to compiler optimization (dead store elimination). | MUST |
| NL-3.3.3 | On platforms that support it, implementations SHOULD use `explicit_bzero()` (BSD/macOS), `SecureZeroMemory()` (Windows), or `memset_s()` (C11 Annex K). | SHOULD |
| NL-3.3.4 | Implementations SHOULD NOT rely on garbage collection to free secret memory. Secrets SHOULD be stored in buffers with explicit lifecycle control. | SHOULD |
| NL-3.3.5 | If using a language with garbage collection (Python, Go, JavaScript), implementations SHOULD use a native extension or FFI call for secure wiping, as GC may copy objects in memory. | SHOULD |

#### 5.2.1 Secure Zeroing Function Selection and Verification

Implementations MUST use platform-specific secure zeroing functions that are guaranteed not to be optimized away by the compiler: `explicit_bzero()` (POSIX), `SecureZeroMemory()` (Windows), or `memset_s()` (C11 Annex K). These functions are specifically designed to resist dead-store elimination by the compiler and MUST be preferred over plain `memset()`.

If none of these platform-specific functions are available, implementations MUST use a volatile function pointer pattern to prevent the compiler from optimizing away the zeroing operation:

```c
static void * (*volatile memset_func)(void *, int, size_t) = memset;
memset_func(secret_buffer, 0, secret_len);
```

Implementations SHOULD verify that zeroing occurred by reading back a sample of the zeroed memory and comparing to zero. The verification SHOULD read at least the first byte, the last byte, and one byte at the midpoint of the buffer. If verification fails (any sampled byte is non-zero after the zeroing operation), the implementation MUST log a CRITICAL security event containing the buffer address range and the number of non-zero bytes detected. The implementation MUST then retry the zeroing operation using an alternative method (e.g., a byte-by-byte volatile write loop) and verify again.

Compiler optimization flags (`-O2`, `-O3`, `-Os`) MUST NOT remove the zeroing operation. Implementations SHOULD include a build-time or CI test that compiles a test program at each supported optimization level, performs a secure zeroing operation, and verifies via inspection of the resulting binary (e.g., by checking for the presence of the zeroing call in the disassembly) or by runtime verification that the zeroing survives optimization. This test MUST be part of the implementation's standard test suite and MUST fail the build if secure zeroing is optimized away.

### 5.3 Language-Specific Guidance

| Language | Secure Wipe Mechanism | Notes |
|----------|----------------------|-------|
| **C** | `explicit_bzero()`, `memset_s()`, or volatile pointer pattern | Compiler may optimize away `memset()`. Use `explicit_bzero()` on BSD/macOS or `SecureZeroMemory()` on Windows. |
| **Rust** | `zeroize` crate | Provides `Zeroize` trait that prevents compiler optimization. Use `ZeroizeOnDrop` for automatic cleanup. |
| **Python** | `ctypes.memset()` on `bytearray` | Python strings are immutable and copied by GC. Use `bytearray` for secrets, then `ctypes.memset(ctypes.addressof(...), 0, len)`. |
| **Go** | `crypto/subtle` or manual loop with `runtime.KeepAlive` | Go's GC may move memory. Use `[]byte` (not `string`), zero explicitly, and prevent optimization with `runtime.KeepAlive`. |
| **Node.js** | `Buffer.alloc()` + `buf.fill(0)` | Use `Buffer` (not `string`) for secrets. `buf.fill(0)` before releasing. |
| **Java** | `char[]` + `Arrays.fill(array, '\0')` | Use `char[]` (not `String`) for secrets. `String` objects are interned and GC-managed. |

### 5.4 Swap Prevention

Implementations MAY use operating system facilities to prevent secret
memory pages from being written to swap (virtual memory on disk):

| Platform | Mechanism | Notes |
|----------|-----------|-------|
| **Linux** | `mlock()` or `mlock2()` | Locks pages in physical RAM. Requires `CAP_IPC_LOCK` or sufficient `RLIMIT_MEMLOCK`. |
| **macOS** | `mlock()` | Same semantics as Linux. |
| **Windows** | `VirtualLock()` | Locks pages in physical RAM. Requires `SE_LOCK_MEMORY_PRIVILEGE`. |

Swap prevention is OPTIONAL (MAY) but RECOMMENDED for production
deployments handling high-sensitivity secrets.

---

## 6. Process Security

### 6.1 No Shell Expansion in Parent

Secret values MUST NOT undergo shell expansion in the parent process.
This means:

1. The parent process MUST NOT pass secrets through a shell interpreter.
   For example, `system("command " + secret)` is PROHIBITED because the
   shell will expand special characters in the secret value.

2. The parent process MUST use `exec()`-family functions (POSIX) or
   `CreateProcess()` (Windows) to launch the child process, NOT
   `system()` or equivalent shell-invoking functions.

3. The command template rewriting (replacing `{{nl:...}}` with
   `$NL_SECRET_N`) MUST occur as a string operation in the parent. The
   actual expansion of `$NL_SECRET_N` to the secret value occurs inside
   the child process's shell.

**Correct:**
```python
# Parent process
import subprocess

env = {
    "NL_SECRET_0": "actual-secret-value",
    "PATH": os.environ.get("PATH", ""),
}
command = 'curl -H "Authorization: Bearer $NL_SECRET_0" https://api.example.com'

result = subprocess.run(
    ["/bin/sh", "-c", command],
    env=env,
    capture_output=True,
    timeout=30,
)
```

**INCORRECT (shell expansion in parent):**
```python
# WRONG - secret is in the command string, visible in ps
import subprocess

secret = "actual-secret-value"
command = f'curl -H "Authorization: Bearer {secret}" https://api.example.com'
result = subprocess.run(command, shell=True, capture_output=True)
```

### 6.2 Template Safety and Shell Escaping

**Ownership Note**: Shell escaping is exclusively a Level 3 (Execution Isolation) responsibility. Level 2 (Action-Based Access) handles output sanitization only. The escaping pipeline is:

1. Level 2 resolves placeholders → produces action template with secret values
2. **Level 3 applies shell escaping** immediately before subprocess invocation
3. Level 3 executes the subprocess in an isolated environment
4. Level 2 sanitizes the output returned to the agent

This separation prevents double-escaping: Level 2 MUST NOT apply shell escaping to action templates. See Chapter 02, Section 9 for the output sanitization scope.

When secrets are injected into shell command templates, the NL Provider MUST escape secret values to prevent shell metacharacter injection.

**Requirements:**
1. All secret values injected into `exec` type actions MUST be shell-escaped using platform-appropriate escaping before injection
2. On POSIX systems, implementations MUST use the equivalent of Python's `shlex.quote()` or Go's `shellescape.Quote()`
3. On Windows, implementations MUST use appropriate CMD/PowerShell escaping
4. The escaping MUST happen AFTER secret resolution and BEFORE subprocess execution
5. Implementations MUST NOT rely on the agent to provide properly escaped templates

**Example:**
If secret value is `password;rm -rf /` and template is `curl -u user:{{nl:PASSWORD}} https://api.example.com`:
- WITHOUT escaping (UNSAFE): `curl -u user:password;rm -rf / https://api.example.com`
- WITH escaping (SAFE): `curl -u user:'password;rm -rf /' https://api.example.com`

**Alternative: Array-based execution:**
Implementations SHOULD prefer array-based subprocess execution over shell invocation where possible:
- PREFERRED: `subprocess.run(["curl", "-u", f"user:{secret}", url])` -- no shell involved
- ACCEPTABLE: `subprocess.run(f"curl -u user:{shlex.quote(secret)} {url}", shell=True)` -- shell with escaping
- FORBIDDEN: `subprocess.run(f"curl -u user:{secret} {url}", shell=True)` -- shell without escaping

#### 6.2.1 Shell Escaping Edge Cases

Shell escaping MUST be applied exactly once. Implementations MUST NOT double-escape values that are already escaped. Double-escaping produces incorrect secret values at the point of use (e.g., a password containing a single quote would gain extra backslashes, causing authentication failures).

To prevent double-escaping, the system MUST track whether a value has been escaped. The recommended approach is to escape at injection time (inside the isolation boundary, immediately before the value is placed into the shell command), never before. Secret values retrieved from storage MUST be stored in their raw, unescaped form until the moment of injection. If a value passes through multiple processing stages, only the final stage that constructs the shell command MUST apply escaping.

Shell escaping applies ONLY to secret values injected via `{{nl:...}}` placeholders into `exec` type actions where a shell interpreter is involved. Literal strings in the agent's command template MUST NOT be escaped -- they are the agent's intended command and escaping them would alter the command's semantics.

For `inject_stdin` and `inject_tempfile` action types, shell escaping MUST NOT be applied. In these action types, the secret value is not passed through a shell interpreter: it is written directly to a pipe (`inject_stdin`) or to a file (`inject_tempfile`). Applying shell escaping to these values would corrupt the secret (e.g., adding unnecessary quote characters around the value).

If a secret value contains null bytes (`\x00`), the null bytes MUST be stripped before injection into any action type, and a warning MUST be logged indicating the secret name and the number of null bytes removed. Null bytes in shell commands cause truncation at the null byte position, which would result in partial secret injection -- a security risk because the truncated command may behave unpredictably. For `inject_tempfile` actions where binary data is expected, implementations MAY allow null bytes if the action explicitly declares `binary: true` in its configuration.

### 6.3 No Core Dumps

Processes that handle secret values MUST have core dumps disabled.
A core dump writes the process's memory to disk, which would include any
secret values still in memory at the time of the crash.

| Platform | Mechanism |
|----------|-----------|
| **Linux** | `prctl(PR_SET_DUMPABLE, 0)` -- disables core dumps for the process. Alternatively, `setrlimit(RLIMIT_CORE, {0, 0})`. |
| **macOS** | `setrlimit(RLIMIT_CORE, {0, 0})` -- sets core dump size limit to zero. |
| **Windows** | `SetErrorMode(SEM_NOGPFAULTERRORBOX)` combined with `WerAddExcludedApplication()` -- prevents crash dump generation. |

Implementations MUST set these before spawning the child process.
For the child process, the settings can be applied by the parent before
`exec()` (in the fork-exec model) or by the child process itself at
startup.

### 6.4 Timeout Enforcement

Every action execution MUST have a timeout. Processes that exceed the
timeout MUST be terminated.

| Requirement | Value |
|-------------|-------|
| Default timeout | 30,000 ms (30 seconds) |
| Maximum timeout | 600,000 ms (10 minutes) |
| Minimum timeout | 1,000 ms (1 second) |
| Configurable | MUST be configurable per action request |

**Timeout enforcement procedure:**

1. The parent process sets a timer when spawning the child.
2. If the child has not exited when the timer fires:
   a. Send `SIGTERM` to the child (POSIX) or `TerminateProcess()`
      (Windows).
   b. Wait 5 seconds for graceful shutdown.
   c. If the child is still running, send `SIGKILL` (POSIX) or
      force-terminate (Windows).
3. Record the timeout in the action response (`status: "timeout"`).
4. Proceed to cleanup (Section 5.1, Stage 4).

#### 6.4.1 Platform-Specific Timeout Behavior

**POSIX systems:** The parent process MUST send `SIGTERM` to the child process when the timeout fires. The parent MUST then wait up to 5 seconds (configurable via `graceful_shutdown_ms`, default 5000ms) for the child to exit gracefully. If the child has not exited after the grace period, the parent MUST send `SIGKILL`. The signal number used at each stage (e.g., signal 15 for SIGTERM, signal 9 for SIGKILL) MUST be recorded in the audit trail.

**Windows:** Windows does not support POSIX signals. For the graceful shutdown phase, implementations MUST use `GenerateConsoleCtrlEvent(CTRL_C_EVENT, processGroupId)` to request graceful termination. The parent MUST then wait up to 5 seconds (configurable) for the child to exit. If the child has not exited after the grace period, the parent MUST call `TerminateProcess(hProcess, 1)` for forced termination. Implementations MUST NOT use `CTRL_BREAK_EVENT` for the graceful phase, as some applications do not handle it cleanly.

If the process does not exit within 1 second after `SIGKILL` (POSIX) or `TerminateProcess()` (Windows), the implementation MUST log a CRITICAL security event. This condition indicates a kernel-level issue (e.g., the process is stuck in an uninterruptible sleep state on Linux, or a driver is blocking termination on Windows). The implementation MUST escalate to the operating system's process reaper mechanism where available (e.g., on Linux, the init process (PID 1) will eventually reap zombie processes; on systemd-managed systems, `systemd-oomd` or `cgroup` kill may be triggered). The implementation MUST NOT proceed to the cleanup phase (Section 5.1, Stage 4) until the child process has fully terminated, to prevent secret material from remaining in the child's address space.

The audit record for a timed-out action MUST include the following fields in the action response metadata: `"exit_reason": "timeout"`, `"timeout_ms": <configured_timeout>` (the timeout value that was configured for this action), and `"graceful_attempted": true/false` (indicating whether the graceful shutdown phase was attempted before forced termination). If the graceful phase was attempted, the record MUST also include `"graceful_exit": true/false` (whether the process exited during the grace period) and `"graceful_wait_ms": <actual_wait>` (the actual time spent waiting during the grace period).

### 6.5 Process Exit Code Handling

| Exit Code | Meaning | Action |
|-----------|---------|--------|
| 0 | Success | Return `status: "success"` with captured output. |
| 1-125 | Command failure | Return `status: "error"` with captured output (including stderr). |
| 126 | Command not executable | Return `status: "error"` with descriptive message. |
| 127 | Command not found | Return `status: "error"` with descriptive message. |
| 128+N | Terminated by signal N | Return `status: "error"` or `"timeout"` depending on cause. |
| -1 (spawn failure) | Failed to create child process | Return `status: "error"` with system error. |

### 6.6 Standard File Descriptor Handling

| Descriptor | Handling |
|-----------|---------|
| `stdin` | Closed (for `exec`) or piped with secret value (for `inject_stdin`). MUST NOT be connected to a terminal or to the agent's stdin. |
| `stdout` | Piped to parent for capture. |
| `stderr` | Piped to parent for capture. |

The parent MUST read from both stdout and stderr pipes concurrently (or
use a mechanism like `select()`, `poll()`, or `epoll()`) to prevent
deadlocks caused by full pipe buffers.

### 6.7 File Descriptor Inheritance

Implementations MUST close all file descriptors except stdin, stdout, and
stderr before executing the isolated subprocess.

On POSIX, use `close_fds=True` (Python) or `CLOEXEC` flag on all
non-standard file descriptors.

---

## 7. Temporary File Security

### 7.1 Overview

The `inject_tempfile` action type (Level 2, Section 5.5) requires
creating temporary files that contain secret values. These files have
strict security requirements because they persist on the filesystem
(even briefly) and could be read by other processes with sufficient
privileges.

### 7.2 Requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| NL-3.5.1 | Temporary files containing secrets MUST be created with permissions `0o400` (read-only, owner only) on POSIX systems, or equivalent restrictive ACLs on Windows. | MUST |
| NL-3.5.2 | Temporary files MUST be created in a secure temporary directory (see Section 7.3). | MUST |
| NL-3.5.3 | Temporary files MUST be overwritten with random data before deletion (see Section 7.4). | MUST |
| NL-3.5.4 | Temporary files MUST have a maximum lifetime. Default: 60 seconds. Configurable. | MUST |
| NL-3.5.5 | If the parent process crashes, a cleanup mechanism SHOULD remove orphaned temporary files on next startup. | SHOULD |
| NL-3.5.6 | Temporary file names SHOULD be unpredictable (e.g., `mkstemp()` pattern). | SHOULD |
| NL-3.5.7 | The temporary directory MUST NOT be world-readable. | MUST |

### 7.3 Secure Temporary Directory

Implementations MUST create a dedicated temporary directory for NL
Protocol secret files. This directory:

1. MUST be owned by the user running the NL-compliant system.
2. MUST have permissions `0o700` (rwx for owner only) on POSIX.
3. MUST NOT be a shared temporary directory (e.g., `/tmp` without a
   subdirectory, as `/tmp` has the sticky bit but files may still be
   readable).
4. SHOULD be on a filesystem that supports POSIX permissions.
5. SHOULD be on a `tmpfs` (RAM-based filesystem) where available, to
   avoid writing secrets to persistent disk.

**RECOMMENDED directory structure:**

```
/tmp/nl-secure-<UID>/
  |-- tmpXXXXXX    (secret file, permissions 0o400)
  |-- tmpYYYYYY    (secret file, permissions 0o400)
```

On Linux with tmpfs:
```
/dev/shm/nl-secure-<UID>/
  |-- tmpXXXXXX
```

On macOS:
```
/private/var/folders/<hash>/nl-secure/
  |-- tmpXXXXXX
```

**Fallback when RAM-backed storage is unavailable:**

If RAM-backed storage (tmpfs/ramfs) is not available, implementations MUST
use the system temporary directory with restrictive permissions (mode 0700).

Implementations MUST log a warning when falling back to disk-backed
temporary storage.

On systems without tmpfs, implementations SHOULD encrypt temporary files
at rest using a session-derived key.

### 7.4 Secure File Deletion

Simply calling `unlink()` or `delete()` on a file does NOT securely
erase the data. The filesystem may retain the data blocks until they
are reused. NL-compliant implementations MUST perform secure deletion:

**Secure deletion procedure:**

```
function secureDeleteFile(path):
    1. Open the file for writing.
    2. Determine the file size.
    3. Write random data (from CSPRNG) over the entire file.
    4. Flush the write to disk: fsync(fd) or FlushFileBuffers().
    5. Close the file.
    6. Delete (unlink) the file.
    7. Optionally: fsync() on the parent directory (Linux) to ensure
       the directory entry removal is persisted.
```

Secure file deletion MUST overwrite file contents with at least ONE pass
of cryptographically random data (from CSPRNG) before unlinking.

On SSD/NVMe storage where overwrite effectiveness is limited,
implementations SHOULD use the filesystem's secure delete feature (e.g.,
`FITRIM`) or rely on full-disk encryption.

**Platform-specific notes:**

| Platform | Notes |
|----------|-------|
| **Linux (ext4, xfs)** | Single overwrite pass is sufficient for modern storage. Journaling filesystems may retain data in the journal; using tmpfs avoids this entirely. |
| **macOS (APFS)** | APFS is a copy-on-write filesystem. Overwriting a file creates a new copy. Using a RAM-based directory (or `diskutil secureErase` for volume-level wipe) is preferred. For individual files, overwrite + unlink is the best available option. |
| **Windows (NTFS)** | NTFS may retain data in alternate streams or the $MFT. Use `FILE_FLAG_DELETE_ON_CLOSE` and overwrite before closing. |
| **tmpfs / ramfs** | Data exists only in RAM. `unlink()` is sufficient since there is no persistent storage. This is the RECOMMENDED backing store for secret tempfiles. |

### 7.5 Temporary File Lifecycle

```
1. CREATE
   - mkstemp() or equivalent to create file with unique name
   - Set permissions to 0o400 (read-only, owner only)
   - Write secret value to file
   - fsync() to ensure data is written
   - Start lifetime timer (default: 60 seconds)

2. USE
   - Child process reads the file (it has read permission)
   - Child process uses the secret (e.g., SSH key, certificate)

3. WIPE
   - After child process exits (or lifetime timer expires):
   - Open file for writing (need to change permissions: chmod 0o600)
   - Overwrite with random data (same size as original content)
   - fsync() to flush
   - Close file

4. DELETE
   - unlink() / delete the file
   - fsync() parent directory (Linux) for dentry removal

5. VERIFY
   - Confirm file no longer exists (stat() returns ENOENT)
   - If orphan detected: log warning, attempt cleanup
```

---

## 8. Cross-Platform Considerations

### 8.1 POSIX (Linux, macOS)

POSIX is the primary platform for the NL Protocol. The isolation model
maps directly to POSIX primitives:

| Concept | POSIX Mechanism |
|---------|----------------|
| Process isolation | `fork()` + `exec()` |
| Environment variable injection | `execve()` env parameter |
| stdout/stderr capture | `pipe()` + `dup2()` |
| Timeout | `alarm()`, `timer_create()`, or thread-based timer |
| No core dumps | `prctl(PR_SET_DUMPABLE, 0)` (Linux) or `setrlimit(RLIMIT_CORE, 0)` |
| Memory wipe | `explicit_bzero()` (BSD/macOS) or volatile pointer pattern |
| Swap prevention | `mlock()` |
| Secure tempdir | `mkdtemp()` with `0o700` permissions |
| Secure tempfile | `mkstemp()` with `fchmod(fd, 0o400)` |
| Namespace isolation (Linux) | `unshare(CLONE_NEWPID \| CLONE_NEWNET)` |

### 8.2 macOS Specifics

macOS provides additional isolation mechanisms:

| Mechanism | Use Case |
|-----------|----------|
| **App Sandbox** | Application-level sandboxing with entitlements. |
| **sandbox-exec** | Profile-based sandboxing for arbitrary processes (deprecated but functional). |
| **Hypervisor.framework** | Lightweight virtualization for hardware-level isolation. |
| **APFS snapshots** | Copy-on-write behavior means file overwrites create new copies. Use tmpfs or RAM disk for secret files. |

For the NL Protocol, the minimum macOS requirements are:

1. `fork()` + `exec()` for process isolation (MUST).
2. `setrlimit(RLIMIT_CORE, 0)` for core dump prevention (MUST).
3. `mlock()` for swap prevention (MAY).
4. Secure temporary directory under `/private/var/folders/` or a RAM
   disk created with `hdiutil` (SHOULD).

### 8.3 Linux Specifics

Linux provides the richest set of isolation primitives:

| Mechanism | Use Case | Conformance |
|-----------|----------|-------------|
| **namespaces** | PID, network, mount isolation | MAY |
| **seccomp** | System call filtering | MAY |
| **cgroups** | Resource limits (CPU, memory) | MAY |
| **tmpfs** | RAM-backed filesystem for tempfiles | SHOULD |
| **prctl** | Core dump control, dumpable flag | MUST |
| **mlock/mlock2** | Swap prevention | MAY |
| **landlock** | Filesystem access control | MAY |

For the NL Protocol, the minimum Linux requirements are:

1. `fork()` + `exec()` for process isolation (MUST).
2. `prctl(PR_SET_DUMPABLE, 0)` for core dump prevention (MUST).
3. tmpfs for secret temporary files (SHOULD).
4. Namespace isolation (MAY): useful for preventing the child process
   from accessing network endpoints or observing other processes.

### 8.4 Windows Specifics

Windows uses a different process model than POSIX. The NL Protocol
maps to Windows primitives as follows:

| Concept | Windows Mechanism |
|---------|------------------|
| Process isolation | `CreateProcess()` with `CREATE_NO_WINDOW` |
| Environment variable injection | `lpEnvironment` parameter of `CreateProcess()` |
| stdout/stderr capture | `CreatePipe()` + `STARTUPINFO.hStdOutput/hStdError` |
| Timeout | `WaitForSingleObject()` with timeout parameter |
| No core dumps | `SetErrorMode(SEM_NOGPFAULTERRORBOX)` |
| Memory wipe | `SecureZeroMemory()` |
| Swap prevention | `VirtualLock()` |
| Secure tempdir | `GetTempPath()` + `CreateDirectory()` with restrictive DACL |
| Secure tempfile | `CreateFile()` with `FILE_ATTRIBUTE_TEMPORARY \| FILE_FLAG_DELETE_ON_CLOSE` |

For the NL Protocol, the minimum Windows requirements are:

1. `CreateProcess()` with explicit environment for process isolation (MUST).
2. `SecureZeroMemory()` for memory wipe (MUST).
3. Secure temporary directory with restrictive ACLs (MUST).
4. `SetErrorMode()` for crash dump prevention (SHOULD).

---

## 9. Advanced Isolation (OPTIONAL)

### 9.1 Namespace Isolation (Linux)

For high-security deployments on Linux, implementations MAY use kernel
namespaces to provide additional isolation:

```
unshare(CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWNS)
```

| Namespace | Isolation Provided |
|-----------|-------------------|
| `CLONE_NEWPID` | Child cannot see or signal other processes. |
| `CLONE_NEWNET` | Child has no network access by default. Network can be selectively configured. |
| `CLONE_NEWNS` | Child has an independent filesystem mount table. Can mount tmpfs privately. |
| `CLONE_NEWUSER` | Child runs as a different user ID. Provides UID isolation without root. |

**Network namespace considerations:** If the action requires network
access (e.g., `curl`), the implementation MUST either:

- Configure the network namespace with the specific endpoints the
  action needs, OR
- Use the host network namespace but apply firewall rules (iptables/
  nftables) to restrict egress.

### 9.2 Container Isolation

Implementations MAY execute actions inside lightweight containers
(e.g., OCI containers via `runc`, `containerd`, or `podman`). Container
isolation provides:

- Filesystem isolation (independent rootfs)
- Network isolation (per-container network namespace)
- Resource limits (cgroups)
- Seccomp profiles (system call filtering)

Container isolation is more overhead than process isolation but provides
stronger security boundaries. It is RECOMMENDED for `autonomous_executor`
and `orchestrator` agent types.

### 9.3 Sandbox Profiles (macOS)

On macOS, implementations MAY use sandbox profiles to restrict the child
process:

```
(version 1)
(deny default)
(allow process-exec)
(allow file-read* (subpath "/usr"))
(allow file-read* (subpath "/private/var/folders"))
(allow network-outbound (remote tcp))
(deny file-write* (subpath "/"))
```

This restricts the child process to reading system files, reading the
secure temporary directory, and making outbound network connections. All
other operations are denied.

---

## 10. Security Boundaries

### 10.1 What Is In Scope

Level 3 isolation protects against the following threats:

| Threat | Mitigation |
|--------|-----------|
| Secret values in agent's context window | Process isolation: secrets exist only in child process. |
| Secret values in command-line arguments | Environment variable injection: secrets passed as env vars, not args. |
| Secret values persisting after execution | Memory wipe: explicit zeroing of secret buffers. |
| Secret values in core dumps | Core dump prevention: `PR_SET_DUMPABLE = 0`. |
| Secret values in swap space | Swap prevention: `mlock()` (optional). |
| Secret values on persistent filesystem | tmpfs for tempfiles; secure deletion with overwrite. |
| Secret values in process listings | No command-line argument exposure. |
| Child process running indefinitely | Timeout enforcement with SIGTERM/SIGKILL. |
| Secret values in action output | Output sanitization (Level 2, Section 9). |

### 10.2 What Is Out of Scope

Level 3 isolation does NOT protect against:

| Threat | Why Out of Scope | Mitigation (if any) |
|--------|-----------------|---------------------|
| Root/admin on the host reading child process memory | An attacker with root access can read any process memory. This is a host security concern, not a protocol concern. | Host hardening, hardware enclaves (SGX/TrustZone). |
| Kernel exploits that break process isolation | Kernel vulnerabilities can bypass process boundaries. | Kernel updates, container isolation, hardware isolation. |
| Side-channel attacks (Spectre, Meltdown) | Microarchitectural attacks can leak data across process boundaries. | CPU microcode updates, kernel mitigations (KPTI). |
| The child process itself being malicious | If the command the agent constructs is malicious, it may exfiltrate the secret via network. | Pre-execution defense (Level 4): block known exfiltration patterns. Network namespace isolation (Section 9.1). |
| Physical access to the machine | An attacker with physical access can read RAM via cold boot attacks or JTAG. | Full disk encryption, memory encryption (AMD SEV, Intel TME). |

---

## 11. Implementation Reference

### 11.1 Python Reference (POSIX)

The following pseudocode illustrates a conformant Level 3 implementation
in Python on a POSIX system:

```python
import subprocess
import os
import ctypes
import tempfile
import secrets as crypto_secrets

def execute_action(command_template, secret_map, timeout_ms=30000):
    """
    Execute a command with secrets injected as environment variables.

    command_template: str with $NL_SECRET_N references (already rewritten
                      from {{nl:...}} placeholders)
    secret_map: dict mapping NL_SECRET_N -> actual secret value
    timeout_ms: maximum execution time in milliseconds
    """

    # Step 1: Build minimal environment
    child_env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
        "LANG": os.environ.get("LANG", "en_US.UTF-8"),
    }
    child_env.update(secret_map)  # Add NL_SECRET_* vars

    # Step 2: Disable core dumps for child
    def preexec():
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        # Linux-specific: prctl(PR_SET_DUMPABLE, 0)
        try:
            import ctypes
            PR_SET_DUMPABLE = 4
            ctypes.cdll['libc.so.6'].prctl(PR_SET_DUMPABLE, 0)
        except Exception:
            pass

    # Step 3: Execute in isolated subprocess
    try:
        result = subprocess.run(
            ["/bin/sh", "-c", command_template],
            env=child_env,
            capture_output=True,
            timeout=timeout_ms / 1000.0,
            preexec_fn=preexec,
        )
        stdout = result.stdout.decode("utf-8", errors="replace")
        stderr = result.stderr.decode("utf-8", errors="replace")
        exit_code = result.returncode
    except subprocess.TimeoutExpired as e:
        stdout = e.stdout.decode("utf-8", errors="replace") if e.stdout else ""
        stderr = e.stderr.decode("utf-8", errors="replace") if e.stderr else ""
        exit_code = -1  # timeout

    # Step 4: Sanitize output (Level 2, Section 9)
    # ... (scan for secret values in stdout/stderr) ...

    # Step 5: Wipe secrets from memory
    for key, value in secret_map.items():
        if isinstance(value, bytearray):
            ctypes.memset(ctypes.addressof(
                (ctypes.c_char * len(value)).from_buffer(value)
            ), 0, len(value))

    # Step 6: Return result
    return {
        "stdout": stdout,
        "stderr": stderr,
        "exit_code": exit_code,
    }
```

### 11.2 Secure Temporary File Reference (POSIX)

```python
import os
import tempfile
import secrets as crypto_secrets

def create_secure_tempfile(secret_value, secure_dir="/tmp/nl-secure"):
    """Create a secure temporary file containing a secret value."""

    # Ensure secure directory exists
    os.makedirs(secure_dir, mode=0o700, exist_ok=True)

    # Create file with mkstemp (secure, unpredictable name)
    fd, path = tempfile.mkstemp(dir=secure_dir)

    try:
        # Write secret value
        os.write(fd, secret_value.encode("utf-8"))
        os.fsync(fd)

        # Set read-only for owner
        os.fchmod(fd, 0o400)
    finally:
        os.close(fd)

    return path


def secure_delete_tempfile(path):
    """Securely delete a temporary file containing a secret."""

    try:
        # Get file size
        size = os.path.getsize(path)

        # Change permissions to allow write
        os.chmod(path, 0o600)

        # Overwrite with random data
        with open(path, "wb") as f:
            f.write(crypto_secrets.token_bytes(size))
            f.flush()
            os.fsync(f.fileno())

        # Delete
        os.unlink(path)

    except FileNotFoundError:
        pass  # Already deleted (e.g., by crash cleanup)
```

---

## 12. Conformance Checklist

### 12.1 Basic Conformance

For Basic conformance, an implementation MUST:

- [ ] Execute actions in an isolated child process (Section 3).
- [ ] Inject secrets as environment variables, not command-line arguments (Section 4).
- [ ] Use explicit environment construction for the child process (Section 4.4).
- [ ] Overwrite secret values in memory after execution (Section 5).
- [ ] Enforce configurable timeouts on all executions (Section 6.3).
- [ ] Capture stdout and stderr for sanitization (Section 6.5).
- [ ] Create temporary files with `0o400` permissions (Section 7.2).
- [ ] Securely delete temporary files (overwrite then unlink) (Section 7.4).
- [ ] NOT pass secrets through shell expansion in the parent process (Section 6.1).
- [ ] Disable core dumps for child processes (Section 6.2).

### 12.2 Standard Conformance

In addition to Basic, Standard conformance SHOULD:

- [ ] Use secure wipe functions that resist compiler optimization (Section 5.2).
- [ ] Use tmpfs or RAM-backed storage for temporary files (Section 7.3).
- [ ] Create a dedicated secure temporary directory (Section 7.3).
- [ ] Implement orphaned tempfile cleanup on startup (Section 7.2).

### 12.3 Advanced Conformance

In addition to Standard, Advanced conformance MAY:

- [ ] Use `mlock()` to prevent secrets from being written to swap (Section 5.4).
- [ ] Use Linux namespace isolation for child processes (Section 9.1).
- [ ] Use container isolation for high-risk action types (Section 9.2).
- [ ] Use macOS sandbox profiles for child processes (Section 9.3).
- [ ] Use a RAM disk for the secure temporary directory.

---

## 13. Security Considerations Summary

| Threat | Level 3 Mitigation | Priority |
|--------|-------------------|----------|
| Secret in agent context | Process isolation | MUST |
| Secret in command args | Env var injection | MUST |
| Secret persisting in RAM | Memory wipe | MUST |
| Secret in core dump | Core dump prevention | MUST |
| Secret in swap | mlock() | MAY |
| Secret on disk (tempfile) | Secure deletion | MUST |
| Secret in process listing | No arg exposure | MUST |
| Process hangs indefinitely | Timeout + SIGKILL | MUST |
| Secret in output | Output sanitization (Level 2) | MUST |
| Child observes other processes | PID namespace | MAY |
| Child accesses network | Network namespace | MAY |

---

## 14. References

- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) -- Requirement Levels
- [POSIX.1-2024](https://pubs.opengroup.org/onlinepubs/9799919799/) -- POSIX Standard
- [`explicit_bzero(3)`](https://man.openbsd.org/explicit_bzero) -- OpenBSD/macOS
- [`prctl(2)`](https://man7.org/linux/man-pages/man2/prctl.2.html) -- Linux
- [`namespaces(7)`](https://man7.org/linux/man-pages/man7/namespaces.7.html) -- Linux
- [`seccomp(2)`](https://man7.org/linux/man-pages/man2/seccomp.2.html) -- Linux
- [`mlock(2)`](https://man7.org/linux/man-pages/man2/mlock.2.html) -- POSIX
- [Zeroize crate](https://crates.io/crates/zeroize) -- Rust secure memory
- [00-overview.md](00-overview.md) -- NL Protocol Overview
- [01-agent-identity.md](01-agent-identity.md) -- Level 1: Agent Identity
- [02-action-based-access.md](02-action-based-access.md) -- Level 2: Action-Based Access

---

*Copyright 2026 Braincol. This specification is licensed under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).*
