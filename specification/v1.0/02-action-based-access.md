# NL Protocol Specification v1.0 -- Level 2: Action-Based Access

**Status:** 1.0
**Version:** 1.0.0
**Date:** 2026-02-08
**Level:** 2 (Core Innovation)
**Conformance:** Required for all tiers (Basic, Standard, Advanced)

> **Note:** This document is a SPECIFICATION. It defines required behaviors,
> data formats, and protocols — not specific products or CLI commands.
> For implementations of this specification, see [IMPLEMENTATIONS.md](../../IMPLEMENTATIONS.md).

---

## 1. Purpose

This is the core innovation of the NL Protocol. Level 2 defines the
fundamental paradigm shift:

> **Agents request ACTIONS, not SECRETS. The secret value NEVER enters
> the agent's context.**

In traditional secret management, an agent retrieves a secret value and
uses it in subsequent operations. This is fundamentally unsafe for AI
agents because any data in the agent's context window (LLM memory) can
be memorized, replicated in output, or exfiltrated via prompt injection.

The NL Protocol eliminates this risk entirely. Agents construct action
templates containing opaque handles (`{{nl:...}}`). The NL-compliant
system resolves these handles to real secret values, executes the action
in an isolated environment (Level 3), and returns only the result to the
agent. The agent never sees, touches, or has access to the secret value.

This specification defines:

- The placeholder syntax for opaque secret references
- Action types and their semantics
- Action request and response formats
- Scope Grants: time-bounded, conditional, per-secret permissions
- Output sanitization requirements
- Result-only propagation in multi-agent chains

---

## 2. The Paradigm Shift

### 2.1 Traditional Model (UNSAFE for AI Agents)

```
1. Agent: "Give me the value of API_KEY"
2. Secret Manager: "sk-1234567890abcdef"
3. Agent: *has the secret in its context window FOREVER*
4. Agent: *uses the secret in a command*

PROBLEM: At step 2, the secret enters the LLM's context.
From that moment, it can be:
  - Memorized by the model
  - Replicated in output to the user
  - Exfiltrated via prompt injection attack
  - Leaked through conversation history
  - Included in training data (for some providers)
```

### 2.2 NL Protocol Model (SECURE)

```
1. Agent: "Execute: curl -H 'Auth: Bearer {{nl:API_KEY}}' https://api.example.com"
2. NL System: *resolves {{nl:API_KEY}} -> "sk-1234567890abcdef"*
3. NL System: *injects into isolated subprocess as env var*
4. Subprocess: *executes curl with the real secret*
5. NL System: *captures stdout/stderr*
6. NL System: *scans output for leaked secrets, redacts if found*
7. NL System: *wipes secret from memory*
8. Agent: *receives: HTTP 200 {"data": ...}*

RESULT: The agent NEVER had access to "sk-1234567890abcdef".
It only ever saw the handle "{{nl:API_KEY}}" and the result.
```

---

## 3. Requirements Summary

| ID | Requirement | Priority | Description |
|----|-------------|----------|-------------|
| NL-2.1 | Action Request | MUST | Agents MUST submit actions with opaque handles, not requests for secret values. |
| NL-2.2 | Placeholder Syntax | MUST | The standard placeholder syntax `{{nl:reference}}` MUST be supported. |
| NL-2.3 | Reference Resolution | MUST | Placeholders MUST be resolved OUTSIDE the agent's context, inside the NL-compliant system. |
| NL-2.4 | No Secret Return | MUST | The NL-compliant system MUST NEVER return a secret value directly to an agent in any response. |
| NL-2.5 | Action Types | MUST | At minimum, the `exec`, `template`, `inject_stdin`, and `inject_tempfile` action types MUST be supported. |
| NL-2.6 | Result Sanitization | MUST | Action output (stdout/stderr) MUST be scanned for leaked secrets before returning to the agent. |
| NL-2.7 | Scope Validation | MUST | Every placeholder MUST be validated against the agent's Scope Grant before resolution. |
| NL-2.8 | Action Response | MUST | Action responses MUST include status, result, list of secrets used (names only, NEVER values), and audit reference. |
| NL-2.9 | Scope Grants | MUST | Implementations MUST support time-bounded, conditional, per-secret permission grants. |
| NL-2.10 | SDK Proxy | SHOULD | Implementations SHOULD support the `sdk_proxy` action type for cloud vendor API proxying. |
| NL-2.11 | Delegation | SHOULD | Implementations SHOULD support the `delegate` action type for multi-agent delegation. |
| NL-2.12 | Dry Run | SHOULD | Agents SHOULD be able to request a dry run that validates permissions without executing. |
| NL-2.13 | Batch Actions | MAY | Implementations MAY support multiple actions in a single request. |
| NL-2.14 | Cross-Provider References | MAY | Implementations MAY support cross-provider placeholder syntax. |

---

## 4. Placeholder Syntax

### 4.1 Grammar

The NL Protocol defines a standard placeholder syntax for referencing
secrets within action templates. The placeholder is an opaque handle: it
identifies a secret but carries no information about the secret's value.

```abnf
placeholder      = "{{nl:" reference "}}"

reference        = simple-ref
                 / categorized-ref
                 / scoped-ref
                 / qualified-ref
                 / provider-ref

simple-ref       = name
categorized-ref  = category "/" name
scoped-ref       = project "/" environment "/" name
qualified-ref    = project "/" environment "/" category "/" name
provider-ref     = provider "://" path

name             = 1*(ALPHA / DIGIT / "_" / "-" / ".")
category         = 1*(ALPHA / DIGIT / "_" / "-")
project          = 1*(ALPHA / DIGIT / "_" / "-")
environment      = 1*(ALPHA / DIGIT / "_" / "-")
provider         = 1*(ALPHA / DIGIT / "_" / "-")
path             = 1*(ALPHA / DIGIT / "_" / "-" / "/" / ".")
```

### 4.2 Reference Formats

| Format | Syntax | Resolution Strategy | Example |
|--------|--------|-------------------|---------|
| **Simple** | `{{nl:NAME}}` | Search all accessible scopes for a secret named `NAME`. If ambiguous (multiple matches), the system MUST return an error. | `{{nl:API_KEY}}` |
| **Categorized** | `{{nl:CATEGORY/NAME}}` | Search within the specified category across accessible projects/environments. | `{{nl:database/DB_PASSWORD}}` |
| **Scoped** | `{{nl:PROJECT/ENVIRONMENT/NAME}}` | Look up the secret in the exact project and environment. | `{{nl:myapp/production/STRIPE_KEY}}` |
| **Fully Qualified** | `{{nl:PROJECT/ENVIRONMENT/CATEGORY/NAME}}` | Exact match: project, environment, category, and name. No ambiguity possible. | `{{nl:myapp/production/payments/STRIPE_KEY}}` |
| **Cross-Provider** | `{{nl:PROVIDER://PATH}}` | Delegate resolution to an external secret provider. The NL-compliant system acts as a bridge. | `{{nl:aws-sm://us-east-1/prod/db-pass}}` |

### 4.3 Resolution Rules

1. **Simple references** MUST be resolved by searching all projects and
   environments accessible to the agent (as defined by the agent's AID
   scope and applicable Scope Grants). If the search yields zero results,
   the system MUST return an error with code `SECRET_NOT_FOUND`. If the
   search yields more than one result, the system MUST return an error
   with code `AMBIGUOUS_REFERENCE` listing the possible qualified paths.

2. **Categorized references** narrow the search to a specific category.
   The same zero/multiple match rules apply.

3. **Scoped and fully qualified references** are exact lookups. They
   either match exactly one secret or return `SECRET_NOT_FOUND`.

4. **Cross-provider references** require the NL-compliant system to have
   a configured bridge to the specified provider. If the provider is not
   configured, the system MUST return `PROVIDER_NOT_CONFIGURED`.

#### 4.3.1 Cross-Provider Reference Resolution

Cross-provider references (`{{nl:PROVIDER://PATH}}`) are an OPTIONAL
extension. Implementations that do not support federation (Chapter 07)
MUST reject any cross-provider reference with error code
`CROSS_PROVIDER_NOT_SUPPORTED`.

For implementations that support cross-provider resolution, the
following rules apply:

1. The `PROVIDER` identifier in the reference MUST match a registered
   federation partner as defined in Chapter 07, Section 6. If the
   provider identifier does not match any registered partner, the system
   MUST return error `PROVIDER_NOT_CONFIGURED`.

2. The request MUST be forwarded to the remote provider over the mTLS
   federation channel established during federation setup (Chapter 07).
   Plaintext or non-authenticated channels MUST NOT be used for
   cross-provider resolution.

3. The remote provider resolves the secret and returns only the action
   result (e.g., command output, API response) to the originating
   system. The remote provider MUST NOT return the raw secret value.
   The originating system forwards the sanitized result to the agent.

4. If the remote provider is unreachable (connection refused, DNS
   failure, TLS handshake failure, or no response within the timeout),
   the action MUST fail with error code `PROVIDER_UNREACHABLE`. The
   system MUST NOT fall back to a local resolution or cached value.

5. The RECOMMENDED timeout for cross-provider resolution is 30 seconds.
   Implementations SHOULD make this timeout configurable. The timeout
   applies to the entire round-trip (connection, request, resolution,
   and response from the remote provider).

### 4.4 Placeholder Resolution Precedence

When a simple reference `{{nl:SECRET_NAME}}` matches secrets in multiple
accessible scopes, resolution follows this precedence order:

1. **Project scope (most specific)** -- matching the current `project`
   in the action context (Section 6.2.4).
2. **Environment scope** -- matching the current `environment` in the
   action context.
3. **Organization scope (least specific)** -- secrets defined at the
   organization level without project or environment qualifiers.

If ambiguity remains after applying the precedence rules (e.g., two
secrets with the same name exist at the same precedence level), the
system MUST return error `AMBIGUOUS_REFERENCE` with the list of
matching scopes included in the error details.

Qualified references (`{{nl:PROJECT/ENVIRONMENT/NAME}}` or fully
qualified `{{nl:PROJECT/ENVIRONMENT/CATEGORY/NAME}}`) bypass the
precedence rules entirely and resolve directly to the specified scope.
If the qualified reference does not match, the system MUST return
`SECRET_NOT_FOUND` without falling back to other scopes.

### 4.5 Backward Compatibility

Implementations MAY support alias prefixes for backward compatibility:

- `{{vault:...}}` as an alias for `{{nl:...}}`

The alias MUST resolve identically to the canonical `{{nl:...}}` format.
Implementations SHOULD log a deprecation warning when aliases are used.

### 4.6 Escaping

If the literal string `{{nl:` appears in content that is NOT a
placeholder, it MUST be escaped as `{{{{nl:` (double the opening braces).
Implementations MUST NOT attempt to resolve escaped placeholders.

### 4.7 Examples

```bash
# Simple reference
curl -H "Authorization: Bearer {{nl:GITHUB_TOKEN}}" https://api.github.com/user

# Categorized reference
psql "postgresql://admin:{{nl:database/DB_PASSWORD}}@localhost/mydb"

# Scoped reference
aws s3 ls --region us-east-1  # with {{nl:braincol/production/AWS_ACCESS_KEY}}

# Fully qualified reference
docker login -u deploy -p {{nl:braincol/production/registry/DOCKER_TOKEN}} ghcr.io

# Cross-provider reference (AWS Secrets Manager)
curl -H "X-Api-Key: {{nl:aws-sm://us-east-1/prod/api-keys/payment-gateway}}" \
  https://payments.example.com/charge

# Multiple placeholders in one template
curl -u "{{nl:api/USERNAME}}:{{nl:api/PASSWORD}}" https://api.example.com/data
```

---

## 5. Action Types

### 5.1 Overview

Actions are typed operations that the NL-compliant system executes on
behalf of the agent. Each action type defines how secrets are injected
and how results are returned.

| Action Type | Description | Secret Injection Method | Conformance |
|-------------|-------------|------------------------|-------------|
| `exec` | Execute a shell command with secret injection | Environment variables in subprocess | MUST |
| `template` | Render a template file with secrets | File written with restricted permissions | MUST |
| `inject_stdin` | Pipe a secret via stdin to a command | stdin pipe (no command-line arguments) | MUST |
| `inject_tempfile` | Create a temporary file containing a secret | Temporary file with 0o400 permissions | MUST |
| `sdk_proxy` | Proxy an SDK/API call with secret credentials | Internal SDK invocation (no subprocess) | SHOULD |
| `delegate` | Delegate an action to another agent with scoped token | Delegation token (Level 7) | SHOULD |

### 5.2 Action Type: `exec`

The agent submits a command template containing placeholders. The
NL-compliant system resolves the placeholders, injects the secret values
as environment variables in an isolated subprocess, and executes the
command.

**How it works:**

1. The system parses the command template and extracts all `{{nl:...}}`
   placeholders.
2. Each placeholder is resolved to a secret value (after scope
   validation).
3. The system creates a mapping: `NL_SECRET_0` = first secret value,
   `NL_SECRET_1` = second, etc.
4. The command template is rewritten to reference these env vars instead
   of the placeholders.
5. The command is executed in an isolated subprocess with the env vars
   set (see Level 3).
6. stdout and stderr are captured and sanitized.
7. Secret values are wiped from memory.

**Example:**

Agent submits:
```json
{
  "action": {
    "type": "exec",
    "template": "curl -H 'Authorization: Bearer {{nl:api/GITHUB_TOKEN}}' https://api.github.com/user"
  }
}
```

System internally executes:
```bash
NL_SECRET_0="ghp_abc123..." \
  curl -H "Authorization: Bearer $NL_SECRET_0" https://api.github.com/user
```

Agent receives:
```json
{
  "result": {
    "stdout": "{\"login\":\"acme-bot\",\"id\":12345}",
    "stderr": "",
    "exit_code": 0
  }
}
```

**The agent never sees `ghp_abc123...`.**

### 5.3 Action Type: `template`

The agent submits a template file path (or inline template content)
containing placeholders. The system resolves all placeholders and writes
the result to a file with restricted permissions.

**Security properties:**
- The output file MUST be created with permissions `0o600` (read/write
  owner only) or more restrictive.
- The output file path MUST be in a secure temporary directory.
- The agent receives confirmation of the file path and the number of
  resolved placeholders, NOT the file contents.

**Example:**

Agent submits:
```json
{
  "action": {
    "type": "template",
    "template_content": "DB_HOST=localhost\nDB_USER=admin\nDB_PASS={{nl:database/DB_PASSWORD}}\nDB_NAME=myapp\n",
    "output_path": "/tmp/nl-secure/app.env"
  }
}
```

Agent receives:
```json
{
  "result": {
    "output_path": "/tmp/nl-secure/app.env",
    "resolved_count": 1,
    "permissions": "0600"
  }
}
```

### 5.4 Action Type: `inject_stdin`

The agent submits a command that expects a secret via stdin. The system
resolves the secret and pipes it to the command's stdin. This avoids
placing secrets in command-line arguments (which are visible in `/proc`
on Linux).

**Example:**

Agent submits:
```json
{
  "action": {
    "type": "inject_stdin",
    "command": "docker login -u deploy --password-stdin ghcr.io",
    "secret_ref": "{{nl:registry/DOCKER_TOKEN}}"
  }
}
```

System internally executes:
```bash
echo "$NL_SECRET_0" | docker login -u deploy --password-stdin ghcr.io
```

Agent receives:
```json
{
  "result": {
    "stdout": "Login Succeeded",
    "stderr": "",
    "exit_code": 0
  }
}
```

### 5.5 Action Type: `inject_tempfile`

The agent needs a secret as a file (certificates, SSH keys, service
account JSON). The system creates a temporary file containing the secret
value, executes the command with a reference to that file, and then
securely deletes the file.

**Security properties:**
- File permissions: `0o400` (read-only, owner only).
- File location: implementation-defined secure temporary directory.
- Lifecycle: created immediately before execution, securely deleted
  immediately after (see Level 3 for secure deletion requirements).
- Maximum lifetime: configurable (default: 60 seconds).

**Example:**

Agent submits:
```json
{
  "action": {
    "type": "inject_tempfile",
    "command": "ssh -i {{nl:SSH_KEY_FILE}} -o StrictHostKeyChecking=yes deploy@prod.example.com 'systemctl restart app'",
    "file_refs": {
      "SSH_KEY_FILE": "{{nl:ssh/id_rsa_deploy}}"
    }
  }
}
```

System internally:
1. Writes the SSH private key to `/tmp/nl-secure/tmpXXXXXX` with `0o400`
   permissions.
2. Rewrites the command: `ssh -i /tmp/nl-secure/tmpXXXXXX ...`
3. Executes the command.
4. Overwrites the file with random bytes, then deletes it.

Agent receives:
```json
{
  "result": {
    "stdout": "",
    "stderr": "",
    "exit_code": 0
  }
}
```

### 5.6 Action Type: `sdk_proxy`

The `sdk_proxy` action type enables cloud vendors and API providers to
implement the NL Protocol natively. Instead of executing a shell command,
the NL-compliant system makes an SDK or API call directly, using the
secret as an authentication credential.

This is the mechanism by which providers like AWS, Stripe, and GitHub
can offer NL-compliant access to their services without requiring agents
to use CLI wrappers.

**Example:**

Agent submits:
```json
{
  "action": {
    "type": "sdk_proxy",
    "provider": "aws",
    "service": "s3",
    "operation": "list_objects_v2",
    "parameters": {
      "Bucket": "my-data-bucket",
      "Prefix": "reports/"
    },
    "credentials_ref": "{{nl:braincol/production/aws/AWS_CREDENTIALS}}"
  }
}
```

System internally:
1. Resolves the credentials.
2. Creates an AWS SDK client with the resolved credentials.
3. Calls `s3.list_objects_v2(Bucket="my-data-bucket", Prefix="reports/")`.
4. Returns the result (without credentials).

Agent receives:
```json
{
  "result": {
    "data": {
      "Contents": [
        {"Key": "reports/2026-01.csv", "Size": 1234},
        {"Key": "reports/2026-02.csv", "Size": 5678}
      ]
    }
  }
}
```

**Conformance:** `sdk_proxy` is RECOMMENDED (SHOULD) but not REQUIRED.
Implementations that do not support `sdk_proxy` MUST support the same
use cases via `exec` with CLI commands.

### 5.7 Action Type: `delegate`

The `delegate` action type allows an agent to request that another agent
perform an action, with scoped permissions. The delegating agent issues
a Delegation Token (see Level 7) that grants the delegate a subset of
its own permissions.

**Example:**

Agent submits:
```json
{
  "action": {
    "type": "delegate",
    "delegate_to": "nl://acme.corp/deploy-bot/2.1.0",
    "delegated_action": {
      "type": "exec",
      "template": "kubectl apply -f deployment.yaml --token={{nl:k8s/DEPLOY_TOKEN}}"
    },
    "delegation_scope": {
      "secrets": ["k8s/DEPLOY_TOKEN"],
      "max_uses": 1,
      "ttl_seconds": 300
    }
  }
}
```

System:
1. Verifies the delegating agent has permission for the requested
   secrets.
2. Verifies the delegation scope is a strict subset of the delegating
   agent's scope.
3. Issues a Delegation Token.
4. Forwards the action to the delegate agent.
5. Returns the result to the delegating agent.

**The delegating agent NEVER sees `DEPLOY_TOKEN`'s value. Neither does
the delegate agent -- it flows through the isolation boundary just as
in a normal `exec` action.**

**Conformance:** `delegate` is RECOMMENDED (SHOULD) for implementations
targeting multi-agent workflows. REQUIRED for Advanced conformance.

---

## 6. Action Request Format

### 6.1 Schema

Every action request MUST conform to the following JSON structure:

```json
{
  "$schema": "https://nlprotocol.org/schemas/v1.0/action-request.json",
  "nl_version": "1.0",
  "request_id": "req_550e8400-e29b-41d4-a716-446655440000",

  "agent": {
    "agent_uri": "nl://anthropic.com/claude-code/1.5.2",
    "instance_id": "550e8400-e29b-41d4-a716-446655440000",
    "attestation": "eyJhbGciOiJFUzI1NiIs..."
  },

  "action": {
    "type": "exec",
    "template": "curl -H 'Authorization: Bearer {{nl:api/GITHUB_TOKEN}}' https://api.github.com/user",
    "context": {
      "project": "braincol",
      "environment": "development"
    },
    "purpose": "Verify GitHub API access for CI setup",
    "timeout_ms": 30000,
    "dry_run": false
  }
}
```

### 6.2 Field Definitions

#### 6.2.1 Top-Level Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `nl_version` | string | MUST | Protocol version. MUST be `"1.0"`. |
| `request_id` | string | MUST | Unique identifier for this request. UUID v4 RECOMMENDED. Used for idempotency and audit correlation. |
| `agent` | object | MUST | Agent identity information. See below. |
| `action` | object | MUST | The action to perform. See below. |

#### 6.2.2 Agent Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `agent_uri` | string | MUST | The agent's URI (Level 1). |
| `instance_id` | string | MUST | The agent's instance ID (Level 1). |
| `attestation` | string | SHOULD (Basic), MUST (Standard+) | The attestation JWT (Level 1). |

#### 6.2.3 Action Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | MUST | One of: `"exec"`, `"template"`, `"inject_stdin"`, `"inject_tempfile"`, `"sdk_proxy"`, `"delegate"`. |
| `template` | string | Conditional | The command or content template with `{{nl:...}}` placeholders. REQUIRED for `exec`. |
| `template_content` | string | Conditional | Inline template content. REQUIRED for `template` if `template_path` is not provided. |
| `template_path` | string | Conditional | Path to a template file. Alternative to `template_content` for the `template` action type. |
| `output_path` | string | Conditional | Output file path for `template` actions. |
| `command` | string | Conditional | Command to execute. REQUIRED for `inject_stdin` and `inject_tempfile`. |
| `secret_ref` | string | Conditional | Single secret reference. REQUIRED for `inject_stdin`. |
| `file_refs` | object | Conditional | Map of placeholder name to secret reference. REQUIRED for `inject_tempfile`. |
| `provider` | string | Conditional | Cloud/API provider identifier. REQUIRED for `sdk_proxy`. |
| `service` | string | Conditional | Provider service name. REQUIRED for `sdk_proxy`. |
| `operation` | string | Conditional | Provider operation name. REQUIRED for `sdk_proxy`. |
| `parameters` | object | Conditional | Operation parameters. For `sdk_proxy`. |
| `credentials_ref` | string | Conditional | Credentials reference. REQUIRED for `sdk_proxy`. |
| `delegate_to` | string | Conditional | Target agent URI. REQUIRED for `delegate`. |
| `delegated_action` | object | Conditional | The action to delegate. REQUIRED for `delegate`. |
| `delegation_scope` | object | Conditional | Scope for the delegation. REQUIRED for `delegate`. |
| `context` | object | SHOULD | Contextual information for resolution. See below. |
| `purpose` | string | SHOULD | Human-readable description of why this action is needed. Recorded in audit trail. |
| `timeout_ms` | integer | SHOULD | Maximum execution time in milliseconds. Default: 30000 (30 seconds). Maximum: 600000 (10 minutes). |
| `dry_run` | boolean | MAY | If `true`, validate permissions and resolve references without executing. Default: `false`. |

#### 6.2.4 Context Object

| Field | Type | Description |
|-------|------|-------------|
| `project` | string | The project context for reference resolution. If provided, simple references are resolved within this project first. |
| `environment` | string | The environment context. Combined with `project` for scoped resolution. |

---

## 7. Action Response Format

### 7.1 Schema

Every action response MUST conform to the following JSON structure:

```json
{
  "$schema": "https://nlprotocol.org/schemas/v1.0/action-response.json",
  "nl_version": "1.0",
  "request_id": "req_550e8400-e29b-41d4-a716-446655440000",
  "action_id": "act_660f9511-f30c-52e5-b827-557766551111",

  "status": "success",

  "result": {
    "stdout": "{\"login\":\"acme-bot\",\"id\":12345}",
    "stderr": "",
    "exit_code": 0
  },

  "secrets_used": [
    "api/GITHUB_TOKEN"
  ],

  "redacted": false,
  "redacted_count": 0,

  "audit_ref": "aud_770a0622-a41d-63f6-c938-668877662222",

  "timing": {
    "received_at": "2026-02-08T14:30:00.000Z",
    "resolved_at": "2026-02-08T14:30:00.050Z",
    "executed_at": "2026-02-08T14:30:00.055Z",
    "completed_at": "2026-02-08T14:30:00.250Z",
    "total_ms": 250
  }
}
```

### 7.2 Field Definitions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `nl_version` | string | MUST | Protocol version. |
| `request_id` | string | MUST | Echo of the request ID for correlation. |
| `action_id` | string | MUST | Unique identifier for this action execution. Generated by the system. |
| `status` | string | MUST | One of: `"success"`, `"denied"`, `"error"`, `"timeout"`, `"dry_run_ok"`. |
| `result` | object | Conditional | Execution result. Present when `status` is `"success"`. |
| `result.stdout` | string | Conditional | Standard output from the executed command. |
| `result.stderr` | string | Conditional | Standard error from the executed command. |
| `result.exit_code` | integer | Conditional | Process exit code. 0 typically indicates success. |
| `result.data` | object | Conditional | Structured result data (for `sdk_proxy` actions). |
| `result.output_path` | string | Conditional | Output file path (for `template` actions). |
| `result.resolved_count` | integer | Conditional | Number of placeholders resolved (for `template` actions). |
| `secrets_used` | string[] | MUST | List of secret reference names that were resolved. MUST contain names only, NEVER values. |
| `redacted` | boolean | MUST | `true` if the output was modified by the sanitizer to remove leaked secrets. |
| `redacted_count` | integer | SHOULD | Number of redactions performed. |
| `audit_ref` | string | MUST | Reference to the audit trail entry for this action. |
| `timing` | object | SHOULD | Timing information for observability. |
| `error` | object | Conditional | Error details. Present when `status` is `"denied"` or `"error"`. |

### 7.3 Status Codes

| Status | Meaning | Result Present? |
|--------|---------|----------------|
| `success` | Action executed successfully. | YES |
| `denied` | Agent lacks permission for the requested action or secrets. | NO (error present) |
| `error` | Action execution failed (e.g., command returned non-zero, secret not found). | Partial (may include stderr) |
| `timeout` | Action exceeded the timeout limit. | Partial (may include partial output) |
| `dry_run_ok` | Dry run: permissions validated, references resolved, but action not executed. | NO |

### 7.4 Error Response

When `status` is `"denied"` or `"error"`:

```json
{
  "status": "denied",
  "error": {
    "code": "SCOPE_VIOLATION",
    "message": "Agent does not have permission to access secret 'production/DB_PASSWORD'",
    "details": {
      "secret_ref": "production/DB_PASSWORD",
      "agent_scope": {
        "environments": ["development", "staging"]
      },
      "required_scope": {
        "environments": ["production"]
      }
    },
    "suggestion": "Request a Scope Grant for the 'production' environment from your administrator."
  },
  "secrets_used": [],
  "redacted": false,
  "audit_ref": "aud_770a0622-..."
}
```

**Error responses MUST NEVER include secret values.** Even in error
scenarios, the NL Protocol's zero-exposure guarantee applies.

### 7.5 Error Code Registry

The following table defines the complete set of error codes used in this
chapter. These codes appear in the `error.code` field of error responses.

| Code | Description |
|------|-------------|
| `SECRET_NOT_FOUND` | Referenced secret does not exist in the store. |
| `SCOPE_VIOLATION` | Agent's AID scope does not cover the requested secret. |
| `GRANT_DENIED` | No active Scope Grant covers this action. |
| `GRANT_EXPIRED` | Matching Scope Grant has passed its `valid_until` timestamp. |
| `GRANT_EXHAUSTED` | Matching Scope Grant has reached its `max_uses` limit. |
| `CONDITION_FAILED` | One or more conditions on the Scope Grant are not met (e.g., time window, trust level, IP range). |
| `AMBIGUOUS_REFERENCE` | Simple reference matches multiple secrets at the same precedence level. The `details` field MUST include the list of matching qualified paths. |
| `CROSS_PROVIDER_NOT_SUPPORTED` | Cross-provider references are not supported by this implementation. |
| `PROVIDER_NOT_CONFIGURED` | The specified cross-provider identifier does not match any configured provider bridge. |
| `PROVIDER_UNREACHABLE` | Remote provider is unavailable for cross-provider resolution (connection failure, timeout, or TLS error). |
| `INVALID_PLACEHOLDER` | Placeholder syntax is malformed and does not conform to the grammar in Section 4.1. |
| `DRY_RUN_FAILED` | Dry run validation failed. The `message` field MUST include the specific reason (e.g., missing grant, expired grant, unresolvable reference). |

> **Note:** Error codes in this chapter use string identifiers.
> Implementations MUST return these exact strings in the `error.code`
> field of error responses. Implementations MAY define additional error
> codes prefixed with `X_` for vendor-specific extensions (e.g.,
> `X_RATE_LIMITED`, `X_BACKEND_TIMEOUT`). Vendor-specific error codes
> MUST NOT collide with the standard codes defined above.

### 7.6 Critical Invariant

The following invariant MUST hold for every action response:

> **The `result` object (including `stdout`, `stderr`, and `data`) MUST
> NOT contain any secret value that was resolved during action
> execution.** If a secret value is detected in the output, it MUST be
> redacted before the response is returned to the agent, and `redacted`
> MUST be set to `true`.

This invariant is enforced by output sanitization (Section 9).

---

## 8. Scope Grants

### 8.1 Overview

Scope Grants are permission objects that bind an agent identity to a set
of allowed actions, secret patterns, and conditions. They are the
authorization mechanism of the NL Protocol.

A Scope Grant answers the question: "Is this agent allowed to perform
this action type on these secrets, right now, under these conditions?"

### 8.2 Schema

```json
{
  "$schema": "https://nlprotocol.org/schemas/v1.0/scope-grant.json",
  "grant_id": "grant_550e8400-e29b-41d4-a716-446655440000",
  "nl_version": "1.0",

  "agent_uri": "nl://anthropic.com/claude-code/1.5.2",
  "instance_id": "550e8400-e29b-41d4-a716-446655440000",
  "organization_id": "org_acme_corp_2024",

  "granted_by": {
    "type": "human",
    "identifier": "andres@acme.corp",
    "granted_at": "2026-02-08T10:00:00Z"
  },

  "permissions": [
    {
      "action_types": ["exec", "inject_stdin"],
      "secrets": ["api/*", "database/DB_PASSWORD"],
      "conditions": {
        "valid_from": "2026-02-08T10:00:00Z",
        "valid_until": "2026-02-08T18:00:00Z",
        "max_uses": 100,
        "require_human_approval": false,
        "min_trust_level": "L1",
        "allowed_environments": ["development", "staging"],
        "allowed_contexts": {
          "repository": "github.com/acme-corp/backend"
        }
      }
    },
    {
      "action_types": ["exec"],
      "secrets": ["production/*"],
      "conditions": {
        "valid_from": "2026-02-08T10:00:00Z",
        "valid_until": "2026-02-08T18:00:00Z",
        "max_uses": 5,
        "require_human_approval": true,
        "min_trust_level": "L2",
        "allowed_environments": ["production"]
      }
    }
  ],

  "revocable": true,
  "revoked": false
}
```

### 8.3 Field Definitions

#### 8.3.1 Top-Level Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `grant_id` | string | MUST | Unique identifier for this grant. |
| `nl_version` | string | MUST | Protocol version. |
| `agent_uri` | string | MUST | The Agent URI this grant applies to. |
| `instance_id` | string | SHOULD | Specific instance. If omitted, the grant applies to all instances of the agent. |
| `organization_id` | string | MUST | The organization that issued the grant. |
| `granted_by` | object | MUST | Who created the grant. |
| `permissions` | array | MUST | List of permission objects. |
| `revocable` | boolean | MUST | Whether the grant can be revoked. Default: `true`. |
| `revoked` | boolean | MUST | Whether the grant has been revoked. Default: `false`. |

#### 8.3.2 Permission Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `action_types` | string[] | MUST | Which action types are permitted: `"exec"`, `"template"`, `"inject_stdin"`, `"inject_tempfile"`, `"sdk_proxy"`, `"delegate"`, or `"*"` for all. |
| `secrets` | string[] | MUST | Glob patterns for allowed secret references. `"*"` matches all secrets (use with extreme caution). `"api/*"` matches all secrets in the `api` category. |
| `conditions` | object | MUST | Conditions that must be met for the permission to be active. |

#### 8.3.3 Conditions Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `valid_from` | string (ISO 8601) | MUST | Start of validity window. The permission is not active before this time. |
| `valid_until` | string (ISO 8601) | MUST | End of validity window. The permission expires after this time. |
| `max_uses` | integer or null | SHOULD | Maximum number of times this permission can be used. `null` = unlimited uses. `0` = zero uses remaining (grant is exhausted). Integer MUST be >= 0; negative values MUST be rejected. See Section 8.4.2 for consumption semantics. |
| `require_human_approval` | boolean | SHOULD | If `true`, each action under this permission requires explicit human approval before execution. Default: `false`. |
| `min_trust_level` | string | MAY | Minimum trust level required. One of: `"L0"`, `"L1"`, `"L2"`, `"L3"`. |
| `allowed_environments` | string[] | MAY | Restrict to specific environments. |
| `allowed_contexts` | object | MAY | Additional context-based restrictions (e.g., restrict to a specific repository or IDE). |
| `allowed_ip_ranges` | string[] | MAY | CIDR ranges from which the action is permitted. |
| `max_concurrent` | integer | MAY | Maximum concurrent actions under this permission. |

### 8.4 Scope Evaluation Algorithm

When an action request is received, the NL-compliant system MUST evaluate
Scope Grants using the following algorithm:

```
function evaluateScope(agent, action):
    grants = findActiveGrants(agent.agent_uri, agent.instance_id)

    for each placeholder in action.template:
        secretRef = extractSecretRef(placeholder)
        permitted = false

        for each grant in grants:
            if grant.revoked:
                continue

            for each permission in grant.permissions:
                if NOT matchesActionType(permission.action_types, action.type):
                    continue

                if NOT matchesSecretPattern(permission.secrets, secretRef):
                    continue

                if NOT evaluateConditions(permission.conditions, agent, action):
                    continue

                permitted = true
                break

            if permitted:
                break

        if NOT permitted:
            return DENIED(secretRef, "No matching Scope Grant")

    return ALLOWED
```

#### 8.4.1 evaluateConditions Specification

The `evaluateConditions` function referenced above MUST be implemented
as follows. Conditions are evaluated in the order listed (fail-fast
strategy). ALL conditions must pass for the function to return `true`.

```
function evaluateConditions(conditions, agent, action):
    context = action.context

    # 1. Time restrictions
    now = currentTimestamp()
    if now < conditions.valid_from OR now > conditions.valid_until:
        return false

    # 2. Minimum trust level
    if conditions.min_trust_level is defined:
        if agent.trust_level < conditions.min_trust_level:
            return false

    # 3. Human approval requirement
    if conditions.require_human_approval == true:
        if action.approval_token is NOT present OR NOT valid:
            return false

    # 4. Allowed contexts
    if conditions.allowed_contexts is defined:
        for each (key, value) in conditions.allowed_contexts:
            if context[key] != value:
                return false

    # 5. Allowed environments
    if conditions.allowed_environments is defined:
        if context.environment NOT in conditions.allowed_environments:
            return false

    # 6. IP restrictions
    if conditions.allowed_ip_ranges is defined:
        if action.source_ip NOT within any CIDR in conditions.allowed_ip_ranges:
            return false

    # 7. Usage limit
    if conditions.max_uses is defined AND conditions.max_uses is not null:
        if currentUsageCount(grant) >= conditions.max_uses:
            return false

    return true
```

Implementations MUST evaluate conditions in the order specified above.
If any condition fails, evaluation MUST stop immediately and return
`false` (fail-fast). This ordering ensures that inexpensive checks
(time, trust level) are performed before potentially expensive checks
(IP lookup, usage count).

#### 8.4.2 max_uses Consumption Semantics

The `max_uses` field controls how many times a permission may be
exercised. The following rules define when a use is consumed:

- A **failed action** (non-zero exit code, application error response,
  or execution error after the action began) DOES consume one use.
  The rationale is that the secret was resolved and injected, so the
  use occurred regardless of outcome.
- A **network or transport failure** that occurs before execution begins
  (i.e., the secret was never resolved or injected) does NOT consume
  a use.
- A **dry run** (Section 11) does NOT consume a use.
- Use consumption MUST be atomic: if two concurrent actions race for
  the last available use, exactly one MUST succeed and the other MUST
  be denied with error `GRANT_EXHAUSTED`.

### 8.5 Grant Lifecycle

1. **Creation:** A Scope Grant is created by a human administrator or by
   the system (for delegation tokens). Creation MUST be recorded in the
   audit trail.

2. **Active:** The grant is active when `valid_from <= now() <= valid_until`
   and `revoked == false` and `uses < max_uses`.

3. **Expired:** The grant has passed its `valid_until` timestamp. Expired
   grants MUST NOT authorize any actions.

4. **Exhausted:** The grant has reached its `max_uses` limit. Exhausted
   grants MUST NOT authorize any actions.

5. **Revoked:** An administrator has explicitly revoked the grant.
   Revocation MUST be recorded in the audit trail. Revocation is
   immediate: in-flight actions MAY complete, but new actions MUST be
   denied.

### 8.6 Example: Time-Bounded, Conditional Grant

This grant allows Claude Code to access development API keys for the
current workday, with a limit of 100 uses:

```json
{
  "grant_id": "grant_daily_dev_2026-02-08",
  "agent_uri": "nl://anthropic.com/claude-code/1.5.2",
  "organization_id": "org_acme_corp_2024",
  "granted_by": {
    "type": "human",
    "identifier": "andres@acme.corp",
    "granted_at": "2026-02-08T09:00:00Z"
  },
  "permissions": [{
    "action_types": ["exec", "template", "inject_stdin", "inject_tempfile"],
    "secrets": ["api/*", "database/DB_*"],
    "conditions": {
      "valid_from": "2026-02-08T09:00:00Z",
      "valid_until": "2026-02-08T18:00:00Z",
      "max_uses": 100,
      "require_human_approval": false,
      "min_trust_level": "L1",
      "allowed_environments": ["development", "staging"],
      "allowed_contexts": {
        "repository": "github.com/acme-corp/backend"
      }
    }
  }],
  "revocable": true,
  "revoked": false
}
```

### 8.7 Secret Rotation and Revocation Propagation

When a secret is rotated (value changed) or permanently revoked, the
NL-compliant system MUST handle in-flight and future actions consistently.

#### 8.7.0 Action States and the Resolution Boundary

For the purposes of rotation semantics, actions exist in one of two
states:

- **Pending:** The action has been validated (identity, Scope Grant)
  but secret resolution has NOT yet begun. The system has not yet
  read the secret value from the store.
- **In-flight:** Secret resolution has begun or execution is underway.
  The secret value has been read from the store and is being (or has
  been) injected into the execution environment.

The **resolution moment** is the transaction boundary between these
two states. Once a secret value is resolved for an action, that value
is used for the entire duration of that action regardless of any
subsequent rotations. Specifically:

- **Pending actions** MUST resolve to the NEW secret value after
  rotation is committed.
- **In-flight actions** MUST complete using the value resolved at
  resolution time (the old value, during any grace period).

Implementations MUST ensure that the transition from pending to
in-flight is atomic with respect to rotation events: an action MUST
NOT begin resolution, observe a partial rotation, and resolve to a
corrupted or inconsistent value.

#### 8.7.1 Requirements

| ID | Requirement | Priority | Description |
|----|-------------|----------|-------------|
| NL-2.15 | Rotation Event | MUST | When a secret is rotated, the system MUST record a `secret_rotated` event in the audit trail with the secret name (NEVER the old or new value), the timestamp, and the identity of the principal who initiated the rotation. |
| NL-2.16 | In-Flight Actions | SHOULD | Actions that are currently executing (inside the isolation boundary) when a rotation occurs SHOULD be allowed to complete. The old value was already injected and is confined to the subprocess. |
| NL-2.17 | Pending Actions | MUST | Actions that have been submitted but not yet started executing MUST resolve the secret to the NEW value. There MUST NOT be a window where a pending action resolves to a stale value after rotation is committed. |
| NL-2.18 | Delegation Token Invalidation | SHOULD | When a secret is rotated, Delegation Tokens (Level 7) that reference the rotated secret by name SHOULD remain valid — the delegate will resolve the new value on next use. Implementations SHOULD NOT invalidate delegation tokens on secret rotation unless the rotation is due to a confirmed compromise. |
| NL-2.19 | Compromise-Driven Revocation | MUST | When a secret is revoked due to a confirmed compromise (as opposed to routine rotation), the system MUST reject all pending and future actions referencing that secret until a new value is provisioned. In-flight actions SHOULD be terminated if the execution environment supports it. |
| NL-2.20 | Agent Notification | MAY | Implementations MAY notify agents when a secret they have used recently has been rotated. The notification MUST contain only the secret name and the event type, NEVER the old or new value. |

#### 8.7.2 Rotation Flow

```
Principal                    NL-Compliant System              Agents
    |                              |                             |
    | 1. Rotate Secret(name)      |                             |
    | ---------------------------> |                             |
    |                              |                             |
    |                    2. Store new value                      |
    |                    3. Mark old value as superseded          |
    |                    4. Write audit: secret_rotated           |
    |                              |                             |
    |                    5. In-flight actions: CONTINUE           |
    |                       (old value in isolation boundary)     |
    |                    6. Pending actions: resolve NEW value    |
    |                              |                             |
    |                              | 7. [OPTIONAL] Notification  |
    |                              |    {name, event: "rotated"} |
    |                              | --------------------------> |
    |                              |                             |
```

---

## 9. Output Sanitization

### 9.1 Purpose

> **Canonical Algorithm.** This section defines the canonical output
> sanitization algorithm for the NL Protocol. Chapter 06 (Attack
> Detection) references this algorithm for hash-based detection.
> Implementations MUST use a single sanitization implementation for
> both output sanitization and attack detection. Divergent
> implementations will cause inconsistencies between redaction and
> detection, creating security gaps.

Even with process isolation (Level 3), a command's stdout or stderr
might accidentally contain a secret value. For example:

- An error message that includes the connection string with the password.
- A debug log that prints environment variables.
- A curl verbose output that shows authentication headers.

Output sanitization is the last line of defense: it scans the action's
output for any secret values that were used in the action and redacts
them before the output reaches the agent.

**Scope Clarification**: Output sanitization (this section) operates on action OUTPUT only — scanning results returned to the agent for leaked secrets. Shell escaping and command construction safety are the responsibility of Level 3 (Execution Isolation, Chapter 03, Section 6.2). Level 2 MUST NOT perform shell escaping on action templates, as this would cause double-escaping when Level 3 applies its own escaping.

### 9.2 Requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| NL-2.6.1 | The system MUST scan stdout and stderr for every secret value used in the action. | MUST |
| NL-2.6.2 | If a secret value is found in the output, it MUST be replaced with `[NL-REDACTED:secret_name]`. | MUST |
| NL-2.6.3 | The system MUST also check for common encodings of the secret: Base64, URL-encoded, hex-encoded. | MUST |
| NL-2.6.4 | If an encoded form is found, it MUST be replaced with `[NL-REDACTED:secret_name:encoding]`. | MUST |
| NL-2.6.5 | Secrets shorter than 4 characters MUST be skipped during output scanning (too many false positives). | MUST |
| NL-2.6.6 | The scanning SHOULD be performed in constant time relative to secret length to avoid timing side channels. | SHOULD |
| NL-2.6.7 | A redaction event MUST be recorded in the audit trail as a security incident. | MUST |
| NL-2.6.8 | The response MUST set `redacted: true` and `redacted_count` to the number of redactions. | MUST |
| NL-2.6.9 | Multiple matches of the same secret in output MUST each be replaced with `[NL-REDACTED:<secret_name>]`. | MUST |
| NL-2.6.10 | Binary null bytes MUST be stripped from output before scanning. | MUST |
| NL-2.6.11 | Multi-line secrets MUST be matched as a single string (newlines included in the match). | MUST |

### 9.3 Scanning Algorithm

```
function sanitizeOutput(output, secretsUsed):
    redacted = false
    redactedCount = 0

    # Step 0: Strip binary null bytes before scanning (NL-2.6.10)
    output = output.replaceAll("\x00", "")

    for each (name, value) in secretsUsed:
        # Skip secrets shorter than 4 characters (NL-2.6.5)
        if length(value) < 4:
            continue

        # Multi-line secrets are matched as a single string,
        # including embedded newlines (NL-2.6.11).
        # Each occurrence is replaced individually (NL-2.6.9).

        # Check plaintext (all occurrences)
        while output.contains(value):
            output = output.replaceFirst(value, "[NL-REDACTED:" + name + "]")
            redacted = true
            redactedCount += 1

        # Check Base64 encoding (all occurrences)
        b64Value = base64Encode(value)
        while output.contains(b64Value):
            output = output.replaceFirst(b64Value, "[NL-REDACTED:" + name + ":base64]")
            redacted = true
            redactedCount += 1

        # Check URL encoding (all occurrences)
        urlValue = urlEncode(value)
        while output.contains(urlValue):
            output = output.replaceFirst(urlValue, "[NL-REDACTED:" + name + ":url]")
            redacted = true
            redactedCount += 1

        # Check hex encoding (all occurrences)
        hexValue = hexEncode(value)
        while output.contains(hexValue):
            output = output.replaceFirst(hexValue, "[NL-REDACTED:" + name + ":hex]")
            redacted = true
            redactedCount += 1

    return (output, redacted, redactedCount)
```

### 9.4 Example

Command: `curl -v -H "Authorization: Bearer {{nl:api/TOKEN}}" https://api.example.com`

Verbose curl output (before sanitization):
```
> GET / HTTP/2
> Host: api.example.com
> Authorization: Bearer sk-1234567890abcdef
> User-Agent: curl/8.0
< HTTP/2 200
{"status":"ok"}
```

After sanitization:
```
> GET / HTTP/2
> Host: api.example.com
> Authorization: Bearer [NL-REDACTED:api/TOKEN]
> User-Agent: curl/8.0
< HTTP/2 200
{"status":"ok"}
```

If the secret value had also appeared in a Base64-encoded form, that
occurrence would be replaced with `[NL-REDACTED:api/TOKEN:base64]`.

> **Note:** The redaction marker format is `[NL-REDACTED:<secret_name>]`
> for plaintext matches and `[NL-REDACTED:<secret_name>:<encoding>]` for
> encoded matches (where `<encoding>` is one of `base64`, `url`, or
> `hex`). Implementations MUST use this exact format. All requirements
> (NL-2.6.2, NL-2.6.4, NL-2.6.9) and the scanning algorithm (Section
> 9.3) use the normative `NL-REDACTED` prefix consistently.

The agent receives the sanitized output. The redaction is logged as a
security event.

### 9.5 Output Size Constraints

To ensure sanitization remains performant:
- Actions producing output smaller than 64 KiB MUST be sanitized within 100ms.
- Actions producing output between 64 KiB and 10 MiB MUST be sanitized within 500ms.
- Actions producing output larger than 10 MiB SHOULD use streaming/chunked sanitization, processing the output in segments no larger than 1 MiB each.
- Actions producing output larger than 100 MiB MAY be rejected by the NL Provider with error code NL-E303 (`EXECUTION_TIMEOUT`).
- Implementations MUST document their maximum supported output size.

---

## 10. Result-Only Propagation

### 10.1 Principle

In multi-agent chains (orchestrator -> sub-agent -> sub-sub-agent), only
**results** flow between agents, never secrets.

```
Orchestrator          Sub-Agent A           Sub-Agent B
     |                     |                     |
     | Delegate(action)    |                     |
     | ------------------> |                     |
     |                     |                     |
     |                     | Delegate(action)    |
     |                     | ------------------> |
     |                     |                     |
     |                     |                     | Execute in
     |                     |                     | isolation
     |                     |                     | (secrets here)
     |                     |                     |
     |                     | Result (no secrets)  |
     |                     | <------------------ |
     |                     |                     |
     | Result (no secrets)  |                     |
     | <------------------ |                     |
     |                     |                     |

  Secrets used by Sub-Agent B are INVISIBLE to Sub-Agent A
  and the Orchestrator. Only the action result propagates.
```

### 10.2 Requirements

1. When an agent receives a result from a delegated action, the result
   MUST have already been sanitized (Section 9).

2. An agent MUST NOT forward secret references (`{{nl:...}}`) from one
   action request to another agent's context. Secret references are
   resolved by the NL-compliant system, not by agents.

3. In a delegation chain, each agent's secrets are isolated from every
   other agent. The delegation token grants permission to use secrets,
   not visibility of secret values.

4. Audit trails (Level 5) MUST record the full delegation chain for
   forensic purposes, but MUST NOT record secret values at any link
   in the chain.

---

## 11. Dry Run Mode

### 11.1 Purpose

Agents SHOULD be able to request a "dry run" that validates permissions
and resolves references without actually executing the action. This
allows agents to check whether they have the necessary permissions before
attempting an action.

### 11.2 Behavior

In dry-run mode, placeholders ARE validated for existence and
accessibility but are NOT resolved to their actual values. The system
MUST NOT resolve, inject, or execute anything in dry-run mode.

When `dry_run: true`, the system MUST verify:

1. The agent's identity is valid (Level 1 attestation).
2. All placeholders reference secrets that exist in the store.
3. The agent has an active Scope Grant covering each referenced secret
   for the requested action type.
4. All conditions on the matching Scope Grant(s) are currently met
   (time window, trust level, environment, IP restrictions, etc.).

The system MUST NOT:

- Resolve any secret to its actual value.
- Inject any secret into an execution environment.
- Execute any command, SDK call, or delegation.
- Consume a `max_uses` count (Section 8.4.2).

If all validations pass, the system returns `status: "dry_run_ok"`.

### 11.3 Example

Request:
```json
{
  "action": {
    "type": "exec",
    "template": "curl -H 'Auth: {{nl:production/API_KEY}}' https://api.example.com",
    "dry_run": true
  }
}
```

Response (permissions insufficient):
```json
{
  "status": "denied",
  "error": {
    "code": "SCOPE_VIOLATION",
    "message": "No active Scope Grant covers secret 'production/API_KEY' for action type 'exec'",
    "suggestion": "Request a Scope Grant for 'production/*' from your administrator."
  }
}
```

Response (permissions sufficient):
```json
{
  "status": "dry_run_ok",
  "secrets_validated": ["production/API_KEY"],
  "grant_refs": ["grant_daily_prod_2026-02-08"],
  "audit_ref": "aud_dry_run_..."
}
```

---

## 12. Security Considerations

### 12.1 Placeholder Injection

If an agent can control the command template, it could attempt to
construct a placeholder that references a secret it should not access.
This is mitigated by Scope Grant validation (Section 8): every
placeholder is validated against the agent's active grants before
resolution.

### 12.2 Template Injection

An agent could attempt to inject malicious content into a template that,
when resolved, causes the execution environment to leak secrets. For
example: `echo {{nl:SECRET}} > /tmp/leaked`. This is mitigated by:

1. Output sanitization (Section 9): the output is scanned.
2. Pre-execution defense (Level 4): dangerous patterns are blocked.
3. Process isolation (Level 3): the subprocess cannot communicate with
   the agent directly.

### 12.3 Timing Side Channels

The time taken to resolve a secret and execute an action could reveal
information about the secret (e.g., its length). Implementations SHOULD
normalize response times where practical. Output sanitization SHOULD use
constant-time comparison where possible.

### 12.4 Denial of Service

An agent could submit a large number of action requests to exhaust
system resources. Implementations SHOULD enforce rate limits per agent
and per Scope Grant.

### 12.5 Cross-Provider Trust

When using cross-provider references (`{{nl:aws-sm://...}}`), the
NL-compliant system becomes a bridge to an external provider. The
security of the resolved secret depends on the external provider's
security posture. Implementations SHOULD document which external
providers are trusted and how credentials for those providers are
managed.

---

## 13. Conformance Checklist

### 13.1 Basic Conformance

For Basic conformance, an implementation MUST:

- [ ] Support the `{{nl:...}}` placeholder syntax (Section 4).
- [ ] Support all four required action types: `exec`, `template`, `inject_stdin`, `inject_tempfile` (Section 5).
- [ ] Implement the Action Request format (Section 6).
- [ ] Implement the Action Response format (Section 7).
- [ ] Support Scope Grants with time bounds and usage limits (Section 8).
- [ ] Implement output sanitization for plaintext and common encodings (Section 9).
- [ ] Never return secret values to the agent in any response.
- [ ] Record all actions in the audit trail (Level 5, if implemented).

### 13.2 Standard Conformance

In addition to Basic, Standard conformance MUST:

- [ ] Support all condition types in Scope Grants (Section 8.3.3).
- [ ] Implement the Scope Grant lifecycle (Section 8.5).
- [ ] Support dry run mode (Section 11).
- [ ] Implement all four encoding checks in sanitization (plaintext, base64, URL, hex).

### 13.3 Advanced Conformance

In addition to Standard, Advanced conformance MUST:

- [ ] Support `sdk_proxy` action type (Section 5.6).
- [ ] Support `delegate` action type (Section 5.7).
- [ ] Enforce result-only propagation in delegation chains (Section 10).
- [ ] Support cross-provider references (Section 4.3.1).

---

## 14. References

- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) -- Requirement Levels
- [00-overview.md](00-overview.md) -- NL Protocol Overview
- [01-agent-identity.md](01-agent-identity.md) -- Level 1: Agent Identity
- [03-execution-isolation.md](03-execution-isolation.md) -- Level 3: Execution Isolation

---

*Copyright 2026 Braincol. This specification is licensed under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).*
