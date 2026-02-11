# NL Protocol -- Developer Guide

**Audience:** Developers who want to adopt the NL Protocol to keep secrets out of AI agent context.

**Last Updated:** 2026-02-08

---

## Table of Contents

1. [What Is the NL Protocol?](#1-what-is-the-nl-protocol)
2. [Core Concept: The Paradigm Shift](#2-core-concept-the-paradigm-shift)
3. [Secret References](#3-secret-references)
4. [Action Types](#4-action-types)
5. [Scope Grants](#5-scope-grants)
6. [Configuring AI Agents](#6-configuring-ai-agents)
7. [Conformance Levels](#7-conformance-levels)
8. [FAQ](#8-faq)
9. [Next Steps](#9-next-steps)

---

## 1. What Is the NL Protocol?

The Never-Leak Protocol (NL Protocol) is an **open specification** that defines how AI agents interact with secrets -- API keys, passwords, tokens, certificates -- without those secrets ever entering the agent's context window, memory, or reasoning state.

The NL Protocol is **not a product**. It is not a CLI tool. It is not a vault. It is a set of rules and data formats that any system can implement.

To use the NL Protocol in your projects, you:

1. **Choose an NL-compliant implementation** that fits your environment. Implementations include secret managers, CLI tools, MCP servers, cloud provider integrations, and agent framework plugins. See [IMPLEMENTATIONS.md](../../IMPLEMENTATIONS.md) for a list of known implementations.
2. **Configure your AI agent** to use NL Protocol concepts: secret references (`{{nl:...}}`), action requests, and result-only access.
3. **Define Scope Grants** that control which agent can access which secrets, when, and under what conditions.

This guide covers the protocol concepts you need to understand regardless of which implementation you choose.

---

## 2. Core Concept: The Paradigm Shift

### The Old Model (Unsafe)

Every AI agent framework today works the same way when it needs a secret:

```
1. Agent decides it needs a credential.
2. Agent reads the credential value (from env, file, vault, or user).
3. Credential value enters the LLM context window.
4. LLM context is sent to a cloud inference provider.
5. Credential persists in logs, memory, and conversation history.
```

At step 2, the secret is compromised. It does not matter how securely you stored it beforehand. Once the value is in the context window, it is out of your control. It can be memorized by the model, replicated in output, exfiltrated via prompt injection, or leaked through conversation history.

### The NL Protocol Model (Secure)

```
1. Agent decides it needs the RESULT of an action that uses a credential.
2. Agent sends an Action Request with {{nl:namespace/SECRET_NAME}} placeholders.
3. An NL-compliant system resolves the placeholders to real secret values.
4. The system executes the action in an isolated process.
5. Only the result is returned to the agent.
6. The credential value never enters the LLM context.
```

### The Key Insight

**Agents do not need secrets. They need the results of actions that use secrets.**

- An agent does not need your Stripe API key. It needs to create a charge.
- An agent does not need your database password. It needs to run a query.
- An agent does not need your SSH key. It needs to deploy code to a server.

The NL Protocol enforces this distinction at the architecture level. The agent expresses *what it wants to do* using secret references. A trusted, NL-compliant system handles *how the secret is used* inside an isolation boundary the agent cannot observe.

### What Changes

| Before NL Protocol | After NL Protocol |
|--------------------|-------------------|
| Agent reads the secret value | Agent writes a template with `{{nl:...}}` placeholders |
| Secret enters agent context, visible to the LLM | Secret is resolved inside an isolated process, invisible to the agent |
| Agent can log, leak, or exfiltrate the value | Agent receives only the action result |
| No audit trail of how the secret was used | Every action is logged with agent identity and action details |

---

## 3. Secret References

Secret references are the placeholder syntax that agents use to refer to secrets without ever seeing their values. A secret reference is an **opaque handle** -- it identifies a secret but carries no information about the secret's value.

### Syntax

All secret references follow this pattern:

```
{{nl:REFERENCE}}
```

The `REFERENCE` part supports five formats, from simple to fully qualified:

### Reference Formats

| Format | Syntax | When to Use | Example |
|--------|--------|-------------|---------|
| **Simple** | `{{nl:NAME}}` | When there is only one secret with that name across all your scopes. | `{{nl:API_KEY}}` |
| **Categorized** | `{{nl:CATEGORY/NAME}}` | When you want to specify the category (most common format). | `{{nl:database/DB_PASSWORD}}` |
| **Scoped** | `{{nl:PROJECT/ENVIRONMENT/NAME}}` | When you need to target a specific project and environment. | `{{nl:myapp/production/STRIPE_KEY}}` |
| **Fully Qualified** | `{{nl:PROJECT/ENV/CATEGORY/NAME}}` | When you want an exact, unambiguous match. | `{{nl:myapp/production/payments/STRIPE_KEY}}` |
| **Cross-Provider** | `{{nl:PROVIDER://PATH}}` | When resolving from an external secret provider (e.g., AWS Secrets Manager). | `{{nl:aws-sm://us-east-1/prod/db-pass}}` |

### Resolution Rules

- **Simple references** search all accessible scopes. If multiple secrets match, the NL-compliant system returns an `AMBIGUOUS_REFERENCE` error.
- **Categorized references** narrow the search to a specific category.
- **Scoped and fully qualified references** are exact lookups -- they match one secret or return `SECRET_NOT_FOUND`.
- **Cross-provider references** delegate resolution to an external provider. If the provider is not configured, the system returns `PROVIDER_NOT_CONFIGURED`.

### Examples in Context

```bash
# Simple reference
curl -H "Authorization: Bearer {{nl:GITHUB_TOKEN}}" https://api.github.com/user

# Categorized reference
psql "postgresql://admin:{{nl:database/DB_PASSWORD}}@localhost/mydb"

# Scoped reference (production credentials)
aws s3 ls --region us-east-1  # with {{nl:braincol/production/AWS_ACCESS_KEY}}

# Fully qualified reference
docker login -u deploy -p {{nl:braincol/production/registry/DOCKER_TOKEN}} ghcr.io

# Cross-provider reference (AWS Secrets Manager)
curl -H "X-Api-Key: {{nl:aws-sm://us-east-1/prod/api-keys/payment-gateway}}" \
  https://payments.example.com/charge

# Multiple placeholders in one template
curl -u "{{nl:api/USERNAME}}:{{nl:api/PASSWORD}}" https://api.example.com/data
```

### Escaping

If you need the literal string `{{nl:` in content that is not a placeholder, escape it by doubling the opening braces: `{{{{nl:`. NL-compliant systems will not attempt to resolve escaped placeholders.

---

## 4. Action Types

The NL Protocol defines six action types. Each action type specifies how a secret is injected into the execution environment and how results are returned. When an agent needs to use a secret, it sends an **Action Request** specifying the action type and a template with secret references.

### 4.1 `exec` -- Execute a Shell Command

The most common action type. The agent provides a command template with `{{nl:...}}` placeholders. The NL-compliant system resolves them, injects secret values as environment variables into an isolated subprocess, and runs the command.

**Action Request:**

```json
{
  "action": {
    "type": "exec",
    "template": "curl -H 'Authorization: Bearer {{nl:api/GITHUB_TOKEN}}' https://api.github.com/user",
    "purpose": "Verify GitHub API access for CI setup",
    "timeout_ms": 30000
  }
}
```

**What the agent receives back:**

```json
{
  "status": "success",
  "result": {
    "stdout": "{\"login\":\"acme-bot\",\"id\":12345}",
    "stderr": "",
    "exit_code": 0
  },
  "secrets_used": ["api/GITHUB_TOKEN"]
}
```

The agent never sees the actual token value. It sees only the result.

**When to use:** API calls, database queries, deployments, any shell command that needs credentials.

**Conformance:** MUST be supported by all implementations.

### 4.2 `template` -- Render a Template with Secrets

The agent provides a template containing placeholders. The system resolves all placeholders and writes the result to a file with restricted permissions. The agent receives confirmation that the file was written, but never sees the file contents.

**Action Request:**

```json
{
  "action": {
    "type": "template",
    "template_content": "DB_HOST=localhost\nDB_USER=admin\nDB_PASS={{nl:database/DB_PASSWORD}}\nDB_NAME=myapp\n",
    "output_path": "/tmp/nl-secure/app.env"
  }
}
```

**What the agent receives back:**

```json
{
  "status": "success",
  "result": {
    "output_path": "/tmp/nl-secure/app.env",
    "resolved_count": 1,
    "permissions": "0600"
  },
  "secrets_used": ["database/DB_PASSWORD"]
}
```

**When to use:** Generating configuration files, `.env` files, Kubernetes manifests, or any file that needs secret values embedded.

**Conformance:** MUST be supported by all implementations.

### 4.3 `inject_stdin` -- Pipe a Secret via stdin

Some tools accept secrets via stdin rather than command-line arguments (e.g., `docker login --password-stdin`). This action type pipes the resolved secret value into the command's stdin.

**Action Request:**

```json
{
  "action": {
    "type": "inject_stdin",
    "command": "docker login -u deploy --password-stdin ghcr.io",
    "secret_ref": "{{nl:registry/DOCKER_TOKEN}}"
  }
}
```

**What the agent receives back:**

```json
{
  "status": "success",
  "result": {
    "stdout": "Login Succeeded",
    "stderr": "",
    "exit_code": 0
  },
  "secrets_used": ["registry/DOCKER_TOKEN"]
}
```

**When to use:** Tools that accept credentials via stdin. This avoids placing secrets in command-line arguments, which are visible in process listings (`ps aux`).

**Conformance:** MUST be supported by all implementations.

### 4.4 `inject_tempfile` -- Create a Temporary File with a Secret

Some tools require secrets as files: SSH private keys, TLS certificates, GCP service account JSON, kubeconfig files. The system creates a temporary file containing the secret value, executes the command referencing that file, and then securely deletes it.

**Action Request:**

```json
{
  "action": {
    "type": "inject_tempfile",
    "command": "ssh -i {{nl:SSH_KEY_FILE}} deploy@prod.example.com 'systemctl restart app'",
    "file_refs": {
      "SSH_KEY_FILE": "{{nl:ssh/id_rsa_deploy}}"
    }
  }
}
```

The system writes the SSH key to a temporary file with `0o400` (read-only, owner only) permissions, rewrites the command to reference the temp file path, executes the command, then overwrites the file with random data and deletes it.

**What the agent receives back:**

```json
{
  "status": "success",
  "result": {
    "stdout": "",
    "stderr": "",
    "exit_code": 0
  },
  "secrets_used": ["ssh/id_rsa_deploy"]
}
```

**When to use:** SSH keys, TLS certificates, service account JSON, kubeconfig files, or any tool that requires a file-based credential.

**Conformance:** MUST be supported by all implementations.

### 4.5 `sdk_proxy` -- Proxy an SDK/API Call

Instead of executing a shell command, the NL-compliant system makes an SDK or API call directly, using the resolved secret as authentication. This is designed for cloud providers (AWS, GCP, Azure) and API platforms (Stripe, GitHub) to implement natively.

**Action Request:**

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
    "credentials_ref": "{{nl:aws/AWS_CREDENTIALS}}"
  }
}
```

**What the agent receives back:**

```json
{
  "status": "success",
  "result": {
    "data": {
      "Contents": [
        {"Key": "reports/2026-01.csv", "Size": 1234},
        {"Key": "reports/2026-02.csv", "Size": 5678}
      ]
    }
  },
  "secrets_used": ["aws/AWS_CREDENTIALS"]
}
```

**When to use:** When an NL-compliant system offers native SDK integration with a cloud provider or API platform. Avoids the overhead of spawning a subprocess.

**Conformance:** SHOULD be supported. Not required for Basic conformance.

### 4.6 `delegate` -- Delegate to Another Agent

In multi-agent systems, an orchestrator agent can delegate a scoped action to a sub-agent. The delegating agent issues a Delegation Token that grants the sub-agent a restricted subset of its own permissions, with time limits and usage caps.

**Action Request:**

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

Neither the delegating agent nor the sub-agent ever sees the `DEPLOY_TOKEN` value. The sub-agent executes the action through its own isolation boundary, and the result flows back to the orchestrator.

**When to use:** Multi-agent workflows where an orchestrator coordinates sub-agents, each with different scoped permissions.

**Conformance:** SHOULD be supported. Required for Advanced conformance.

---

## 5. Scope Grants

Scope Grants are the permission model of the NL Protocol. A Scope Grant answers the question: **Is this agent allowed to perform this action type on these secrets, right now, under these conditions?**

### What a Scope Grant Controls

Every Scope Grant binds together:

- **An agent identity** (which agent)
- **Allowed action types** (exec, template, inject_stdin, etc.)
- **Allowed secrets** (glob patterns like `api/*` or `database/DB_PASSWORD`)
- **Time bounds** (valid from / valid until)
- **Usage limits** (max number of uses)
- **Conditions** (minimum trust level, required environments, human approval)

### Schema (Abbreviated)

```json
{
  "grant_id": "grant_550e8400-e29b-41d4-a716-446655440000",
  "agent_uri": "nl://anthropic.com/claude-code/1.5.2",
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
        "allowed_environments": ["development", "staging"]
      }
    }
  ],

  "revocable": true,
  "revoked": false
}
```

### Grant Lifecycle

1. **Created** -- A human administrator (or the system, for delegation) creates the grant.
2. **Active** -- The current time is between `valid_from` and `valid_until`, the grant is not revoked, and usage is below `max_uses`.
3. **Expired** -- The `valid_until` timestamp has passed.
4. **Exhausted** -- The `max_uses` limit has been reached.
5. **Revoked** -- An administrator explicitly revoked the grant.

Expired, exhausted, and revoked grants cannot authorize any actions.

### Practical Example

This grant allows a Claude Code agent to access development API keys and database credentials for the current workday, up to 100 uses, in the development and staging environments:

```json
{
  "grant_id": "grant_daily_dev_2026-02-08",
  "agent_uri": "nl://anthropic.com/claude-code/1.5.2",
  "permissions": [{
    "action_types": ["exec", "template", "inject_stdin", "inject_tempfile"],
    "secrets": ["api/*", "database/DB_*"],
    "conditions": {
      "valid_from": "2026-02-08T09:00:00Z",
      "valid_until": "2026-02-08T18:00:00Z",
      "max_uses": 100,
      "allowed_environments": ["development", "staging"]
    }
  }]
}
```

If the agent tries to access `production/STRIPE_KEY`, the request is denied because the grant only covers `api/*` and `database/DB_*` in development and staging environments.

For the full Scope Grant schema and evaluation algorithm, see [02-action-based-access.md](../../specification/v1.0/02-action-based-access.md), Sections 8-8.6.

---

## 6. Configuring AI Agents

To adopt the NL Protocol, you need to instruct your AI agent to use **secret references** and **action-based access** instead of reading secret values directly. The instructions you give should be implementation-agnostic -- they describe the *protocol behavior*, and whatever NL-compliant system you have installed handles the execution.

### The Core Rules

Every agent instruction file should communicate these principles:

1. **All secret access MUST go through action requests with `{{nl:namespace/SECRET_NAME}}` syntax.**
2. **Never read, echo, cat, export, or log secret values directly.**
3. **Express what you need to do, not what credentials you need to read.**

### Claude Code

Add instructions to your project's `CLAUDE.md` file:

```markdown
# Secret Handling (NL Protocol)

NEVER read secrets directly from environment variables, .env files, or vaults.
ALWAYS use secret references with {{nl:...}} syntax in action requests.

Instead of:
  export API_KEY=$(cat .env | grep API_KEY | cut -d= -f2)
  curl -H "Authorization: Bearer $API_KEY" https://api.openai.com/v1/models

Do this:
  Submit an action request with:
  curl -H "Authorization: Bearer {{nl:api/OPENAI_KEY}}" https://api.openai.com/v1/models

The NL-compliant system will resolve the secret, execute the command in isolation,
and return only the result. You will never see the secret value.

Available secret references:
- {{nl:api/OPENAI_KEY}} - OpenAI API key
- {{nl:db/POSTGRES_URL}} - PostgreSQL connection string
- {{nl:aws/ACCESS_KEY}} - AWS access key ID
- {{nl:aws/SECRET_KEY}} - AWS secret access key
```

### Cursor

Add a `.cursor/rules` file to your project:

```
When performing actions that require secrets or credentials:
1. Never read secrets from .env, environment variables, or config files.
2. Use NL Protocol secret references: {{nl:namespace/SECRET_NAME}}
3. Express the action you need (e.g., "make an API call to...") using
   {{nl:...}} placeholders in the command. The NL-compliant system will
   resolve the secrets and execute the command.
4. You will receive only the result, never the secret value.
```

### GitHub Copilot

Add instructions to your `.github/copilot-instructions.md`:

```markdown
# Security: NL Protocol Secret Handling

All secret access MUST go through NL Protocol action requests.
Never read, cat, echo, or export secrets directly.
Use the syntax: {{nl:namespace/SECRET_NAME}} as a placeholder in commands.
The secret value will be resolved and injected by the NL-compliant system.
You will receive only the command result, never the secret itself.
```

### General Principle

The pattern is the same for any agent:

1. **Tell the agent** that secrets are accessed through `{{nl:...}}` placeholders, not by reading values.
2. **List the available secret references** so the agent knows what paths exist.
3. **Explain the behavior**: the agent writes the *shape* of the command, and an NL-compliant system handles resolution, execution in isolation, and returning the result.

The specific mechanism by which the NL-compliant system receives the action request (CLI tool, MCP server, API endpoint, agent framework plugin) is determined by which implementation you have installed. The agent instructions should focus on the *protocol concept* (use `{{nl:...}}` references), not on a specific product.

---

## 7. Conformance Levels

The NL Protocol defines seven independent levels and three conformance tiers. Implementations can adopt levels incrementally, and you can choose the tier that fits your needs.

### The Three Tiers

| Tier | Levels Required | What You Get |
|------|----------------|-------------|
| **Basic** | Levels 1-3 | Agent identity, action-based access with secret references, execution in isolated processes. Secrets never enter agent context. This is the foundation. |
| **Standard** | Levels 1-5 | Basic, plus pre-execution defense (blocks dangerous commands before they run) and immutable, hash-chained audit trails of every agent-secret interaction. |
| **Advanced** | Levels 1-7 | Standard, plus real-time attack detection and response, and cross-agent trust with delegation tokens for multi-agent systems. |

### Which Tier Should You Target?

| You Are... | Target Tier | Why |
|------------|-------------|-----|
| An individual developer on side projects | **Basic** | Secrets never enter agent context. Fast setup. Immediate risk reduction. |
| A team shipping production software | **Basic** or **Standard** | Basic protection, plus audit trails if you need accountability. |
| A team with compliance requirements (SOC 2, ISO 27001) | **Standard** | Auditable secret governance. Pre-execution defense against injection. |
| An enterprise running multi-agent systems | **Advanced** | Full defense-in-depth. Cross-agent delegation. Attack detection. |

### The Seven Levels

| Level | Name | Summary |
|-------|------|---------|
| 1 | Agent Identity | Every agent has a unique, verifiable identity with scoped capabilities. |
| 2 | Action-Based Access | Agents request actions via `{{nl:...}}` placeholders, not secret values. Scope Grants control permissions. |
| 3 | Execution Isolation | Secrets are resolved and consumed inside an isolated subprocess. Memory is wiped after execution. |
| 4 | Pre-Execution Defense | Dangerous commands (injection, exfiltration patterns) are intercepted and blocked before execution. |
| 5 | Audit and Integrity | Every action is recorded in an immutable, hash-chained, HMAC-protected audit trail. |
| 6 | Attack Detection | Exfiltration attempts, prompt injection, and anomalous behavior are detected, scored, and responded to automatically. |
| 7 | Cross-Agent Trust | Agents can delegate scoped authority to sub-agents via delegation tokens. Cross-organization federation without secret exposure. |

### Start Basic, Grow Later

You do not need to implement everything on day one. Start with Basic conformance (Levels 1-3). It eliminates the most critical risk: secrets in agent context. Upgrade to Standard or Advanced when your compliance requirements or threat model demands it.

---

## 8. FAQ

### Is NL Protocol a product?

No. NL Protocol is an **open specification**, licensed under CC BY 4.0. It defines behaviors, data formats, and security requirements. Anyone can implement it. The specification lives in this repository. For a list of implementations, see [IMPLEMENTATIONS.md](../../IMPLEMENTATIONS.md).

### Do I need to change my AI agent's code?

No. The NL Protocol does not require modifications to the agent's source code. You configure the agent via its instruction mechanism (e.g., `CLAUDE.md`, `.cursor/rules`, `.github/copilot-instructions.md`) to use `{{nl:...}}` secret references instead of reading secret values. The NL-compliant system you install handles everything else: resolving references, executing in isolation, and returning results.

### What about my existing secret manager (HashiCorp Vault, 1Password, AWS Secrets Manager)?

The NL Protocol works as a **layer on top of** your existing secret infrastructure. It does not replace your secret manager. NL-compliant implementations can bridge to your existing secret stores using cross-provider references (e.g., `{{nl:aws-sm://us-east-1/prod/db-pass}}`) or backend adapters. Your secrets stay where they are; the NL Protocol governs how agents *access* them.

### What if the agent tries to read a secret directly anyway?

The NL Protocol does not prevent an agent from running `cat .env` -- that is an agent framework concern. However, you can mitigate this by:

- **Removing plaintext secrets** from the agent's filesystem entirely (store them only in the NL-compliant system's backing store).
- **Using pre-execution defense** (Standard conformance, Level 4) to detect and block exfiltration commands.
- **Configuring your agent's permission system** to deny file reads on sensitive paths.

The strongest protection comes from not having secrets in places the agent can read. If the only way to access a secret is through `{{nl:...}}` action requests, the agent has no alternative path.

### What is the performance overhead?

This depends entirely on the implementation you choose. The protocol itself adds no overhead -- it is a specification, not software. In practice, NL-compliant implementations typically add tens of milliseconds for secret resolution and subprocess setup. For most use cases (API calls, database queries, deployments), this is negligible compared to the network latency of the operation itself.

### Can I use NL Protocol in CI/CD pipelines?

Yes. The protocol is designed to work in any environment where an agent (or automated process) needs to use secrets. CI/CD pipelines are a natural fit. The specifics of integration depend on which NL-compliant implementation you use and how it integrates with your CI/CD platform (GitHub Actions, GitLab CI, Jenkins, etc.).

### How does this compare to just using environment variables?

Environment variables are better than hardcoded secrets, but they are still visible to the agent. When an agent runs `env` or `echo $API_KEY`, the secret enters the context window. With the NL Protocol, secrets are injected into an *isolated subprocess* that the agent cannot inspect. The agent's main process -- and therefore the LLM context -- never contains the secret value.

### Where can I get a working implementation?

[Braincol Vault](https://github.com/braincol/braincol-vault) is the reference implementation of the NL Protocol, licensed under Apache-2.0 (open-source core). It implements Levels 1--5 (Standard conformance) with 16 MCP tools, 7 AI agent configurations, a CLI, REST API, Web Dashboard, and MCP Server. See [IMPLEMENTATIONS.md](../../IMPLEMENTATIONS.md) for a full description and for other implementations as they become available.

### What if I want to build my own NL-compliant implementation?

Read the full specification, starting with [00-overview.md](../../specification/v1.0/00-overview.md). The specification defines all required behaviors, data formats, and conformance tests. If you are a platform provider (cloud vendor, secret manager, agent framework), see the [PLATFORM-GUIDE.md](PLATFORM-GUIDE.md) for implementation guidance specific to your domain.

---

## 9. Next Steps

### Read the Specification

The full NL Protocol specification is organized by level:

| Level | Document | Topic |
|-------|----------|-------|
| Overview | [00-overview.md](../../specification/v1.0/00-overview.md) | Architecture, goals, terminology, conformance tiers |
| 1 | [01-agent-identity.md](../../specification/v1.0/01-agent-identity.md) | Agent URI, identity documents, attestation, trust levels |
| 2 | [02-action-based-access.md](../../specification/v1.0/02-action-based-access.md) | Placeholder syntax, action types, scope grants, output sanitization |
| 3 | [03-execution-isolation.md](../../specification/v1.0/03-execution-isolation.md) | Process isolation, env var injection, memory protection |
| 4 | [04-pre-execution-defense.md](../../specification/v1.0/04-pre-execution-defense.md) | Command interception, deny rules, evasion detection |
| 5 | [05-audit-integrity.md](../../specification/v1.0/05-audit-integrity.md) | Hash-chained audit log, tamper evidence |
| 6 | [06-attack-detection.md](../../specification/v1.0/06-attack-detection.md) | Attack taxonomy, threat scoring, automated response |
| 7 | [07-cross-agent-trust.md](../../specification/v1.0/07-cross-agent-trust.md) | Delegation tokens, federation, result-only propagation |

### Find an Implementation

See [IMPLEMENTATIONS.md](../../IMPLEMENTATIONS.md) for NL-compliant implementations you can use today. [Braincol Vault](https://github.com/braincol/braincol-vault) is the reference implementation (Apache-2.0, Standard conformance, Levels 1--5).

### For Platform Providers

If you are building a secret manager, cloud service, or agent framework and want to implement NL Protocol support, see the [PLATFORM-GUIDE.md](PLATFORM-GUIDE.md).

### Get Involved

- **GitHub Discussions**: Ask questions, share use cases, report issues.
- **Contributing**: See [CONTRIBUTING.md](../../CONTRIBUTING.md) to get involved in the specification.

---

<p align="center">
  <sub>Your agent is powerful enough to deploy your entire infrastructure. It should not also be holding the keys.</sub>
</p>
