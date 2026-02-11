# NL Protocol Specification v1.0 -- Level 1: Agent Identity

**Status:** 1.0
**Version:** 1.0.0
**Date:** 2026-02-08
**Level:** 1 (Foundation)
**Conformance:** Required for all tiers (Basic, Standard, Advanced)

> **Note:** This document is a SPECIFICATION. It defines required behaviors,
> data formats, and protocols — not specific products or CLI commands.
> For implementations of this specification, see [IMPLEMENTATIONS.md](../../IMPLEMENTATIONS.md).

---

## 1. Purpose

Every agent that interacts with secrets MUST have a unique, verifiable,
governable identity. Without identity, it is impossible to:

- Enforce per-agent access policies (Level 2)
- Attribute actions in audit trails (Level 5)
- Detect anomalous behavior per agent (Level 6)
- Establish trust between agents (Level 7)
- Revoke access to a single compromised agent without disrupting others

Agent identity is the foundation upon which every other level of the NL
Protocol is built.

This specification defines:

- The Agent URI format for globally unique identification
- The Agent Identity Document (AID) structure
- Agent type taxonomy and risk profiles
- Agent lifecycle states and transitions
- Platform attestation via signed JWTs
- Trust levels from self-attested to third-party-certified
- Registration and verification flows

---

## 2. Requirements Summary

| ID | Requirement | Priority | Description |
|----|-------------|----------|-------------|
| NL-1.1 | Agent URI | MUST | Every agent MUST have a globally unique URI in the `nl://` scheme. |
| NL-1.2 | Agent Identity Document | MUST | Every agent MUST have a structured AID containing identity, capabilities, context, and lifecycle metadata. |
| NL-1.3 | Agent Type | MUST | Every agent MUST declare its type from the standard taxonomy. |
| NL-1.4 | Agent Capabilities | MUST | Every AID MUST declare the set of action types the agent is authorized to perform. |
| NL-1.5 | Agent Lifecycle | MUST | Every agent MUST have a lifecycle state that governs whether it can perform actions. |
| NL-1.6 | Agent Credential | MUST | Every agent MUST authenticate using a credential mechanism supported by the NL-compliant system. |
| NL-1.7 | Platform Attestation | SHOULD (Basic), MUST (Standard+) | Platform Providers SHOULD sign attestation JWTs for agents they provision. Attestation is REQUIRED for Standard and Advanced conformance. |
| NL-1.8 | Trust Level | MUST | Every agent MUST have an assigned trust level (L0-L3) that reflects its identity assurance. |
| NL-1.9 | Session Context | SHOULD | The AID SHOULD include session context (IDE, repository, branch, workspace) when available. |
| NL-1.10 | Expiration | MUST | Every AID MUST have an `expires_at` timestamp. Expired AIDs MUST be rejected. |
| NL-1.11 | Delegation Chain | SHOULD | The AID SHOULD record the delegation chain: which human or parent agent authorized this agent. |
| NL-1.12 | Organization Binding | MUST | Every agent MUST be bound to an organization identifier. |

---

## 3. Agent URI Format

### 3.1 Syntax

Every agent MUST be identified by a URI in the following format:

```
nl://VENDOR/AGENT_TYPE/VERSION
```

Where:

- `nl://` is the scheme identifier for the Never-Leak Protocol.
- `VENDOR` is the DNS-style domain of the organization that produces or
  operates the agent. It MUST be a valid domain name (lowercase, no port,
  no trailing dot).
- `AGENT_TYPE` is a kebab-case identifier for the agent software. It MUST
  consist of lowercase ASCII letters, digits, and hyphens. It MUST NOT
  begin or end with a hyphen.
- `VERSION` is a semantic version string (MAJOR.MINOR.PATCH). Pre-release
  and build metadata suffixes (e.g., `-beta.1`, `+build.42`) are OPTIONAL.

### 3.2 ABNF Grammar

```abnf
agent-uri    = "nl://" vendor "/" agent-type "/" version
vendor       = domain-name
agent-type   = LCALPHA *(LCALPHA / DIGIT / "-") LCALPHA
             / LCALPHA
version      = 1*DIGIT "." 1*DIGIT "." 1*DIGIT [pre-release] [build]
pre-release  = "-" 1*(ALPHA / DIGIT / ".")
build        = "+" 1*(ALPHA / DIGIT / ".")
domain-name  = label *("." label)
label        = LCALPHA *(LCALPHA / DIGIT / "-")
LCALPHA      = %x61-7A  ; a-z
```

### 3.3 Examples

| Agent | Agent URI |
|-------|-----------|
| Claude Code v1.5.2 by Anthropic | `nl://anthropic.com/claude-code/1.5.2` |
| Cursor AI v0.45.0 | `nl://cursor.com/cursor-ai/0.45.0` |
| GitHub Copilot v1.200.0 | `nl://github.com/copilot/1.200.0` |
| OpenAI Codex CLI v1.0.0 | `nl://openai.com/codex-cli/1.0.0` |
| Windsurf by Codeium v1.2.0 | `nl://codeium.com/windsurf/1.2.0` |
| Custom deploy bot by Acme Corp | `nl://acme.corp/deploy-bot/2.1.0` |
| CI pipeline runner by Acme Corp | `nl://acme.corp/ci-runner/1.0.0` |
| Human user (via CLI) | `nl://acme.corp/human/0.0.0` |

### 3.4 Uniqueness and Instance Distinction

The combination of `VENDOR + AGENT_TYPE + VERSION` identifies a specific
**agent software release**. Two different agent products MUST NOT share
the same URI.

However, multiple *instances* of the same agent software (e.g., two
concurrent Claude Code sessions) share the same Agent URI. Instances are
distinguished by the `instance_id` field within the AID (see Section 4).

**Example:** Developer Alice and developer Bob both use Claude Code 1.5.2.
Both agents have the URI `nl://anthropic.com/claude-code/1.5.2`, but
Alice's instance has `instance_id: "a1b2..."` and Bob's has
`instance_id: "c3d4..."`.

### 3.5 Relationship to SPIFFE

The `nl://` URI scheme is inspired by SPIFFE's `spiffe://` URIs but serves
a different purpose. SPIFFE identifies infrastructure workloads; NL URIs
identify AI agent software. Implementations MAY maintain a mapping between
SPIFFE IDs and NL Agent URIs for organizations that use both systems.

---

## 4. Agent Identity Document (AID)

### 4.1 Overview

The Agent Identity Document (AID) is a JSON structure that fully describes
an agent's identity, capabilities, attestation, session context, and
lifecycle state. Every agent MUST present a valid AID when submitting
action requests to an NL-compliant system.

The AID is NOT a secret. It is an identity document analogous to a
passport: it describes who the agent is, not what secrets it can access.
Access is governed by Scope Grants (Level 2).

### 4.2 Complete Schema

```json
{
  "$schema": "https://nlprotocol.org/schemas/v1.0/aid.json",
  "nl_version": "1.0",

  "agent_uri": "nl://anthropic.com/claude-code/1.5.2",
  "instance_id": "550e8400-e29b-41d4-a716-446655440000",
  "organization_id": "org_acme_corp_2024",

  "agent_type": "coding_assistant",
  "trust_level": "L2",

  "delegated_by": {
    "type": "human",
    "identifier": "andres@acme.corp",
    "delegation_time": "2026-02-08T10:00:00Z"
  },

  "capabilities": [
    "exec",
    "template",
    "inject_stdin",
    "inject_tempfile"
  ],

  "scope": {
    "projects": ["braincol", "xpro"],
    "environments": ["development", "staging"],
    "categories": ["api", "database"],
    "secret_patterns": ["api/*", "database/DB_*"]
  },

  "public_key": {
    "algorithm": "ES256",
    "value": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE..."
  },

  "attestation": {
    "type": "jwt",
    "token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImFudGhyb3BpYy1ubC0yMDI2LTAxIn0...",
    "issuer": "anthropic.com",
    "issued_at": "2026-02-08T10:00:00Z",
    "expires_at": "2026-02-08T22:00:00Z"
  },

  "session_context": {
    "ide": "vscode",
    "ide_version": "1.96.0",
    "repository": "github.com/acme-corp/backend",
    "branch": "feature/payments",
    "workspace": "/Users/andres/projects/backend",
    "os": "darwin",
    "hostname": "andres-macbook"
  },

  "lifecycle": "active",

  "created_at": "2026-02-08T10:00:00Z",
  "expires_at": "2026-02-08T22:00:00Z",
  "last_active_at": "2026-02-08T14:30:00Z"
}
```

### 4.3 Field Definitions

#### 4.3.1 Required Fields

Every AID MUST contain the following fields:

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| `nl_version` | string | MUST be `"1.0"` | The NL Protocol version this AID conforms to. |
| `agent_uri` | string | MUST match Section 3.2 ABNF | The Agent URI identifying the agent software. |
| `instance_id` | string | UUID v4 (RFC 4122) | Unique identifier for this agent instance. Generated by the NL-compliant system during registration. |
| `organization_id` | string | Non-empty, printable ASCII | The identifier of the organization that registered this agent. Format is implementation-defined. |
| `agent_type` | string | One of the values in Section 5 | The agent's type from the standard taxonomy. |
| `trust_level` | string | `"L0"` or `"L1"` or `"L2"` or `"L3"` | The trust level, reflecting the strength of identity verification. See Section 7. |
| `capabilities` | string[] | Non-empty array | List of action types this agent is authorized to request. Valid values: `"exec"`, `"template"`, `"inject_stdin"`, `"inject_tempfile"`, `"sdk_proxy"`, `"delegate"`. |
| `lifecycle` | string | One of the values in Section 6 | Current lifecycle state. |
| `created_at` | string | ISO 8601, UTC | When this AID was created. |
| `expires_at` | string | ISO 8601, UTC, after `created_at` | When this AID expires. See expiration boundary semantics below. |

**Expiration boundary semantics:** The comparison `expires_at > now()`
uses the NL Provider's system clock at the time the request is received
(not when processing completes). This means an AID that expires during
the processing of an action request is still considered valid for that
request, provided it was valid at the moment the request arrived.
Implementations SHOULD use monotonic clocks for timeout enforcement
(e.g., session inactivity timers) and wall clocks for expiration
comparison (e.g., `expires_at` checks).

#### 4.3.2 Recommended Fields

The following fields are RECOMMENDED. Implementations SHOULD include them.

| Field | Type | Description |
|-------|------|-------------|
| `public_key` | object | The agent's public key for delegation token signing. Contains `algorithm` (string, e.g., `"ES256"`, `"Ed25519"`) and `value` (string, base64url-encoded public key). SHOULD for Basic conformance, MUST for Standard and Advanced conformance. Required for delegation token signing (see Chapter 07). |
| `delegated_by` | object | Who authorized this agent. See Section 4.3.4. |
| `scope` | object | Access scope restrictions. See Section 4.3.5. |
| `attestation` | object | Platform attestation JWT. See Section 8. REQUIRED for Standard+ conformance. |
| `session_context` | object | Runtime context. See Section 4.3.6. |
| `last_active_at` | string (ISO 8601) | Timestamp of the agent's most recent action. Updated by the NL-compliant system. |

#### 4.3.3 Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `metadata` | object | Arbitrary key-value pairs for implementation-specific data. Keys MUST be strings. Values MUST be strings, numbers, or booleans. |

#### 4.3.4 Delegation Chain (`delegated_by`)

```json
{
  "type": "human | agent",
  "identifier": "andres@acme.corp | nl://acme.corp/orchestrator/1.0.0",
  "delegation_time": "2026-02-08T10:00:00Z",
  "parent_instance_id": "optional-uuid-of-parent-agent"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | `"human"` if delegated by a human user, `"agent"` if delegated by a parent agent. |
| `identifier` | string | For humans: email address or username. For agents: the parent agent's Agent URI. |
| `delegation_time` | string (ISO 8601) | When the delegation occurred. |
| `parent_instance_id` | string (UUID, optional) | If delegated by an agent, the parent's `instance_id`. Enables audit chain linking. |

#### 4.3.5 Scope Object

The scope object restricts what secrets the agent can reference. If
omitted, the agent has no inherent scope and MUST rely entirely on
explicit Scope Grants (Level 2).

```json
{
  "projects": ["braincol", "xpro"],
  "environments": ["development", "staging"],
  "categories": ["api", "database"],
  "secret_patterns": ["api/*", "database/DB_*"]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `projects` | string[] | Allowed projects. `["*"]` means all projects. |
| `environments` | string[] | Allowed environments. `["*"]` means all environments. |
| `categories` | string[] (optional) | Allowed secret categories. If omitted, all categories are allowed within the specified projects/environments. |
| `secret_patterns` | string[] (optional) | Glob patterns for allowed secret names. See glob pattern semantics below. |

**Secret name pattern glob syntax:**

Secret name patterns use glob syntax with the following rules:

- `*` matches any sequence of characters EXCEPT `/` (single level).
  For example, `api/*` matches `api/KEY` but does NOT match
  `api/v2/KEY`.
- `**` matches any sequence of characters INCLUDING `/` (multi-level).
  For example, `api/**` matches `api/KEY`, `api/v2/KEY`, and
  `api/v2/internal/KEY`.
- `?` matches exactly one character. For example, `DB_?` matches
  `DB_A` but does NOT match `DB_AB`.
- Patterns are anchored: `api/*` matches `api/KEY` but NOT
  `my-api/KEY`. The pattern must match from the beginning of the
  secret name.
- An empty segment after `*` is not matched: `api/*` does NOT match
  `api/` (a trailing separator with no name component).

**Scope semantics:** The `scope` field in an AID defines the MAXIMUM
boundary of what an agent MAY access. Scope Grants (Chapter 02) define
ACTUAL access within that boundary. Access is granted only when BOTH
the AID scope AND an active Scope Grant permit the action (logical AND).

For example, if an AID scope has `environments: ["dev"]` and a Scope
Grant specifies `allowed_environments: ["prod"]`, the action MUST be
denied because `prod` is outside the AID scope boundary. The AID scope
acts as an upper bound; Scope Grants cannot expand access beyond it.

**Scope evaluation rule:** A secret reference `{{nl:project/environment/category/name}}`
is within scope if and only if:

1. `project` matches at least one entry in `projects` (or `projects` contains `"*"`), AND
2. `environment` matches at least one entry in `environments` (or `environments` contains `"*"`), AND
3. `category` matches at least one entry in `categories` (or `categories` is omitted), AND
4. The fully qualified secret path matches at least one pattern in `secret_patterns` (or `secret_patterns` is omitted).

#### 4.3.6 Session Context

All session context fields are OPTIONAL. Implementations SHOULD populate
them when the information is available.

```json
{
  "ide": "vscode",
  "ide_version": "1.96.0",
  "repository": "github.com/acme-corp/backend",
  "branch": "feature/payments",
  "workspace": "/Users/andres/projects/backend",
  "os": "darwin",
  "hostname": "andres-macbook"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `ide` | string | IDE or development environment: `"vscode"`, `"jetbrains"`, `"neovim"`, `"terminal"`, etc. |
| `ide_version` | string | Version of the IDE. |
| `repository` | string | The repository the agent is working in (e.g., `"github.com/acme/app"`). |
| `branch` | string | The active Git branch. |
| `workspace` | string | The local workspace/directory path. |
| `os` | string | The operating system: `"darwin"`, `"linux"`, `"windows"`. |
| `hostname` | string | The machine hostname. |

Session context is valuable for:

- **Anomaly detection (Level 6):** Detecting when an agent's session
  context changes unexpectedly (e.g., same agent appearing from a
  different hostname).
- **Policy evaluation:** Scope Grants MAY be conditional on session
  context (e.g., "only allow production access from CI/CD, not from
  developer laptops").
- **Audit enrichment (Level 5):** Recording what the agent was doing
  when it accessed a secret.

### 4.4 Validation Rules

An NL-compliant system MUST validate the following when receiving an AID:

1. `nl_version` MUST be a supported protocol version.
2. `agent_uri` MUST conform to the ABNF grammar in Section 3.2.
3. `instance_id` MUST be a valid UUID v4.
4. `organization_id` MUST be non-empty and MUST match a registered
   organization in the system.
5. `agent_type` MUST be one of the values defined in Section 5.
6. `trust_level` MUST be one of `"L0"`, `"L1"`, `"L2"`, `"L3"`.
7. `capabilities` MUST be a non-empty array containing only valid
   action type strings.
8. `lifecycle` MUST be `"active"` for the agent to perform actions.
   Agents in any other state MUST be rejected with an error indicating
   the lifecycle state.
9. `expires_at` MUST be in the future. Expired AIDs MUST be rejected.
10. `created_at` MUST be in the past (allowing for clock skew tolerance).
11. If `attestation` is present, it MUST be validated according to
    Section 8.
12. If the NL-compliant system requires Standard or Advanced conformance,
    `attestation` MUST be present and valid.

When validation fails, the system MUST return an error response specifying
which field(s) failed validation and why. The error MUST NOT include any
secret values.

---

## 5. Agent Type Taxonomy

### 5.1 Standard Types

Every agent MUST declare its type. The type determines the agent's risk
profile and informs policy decisions.

| Type | Risk Level | Typical Context | Typical Secret Access | Examples |
|------|-----------|----------------|----------------------|----------|
| `coding_assistant` | MEDIUM | IDE, local terminal | Dev API keys, test tokens, dev DB passwords | Claude Code, Cursor, Copilot, Windsurf, Aider |
| `autonomous_executor` | HIGH | Headless execution, infrastructure management | Cloud credentials, deploy tokens, production DB passwords | Deploy bots, migration agents, scaling agents |
| `orchestrator` | VERY HIGH | Multi-agent coordination, workflow management | Cross-service credentials, admin tokens, delegation authority | Workflow coordinators, multi-agent systems |
| `ci_cd_pipeline` | HIGH | GitHub Actions, Jenkins, GitLab CI, CircleCI | Registry tokens, deploy keys, cloud credentials, signing keys | CI runners, deployment pipelines |
| `human` | LOW (comparative) | CLI, Web UI, interactive sessions | All (per role assignment) | Developers, DevOps engineers, security admins |
| `custom` | VARIABLE | Organization-defined | Organization-defined | Internal bots, proprietary agents, security scanners |

### 5.2 Risk Implications

Implementations SHOULD use agent type to inform default policy decisions:

1. `orchestrator` agents SHOULD require human approval for first-time
   access to production secrets.
2. `autonomous_executor` agents SHOULD have shorter AID expiration times
   (RECOMMENDED: 1-4 hours) than `coding_assistant` agents
   (RECOMMENDED: 8-12 hours).
3. `ci_cd_pipeline` agents SHOULD have AIDs scoped to the specific
   pipeline run and SHOULD expire when the run completes.
4. `human` agents MAY have relaxed session timeouts for interactive use,
   but the action-based model (Level 2) still applies: even human agents
   interact with secrets via opaque handles.
5. `custom` agents MUST include a `risk_level` field in their AID
   `metadata` with one of: `"low"`, `"medium"`, `"high"`, `"very_high"`.

### 5.3 Extensibility

Organizations MAY define additional agent types beyond the standard
taxonomy. Custom types MUST use a namespaced format to avoid collisions:

```
custom:ORGANIZATION/TYPE_NAME
```

Examples:
- `custom:acme.corp/security-scanner`
- `custom:acme.corp/data-migrator`
- `custom:stripe.com/payment-validator`

Custom types MUST be registered with the NL-compliant system before use.
The registration MUST include a declared risk level.

---

## 6. Agent Lifecycle

### 6.1 States

Every agent has a lifecycle state that determines whether it can perform
actions:

```
                    register
      (none) ───────────────────> PROVISIONED
                                      |
                                 activate
                                (first auth
                                 or admin)
                                      |
                                      v
    reactivate ───────────────>  ACTIVE  <─────────── (normal operation)
         ^                      /      \
         |                 suspend    revoke
         |                    /          \
         |                   v            v
         |              SUSPENDED      REVOKED
         |                   |         (terminal)
         +───────────────────+
              reactivate
              (admin only)
```

| State | Can Perform Actions? | Description |
|-------|---------------------|-------------|
| `provisioned` | NO | Agent is registered but not yet activated. Credentials have been issued but not yet used. This is the initial state after registration. |
| `active` | YES | Agent is authorized to perform actions within its scope and capabilities. This is the only state that permits action requests. |
| `suspended` | NO | Agent is temporarily disabled. Can be reactivated by an administrator. All pending actions MUST be rejected. All outstanding delegation tokens MUST be invalidated. |
| `revoked` | NO | Agent is permanently disabled. This is a terminal state. The agent MUST NOT be reactivated. A new AID must be issued if the agent software needs to operate again. |

### 6.2 State Transitions

| Transition | From | To | Triggered By | Description |
|-----------|------|-----|-------------|-------------|
| `register` | (none) | `provisioned` | Principal (human admin) | A new agent is registered with the NL-compliant system. |
| `activate` | `provisioned` | `active` | First successful authentication, or explicit admin action | The agent demonstrates it has valid credentials. |
| `suspend` | `active` | `suspended` | Admin action, automated threat response (Level 6), policy violation, or AID expiration | The agent is temporarily disabled. |
| `reactivate` | `suspended` | `active` | Admin action ONLY | A suspended agent is re-enabled. Requires explicit human decision. |
| `revoke` | `active` or `suspended` | `revoked` | Admin action, or automated response to confirmed compromise | The agent is permanently disabled. |

### 6.3 Rules

1. An NL-compliant system MUST reject action requests from agents in any
   state other than `active`. The rejection response MUST include the
   agent's current lifecycle state.

2. When an agent transitions to `suspended` or `revoked`, all outstanding
   delegation tokens issued by that agent MUST be invalidated immediately.
   Sub-agents that depend on those tokens MUST have their in-flight
   actions rejected.

3. The `revoked` state is terminal. Implementations MUST NOT allow
   transition from `revoked` to any other state. If the same agent
   software needs to operate again, a new AID with a new `instance_id`
   MUST be issued.

4. All lifecycle transitions MUST be recorded in the audit trail
   (Level 5) with the following metadata:
   - Agent URI and instance ID
   - Previous state and new state
   - Who triggered the transition (admin email, automated system, etc.)
   - Timestamp
   - Reason (free text)

5. Implementations SHOULD support automatic suspension when an agent's
   `expires_at` timestamp is reached. The transition reason MUST be
   recorded as `"aid_expired"`.

6. Implementations SHOULD support configurable auto-suspend after a
   period of inactivity (RECOMMENDED default: 24 hours of no action
   requests).

### 6.4 Revocation and Suspension Authority

The following principals have authority to initiate agent lifecycle transitions:

| Transition | Authorized Principals |
|---|---|
| Active → Suspended | Organization administrators, automated threat response systems (Level 6), the agent's own NL Provider |
| Suspended → Active | Organization administrators only |
| Active → Revoked | Organization administrators, automated threat response systems (when threat score ≥ 80) |
| Suspended → Revoked | Organization administrators only |

**Definitions**:
- **Organization Administrator**: A human principal with explicit administrative role assignment at the organization level, authenticated through the organization's identity provider. Administrator actions MUST be recorded in the audit trail with the administrator's identity.
- **Automated Threat Response**: The Level 6 attack detection system MAY initiate suspension when the agent's threat score reaches the ORANGE threshold (≥ 60) and revocation at the RED threshold (≥ 80), as defined in Chapter 06, Section 5.1.1.

Sub-agents MUST NOT initiate lifecycle transitions on parent agents or peer agents. Lifecycle transitions flow downward only: a parent agent's revocation cascades to its sub-agents (see Chapter 07, Section 3.8.1), but a sub-agent's revocation does NOT affect its parent.

---

## 7. Trust Levels

### 7.1 Overview

Trust levels provide graduated identity assurance. Higher trust levels
indicate stronger verification of the agent's claimed identity, enabling
NL-compliant systems to make more nuanced policy decisions.

Trust levels are NOT a replacement for Scope Grants (Level 2). An L3
agent with no applicable Scope Grant still cannot access any secrets.
Trust levels inform *eligibility*; Scope Grants provide *authorization*.

### 7.2 Level Definitions

| Level | Name | How Achieved | Identity Assurance | Required Evidence |
|-------|------|-------------|-------------------|-------------------|
| **L0** | Self-Attested | Agent declares its own identity with no external verification. | LOW -- the agent could be impersonating another. Identity is based solely on the credential issued during registration. | Valid credential only. |
| **L1** | Org-Verified | The organization that registered the agent has verified its identity through internal processes (admin approval, API key issuance, internal PKI). | MEDIUM -- the organization vouches for the agent, but no external party has verified. | Valid credential + organization admin has explicitly approved the registration. |
| **L2** | Vendor-Attested | The Platform Provider (e.g., Anthropic, OpenAI, Google) has signed a JWT attesting to the agent's identity. The JWT is verifiable using the vendor's published public key. | HIGH -- a trusted external party vouches for the agent's authenticity. | Valid credential + valid attestation JWT signed by the Platform Provider. |
| **L3** | Third-Party-Certified | An independent security auditor or certification body has verified the agent's identity, security properties, and NL Protocol compliance. | VERY HIGH -- independent, external verification with formal certification. | Valid credential + L2 attestation + certification document from a recognized certifier. |

### 7.3 Trust Level Requirements

1. Every AID MUST include a `trust_level` field.

2. An NL-compliant system MUST verify that the claimed trust level is
   supported by the evidence provided:
   - **L0:** No additional evidence beyond a valid credential.
   - **L1:** The `organization_id` MUST match a registered organization,
     the agent credential MUST be valid, and an admin MUST have
     explicitly approved the agent's registration.
   - **L2:** In addition to L1, the `attestation` field MUST contain a
     valid, unexpired JWT signed by the Platform Provider identified in
     the `agent_uri`'s vendor component.
   - **L3:** In addition to L2, the `attestation` field MUST also contain
     or reference a certification document from a recognized certification
     authority.

3. Scope Grants (Level 2) MAY require a minimum trust level. For example:
   ```json
   {
     "permissions": [{
       "secrets": ["production/*"],
       "conditions": {
         "min_trust_level": "L2"
       }
     }]
   }
   ```

4. Implementations SHOULD log trust level mismatches as security events.
   For example, an L0 agent attempting to use a grant that requires L2
   SHOULD be logged with severity `WARNING`.

### 7.4 Trust Level Progression

An agent's trust level MAY be promoted over time as evidence is provided:

```
L0 ──(admin approval)──> L1 ──(vendor JWT)──> L2 ──(certification)──> L3
```

- Promotion MUST be recorded in the audit trail.
- Trust level MUST NOT be demoted. If trust in an agent is reduced, the
  agent SHOULD be revoked and a new AID issued at the appropriate level.
- Promotion does not require a new `instance_id`; the existing AID is
  updated in place.

### 7.5 Trust Level Demotion vs Revocation

Trust level demotion (e.g., L2 to L1) is NOT permitted for active
agents. The trust level assigned to an agent reflects the strongest
verified evidence at the time of assignment, and reducing it while the
agent remains active would create ambiguity about the agent's actual
identity assurance.

Revocation of attestation is distinct from demotion. If the attestation
that justified a trust level is invalidated (e.g., vendor revokes the
signing key, the attestation JWT expires without renewal, or the vendor
withdraws trust in the agent), the agent's AID MUST be revoked entirely
-- it MUST NOT be demoted to a lower trust level.

After revocation, a new AID MAY be issued at a lower trust level
through the standard registration flow (Section 9). The new AID will
receive a new `instance_id`, ensuring a clean break in the audit trail
and preventing any confusion between the revoked identity and the
newly issued one.

**Rules:**

1. Implementations MUST NOT allow trust level changes from a higher
   level to a lower level on an active AID (i.e., L2 to L1, L3 to L2,
   etc.).
2. If vendor attestation is revoked or invalidated, the agent's AID
   MUST be revoked (lifecycle transitions to `revoked`).
3. A new AID MAY be issued at the appropriate lower trust level after
   revocation, subject to the standard registration and approval process.
4. All revocations triggered by attestation invalidation MUST be
   recorded in the audit trail with the reason
   `"attestation_invalidated"`.

---

## 8. Platform Attestation

### 8.1 Overview

Platform attestation is a mechanism by which a Platform Provider (e.g.,
Anthropic, OpenAI, Google, GitHub) cryptographically asserts that an agent
is genuine software produced and distributed by that vendor, running in a
legitimate runtime context.

Attestation provides strong identity assurance without requiring the
NL-compliant system to trust the agent directly. Instead, trust is
delegated to the Platform Provider, whose public key is known and
verifiable.

**Conformance:**
- Basic: Attestation is OPTIONAL (MAY).
- Standard: Attestation is REQUIRED (MUST) for all non-human agents.
- Advanced: Attestation is REQUIRED (MUST), including from third-party
  certifiers.

### 8.2 Attestation JWT Structure

The attestation is a JSON Web Token (JWT, RFC 7519) signed using JSON
Web Signature (JWS, RFC 7515).

**Algorithm requirements:**
- MUST use an asymmetric algorithm: `ES256`, `ES384`, `RS256`, or `EdDSA`.
- MUST NOT use symmetric algorithms (`HS256`, `HS384`, `HS512`).
- `ES256` (ECDSA with P-256 and SHA-256) is RECOMMENDED as the default.

#### 8.2.1 JWT Header

```json
{
  "alg": "ES256",
  "typ": "JWT",
  "kid": "anthropic-nl-signing-key-2026-01"
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `alg` | MUST | Signing algorithm. One of: `ES256`, `ES384`, `RS256`, `EdDSA`. |
| `typ` | MUST | Token type. MUST be `"JWT"`. |
| `kid` | SHOULD | Key identifier for key rotation support. Maps to a key in the vendor's JWK Set. |

#### 8.2.2 JWT Payload

```json
{
  "iss": "anthropic.com",
  "sub": "nl://anthropic.com/claude-code/1.5.2",
  "aud": "nl-protocol",
  "iat": 1738922400,
  "exp": 1738965600,
  "jti": "att_550e8400-e29b-41d4-a716-446655440000",

  "nl_claims": {
    "agent_type": "coding_assistant",
    "agent_version": "1.5.2",
    "agent_build": "2026.02.01-stable",
    "runtime_environment": "user-device",
    "security_properties": [
      "sandboxed_execution",
      "no_persistent_memory",
      "output_filtering",
      "tool_approval_required"
    ],
    "nl_protocol_version": "1.0",
    "conformance_level": "standard"
  }
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `iss` | MUST | The Platform Provider's domain. MUST match the vendor component of the `sub` URI. |
| `sub` | MUST | The Agent URI being attested. MUST match `nl://` format. |
| `aud` | MUST | Audience. MUST be `"nl-protocol"`. |
| `iat` | MUST | Issued-at timestamp (Unix epoch seconds). |
| `exp` | MUST | Expiration timestamp (Unix epoch seconds). MUST be after `iat`. Maximum allowed lifetime: 24 hours. |
| `jti` | MUST | Unique token identifier. MUST be globally unique. Used for replay prevention. |
| `nl_claims` | MUST | NL Protocol-specific claims object. See below. |

#### 8.2.3 NL Claims Object

| Claim | Required | Description |
|-------|----------|-------------|
| `agent_type` | MUST | The agent type. MUST match the AID's `agent_type`. |
| `agent_version` | MUST | The agent software version. MUST match the version in the Agent URI. |
| `agent_build` | MAY | Build identifier for additional specificity. |
| `runtime_environment` | SHOULD | Where the agent executes: `"user-device"`, `"cloud-hosted"`, `"ci-cd"`, `"container"`, `"edge"`. |
| `security_properties` | SHOULD | List of security features the agent implements. Informational, not enforced by the protocol. |
| `nl_protocol_version` | MUST | The NL Protocol version the agent claims conformance with. |
| `conformance_level` | SHOULD | The claimed conformance level: `"basic"`, `"standard"`, `"advanced"`. |

### 8.3 Attestation Verification

An NL-compliant system MUST verify attestation JWTs using the following
procedure:

**Step 1: Obtain the vendor's public key.**

The system MUST obtain the Platform Provider's public key from a trusted
source. Implementations MUST support at least one of the following
discovery mechanisms:

- **Well-known URL (RECOMMENDED):**
  ```
  https://VENDOR/.well-known/nl-protocol/jwks.json
  ```
  The response MUST be a JWK Set (RFC 7517). The system SHOULD cache
  the JWK Set and refresh it periodically (RECOMMENDED: every 1 hour)
  or when a `kid` is not found in the cached set.

- **Manual configuration:**
  Admin-provided public key or JWK, configured directly in the
  NL-compliant system. This is acceptable for testing, development,
  and organizations that do not publish a well-known URL.

**Step 2: Verify the JWT signature.**

Using the public key identified by the `kid` header (or the sole key if
no `kid` is present), verify the JWS signature. If verification fails,
the attestation MUST be rejected.

**Step 3: Validate the claims.**

1. `iss` MUST match the vendor domain in the `agent_uri`.
2. `sub` MUST match the `agent_uri` in the AID exactly.
3. `aud` MUST be `"nl-protocol"`.
4. `exp` MUST be in the future (allowing for clock skew tolerance).
5. `iat` MUST be in the past (allowing for clock skew tolerance).
6. `jti` MUST NOT have been seen before (replay prevention). The system
   MUST maintain a set of seen `jti` values. Entries MAY be pruned after
   the corresponding token's `exp` time has passed.
7. `nl_claims.agent_type` MUST match the AID's `agent_type`.
8. `nl_claims.nl_protocol_version` MUST be compatible with the system's
   supported version(s).

**Step 4: Cache the result.**

Implementations SHOULD cache successful verification results, keyed by
`jti`, for the remaining lifetime of the JWT. This avoids repeated
cryptographic operations for the same attestation within a session.

**Attestation cache limits and invalidation:**

Implementations SHOULD limit the attestation verification cache to a
maximum of 10,000 entries. When the cache is full, implementations MUST
evict the entry whose corresponding JWT `exp` timestamp is nearest
(i.e., closest to expiration). Cached verification results MUST NOT be
used after their corresponding JWT's `exp` timestamp has passed;
implementations MUST either eagerly prune expired entries or check `exp`
on every cache hit and discard stale results.

If the system detects a clock adjustment greater than 5 seconds (forward
or backward), all cached attestation verification results MUST be
invalidated immediately. This prevents stale cache entries from being
treated as valid after a time correction that may affect `exp`
evaluation.

Implementations MUST use a dedicated cache for attestation verification
results. The cache MUST NOT be shared with application-level caches
(e.g., HTTP response caches, session caches) to prevent cache poisoning
or unintended eviction by unrelated workloads.

### 8.4 Key Distribution

Platform Providers that support NL Protocol attestation SHOULD publish
their public keys at the well-known URL:

```
GET https://VENDOR/.well-known/nl-protocol/jwks.json
```

**Example response:**

```json
{
  "keys": [
    {
      "kty": "EC",
      "crv": "P-256",
      "kid": "anthropic-nl-signing-key-2026-01",
      "use": "sig",
      "alg": "ES256",
      "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
      "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
    },
    {
      "kty": "EC",
      "crv": "P-256",
      "kid": "anthropic-nl-signing-key-2026-02",
      "use": "sig",
      "alg": "ES256",
      "x": "a1b2c3...",
      "y": "d4e5f6..."
    }
  ]
}
```

**Key rotation protocol:**

1. Vendor publishes a new key with a new `kid`.
2. Vendor begins signing new attestations with the new key.
3. Old key remains published until all JWTs signed with it have expired.
4. Vendor removes the old key from the JWK Set.

NL-compliant systems SHOULD handle `kid` misses by refreshing the
JWK Set before rejecting the attestation.

### 8.5 Runtime Integrity and Supply Chain Considerations

Agent attestation (this section) verifies the agent's identity and software version at registration time. However, attestation alone does not defend against supply chain compromises where the agent binary is modified after registration.

**Recommended Mitigations** (not normatively required by this specification):

1. **Periodic Re-Attestation**: Implementations SHOULD re-verify agent attestation at regular intervals (recommended: every 24 hours) and on each new session establishment.

2. **Binary Integrity Monitoring**: Where supported by the platform, implementations SHOULD verify the agent binary's cryptographic hash against the vendor's published hash before each session.

3. **Behavioral Canaries**: Implementations SHOULD deploy honeypot secrets (Chapter 06, Section 4.5) that legitimate agents would never access. Access to these secrets indicates potential compromise regardless of attestation status.

4. **Anomaly Correlation**: Level 6 (Attack Detection) behavioral analysis (Chapter 06, Section 4.4) provides a secondary defense layer. Compromised agents that alter their access patterns will trigger behavioral anomaly alerts.

**Note**: Full runtime integrity verification (measured boot, TPM-based attestation, runtime binary measurement) is outside the scope of this specification and is expected to be addressed by the host platform's security architecture.

### 8.6 Public Key Trust Chain

This subsection specifies the requirements for obtaining, caching, and
trusting vendor public keys used to verify attestation JWTs.

**Key Retrieval:**

1. Public keys MUST be obtained via HTTPS from the vendor's well-known
   JWKS endpoint (`https://VENDOR/.well-known/nl-protocol/jwks.json`).
2. The JWKS URL MUST use HTTPS. Implementations MUST reject any JWKS
   endpoint URL that uses plaintext HTTP.
3. Implementations MUST validate the TLS certificate of the JWKS
   endpoint against the system's trusted certificate store.

**Key Caching:**

4. Implementations MUST pin or cache public keys obtained from the JWKS
   endpoint with a maximum TTL of 24 hours. After 24 hours, cached keys
   MUST be considered stale and MUST be refreshed from the JWKS endpoint
   before use.
5. If the JWKS endpoint is unreachable, cached keys MAY be used until
   the TTL expires. After the TTL has expired and the endpoint remains
   unreachable, attestation verification MUST fail. Implementations
   MUST NOT use stale keys beyond the 24-hour TTL under any
   circumstances.

**Key Rotation Support:**

6. Implementations MUST support multiple active keys in the JWKS
   endpoint simultaneously (i.e., the `keys` array MAY contain more
   than one key).
7. The correct key for a given attestation JWT MUST be selected using
   the `kid` (Key ID) header in the JWT. If the JWT header contains a
   `kid` that does not match any key in the cached JWKS, the
   implementation MUST refresh the JWKS from the endpoint before
   rejecting the attestation.
8. If the JWT header does not contain a `kid` and the JWKS contains
   exactly one key, that key MUST be used. If the JWKS contains multiple
   keys and no `kid` is present, the attestation MUST be rejected.

---

## 9. Agent Registration

### 9.1 Registration Flow

```
Admin (Human)                NL-Compliant System          Platform Provider
     |                              |                            |
     | 1. Register Agent Request    |                            |
     |  { agent_uri, type, scope,   |                            |
     |    capabilities, org_id,     |                            |
     |    delegated_by }            |                            |
     | ---------------------------> |                            |
     |                              |                            |
     |                    2. Validate agent_uri format            |
     |                    3. Verify org_id exists                 |
     |                    4. Generate instance_id (UUID v4)       |
     |                    5. Generate credential (API key)        |
     |                    6. Store credential hash (NOT plaintext)|
     |                    7. Create AID with lifecycle=provisioned|
     |                    8. Set trust_level = L1 (org-verified)  |
     |                    9. Write audit record                   |
     |                              |                            |
     | 10. Registration Response    |                            |
     |  { aid, credential }         |                            |
     |  (credential shown ONCE)     |                            |
     | <--------------------------- |                            |
     |                              |                            |
     |    [OPTIONAL: Request vendor attestation]                 |
     |                              |                            |
     |                              | 11. Request attestation    |
     |                              |  { agent_uri }             |
     |                              | -------------------------> |
     |                              |                            |
     |                              | 12. Attestation JWT        |
     |                              | <------------------------- |
     |                              |                            |
     |                    13. Verify attestation JWT              |
     |                    14. Update AID: attestation = JWT       |
     |                    15. Promote trust_level: L1 -> L2       |
     |                    16. Write audit record                  |
     |                              |                            |
```

### 9.2 Registration Request Format

```json
{
  "agent_uri": "nl://anthropic.com/claude-code/1.5.2",
  "organization_id": "org_acme_corp_2024",
  "agent_type": "coding_assistant",
  "capabilities": ["exec", "template", "inject_stdin", "inject_tempfile"],
  "scope": {
    "projects": ["braincol"],
    "environments": ["development", "staging"],
    "categories": ["api", "database"]
  },
  "delegated_by": {
    "type": "human",
    "identifier": "andres@acme.corp"
  },
  "session_context": {
    "ide": "vscode",
    "repository": "github.com/acme-corp/backend"
  },
  "requested_ttl_hours": 12
}
```

### 9.3 Registration Response Format

```json
{
  "aid": {
    "nl_version": "1.0",
    "agent_uri": "nl://anthropic.com/claude-code/1.5.2",
    "instance_id": "550e8400-e29b-41d4-a716-446655440000",
    "organization_id": "org_acme_corp_2024",
    "agent_type": "coding_assistant",
    "trust_level": "L1",
    "capabilities": ["exec", "template", "inject_stdin", "inject_tempfile"],
    "scope": {
      "projects": ["braincol"],
      "environments": ["development", "staging"],
      "categories": ["api", "database"]
    },
    "delegated_by": {
      "type": "human",
      "identifier": "andres@acme.corp",
      "delegation_time": "2026-02-08T10:00:00Z"
    },
    "lifecycle": "provisioned",
    "created_at": "2026-02-08T10:00:00Z",
    "expires_at": "2026-02-08T22:00:00Z"
  },
  "credential": {
    "type": "api_key",
    "value": "nlk_live_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
    "note": "This value is shown ONCE. Store it securely. It cannot be retrieved again."
  }
}
```

**CRITICAL security requirements for credential issuance:**

1. The credential value MUST be returned exactly once during registration.
2. The NL-compliant system MUST NOT store the plaintext credential. It
   MUST store only a salted, computationally expensive hash (e.g.,
   Argon2id, bcrypt) for verification.
3. The credential MUST have sufficient entropy: minimum 256 bits
   (RECOMMENDED: 32 bytes, base62-encoded).
4. The credential prefix (`nlk_live_` in the example) is OPTIONAL but
   RECOMMENDED for easy identification and secret scanning tools.

### 9.4 Credential Types

Implementations MUST support at least one of the following credential
types:

| Type | Format | Use Case |
|------|--------|----------|
| `api_key` | Opaque string (e.g., `nlk_live_...`) | Default. Simple, stateless authentication. |
| `bearer_token` | JWT or opaque token | Short-lived, suitable for CI/CD. |
| `mtls_certificate` | X.509 certificate | High-security environments with PKI infrastructure. |

Implementations MAY support additional credential types.

#### 9.4.1 Credential Format Specifications

To ensure interoperability across implementations, the following formal
format specifications apply to each credential type:

**`api_key`:**

- Format: String, prefix `nlk_` followed by an optional environment
  segment (e.g., `live_`, `test_`) and 32 or more alphanumeric
  characters.
- Regex: `^nlk_([a-z]+_)?[A-Za-z0-9]{32,}$`
- Example: `nlk_live_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6`
- The prefix `nlk_` is REQUIRED for interoperability. The environment
  segment is OPTIONAL but RECOMMENDED.
- Minimum entropy: 256 bits (see Section 9.3).

**Credential entropy and randomness requirements:**

Implementations MUST verify that generated credentials contain at least
256 bits of entropy. This applies to the random portion of the
credential (i.e., the segment after any fixed prefix such as `nlk_live_`).

Credentials MUST be generated using a cryptographically secure
pseudorandom number generator (CSPRNG). Acceptable sources include
`/dev/urandom` (Linux/macOS), `BCryptGenRandom` (Windows),
`crypto.getRandomValues()` (Web Crypto API), and equivalent
platform-provided CSPRNGs. If the CSPRNG is unavailable or returns an
error, credential generation MUST fail immediately. Implementations MUST
NOT fall back to weak randomness sources (e.g., `Math.random()`,
`rand()`, time-seeded PRNGs) under any circumstances.

Implementations SHOULD NOT incorporate sequential counters, timestamps,
or other predictable components into the random portion of the
credential. Including such components reduces effective entropy and may
enable enumeration attacks. The prefix and optional environment segment
(e.g., `nlk_live_`) are exempt from this requirement as they are
intentionally deterministic for identification purposes.

**`bearer_token`:**

- Format: JWT (RFC 7519) signed by the NL Provider.
- The JWT MUST include the following claims:
  - `sub`: The agent's Agent URI (e.g., `nl://anthropic.com/claude-code/1.5.2`).
  - `iss`: The NL Provider's identifier (e.g., the provider's domain).
  - `exp`: Expiration timestamp (Unix epoch seconds). MUST be set.
    RECOMMENDED maximum lifetime: 1 hour for CI/CD, 12 hours for
    interactive sessions.
  - `iat`: Issued-at timestamp (Unix epoch seconds). MUST be set.
- The JWT MAY include additional claims such as `jti` (for replay
  prevention) and `scope` (for token-scoped access restrictions).
- Signing algorithm requirements follow Section 8.2 (asymmetric
  algorithms only).

**`mtls_certificate`:**

- Format: X.509 certificate in PEM format (RFC 7468).
- The certificate MUST include the agent's Agent URI in the Subject
  Alternative Name (SAN) extension, using the URI type
  (e.g., `URI:nl://anthropic.com/claude-code/1.5.2`).
- The certificate MUST be signed by a Certificate Authority (CA)
  trusted by the NL Provider, or by the organization's internal CA.
- The certificate's `notAfter` field serves as the credential
  expiration. Implementations MUST reject expired certificates.
- RECOMMENDED key type: ECDSA P-256. RSA keys MUST be at least
  2048 bits.

---

## 10. Example Flows

### 10.1 Registering a Claude Code Agent

**Step 1: Admin registers the agent**

An NL-compliant implementation MUST expose a registration endpoint (API,
CLI, or admin console). The admin submits a registration request
conforming to Section 9.2:

```json
{
  "agent_uri": "nl://anthropic.com/claude-code/1.5.2",
  "organization_id": "org_acme_corp_2024",
  "agent_type": "coding_assistant",
  "capabilities": ["exec", "template", "inject_stdin", "inject_tempfile"],
  "scope": {
    "projects": ["braincol"],
    "environments": ["development", "staging"]
  },
  "delegated_by": {
    "type": "human",
    "identifier": "andres@acme.corp"
  },
  "requested_ttl_hours": 12
}
```

**Step 2: System responds with AID and credential**

The NL-compliant system returns a registration response conforming to
Section 9.3:

```json
{
  "aid": {
    "nl_version": "1.0",
    "agent_uri": "nl://anthropic.com/claude-code/1.5.2",
    "instance_id": "550e8400-e29b-41d4-a716-446655440000",
    "organization_id": "org_acme_corp_2024",
    "agent_type": "coding_assistant",
    "trust_level": "L1",
    "lifecycle": "provisioned",
    "created_at": "2026-02-08T10:00:00Z",
    "expires_at": "2026-02-08T22:00:00Z"
  },
  "credential": {
    "type": "api_key",
    "value": "nlk_live_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
    "note": "This value is shown ONCE. Store it securely."
  }
}
```

**Step 3: Configure the agent**

The credential is placed in the agent's environment using whatever
mechanism the NL-compliant implementation provides. For example, an
implementation that exposes an MCP server might be configured as:

```json
{
  "mcpServers": {
    "nl-secret-provider": {
      "command": "nl-provider",
      "args": ["mcp"],
      "env": {
        "NL_AGENT_USER": "claude-code",
        "NL_AGENT_CREDENTIAL": "nlk_live_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
      }
    }
  }
}
```

> The specific environment variable names and configuration format are
> implementation-defined. The example above is illustrative.

**Step 4: First action activates the agent**

When the agent submits its first valid action request, the NL-compliant
system transitions the lifecycle from `provisioned` to `active` and
records the activation in the audit trail.

### 10.2 Verifying Agent Identity on Action Request

When an NL-compliant system receives an action request, it performs
identity verification before processing the action:

```
Agent                           NL-Compliant System
  |                                    |
  | Action Request                     |
  | {                                  |
  |   "nl_version": "1.0",            |
  |   "agent": {                      |
  |     "agent_uri": "nl://...",      |
  |     "instance_id": "550e...",     |
  |     "attestation": "eyJ..."       |
  |   },                              |
  |   "action": { ... }               |
  | }                                  |
  | ---------------------------------->|
  |                                    |
  |       1. Extract agent_uri and instance_id
  |       2. Look up agent in registry by instance_id
  |       3. Verify credential (compare salted hash)
  |       4. Check lifecycle == "active"
  |       5. Check expires_at > now()
  |       6. IF attestation present:
  |          a. Verify JWT signature against vendor public key
  |          b. Verify JWT claims (iss, sub, aud, exp, iat, jti)
  |          c. Check jti for replay
  |       7. Verify trust_level is consistent with evidence
  |       8. Check capabilities include requested action type
  |       9. Evaluate scope against requested secret references
  |      10. ALL pass? -> proceed to action processing (Level 2)
  |          ANY fail? -> return error with specific reason
  |                                    |
  | Response                           |
  | (action result or identity error)  |
  | <----------------------------------|
  |                                    |
```

**Error response example (identity verification failure):**

```json
{
  "error": {
    "code": "IDENTITY_VERIFICATION_FAILED",
    "reason": "Agent lifecycle is 'suspended', expected 'active'",
    "agent_uri": "nl://anthropic.com/claude-code/1.5.2",
    "instance_id": "550e8400-e29b-41d4-a716-446655440000",
    "suggestion": "Contact your administrator to reactivate this agent."
  }
}
```

### 10.3 Multi-Agent Delegation Identity

When an orchestrator delegates to a sub-agent, identity chains are
maintained:

```json
// Orchestrator's AID (abbreviated)
{
  "agent_uri": "nl://acme.corp/orchestrator/1.0.0",
  "instance_id": "aaaa-bbbb-cccc-dddd",
  "agent_type": "orchestrator",
  "trust_level": "L2",
  "capabilities": ["exec", "delegate"],
  "scope": {
    "projects": ["braincol"],
    "environments": ["development", "staging", "production"]
  }
}
```

```json
// Sub-agent's AID shows the delegation chain
{
  "agent_uri": "nl://acme.corp/deploy-bot/2.1.0",
  "instance_id": "eeee-ffff-0000-1111",
  "agent_type": "autonomous_executor",
  "trust_level": "L2",
  "delegated_by": {
    "type": "agent",
    "identifier": "nl://acme.corp/orchestrator/1.0.0",
    "parent_instance_id": "aaaa-bbbb-cccc-dddd",
    "delegation_time": "2026-02-08T14:00:00Z"
  },
  "capabilities": ["exec"],
  "scope": {
    "projects": ["braincol"],
    "environments": ["production"],
    "categories": ["deploy"]
  }
}
```

**Identity invariants in delegation:**

1. The sub-agent's scope MUST be a strict subset of the orchestrator's scope.
2. The sub-agent's capabilities MUST be a subset of the orchestrator's capabilities.
3. The delegation chain is recorded and auditable.
4. Revoking the orchestrator automatically invalidates the sub-agent's
   delegation authority.

---

## 11. Security Considerations

### 11.1 AID Confidentiality

The AID is NOT a secret. It is an identity document. However, the
`credential` issued during registration IS a secret and MUST be
protected accordingly. Implementations SHOULD treat credentials with the
same security posture as passwords.

### 11.2 Replay Prevention

Attestation JWTs include a `jti` (JWT ID) claim. NL-compliant systems
MUST maintain a set of seen `jti` values and reject duplicates. The set
SHOULD be pruned when the corresponding token's `exp` timestamp passes.

### 11.3 Instance ID Generation

The `instance_id` MUST be generated by the NL-compliant system, not by
the agent. This prevents agents from choosing predictable or colliding
instance IDs.

### 11.4 Clock Skew

Implementations MUST allow a configurable clock skew tolerance when
validating timestamps (`iat`, `exp`, `expires_at`, `created_at`).
RECOMMENDED default: 30 seconds.

### 11.5 Credential Rotation

Implementations SHOULD support credential rotation without requiring a
new AID. The agent's `instance_id` and identity persist; only the
credential value changes. Rotation MUST be recorded in the audit trail.

### 11.6 Agent URI Spoofing

An agent could claim an `agent_uri` that does not correspond to its
actual software (e.g., a malicious agent claiming to be Claude Code).
Platform attestation (Section 8) mitigates this: only Anthropic can
sign a valid attestation for `nl://anthropic.com/*`.

For L0 and L1 trust levels where attestation is not required, the
organization takes responsibility for verifying agent identity through
its internal registration process.

---

## 12. Conformance Checklist

### 12.1 Basic Conformance

For Basic conformance, an implementation MUST:

- [ ] Support the `nl://` Agent URI format (Section 3).
- [ ] Issue and validate AIDs with all required fields (Section 4.3.1).
- [ ] Enforce the agent type taxonomy (Section 5).
- [ ] Implement all four lifecycle states and valid transitions (Section 6).
- [ ] Assign trust levels L0 or L1 (Section 7).
- [ ] Support agent registration with credential issuance (Section 9).
- [ ] Validate AIDs on every action request (Section 4.4).
- [ ] Reject agents with `lifecycle != "active"` or `expires_at` in the past.

### 12.2 Standard Conformance

In addition to Basic, Standard conformance MUST:

- [ ] Require platform attestation (L2 trust level) for all non-human agents.
- [ ] Verify attestation JWTs using the vendor's public key (Section 8.3).
- [ ] Support well-known URL key discovery (Section 8.4).
- [ ] Enforce attestation expiration (`exp` claim).
- [ ] Implement replay prevention via `jti` tracking.

### 12.3 Advanced Conformance

In addition to Standard, Advanced conformance MUST:

- [ ] Support L3 (third-party-certified) trust levels.
- [ ] Support delegation chains in AIDs (Section 10.3).
- [ ] Validate delegation scope as strict subset of parent scope.
- [ ] Cascade revocation through delegation chains.

---

## 13. References

- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) -- Requirement Levels
- [RFC 4122](https://www.rfc-editor.org/rfc/rfc4122) -- UUID URN Namespace
- [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515) -- JSON Web Signature (JWS)
- [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517) -- JSON Web Key (JWK)
- [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519) -- JSON Web Token (JWT)
- [SPIFFE](https://spiffe.io/) -- Secure Production Identity Framework
- [00-overview.md](00-overview.md) -- NL Protocol Overview
- [02-action-based-access.md](02-action-based-access.md) -- Level 2: Action-Based Access

---

*Copyright 2026 Braincol. This specification is licensed under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).*
