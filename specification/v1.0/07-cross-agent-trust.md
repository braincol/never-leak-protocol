# NL Protocol Specification v1.0 -- Chapter 07: Cross-Agent Trust & Federation

**Status:** 1.0
**Version:** 1.0.0
**Date:** 2026-02-08

> **Note:** This document is a SPECIFICATION. It defines required behaviors,
> data formats, and protocols — not specific products or CLI commands.
> For implementations of this specification, see [IMPLEMENTATIONS.md](../../IMPLEMENTATIONS.md).

## 1. Introduction

This chapter defines how agents establish trust, delegate authority, and collaborate across organizational boundaries under the NL Protocol. In production agentic systems, agents rarely operate in isolation. An orchestrator dispatches tasks to specialized sub-agents, agents in different organizations exchange data through federated workflows, and agents delegate authority to perform actions on their behalf. Each of these interactions creates a potential vector for secret exposure, privilege escalation, and unauthorized access.

The cross-agent trust model defined in this chapter ensures that:

1. Agents can delegate bounded authority to other agents without exposing secrets.
2. Delegation is strictly downward-scoped: a delegate can NEVER have more access than its delegator.
3. Cross-organization collaboration is possible without either organization's secrets leaving their boundary.
4. Compromised agents can be globally revoked across all trust relationships.
5. The entire delegation chain is auditable with full accountability at every level.

This is the most forward-looking chapter of the NL Protocol v1.0. Some mechanisms described here -- particularly zero-knowledge verification and global federation -- represent capabilities that existing implementations will adopt progressively. The specification defines them precisely so that early implementations are compatible with future ones.

### 1.1 Relationship to Other Chapters

This chapter builds on and integrates with:

- **Chapter 01 (Agent Identity)**: All trust relationships are rooted in verifiable agent identities (AIDs). Delegation tokens reference issuer and subject AIDs.
- **Chapter 02 (Action-Based Access)**: Delegation tokens are derived from and constrained by the delegator's active scopes.
- **Chapter 03 (Execution Isolation)**: Delegated actions execute in isolated environments. Secrets never leave the isolation boundary.
- **Chapter 05 (Audit Integrity)**: All delegation, federation, and revocation events are recorded in the audit trail.
- **Chapter 06 (Attack Detection)**: Agent revocation triggered by attack detection propagates through delegation chains and federation relationships.

## 2. Delegation Model

### 2.1 Delegation Principles

The NL Protocol delegation model is governed by three invariant principles:

1. **Strictly downward-scoped**: A delegate MUST NEVER receive more permissions than the delegator possesses. Every delegation is a strict narrowing of access.
2. **Bounded depth**: Delegation chains MUST have a configurable maximum depth (RECOMMENDED default: 3). Each re-delegation decrements the remaining depth by 1.
3. **Result-only propagation**: In any delegation chain, only the results of actions flow between agents. Secrets MUST NEVER be passed from one agent to another.

### 2.2 Roles

| Role | Description |
|------|-------------|
| **Delegator** | The agent that grants a subset of its permissions to another agent. Also called the "issuer" of the delegation token. |
| **Delegate** | The agent that receives delegated permissions. Also called the "subject" of the delegation token. |
| **NL Provider** | The system that manages secrets, verifies delegation tokens, executes actions in isolation, and returns results. |
| **Human Principal** | The human user or administrator at the root of the trust chain who originally granted permissions to the delegator. |

### 2.3 Delegation Chain

A delegation chain is a sequence of delegations from a human principal through one or more agents:

```
Human Principal (root of trust)
    |
    | Grants scope to Agent A
    v
Agent A (delegator)
    |
    | Issues delegation token to Agent B
    | (subset of Agent A's scope)
    v
Agent B (delegate / re-delegator)
    |
    | Issues delegation token to Agent C
    | (subset of Agent B's delegated scope)
    v
Agent C (delegate)
    |
    | Executes action using delegation token
    v
NL Provider (verifies full chain, executes in isolation)
```

The maximum depth of this chain is configurable. With a default maximum depth of 3:
- Agent A can delegate to Agent B (depth 1).
- Agent B can re-delegate to Agent C (depth 2).
- Agent C can re-delegate to Agent D (depth 3).
- Agent D MUST NOT re-delegate (depth limit reached).

#### 2.3.1 Delegation Depth Configuration

The maximum delegation depth is stored in the NL Provider's configuration, NOT in individual delegation tokens. The `delegation_depth_remaining` field in a token reflects the remaining depth at issuance time, but the authoritative limit is the provider-level configuration.

- **Default value**: 3 (orchestrator -> sub-agent -> sub-sub-agent). This permits three levels of delegation below the human principal.
- **Enforcement**: The depth limit MUST be enforced at token creation time. When an agent at depth N in the delegation chain attempts to create a delegation token, the system MUST verify that N < `max_delegation_depth`. If this check fails, the token creation request MUST be rejected with error code `DELEGATION_DEPTH_EXCEEDED` (wire protocol error `NL-E703`).
- **Configuration changes**: Changing the `max_delegation_depth` value does NOT affect existing tokens. Tokens created under the previous limit remain valid until they expire or are explicitly revoked. Only new token creation requests are evaluated against the updated limit.

**Grace Period for Depth Reduction**: When `max_delegation_depth` is reduced, implementations SHOULD apply a grace period:
- Existing tokens at depths exceeding the new limit remain valid until their natural expiration
- No NEW delegations may be created that exceed the new limit, effective immediately
- Implementations MUST log a WARNING for each action that uses a token at a depth exceeding the current `max_delegation_depth` configuration
- The grace period MUST NOT exceed the maximum token lifetime configured for the provider
- After the grace period, any remaining tokens at excessive depth MUST be automatically revoked

This ensures that depth reductions take full effect within one token lifetime cycle while avoiding abrupt disruption of active delegation chains.

- **Minimum value**: The `max_delegation_depth` MUST be at least 1 (allowing at least one level of delegation). A value of 0 effectively disables delegation and MUST be treated as "delegation not supported" by the provider.

## 3. Delegation Token

### 3.1 Token Structure

A delegation token is a signed, self-contained credential that grants the recipient a bounded subset of the delegating agent's permissions. Delegation tokens MUST conform to the following structure:

```json
{
  "token_id": "<uuid-v4>",
  "type": "delegation",
  "issuer": "<AID URI of the delegating agent>",
  "subject": "<AID URI of the delegate agent>",
  "scope": {
    "secrets": ["<list of secret references the delegate may use>"],
    "actions": ["<list of action types the delegate may perform>"],
    "resource_constraints": {},
    "max_uses": "<integer, maximum number of times this token may be used>"
  },
  "chain": [
    "<identity of each entity in the trust chain, from root to issuer>"
  ],
  "delegation_depth_remaining": "<integer, how many more re-delegations are permitted>",
  "parent_token_id": "<token_id of the parent delegation, or null for first-level>",
  "parent_scope_id": "<scope_id from which this delegation derives>",
  "issued_at": "<ISO-8601 UTC>",
  "expires_at": "<ISO-8601 UTC>",
  "nonce": "<cryptographic nonce for replay prevention>",
  "signature": {
    "algorithm": "<ES256 | EdDSA>",
    "value": "<base64-encoded signature over canonical JSON of all fields except signature>"
  }
}
```

### 3.2 Required Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `token_id` | string | MUST | Globally unique identifier (UUID v4) for the delegation token. |
| `type` | string | MUST | MUST be the literal string `"delegation"`. |
| `issuer` | string | MUST | AID URI (Chapter 01) of the agent issuing the delegation. |
| `subject` | string | MUST | AID URI (Chapter 01) of the agent receiving the delegation. |
| `scope.secrets` | array | MUST | List of NL Protocol secret references (e.g., `["aws/DEPLOY_KEY", "database/DB_URL"]`) the delegate is authorized to use. MUST be a subset of the issuer's accessible secrets. |
| `scope.actions` | array | MUST | List of action types (Chapter 02) the delegate is authorized to perform (e.g., `["exec", "template"]`). |
| `scope.max_uses` | integer | MUST | Maximum number of times the delegation token may be used. MUST be finite (unlimited-use tokens are prohibited). RECOMMENDED: 1 for single-action delegations. |
| `scope.resource_constraints` | object | MAY | Additional resource constraints (same format as Chapter 02, Section 2.2). |
| `chain` | array | MUST | Ordered list of identities in the trust chain, from the root human principal to the issuer. Each entry is either a human identity string (e.g., `"human:alice@company.com"`) or an agent AID URI. |
| `delegation_depth_remaining` | integer | MUST | Number of additional re-delegations permitted. Decremented by 1 at each level. When 0, the subject MUST NOT re-delegate. |
| `parent_token_id` | string | MUST | Token ID of the parent delegation token, or `null` for first-level delegations derived directly from a scope grant. |
| `parent_scope_id` | string | MUST | Scope ID (Chapter 02) from which this delegation derives. |
| `issued_at` | string | MUST | ISO 8601 UTC timestamp of when the token was issued. |
| `expires_at` | string | MUST | ISO 8601 UTC timestamp of when the token expires. MUST be in the future at issuance time. SHOULD be short-lived (RECOMMENDED: 5 minutes for single-action delegations, 1 hour maximum for multi-use delegations). |
| `nonce` | string | MUST | Cryptographically random value (minimum 128 bits, base64-encoded) for replay prevention. |
| `signature` | object | MUST | Digital signature over the canonical JSON (RFC 8785) representation of all fields except `signature`, produced by the issuer's private key. |

### 3.3 Delegation Token Example

```json
{
  "token_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "type": "delegation",
  "issuer": "nl://anthropic.com/claude-code/1.5.2",
  "subject": "nl://example.com/deploy-agent/1.0.0",
  "scope": {
    "secrets": ["aws/DEPLOY_KEY"],
    "actions": ["exec"],
    "resource_constraints": {
      "exec": {
        "allowed_commands": ["aws ecs update-service *"],
        "network_destinations": ["*.amazonaws.com"]
      }
    },
    "max_uses": 1
  },
  "chain": [
    "human:alice@company.com",
    "nl://anthropic.com/claude-code/1.5.2"
  ],
  "delegation_depth_remaining": 2,
  "parent_token_id": null,
  "parent_scope_id": "scope-20260208-prod-deploy",
  "issued_at": "2026-02-08T10:30:00Z",
  "expires_at": "2026-02-08T10:35:00Z",
  "nonce": "dGhpcyBpcyBhIHJhbmRvbSBub25jZQ==",
  "signature": {
    "algorithm": "ES256",
    "value": "MEUCIQDf...base64..."
  }
}
```

### 3.4 Delegation Token Transmission

Delegation tokens are stored by the NL Provider and referenced by `token_id`. The full token object (including signature) is NEVER transmitted to agents. Agents only receive the `token_id` string. When an agent presents a `token_id` for delegation, the NL Provider retrieves the full token internally for verification. For cross-provider delegation (federation), the full token object IS transmitted between NL Providers over the mTLS-secured federation channel.

#### Token Binding for Delegation Security

To prevent stolen `token_id` values from being used by unauthorized agents, delegation tokens SHOULD include a binding mechanism:

1. **Token Binding Key**: When creating a delegation token, the NL Provider generates a `token_binding_key` (256-bit random value) and provides it to the authorized agent alongside the `token_id`.

2. **Binding Proof**: When an agent presents a `token_id` to access delegated secrets, it MUST include a `binding_proof` field:
   ```
   binding_proof = HMAC-SHA256(token_binding_key, token_id || agent_id || timestamp)
   ```

3. **Verification**: The NL Provider verifies:
   - The `binding_proof` is valid for the presenting agent's `agent_id`
   - The timestamp is within the acceptable window (±30 seconds)
   - The `token_binding_key` matches the one stored for this token

4. **Fallback**: Implementations that do not support token binding MUST require mTLS client certificate verification as an alternative binding mechanism, ensuring the presenting agent's identity matches the delegation subject.

**Note**: Token binding is RECOMMENDED for all deployments and REQUIRED for Advanced conformance (Level 7).

### 3.5 Delegation Token Expiration Boundary

Token expiration uses strict less-than comparison: a token is valid when `now() < expires_at`. A request arriving exactly at `expires_at` MUST be rejected.

### 3.6 Delegation Constraints

Delegation MUST satisfy all of the following constraints. Violation of any constraint MUST cause the delegation to be rejected:

1. **Subset rule**: The delegation token's `scope.secrets` MUST be a subset of the issuer's accessible secrets. The `scope.actions` MUST be a subset of the issuer's permitted actions. An agent MUST NOT delegate permissions it does not itself possess.

2. **Time bound rule**: The delegation token's `expires_at` MUST NOT exceed the issuer's scope `validUntil` (Chapter 02). The token's validity window MUST fall entirely within the issuer's scope validity window.

3. **Depth limit rule**: `delegation_depth_remaining` MUST be strictly less than the issuer's own remaining delegation depth. If the issuer has `delegation_depth_remaining = 0`, the issuer MUST NOT issue delegation tokens.

4. **Use limit rule**: `scope.max_uses` MUST be finite. A value of 0 or negative MUST be rejected. The RECOMMENDED value for single-action delegations is 1.

5. **Attestation rule**: The subject agent's trust level (Chapter 01) MUST meet the minimum trust level required for the interaction type (see Section 6.2).

6. **Signature rule**: The delegation token MUST be signed by the issuer's private key. The signature MUST be verifiable using the issuer's public key from their AID.

### 3.7 Delegation Verification

When a delegate agent presents a delegation token to the NL Provider to perform an action, the NL Provider MUST execute the following verification steps in order:

1. **Token integrity**: Verify the delegation token's signature against the issuer's public key from their AID.
2. **Token freshness**: Verify that the current time falls within the `[issued_at, expires_at]` window. Verify that the `nonce` has not been seen before (replay prevention).
3. **Token usage**: Verify that the token's use count has not exceeded `scope.max_uses`.
4. **Issuer validity**: Verify that the issuer's AID is valid and not revoked (Chapter 01).
5. **Subject match**: Verify that the presenting agent's AID matches the `subject` field.
6. **Chain verification**: Walk the `chain` array and verify each link:
   - For the root entry (human principal): Verify the human's identity and scope grant.
   - For each agent entry: Verify the agent's AID and the parent delegation token (via `parent_token_id`).
   - At each link: Verify the subset rule (each delegation is a strict narrowing).
7. **Action authorization**: Verify that the requested action falls within `scope.actions` and targets resources within `scope.resource_constraints`.
8. **Secret authorization**: Verify that the requested secrets fall within `scope.secrets`.

If ANY verification step fails, the action MUST be denied and a Security Incident Record MUST be generated (Chapter 06).

#### 3.7.1 Nonce Collision and Replay Prevention

The `nonce` field in delegation tokens provides replay prevention. The following requirements govern nonce generation and verification:

1. **Generation**: Nonces MUST be generated using a CSPRNG (Cryptographically Secure Pseudo-Random Number Generator) with at least 128 bits of entropy. Acceptable formats include UUID v4 or 16 random bytes, hex-encoded. Implementations MUST NOT use sequential or predictable nonce generation schemes.

2. **Nonce store lifetime**: The nonce store MUST retain seen nonces for the lifetime of the corresponding delegation token. When a token expires (i.e., `expires_at` is in the past), its nonce MAY be evicted from the store. Nonces associated with unexpired tokens MUST NOT be evicted.

3. **Distributed deployments**: In distributed deployments, the nonce store MUST be shared across all nodes that verify delegation tokens. Implementations SHOULD use a centralized cache (e.g., Redis with TTL matching token lifetime) or a consensus-based store to ensure consistency. A nonce seen by any node MUST be visible to all nodes before a subsequent verification attempt could succeed.

4. **Fail-closed behavior**: If the nonce store is unavailable (e.g., cache connection failure), delegation verification MUST fail with error code `NL-E700` (fail-closed). The system MUST NOT skip replay detection or fall back to a mode that does not check nonces. This is a hard requirement: availability of the nonce store is a prerequisite for delegation verification.

5. **Collision probability**: With 128-bit random nonces, the probability of collision is negligible (~2^-64 after 2^64 tokens generated). This margin is considered safe for all practical deployment scales. Implementations MUST NOT reduce the nonce entropy below 128 bits.

```
DELEGATION VERIFICATION FLOW:

+-------------------+
| Delegate presents |
| delegation token  |
+--------+----------+
         |
         v
+--------+----------+
| 1. Verify token   |--FAIL--> DENY + Incident Record
|    signature       |
+--------+----------+
         |OK
         v
+--------+----------+
| 2. Verify token   |--FAIL--> DENY + Incident Record
|    freshness       |          (expired or replayed)
+--------+----------+
         |OK
         v
+--------+----------+
| 3. Verify usage   |--FAIL--> DENY + Incident Record
|    count           |          (max_uses exceeded)
+--------+----------+
         |OK
         v
+--------+----------+
| 4. Verify issuer  |--FAIL--> DENY + Incident Record
|    AID validity    |          (issuer revoked)
+--------+----------+
         |OK
         v
+--------+----------+
| 5. Verify subject |--FAIL--> DENY + Incident Record
|    AID match       |          (wrong agent)
+--------+----------+
         |OK
         v
+--------+----------+
| 6. Verify full    |--FAIL--> DENY + Incident Record
|    chain (subset  |          (subset violation)
|    rule at each   |
|    link)          |
+--------+----------+
         |OK
         v
+--------+----------+
| 7. Verify action  |--FAIL--> DENY + Incident Record
|    authorization   |
+--------+----------+
         |OK
         v
+--------+----------+
| 8. Verify secret  |--FAIL--> DENY + Incident Record
|    authorization   |
+--------+----------+
         |OK
         v
  ACTION AUTHORIZED
  Execute in isolation (Chapter 03)
  Return result only (Section 5)
```

### 3.8 Delegation Revocation

The delegating agent (issuer) or any ancestor in the delegation chain MAY revoke a delegation token at any time. Revocation follows these rules:

1. Revocation of a delegation token MUST automatically revoke all tokens derived from it (transitive revocation).
2. Revocation of an agent's AID (Chapter 01) MUST automatically revoke all delegation tokens issued BY that agent and all delegation tokens issued TO that agent.
3. Revocation MUST take effect immediately. In-flight actions using the revoked token SHOULD be cancelled if possible, or their results MUST be quarantined.
4. Revocation events MUST be recorded in the audit trail (Chapter 05).
5. The NL Provider MUST maintain a revocation list for delegation tokens and MUST check this list during delegation verification (Step 2 or as an additional step).

#### 3.8.1 Delegation Revocation Cascading

Revocation of an agent's AID MUST cascade transitively through the entire delegation chain. The cascade proceeds as follows:

1. All delegation tokens where the revoked agent is the `delegator` (issuer) are revoked.
2. All delegation tokens where a revoked-in-step-1 delegate is itself a delegator are also revoked (recursive descent).
3. The cascade continues until all transitive descendants in the delegation tree are revoked.

**Atomicity requirements:**

The cascade MUST be atomic: either all tokens in the affected chain are revoked, or none are (transaction semantics). Implementations SHOULD use database transactions or equivalent mechanisms to ensure atomicity.

If atomic cascade is not feasible in a distributed system, the system MUST use best-effort revocation with the following guarantees:

- **Immediate local revocation**: All known tokens in the local trust domain MUST be revoked synchronously.
- **Asynchronous propagation**: Revocation MUST be propagated to federation partners per the Section 7.5 retry protocol (exponential backoff with 5 retries).
- **Optimistic revocation**: Tokens pending propagation MUST be treated as revoked locally. Any verification request for a token that is pending remote propagation MUST be denied. The system MUST NOT allow a token to be used during the propagation window.

**Cascade depth:**

Revocation MUST cascade regardless of delegation depth. The `max_delegation_depth` configuration limit applies only to token creation, not to revocation propagation. A delegation chain of depth 5 (created under a previous, more permissive configuration) MUST still be fully revoked when the root is revoked.

**Audit requirements:**

Each revoked token in the cascade MUST generate its own audit record. The audit record MUST include:
- `reason`: `"cascade_from_parent"` for all tokens revoked as a result of cascade (not the root).
- `root_revocation_id`: A reference to the original revocation event that triggered the cascade.
- `cascade_depth`: The distance from the root revocation in the delegation tree (0 for direct children, 1 for grandchildren, etc.).

## 4. Delegation Protocol Flow

### 4.1 End-to-End Flow

The following describes the complete protocol flow when Agent A delegates to Agent B:

```
+----------------+    +----------------+    +------------------+
|   Agent A      |    |  NL Provider   |    |    Agent B       |
| (delegator)    |    |                |    |   (delegate)     |
+-------+--------+    +-------+--------+    +--------+---------+
        |                      |                      |
        | 1. REQUEST           |                      |
        | DELEGATION TOKEN     |                      |
        | (subject=Agent B,    |                      |
        |  scope={...})        |                      |
        +--------------------->|                      |
        |                      |                      |
        |              2. VERIFY                      |
        |              Agent A has                    |
        |              permission to                  |
        |              delegate the                   |
        |              requested scope                |
        |                      |                      |
        |              3. CREATE                      |
        |              scoped delegation              |
        |              token for Agent B              |
        |                      |                      |
        | 4. RETURN            |                      |
        | token_id (reference) |                      |
        | NOT the token itself |                      |
        |<---------------------+                      |
        |                      |                      |
        | 5. PASS token_id     |                      |
        | to Agent B           |                      |
        | (via message or      |                      |
        |  task assignment)     |                      |
        +-------------------------------------------->|
        |                      |                      |
        |                      | 6. PRESENT           |
        |                      | token_id + action    |
        |                      | request              |
        |                      |<---------------------+
        |                      |                      |
        |              7. VERIFY                      |
        |              delegation token               |
        |              (full chain, Section 3.7)      |
        |                      |                      |
        |              8. EXECUTE                     |
        |              action in isolation             |
        |              (Chapter 03)                   |
        |              Resolve secrets.               |
        |              Run command.                   |
        |              Sanitize output.               |
        |                      |                      |
        |                      | 9. RETURN            |
        |                      | sanitized result     |
        |                      | (NOT secrets)        |
        |                      +--------------------->|
        |                      |                      |
        |                      |       10. Agent B    |
        |                      |       processes      |
        |                      |       result         |
        |                      |                      |
        | 11. Agent B RETURNS  |                      |
        | result to Agent A    |                      |
        | (NOT secrets)        |                      |
        |<--------------------------------------------+
        |                      |                      |
        |              12. AUDIT                      |
        |              Full chain logged:             |
        |              Agent A -> Agent B             |
        |              token_id, action,              |
        |              result hash, timestamps        |
        |                      |                      |
```

### 4.2 Critical Protocol Properties

The delegation protocol flow preserves the following security properties:

1. **Agent A never sees the secrets** that Agent B uses to execute the delegated action. Agent A receives only the result.
2. **Agent B never sees the delegation token itself** until it presents the `token_id` to the NL Provider. The NL Provider stores the token; Agent A passes only the reference.
3. **The NL Provider is the sole custodian** of both secrets and delegation tokens. No agent in the chain holds plaintext secrets or full token data.
4. **The full chain is audited**: Every step -- from delegation request to result return -- is recorded in the audit trail with cryptographic integrity (Chapter 05).

### 4.3 Token Reference Passing

Agent A MUST pass only the `token_id` (a reference) to Agent B, NOT the full delegation token. This prevents the delegate from inspecting the token's scope and crafting attacks based on knowledge of the delegation's boundaries.

The `token_id` SHOULD be passed through the existing inter-agent communication channel (e.g., MCP messages, A2A protocol messages, or implementation-specific task assignment mechanisms). The `token_id` is not sensitive -- it is useless without the NL Provider's verification -- but SHOULD be transmitted over an authenticated channel to prevent interception and use by unauthorized agents.

## 5. Result-Only Propagation

### 5.1 Principle

In any multi-agent chain -- whether through delegation, federation, or simple task orchestration -- only the RESULTS of actions flow between agents. Secrets MUST NEVER be passed from one agent to another, regardless of the trust relationship between them.

This is the fundamental invariant of cross-agent interaction in the NL Protocol.

### 5.2 Result-Only Flow

```
MULTI-AGENT CHAIN: Agent A -> Agent B -> Agent C

Step 1: Agent A assigns task to Agent B
        Agent A passes: task description + delegation token_id
        Agent A does NOT pass: any secrets

Step 2: Agent B determines it needs Agent C for a sub-task
        Agent B issues sub-delegation token (from Agent A's delegation)
        Agent B passes to Agent C: sub-task description + sub-delegation token_id
        Agent B does NOT pass: any secrets or Agent A's delegation token

Step 3: Agent C executes the sub-task
        Agent C presents sub-delegation token_id to NL Provider
        NL Provider: verifies chain (A -> B -> C), resolves secrets, executes
        NL Provider returns: sanitized result to Agent C
        Agent C does NOT receive: any secret values

Step 4: Agent C returns result to Agent B
        Agent C passes: execution result (sanitized)
        Agent C does NOT pass: any secrets (it never had them)

Step 5: Agent B processes result, returns to Agent A
        Agent B passes: processed result
        Agent B does NOT pass: any secrets

RESULT: At no point in the chain did any agent hold a secret value.
        Secrets existed only within the NL Provider's isolation boundary.
        Full chain: A -> B -> C is audited with accountability at each level.
```

### 5.3 Result Sanitization Across Agent Boundaries

Before results are returned across agent boundaries (from NL Provider to delegate, or from delegate to delegator), they MUST be sanitized per Chapter 03 and Chapter 06:

1. The result MUST be checked against all secret values that were used during execution using hash-based detection (Chapter 06, Section 4.2).
2. Any matches MUST be redacted with `[NL-REDACTED:<secret_reference>]`.
3. Redaction events MUST be flagged in the audit trail.
4. If redaction occurs, a T8 (Secret in Output) incident MUST be generated (Chapter 06).

### 5.4 Prohibition of Secret Forwarding

The following behaviors are explicitly prohibited and MUST be detected and blocked:

1. An agent requesting a secret value via the NL Protocol and then passing that value to another agent in a message or task assignment.
2. An agent embedding a secret value in a result returned to a delegator.
3. An agent including NL Protocol placeholder references (e.g., `{{nl:SECRET}}`) in messages to other agents, expecting the receiving agent's NL Provider to resolve them. (Each agent MUST resolve its own placeholders through its own NL Provider.)

Violations MUST generate a Security Incident Record of type T8 or T9 (Chapter 06).

## 6. Cross-Organization Federation

### 6.1 Federation Scenario

Federation enables agents from different organizations to collaborate without either organization's secrets leaving their boundary:

```
+---------------------------+          +---------------------------+
|     ORGANIZATION A        |          |     ORGANIZATION B        |
|                           |          |                           |
| +--------+  +-----------+ |          | +-----------+  +--------+ |
| | Agent  |  |    NL     | |          | |    NL     |  | Agent  | |
| |   A    |  | Provider  | |          | | Provider  |  |   B    | |
| |        |  |    A      | |          | |    B      |  |        | |
| +---+----+  +-----+-----+ |          | +-----+-----+  +---+----+ |
|     |              |       |          |       |              |     |
|     |  Secrets A   |       |   TRUST  |       |  Secrets B   |     |
|     |  never leave |       |<-------->|       |  never leave |     |
|     |  Org A       |       |FEDERATION|       |  Org B       |     |
|     |              |       |          |       |              |     |
+---------------------------+          +---------------------------+

FLOW:
1. Agent A needs data from Org B's API (which requires Org B's credentials)
2. Agent A sends an NL action request to Org A's NL Provider
3. Org A's NL Provider forwards a federated action request to Org B's NL Provider
4. Org B's NL Provider: validates the request, resolves Org B's secrets,
   executes the action in isolation
5. Org B's NL Provider returns the sanitized RESULT to Org A's NL Provider
6. Org A's NL Provider returns the result to Agent A

RESULT: Agent A received the API response.
        Agent A never saw Org B's credentials.
        Org B's secrets never left Org B's NL Provider.
```

### 6.2 Trust Establishment

Federation connections between NL Providers MUST use mutual TLS (mTLS) authentication. Each NL Provider MUST present a valid X.509 certificate during the TLS handshake. The certificate's Subject Alternative Name MUST match the federation partner's registered domain. Self-signed certificates MUST NOT be accepted for federation. Certificates MUST be issued by a trusted CA or a federation-specific CA agreed upon in the Federation Agreement.

Before federated interactions can occur, the two organizations MUST establish a trust relationship:

#### 6.2.1 Trust Level Requirements

| Interaction Type | Minimum Trust Level |
|-----------------|---------------------|
| Read-only data exchange (public data) | L0 (self-attested) |
| Read-only data exchange (internal data) | L1 (org-verified) |
| Action delegation (within organization) | L1 (org-verified) |
| Action delegation (cross-organization) | L2 (vendor-attested) |
| Secret-dependent action delegation (cross-org) | L2 (vendor-attested) |
| Federation trust anchor establishment | L3 (third-party-certified) |

#### 6.2.2 Trust Establishment Protocol

Federation trust is established through a combination of platform attestation and token exchange:

```
TRUST ESTABLISHMENT FLOW:

+---------------------+                    +---------------------+
| Org A Administrator |                    | Org B Administrator |
+----------+----------+                    +----------+----------+
           |                                          |
           | 1. Initiate federation request           |
           |   (org_a_domain, trust_level, purposes)  |
           +----------------------------------------->|
           |                                          |
           |          2. Review and approve            |
           |          federation request               |
           |                                          |
           |   3. Exchange trust domain root           |
           |      certificates / public keys           |
           |<---------------------------------------->|
           |                                          |
           | 4. Agree on federation policy:            |
           |    - Allowed action types                 |
           |    - Maximum delegation depth             |
           |    - Audit requirements                   |
           |    - Incident response procedures         |
           |    - Revocation notification channel      |
           |<---------------------------------------->|
           |                                          |
           | 5. Sign Federation Agreement Document     |
           |    (both parties sign, stored by both)    |
           |<---------------------------------------->|
           |                                          |
           | 6. Configure NL Providers:                |
           |    - Register remote trust domain         |
           |    - Configure mTLS certificates          |
           |    - Set federation policy                |
           |    - Test connectivity                    |
           +----------+  +----------+-----------------+
                      |  |
                      v  v
              FEDERATION ACTIVE
              (agents can now make
               cross-org requests)
```

#### 6.2.3 Federation Agreement Document

A Federation Agreement Document MUST contain:

```json
{
  "agreement_id": "<uuid-v4>",
  "version": "1.0",
  "parties": {
    "party_a": {
      "organization": "company-a.com",
      "trust_domain": "nl://company-a.com",
      "root_public_key": { "kty": "EC", "crv": "P-256", "...": "..." },
      "nl_provider_endpoint": "https://nl.company-a.com/v1",
      "admin_contact": "security@company-a.com"
    },
    "party_b": {
      "organization": "company-b.com",
      "trust_domain": "nl://company-b.com",
      "root_public_key": { "kty": "EC", "crv": "P-256", "...": "..." },
      "nl_provider_endpoint": "https://nl.company-b.com/v1",
      "admin_contact": "security@company-b.com"
    }
  },
  "policy": {
    "trust_level_required": "L2",
    "allowed_action_types": ["exec", "template"],
    "max_delegation_depth": 2,
    "max_token_ttl_seconds": 300,
    "audit_sharing": "required",
    "incident_notification": "required",
    "revocation_propagation": "immediate"
  },
  "effective_from": "2026-02-08T00:00:00Z",
  "expires_at": "2027-02-08T00:00:00Z",
  "signatures": {
    "party_a": { "algorithm": "ES256", "value": "..." },
    "party_b": { "algorithm": "ES256", "value": "..." }
  }
}
```

### 6.3 Federated Action Request

When an agent in Organization A needs to perform an action that requires Organization B's secrets, the request follows this protocol:

```
+----------+    +-------------+    +-------------+    +----------+
| Agent A  |    | NL Provider |    | NL Provider |    |  Org B   |
| (Org A)  |    |    (Org A)  |    |    (Org B)  |    | Secrets  |
+----+-----+    +------+------+    +------+------+    +----+-----+
     |                 |                  |                  |
     | 1. Action       |                  |                  |
     | request with    |                  |                  |
     | federated ref   |                  |                  |
     +---------------->|                  |                  |
     |                 |                  |                  |
     |        2. Detect federated         |                  |
     |           secret reference         |                  |
     |           (e.g., {{nl:@company-b/  |                  |
     |            api/SERVICE_KEY}})      |                  |
     |                 |                  |                  |
     |                 | 3. Federated     |                  |
     |                 | action request   |                  |
     |                 | (mTLS, signed)   |                  |
     |                 +----------------->|                  |
     |                 |                  |                  |
     |                 |         4. Verify federation        |
     |                 |            agreement                |
     |                 |         5. Verify requesting        |
     |                 |            agent's trust level      |
     |                 |         6. Verify action is         |
     |                 |            allowed by policy        |
     |                 |                  |                  |
     |                 |                  | 7. Resolve       |
     |                 |                  | Org B's secrets  |
     |                 |                  +----------------->|
     |                 |                  |                  |
     |                 |                  | 8. Execute in    |
     |                 |                  | isolation        |
     |                 |                  |<-----------------+
     |                 |                  |                  |
     |                 |                  | 9. Sanitize      |
     |                 |                  | output           |
     |                 |                  |                  |
     |                 | 10. Return       |                  |
     |                 | sanitized result |                  |
     |                 |<-----------------+                  |
     |                 |                  |                  |
     | 11. Return      |                  |                  |
     | result to       |                  |                  |
     | Agent A         |                  |                  |
     |<----------------+                  |                  |
     |                 |                  |                  |
     |        12. Both NL Providers       |                  |
     |            record audit entries    |                  |
     |            with shared             |                  |
     |            correlation_id          |                  |
     |                 |                  |                  |
```

### 6.4 Federated Secret Reference Syntax

To reference a secret in a federated organization, the NL Protocol extends the placeholder syntax:

```
{{nl:@<federation_domain>/<secret_path>}}
```

Examples:
```
{{nl:@company-b.com/api/SERVICE_KEY}}
{{nl:@partner-org.io/payments/STRIPE_KEY}}
{{nl:@cloud-vendor.com/infra/DB_PASSWORD}}
```

The `@` prefix signals to the NL Provider that this is a federated reference. The domain portion MUST match a registered federation partner. If the domain is not recognized, the action MUST be rejected.

### 6.5 Federated Audit Correlation

Each federated interaction MUST be logged in BOTH organizations' audit trails. To enable correlation:

1. The requesting NL Provider (Org A) generates a `federation_correlation_id` (UUID v4).
2. This ID is included in the federated action request to Org B.
3. Both Org A and Org B include this ID in their respective audit records.
4. Neither organization shares internal audit details beyond the correlation ID and the interaction summary.

The audit record in each organization MUST include:

| Field | Org A (requester) | Org B (executor) |
|-------|-------------------|------------------|
| `federation_correlation_id` | Generated | Received |
| `federation_partner` | `company-b.com` | `company-a.com` |
| `federation_agreement_id` | Agreement ID | Agreement ID |
| `action_requested` | Full action | Full action |
| `secrets_used` | N/A (not visible) | List of secret names (not values) |
| `result_hash` | SHA-256 of result | SHA-256 of result |
| `outcome` | success/failure | success/failure |

## 7. Global Revocation Protocol

### 7.1 Purpose

When an agent is compromised, its access MUST be revoked not only within its own organization but across all federated providers with which it has active trust relationships. The Global Revocation Protocol defines how this propagation occurs.

### 7.2 Revocation Request

A revocation request is initiated by an administrator or by the automated response system (Chapter 06, Section 5.5) and is sent to the NL Provider's revocation endpoint:

```
POST /nl-protocol/v1/revoke
Content-Type: application/json
Authorization: Bearer <admin-token>

{
  "revocation_id": "<uuid-v4>",
  "agent_uri": "nl://example.com/compromised-agent/1.0.0",
  "scope": "<global | local | federated>",
  "reason": "<compromised | decommissioned | policy_violation | administrative>",
  "effective": "<immediate | scheduled>",
  "effective_at": "<ISO-8601 UTC, required if effective=scheduled>",
  "propagate_to": ["<* for all federations, or list of specific domains>"],
  "revoke_delegations": true,
  "cancel_inflight": true,
  "initiated_by": "<admin identity or 'automated:chapter06'>",
  "evidence_refs": ["<incident_id references, if applicable>"],
  "signature": {
    "algorithm": "ES256",
    "value": "<signature over canonical JSON by the authorized admin or NL Provider>"
  }
}
```

### 7.3 Revocation Scope

| Scope | Description |
|-------|-------------|
| `local` | Revoke the agent's AID and all delegation tokens within the local trust domain only. |
| `federated` | Revoke locally AND notify specified federated partners to revoke the agent's access in their domains. |
| `global` | Revoke locally AND notify ALL federated partners (indicated by `propagate_to: ["*"]`). |

### 7.4 Revocation Propagation Flow

```
GLOBAL REVOCATION: Agent compromised in Org A

+-------------+     +-------------+     +-------------+     +-------------+
| Org A       |     | Org B       |     | Org C       |     | Org D       |
| NL Provider |     | NL Provider |     | NL Provider |     | NL Provider |
+------+------+     +------+------+     +------+------+     +------+------+
       |                   |                   |                   |
       | 1. Agent revoked  |                   |                   |
       |    locally         |                   |                   |
       |                   |                   |                   |
       | 2. Propagate to   |                   |                   |
       |    all federation  |                   |                   |
       |    partners        |                   |                   |
       +------------------>|                   |                   |
       +---------------------------------------->|                   |
       +----------------------------------------------------------->|
       |                   |                   |                   |
       |          3. Each partner:             |                   |
       |          - Revoke agent's access      |                   |
       |          - Revoke delegation tokens   |                   |
       |          - Cancel in-flight actions   |                   |
       |          - Log revocation event       |                   |
       |                   |                   |                   |
       |  4. ACK           |                   |                   |
       |<------------------+                   |                   |
       |<------------------------------------------+                   |
       |<-----------------------------------------------------------+
       |                   |                   |                   |
       | 5. Revocation     |                   |                   |
       |    confirmed      |                   |                   |
       |    across all     |                   |                   |
       |    partners       |                   |                   |
       |                   |                   |                   |
```

### 7.5 Revocation Requirements

1. **Immediacy**: When `effective: "immediate"`, revocation MUST take effect within the local trust domain in less than 1 second. Propagation to federated partners SHOULD complete within 30 seconds.

2. **In-flight actions**: When `cancel_inflight: true`, all actions currently executing on behalf of the revoked agent SHOULD be cancelled. If cancellation is not possible, results MUST be quarantined and reviewed before delivery.

3. **Delegation cascade**: When `revoke_delegations: true`, ALL delegation tokens issued BY the agent AND all delegation tokens issued TO the agent MUST be revoked. Revocation MUST cascade through the entire delegation tree (transitive closure).

4. **Acknowledgment**: Each federated partner MUST acknowledge the revocation request. If a federated partner does not acknowledge revocation within 60 seconds, the issuing NL Provider MUST:
   1. Retry with exponential backoff (1s, 2s, 4s, 8s, 16s, 32s).
   2. After 5 failed retries, mark the delegation as `revoked_locally` and generate a CRITICAL alert.
   3. The issuing provider MUST treat the delegation as revoked regardless of partner acknowledgment (optimistic revocation).
   4. When the partner becomes reachable again, revocation MUST be re-sent and confirmed.

5. **Audit**: Revocation events MUST be logged in the audit trail of every involved NL Provider. The `revocation_id` MUST be included in all related audit records for correlation.

6. **Idempotency**: Revocation requests MUST be idempotent. Receiving a revocation request for an already-revoked agent MUST NOT produce an error; it SHOULD be acknowledged and logged.

### 7.6 Revocation Response

```json
{
  "revocation_id": "<matching the request>",
  "status": "<completed | partial | failed>",
  "local_result": {
    "aid_revoked": true,
    "delegation_tokens_revoked": 5,
    "inflight_actions_cancelled": 2
  },
  "federation_results": [
    {
      "partner": "company-b.com",
      "status": "completed",
      "delegation_tokens_revoked": 1,
      "acknowledged_at": "2026-02-08T10:30:01.234Z"
    },
    {
      "partner": "company-c.com",
      "status": "completed",
      "delegation_tokens_revoked": 0,
      "acknowledged_at": "2026-02-08T10:30:02.567Z"
    }
  ],
  "completed_at": "2026-02-08T10:30:02.567Z"
}
```

## 8. Zero-Knowledge Verification

> **EXPERIMENTAL**: This section describes a future capability that is included in v1.0 for forward compatibility. Implementations SHOULD NOT rely on this section for production systems in the initial release. The mechanisms described here will be refined in subsequent versions of the specification.

### 8.1 Motivation

In certain privacy-sensitive cross-organization scenarios, an agent may need to prove that it is authorized to perform an action without revealing:

- Its specific identity (beyond "an agent from Organization A").
- The specific scope of its authorization.
- The delegation chain that led to its authorization.

This enables scenarios such as:
- Anonymous but authorized API consumption.
- Privacy-preserving compliance verification.
- Cross-organization collaboration where organizational structure is confidential.

### 8.2 Conceptual Model

Zero-knowledge verification in the NL Protocol context would allow an agent to produce a proof that satisfies:

1. **Completeness**: If the agent is genuinely authorized, the verifier will accept the proof.
2. **Soundness**: If the agent is NOT authorized, no proof will be accepted.
3. **Zero-knowledge**: The verifier learns nothing beyond the fact that the agent is authorized.

### 8.3 Candidate Approaches

The following approaches are under consideration for future versions:

1. **ZK-SNARKs for delegation chain verification**: The agent produces a zero-knowledge proof that a valid delegation chain exists from a recognized trust anchor to itself, without revealing the chain's contents.

2. **Blind signatures for anonymous delegation tokens**: The NL Provider issues a delegation token that is blindly signed, allowing the delegate to present it without linking it back to the specific delegation event.

3. **Group signatures for organizational attestation**: All agents within an organization share a group signing key. An agent can prove membership in the organization without revealing which specific agent it is.

### 8.4 Implementation Guidance

Implementations that wish to experiment with zero-knowledge verification SHOULD:

1. Treat ZK capabilities as an optional extension to the standard delegation model (Section 3).
2. Ensure that ZK proofs are verifiable by any NL Provider without specialized hardware.
3. Maintain the same audit requirements: even ZK-verified actions MUST produce audit records (though the audit record MAY use pseudonymous identifiers).
4. Provide a fallback to standard delegation verification for providers that do not support ZK.

## 9. Agent Compliance Attestation

### 9.1 Purpose

For the cross-agent trust model to function, agents MUST be able to prove that they are NL Protocol-compliant. An agent that claims compliance but does not actually implement the required security mechanisms is a threat to the entire trust network.

### 9.2 Compliance Claim

An agent's compliance level MUST be declared in its Agent Identity Document (AID, Chapter 01) as an additional field:

```json
{
  "agent_uri": "nl://example.com/data-analyst/1.0.0",
  "public_key": {
    "algorithm": "ES256",
    "value": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE..."
  },
  "organization_id": "org_example",
  "created_at": "2026-02-08T00:00:00Z",
  "expires_at": "2026-03-08T00:00:00Z",
  "capabilities": ["exec", "template"],
  "nlProtocolCompliance": {
    "level": "advanced",
    "version": "1.0.0",
    "conformance_report_uri": "https://example.com/compliance/agent-v1-report.json",
    "last_verified": "2026-02-01T00:00:00Z",
    "verifier": "nl://nlprotocol.org/conformance-authority/1.0.0"
  },
  "attestation": { "...": "..." }
}
```

### 9.3 Conformance Levels

| Level | Name | Chapters Required | Description |
|-------|------|-------------------|-------------|
| `basic` | NL Protocol Basic | 01, 02, 03 | Agent identity, action-based access, execution isolation. |
| `standard` | NL Protocol Standard | 01, 02, 03, 04, 05 | Basic + pre-execution defense, audit integrity. |
| `advanced` | NL Protocol Advanced | 01, 02, 03, 04, 05, 06, 07 | Standard + attack detection, cross-agent trust. |

### 9.4 Verification Methods

Compliance can be verified through:

1. **Self-assessment**: The agent's operator runs the NL Protocol conformance test suite and publishes the results. This is the minimum requirement for `basic` conformance.

2. **Automated verification**: A conformance authority runs the test suite against the agent's NL Provider and issues a signed verification report. This is RECOMMENDED for `standard` conformance.

3. **Third-party certification**: An independent auditor reviews the implementation and issues a certification. This is RECOMMENDED for `advanced` conformance and for agents participating in cross-organization federation.

### 9.5 Conformance Test Suite

The NL Protocol conformance test suite is published as a separate, open-source repository under the Apache 2.0 license. The test suite includes:

- **Level 01 tests**: AID generation, signature verification, key rotation, revocation.
- **Level 02 tests**: Scope creation, delegation, subset rule enforcement, deny-by-default.
- **Level 03 tests**: Isolation boundary enforcement, resource limit enforcement, cleanup verification.
- **Level 04 tests**: Schema validation, prompt injection detection, rate limiting.
- **Level 05 tests**: Audit record generation, hash chain verification, checkpoint validation.
- **Level 06 tests**: Attack type detection (T1-T11), threat scoring computation, automated response.
- **Level 07 tests**: Delegation token generation and verification, chain verification, revocation propagation, result-only propagation.

### 9.6 Trust Level Mapping

The compliance level of an agent informs the trust level it can achieve:

| Compliance Level | Maximum Trust Level Achievable |
|-----------------|-------------------------------|
| None (no claim) | L0 (self-attested) |
| `basic` (self-assessed) | L0 (self-attested) |
| `basic` (automated) | L1 (org-verified) |
| `standard` (automated) | L1 (org-verified) |
| `standard` (third-party) | L2 (vendor-attested) |
| `advanced` (automated) | L2 (vendor-attested) |
| `advanced` (third-party) | L3 (third-party-certified) |

This mapping ensures that higher-trust interactions require stronger compliance evidence.

## 10. Integration Examples

### 10.1 Example: CI/CD Pipeline Delegation

An orchestrator agent delegates deployment authority to a specialized deploy agent:

```
Scenario:
  - Claude Code (orchestrator) is building and testing a project
  - After tests pass, it needs to deploy to AWS ECS
  - Claude Code delegates deploy authority to deploy-agent
  - deploy-agent uses AWS credentials to update the ECS service

Flow:
  1. Claude Code requests delegation token:
     issuer:  nl://anthropic.com/claude-code/1.5.2
     subject: nl://example.com/deploy-agent/1.0.0
     scope:   { secrets: ["aws/ECS_DEPLOY_KEY"], actions: ["exec"], max_uses: 1 }
     expires: 5 minutes

  2. NL Provider verifies Claude Code has access to aws/ECS_DEPLOY_KEY
     and creates the delegation token.

  3. Claude Code passes token_id to deploy-agent:
     "Deploy the latest build to production. Delegation: token_id=abc-123"

  4. deploy-agent presents token_id to NL Provider:
     Action: exec "aws ecs update-service --cluster prod --service api
             --force-new-deployment"
     With: {{nl:aws/ECS_DEPLOY_KEY}} resolved as AWS credentials

  5. NL Provider verifies delegation chain, executes in isolation,
     returns: "Service updated successfully. Deployment ID: dep-xyz-789"

  6. deploy-agent returns result to Claude Code.
     Claude Code never saw the AWS credentials.
```

### 10.2 Example: Cross-Organization API Integration

Company A's agent needs to fetch data from Company B's API:

```
Scenario:
  - Company A's data-analyst agent needs sales data from Company B's API
  - Company B's API requires an API key that Company A must never see
  - Both companies have federated their NL Providers

Flow:
  1. data-analyst requests:
     Action: exec "curl {{nl:@company-b.com/api/SALES_API_KEY}}
             https://api.company-b.com/v2/sales?quarter=Q4"

  2. Company A's NL Provider detects the @company-b.com prefix.
     Looks up federation agreement with company-b.com.
     Sends federated action request to Company B's NL Provider (mTLS).

  3. Company B's NL Provider:
     - Verifies federation agreement
     - Verifies Company A's agent trust level (>= L2)
     - Resolves SALES_API_KEY from Company B's secret store
     - Executes curl in isolation
     - Sanitizes output (removes any trace of SALES_API_KEY)
     - Returns: {"sales": [{"quarter": "Q4", "revenue": 1250000}]}

  4. Company A's NL Provider returns the result to data-analyst.

  5. Both NL Providers log the interaction with shared correlation_id.

  Result: Company A got the sales data.
          Company B's API key never left Company B.
          Full audit trail exists in both organizations.
```

### 10.3 Example: Multi-Agent Pipeline with Result-Only Propagation

A three-agent pipeline processes data without any agent seeing another's secrets:

```
Scenario:
  - Agent A (data-collector): Has access to external API credentials
  - Agent B (data-processor): Has access to internal database credentials
  - Agent C (report-generator): Has access to email service credentials
  - Each agent can only see its own secrets

Flow:
  1. Agent A fetches data from external API:
     {{nl:api/EXTERNAL_KEY}} used to authenticate.
     Returns: raw data (JSON) -- no secrets in output.

  2. Agent A passes raw data to Agent B (via delegation token):
     Agent B stores processed results in internal database.
     {{nl:database/DB_PASSWORD}} used to authenticate.
     Returns: "1,247 records stored in analytics.q4_sales"

  3. Agent B passes confirmation to Agent C (via sub-delegation):
     Agent C generates report and emails to stakeholders.
     {{nl:email/SMTP_PASSWORD}} used to authenticate.
     Returns: "Report emailed to team@company.com"

  Chain accountability:
    A -> B -> C: Full audit trail with delegation tokens at each link.
    Agent A never saw DB_PASSWORD or SMTP_PASSWORD.
    Agent B never saw EXTERNAL_KEY or SMTP_PASSWORD.
    Agent C never saw EXTERNAL_KEY or DB_PASSWORD.
```

## 11. Security Considerations

- **Delegation chain complexity**: Delegation chains create transitive trust. A compromise of any agent in the chain can affect all downstream agents. Shallow delegation depths (RECOMMENDED: maximum 3) and short token lifetimes (RECOMMENDED: 5 minutes) mitigate this risk.

- **Token theft**: While delegation tokens are stored by the NL Provider (not agents), the `token_id` reference could be intercepted. Implementations MUST ensure that `token_id` alone is insufficient to execute actions -- the presenting agent's AID MUST also be verified against the token's `subject` field.

- **Federation trust decay**: Federation agreements should be regularly reviewed and renewed. Stale federation relationships with organizations that have changed security posture are a risk. Implementations SHOULD support automatic expiration of federation agreements and SHOULD alert administrators before expiration.

- **Revocation latency**: In federated environments, revocation propagation introduces a window during which a revoked agent could still execute actions at a remote partner. The 30-second propagation target (Section 7.5) represents a practical compromise between security and reliability. For extremely sensitive operations, implementations SHOULD additionally verify agent status in real-time by querying the issuing NL Provider.

- **Result-only propagation limitations**: While result-only propagation prevents direct secret exposure, side-channel attacks through result content remain possible. For example, a compromised agent could craft a command that produces output encoding the secret in a non-obvious way. Hash-based detection (Chapter 06, Section 4.2) and entropy analysis (Chapter 06, Section 4.3) are the primary mitigations.

- **Federation as attack vector**: A compromised federated partner could send malicious action requests or false revocation notices. Federation agreements MUST be authenticated with mTLS and signed by both parties. Revocation requests MUST be signed by the initiating NL Provider's key. Implementations SHOULD rate-limit cross-federation requests.

- **Zero-knowledge privacy tradeoffs**: Zero-knowledge verification (Section 8) trades auditability for privacy. Implementations that enable ZK verification MUST carefully consider the forensic implications: in the event of a security incident, the inability to identify the specific agent involved may impede investigation.

- **Compliance attestation trust**: Self-assessed compliance claims are inherently less trustworthy than third-party certifications. The trust level mapping (Section 9.6) reflects this: self-assessment achieves at most L0, while third-party certification can achieve L3. Organizations SHOULD require at least automated verification for agents participating in cross-organization federation.

- **Single point of failure**: The NL Provider is a critical component in the trust model. If the NL Provider is unavailable, all delegation verification fails. Implementations SHOULD deploy NL Providers with high availability (redundancy, failover) and SHOULD cache delegation tokens for short-lived offline verification (with reduced trust guarantees).
