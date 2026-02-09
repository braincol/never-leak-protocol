# Never-Leak Protocol Specification v1.0 -- Overview

**Status:** 1.0
**Version:** 1.0.0
**Date:** 2026-02-08
**Authors:** Braincol Strategy
**License:** CC BY 4.0

> **Note:** This document is a SPECIFICATION. It defines required behaviors,
> data formats, and protocols — not specific products or CLI commands.
> For implementations of this specification, see [IMPLEMENTATIONS.md](../../IMPLEMENTATIONS.md).

---

## Abstract

The Never-Leak Protocol (NL Protocol) is an open specification that defines how
AI agents interact with secrets -- credentials, API keys, tokens, certificates,
and any other sensitive material -- without those secrets ever entering the
agent's context window, memory, or reasoning state.

The core innovation is a paradigm shift: agents request **actions**, not
**secrets**. A secret value is resolved, injected, and consumed inside an
isolated execution boundary that the agent cannot observe. The agent receives
only the result of the action, never the secret itself.

The protocol is structured as seven independent but complementary levels,
ranging from agent identity (Level 1) to cross-agent trust and federation
(Level 7). Implementations MAY adopt levels incrementally; conformance is
assessed at three tiers (Basic, Standard, Advanced) corresponding to
increasing subsets of the levels.

The NL Protocol is framework-agnostic, model-agnostic, and
platform-agnostic. It is designed to be implementable by secret managers,
cloud providers (AWS, GCP, Azure), CI/CD systems (GitHub Actions, GitLab CI),
agent platforms (Anthropic, OpenAI, Google), and any system that mediates
between an AI agent and sensitive material.

---

## 1. Motivation

AI agents are rapidly gaining the ability to read files, execute code, call
APIs, manage infrastructure, and coordinate with other agents. Each of these
capabilities requires secrets: API keys to authenticate, database passwords to
connect, TLS certificates to establish trust, cloud credentials to provision
resources.

Current practice treats agents like human users: secrets are retrieved and
placed into the agent's working memory. This is fundamentally unsafe because:

1. **The agent's context is adversarial territory.** Any data in an LLM's
   context window can be memorized, replicated in output, or exfiltrated via
   prompt injection. A secret that enters the context is a secret that is
   leaked.

2. **Agents inherit ambient authority.** Most agent frameworks give agents the
   full permissions of the user or service account that spawned them, with no
   mechanism to scope or attenuate those permissions per-task.

3. **Multi-agent pipelines amplify risk.** When agents delegate to other
   agents, secrets propagate through the chain. Each hop is an additional
   exfiltration surface.

4. **Audit trails are inadequate.** Existing logging is mutable, unsigned,
   and rarely captures agent-specific metadata (which agent, what type, what
   scope, what attestation).

5. **There is no governance model.** Organizations cannot answer basic
   questions: Which agents have access to which secrets? What did agent X do
   with secret Y? Can I revoke access to a single agent without disrupting
   others?

The NL Protocol provides a specification-level answer to all of these problems.

---

## 2. Goals

The NL Protocol aims to:

| ID | Goal |
|----|------|
| G1 | **Prevent secret exposure.** Secret values MUST never enter the agent's context window, conversation history, reasoning trace, or any memory accessible to the LLM. |
| G2 | **Enable action-based access.** Agents request operations that require secrets; the system resolves, injects, and executes in isolation, returning only the result. |
| G3 | **Provide cryptographic agent identity.** Every agent MUST have a verifiable, attested identity with scoped capabilities, lifecycle management, and trust levels. |
| G4 | **Support governance at scale.** Organizations MUST be able to define, enforce, audit, and revoke per-agent, per-secret, time-bounded, conditional access policies. |
| G5 | **Enable multi-agent delegation.** Orchestrator agents MUST be able to delegate scoped, time-limited authority to sub-agents without exposing secrets. |
| G6 | **Be implementable by platform vendors.** AWS, Stripe, GitHub, Anthropic, and similar providers MUST be able to implement the protocol in their existing systems. |
| G7 | **Produce immutable audit trails.** Every agent-secret interaction MUST generate a cryptographically chained, tamper-evident audit record. |
| G8 | **Be incrementally adoptable.** Implementations MUST be able to adopt levels 1-3 without implementing levels 4-7. |

---

## 3. Non-Goals

The NL Protocol explicitly does NOT aim to:

| ID | Non-Goal | Rationale |
|----|----------|-----------|
| NG1 | Replace TLS/mTLS | The protocol operates at the application layer. Transport security is orthogonal and assumed. |
| NG2 | Replace OAuth 2.0 | OAuth authenticates users and authorizes applications. NL Protocol governs how authenticated agents use secrets. The two are complementary. |
| NG3 | Prescribe encryption algorithms | The protocol defines security requirements (AEAD, key wrapping) but does not mandate specific ciphers. |
| NG4 | Define a secret storage format | How secrets are stored at rest is an implementation concern. The protocol governs access, not storage. |
| NG5 | Be a general-purpose authorization framework | The protocol is specifically scoped to agent-secret interactions. General RBAC/ABAC is out of scope. |
| NG6 | Prevent all prompt injection | Prompt injection defense is a broader problem. The protocol mitigates its impact on secrets specifically. |
| NG7 | Require a specific agent framework | The protocol works with any agent system: LangChain, CrewAI, AutoGen, MCP, A2A, or custom. |

---

## 4. Design Principles

1. **Zero Trust by Default.** No agent, tool, or message is trusted without
   explicit verification. Every action requires authorization at the point of
   execution.

2. **Secrets Are Opaque.** Agents interact with secret *references*
   (`{{nl:...}}`), never secret *values*. The reference is a handle; the
   value is resolved only inside the isolation boundary.

3. **Least Privilege.** Agents receive only the permissions necessary to
   complete a specific task. Permissions are scoped by action type, secret
   pattern, time window, and usage count.

4. **Defense in Depth.** Security is enforced at seven independent layers.
   A failure at one layer does not compromise the system if other layers
   are intact.

5. **Auditability.** Every agent action produces an immutable, cryptographically
   chained record that can be independently verified without revealing secret
   values.

6. **Governance First.** The protocol treats governance (who can do what, when,
   under what conditions, as attested by whom) as a first-class concern, not
   an afterthought.

7. **Interoperability.** The protocol is designed to work across agent
   frameworks, model providers, cloud platforms, and deployment topologies
   without vendor lock-in.

8. **Correct by Default.** Secure behavior MUST be the default. Insecure
   configurations MUST require explicit, audited opt-in.

### Trust Model Assumptions

This protocol operates under the following trust assumptions:

1. **NL Provider Infrastructure Trust**: The NL Provider infrastructure is assumed to be trustworthy and uncompromised. A compromised NL Provider could forge delegation tokens, manipulate audit records, or resolve secrets without authorization. This assumption is fundamental to the protocol's security guarantees.

2. **Mitigations for Infrastructure Compromise**: Organizations requiring defense against compromised NL Provider infrastructure SHOULD employ additional controls beyond this protocol:
   - Immutable audit trail backends (external ledgers, append-only storage, transparency logs)
   - Separation of key custody across multiple systems
   - Regular cryptographic audits of audit chain integrity by independent parties
   - Hardware security modules (HSMs) for signing key protection

3. **Runtime Environment Trust**: The protocol assumes the host operating system and hardware platform provide correct isolation primitives (process isolation, memory protection, filesystem permissions). Compromised OS-level controls are outside the scope of this specification.

### Policy Evaluation Order

When multiple policy layers apply to an action request, implementations MUST evaluate them in the following order:

1. **Deny Rules (Level 4)**: Pre-execution deny rules are evaluated first. If any deny rule matches, the action is BLOCKED immediately. No further evaluation occurs.
2. **Agent Identity Scope (Level 1)**: The AID's `scope` field defines the maximum boundary of permitted operations. If the requested action falls outside the AID scope, it is DENIED.
3. **Scope Grant Authorization (Level 2)**: Active scope grants are evaluated. The action proceeds only if a valid, non-expired scope grant covers the requested secret and action type.
4. **Conditional Evaluation (Level 2)**: If the matching scope grant has conditions (time windows, IP restrictions, `max_uses`), these are evaluated. Failure at this stage results in denial.
5. **Delegation Verification (Level 7)**: If the action involves a delegated token, delegation chain validity is verified (subset rule, depth limit, expiration, signature).

This evaluation order ensures that restrictive controls (deny rules) always take precedence over permissive controls (scope grants), consistent with Design Principle #1 (Fail Closed by Default).

---

## 5. Terminology and Glossary

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this specification are
to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

### 5.1 Core Definitions

| Term | Definition |
|------|------------|
| **Agent** | An autonomous or semi-autonomous software entity that uses an AI model to reason about and execute tasks on behalf of a Principal. Agents include coding assistants, autonomous executors, orchestrators, CI/CD pipelines, and custom agent types. |
| **Principal** | The human user, organization, or system on whose behalf an agent operates. The Principal is the ultimate authority for granting and revoking agent access. |
| **Platform Provider** | An organization that hosts, distributes, or attests to the identity of agents. Examples: Anthropic (Claude), OpenAI (GPT/Codex), Google (Gemini), GitHub (Copilot). Platform Providers sign attestation JWTs for agents they provision. |
| **Secret** | Any sensitive datum that grants access to a resource: API keys, passwords, tokens, certificates, private keys, connection strings, or any value whose exposure would constitute a security breach. |
| **Opaque Handle** | A symbolic reference to a secret (`{{nl:...}}`) that carries no information about the secret's value. The handle is the only form of secret reference that an agent ever sees. |
| **Action** | A discrete operation that requires one or more secrets to execute. Actions have typed semantics: `exec`, `template`, `inject_stdin`, `inject_tempfile`, `sdk_proxy`, `delegate`. The agent submits action requests; the NL-compliant system executes them. |
| **Action Request** | A structured JSON message from an agent to an NL-compliant system, specifying the action type, template with opaque handles, context, and purpose. |
| **Action Response** | A structured JSON message from an NL-compliant system to an agent, containing the result of the action (stdout, stderr, exit code) but never the secret values used. |
| **Delegation Token** | A short-lived, scope-restricted, cryptographically signed token that allows one agent to grant a subset of its permissions to another agent. Delegation tokens have bounded lifetime, limited use count, and are recorded in the audit trail. |
| **Scope Grant** | A permission object that binds an agent identity to a set of allowed actions, secret patterns, and conditions (time bounds, usage limits, approval requirements). |
| **Agent Identity Document (AID)** | A JSON structure that fully describes an agent's identity, capabilities, attestation, session context, and lifecycle state. See [01-agent-identity.md](01-agent-identity.md). |
| **Agent URI** | A structured identifier for an agent: `nl://vendor/agent-type/version`. Globally unique within the NL Protocol namespace. |
| **Attestation** | A cryptographic proof (JWT) signed by a Platform Provider or third-party certifier, asserting that an agent is who it claims to be. |
| **Trust Level** | A graduated measure of identity assurance: L0 (self-attested), L1 (org-verified), L2 (vendor-attested), L3 (third-party-certified). |
| **Isolation Boundary** | The security perimeter within which secrets exist during action execution. Secrets MUST NOT cross this boundary in any form observable by the agent. |
| **Result Sanitization** | The process of scanning action output (stdout, stderr) for accidentally leaked secret values before returning the result to the agent. |
| **Result-Only Propagation** | The principle that in multi-agent chains, only action results (not secrets) flow between agents. |
| **NL-Compliant System** | Any system that implements one or more levels of the NL Protocol and has passed the corresponding conformance tests. |
| **Conformance Level** | The tier of protocol compliance: Basic (Levels 1-3), Standard (Levels 1-5), Advanced (Levels 1-7). |
| **Credential** | An authentication artifact (API key, bearer token, mTLS certificate) used by an agent to authenticate with an NL Provider. Credentials are a TYPE of secret managed by the NL Provider. |
| **Scope** | The boundary defined in an AID limiting what secrets an agent MAY access. See Chapter 01. |
| **Scope Grant** | A discrete authorization object granting ACTUAL access to specific secrets within an agent's scope boundary. See Chapter 02. |
| **Token** | This specification uses 'token' in multiple contexts: 'delegation token' (Chapter 07), 'bearer token' (authentication credential), 'honeypot token' (decoy secret). Context determines meaning. |

---

## 6. Architecture Overview

### 6.1 System Components

```
+------------------------------------------------------------------+
|                        PRINCIPAL (Human)                          |
|   Defines policies, registers agents, approves grants             |
+-------------------------------+----------------------------------+
                                |
                     Policy & Grant Management
                                |
                                v
+------------------------------------------------------------------+
|                    NL-COMPLIANT SYSTEM                            |
|                                                                  |
|  +------------------+  +-------------------+  +---------------+  |
|  | Identity Service |  | Policy Engine     |  | Audit Engine  |  |
|  |                  |  |                   |  |               |  |
|  | - Agent Registry |  | - Scope Grants    |  | - Hash Chain  |  |
|  | - AID Issuance   |  | - Condition Eval  |  | - HMAC Sigs   |  |
|  | - Attestation    |  | - Action Routing  |  | - Forensics   |  |
|  |   Verification   |  | - Deny Rules      |  |               |  |
|  +--------+---------+  +--------+----------+  +-------+-------+  |
|           |                     |                      |          |
|           +----------+----------+----------+-----------+          |
|                      |                     |                      |
|            +---------v---------+  +--------v---------+            |
|            | Secret Resolver   |  | Output Sanitizer |            |
|            |                   |  |                  |            |
|            | - Handle -> Value |  | - Leak Detection |            |
|            | - Provider Bridge |  | - Redaction      |            |
|            +--------+----------+  +--------+---------+            |
|                     |                      |                      |
|           +---------v----------------------v---------+            |
|           |           ISOLATION BOUNDARY             |            |
|           |                                          |            |
|           |  +------------------------------------+  |            |
|           |  | Isolated Subprocess               |  |            |
|           |  |                                    |  |            |
|           |  | - Secrets as env vars              |  |            |
|           |  | - No shell expansion in parent     |  |            |
|           |  | - No core dumps                    |  |            |
|           |  | - Timeout enforcement              |  |            |
|           |  | - Memory wipe on exit              |  |            |
|           |  +------------------------------------+  |            |
|           +------------------------------------------+            |
+-------------------------------+----------------------------------+
                                |
                    Action Request / Response
                   (Opaque Handles, never values)
                                |
                                v
+------------------------------------------------------------------+
|                           AGENT                                   |
|                                                                  |
|  +------------------+  +-------------------+  +---------------+  |
|  | Agent Identity   |  | Action Builder    |  | Result Parser |  |
|  |                  |  |                   |  |               |  |
|  | - AID            |  | - Template with   |  | - stdout      |  |
|  | - Attestation    |  |   {{nl:...}}      |  | - stderr      |  |
|  | - Session Ctx    |  |   handles only    |  | - exit code   |  |
|  +------------------+  +-------------------+  +---------------+  |
|                                                                  |
|  NEVER sees: secret values, decrypted material, raw credentials  |
+------------------------------------------------------------------+
```

### 6.2 Chapter Dependencies

Implementations MUST satisfy chapter dependencies in order:
- **Level 1** (Agent Identity): No dependencies
- **Level 2** (Action-Based Access): Requires Level 1
- **Level 3** (Execution Isolation): Requires Level 2
- **Level 4** (Pre-Execution Defense): Requires Levels 1-3
- **Level 5** (Audit Integrity): Requires Levels 1-3
- **Level 6** (Attack Detection): Requires Levels 1-5 (Level 5 is a **critical dependency** -- audit integrity is essential for attack detection correlation and evidence preservation)
- **Level 7** (Cross-Agent Trust): Requires Levels 1-5 (Level 5 is a **critical dependency** -- delegation chains and federation events MUST be auditable for trust verification)
- **Wire Protocol** (Chapter 08): Required by all levels for network communication

Note: Levels 4 and 5 may be implemented in parallel. Levels 6 and 7 may be implemented in parallel.

**Foundational Dependency**: Level 5 (Audit Integrity) is a critical prerequisite for Levels 6 and 7. Loss of audit integrity MUST automatically place Levels 6 (Attack Detection) and 7 (Cross-Agent Trust) in a fail-closed state. Implementations MUST NOT operate Levels 6-7 features if the audit subsystem is non-functional.

### 6.3 Data Flow

```
Agent                    NL-Compliant System              Secret Store
  |                              |                             |
  |  1. Action Request           |                             |
  |  (template with {{nl:...}}) --->                           |
  |                              |                             |
  |                    2. Verify Agent Identity                 |
  |                    3. Evaluate Scope Grants                 |
  |                    4. Pre-Execution Defense                 |
  |                              |                             |
  |                              |  5. Resolve {{nl:...}}      |
  |                              | --------------------------> |
  |                              |  6. Return secret values    |
  |                              | <-------------------------- |
  |                              |                             |
  |                    7. Inject secrets into                   |
  |                       isolated subprocess                  |
  |                    8. Execute action                        |
  |                    9. Capture output                        |
  |                   10. Sanitize output                       |
  |                   11. Wipe secrets from memory              |
  |                   12. Write audit record                    |
  |                              |                             |
  | 13. Action Response          |                             |
  | (result only, no secrets) <--|                             |
  |                              |                             |
```

### 6.4 Multi-Agent Delegation Flow

```
Principal          Orchestrator Agent       Sub-Agent          NL System
    |                     |                     |                  |
    | Grant(scope=broad) -->                    |                  |
    |                     |                     |                  |
    |                     | DelegationToken     |                  |
    |                     | (scope=narrow,      |                  |
    |                     |  max_uses=1,        |                  |
    |                     |  ttl=5min)          |                  |
    |                     | ------------------> |                  |
    |                     |                     |                  |
    |                     |                     | Action Request   |
    |                     |                     | + DelegToken     |
    |                     |                     | ---------------> |
    |                     |                     |                  |
    |                     |                     |     Execute in   |
    |                     |                     |     isolation    |
    |                     |                     |                  |
    |                     |                     | Action Response  |
    |                     |                     | (result only)    |
    |                     |                     | <--------------- |
    |                     |                     |                  |
    |                     | Result              |                  |
    |                     | (no secrets)        |                  |
    |                     | <------------------ |                  |
    |                     |                     |                  |

  At NO point does the Orchestrator see the secrets used by the Sub-Agent.
  The DelegationToken grants scoped permission, not secret access.
```

---

## 7. Protocol Levels

The NL Protocol is structured as seven levels. Each level addresses a
distinct security concern. Levels are independent but complementary: an
implementation MAY adopt levels incrementally.

```
  LEVEL 7  Cross-Agent Trust & Federation
     |     Agents trust each other across organizations
     |     without sharing secrets
     |
  LEVEL 6  Attack Detection & Response
     |     Detect and respond to exfiltration attempts,
     |     prompt injection, and anomalous behavior
     |
  LEVEL 5  Audit & Integrity
     |     Immutable, hash-chained, HMAC-protected
     |     audit trail of every agent-secret interaction
     |
  LEVEL 4  Pre-Execution Defense
     |     Intercept and block dangerous actions before
     |     execution; deny rules, evasion detection
     |
  LEVEL 3  Execution Isolation                          <-- This document
     |     Secrets exist only inside isolated subprocess;      covers
     |     memory wipe, no core dumps, timeout                 Levels 1-3
     |
  LEVEL 2  Action-Based Access
     |     Agents request ACTIONS, not SECRETS;
     |     placeholder syntax, scope grants
     |
  LEVEL 1  Agent Identity
           Cryptographic identity, attestation, trust
           levels, lifecycle, capabilities
```

| Level | Specification | Summary |
|-------|--------------|---------|
| 1 | [01-agent-identity.md](01-agent-identity.md) | Agent identity, attestation, trust levels, lifecycle |
| 2 | [02-action-based-access.md](02-action-based-access.md) | Action types, placeholder syntax, scope grants, output sanitization |
| 3 | [03-execution-isolation.md](03-execution-isolation.md) | Process isolation, env var injection, memory protection, tempfile security |
| 4 | 04-pre-execution-defense.md | Command interception, deny rules, evasion detection |
| 5 | 05-audit-integrity.md | Hash-chained audit log, HMAC protection, tamper evidence |
| 6 | 06-attack-detection.md | Attack taxonomy, threat scoring, automated response |
| 7 | 07-cross-agent-trust.md | Delegation tokens, federation, result-only propagation |

---

## 8. Conformance Levels

Not every implementation needs to support all seven levels. The NL Protocol
defines three conformance tiers that allow incremental adoption:

### 8.1 Conformance Matrix

| Requirement | Basic | Standard | Advanced |
|-------------|:-----:|:--------:|:--------:|
| **Level 1:** Agent Identity | MUST | MUST | MUST |
| **Level 2:** Action-Based Access | MUST | MUST | MUST |
| **Level 3:** Execution Isolation | MUST | MUST | MUST |
| **Level 4:** Pre-Execution Defense | -- | MUST | MUST |
| **Level 5:** Audit & Integrity | -- | MUST | MUST |
| **Level 6:** Attack Detection & Response | -- | -- | MUST |
| **Level 7:** Cross-Agent Trust & Federation | -- | -- | MUST |
| **Attestation:** Vendor-signed JWTs | MAY | MUST | MUST |
| **Audit:** Hash-chain integrity | -- | MUST | MUST |
| **Delegation:** Scoped delegation tokens | -- | -- | MUST |

### 8.2 NL Protocol Basic (Levels 1-3)

**Requirements:** Levels 1, 2, 3 fully implemented.
**Verification:** Self-assessment + public conformance test suite.

Guarantees:
- Every agent has a unique, typed identity with scoped capabilities.
- Agents request actions via opaque handles; secret values never enter agent
  context.
- Secrets are resolved and consumed inside an isolated subprocess.
- Action output is sanitized before returning to the agent.

Target audience: individual developers, early-stage startups, open-source
projects.

### 8.3 NL Protocol Standard (Levels 1-5)

**Requirements:** Levels 1-5 fully implemented. Vendor attestation REQUIRED.
**Verification:** Automated conformance test suite + self-assessment report.

Additional guarantees (beyond Basic):
- Dangerous commands are intercepted and blocked before execution.
- Evasion attempts (encoding, subshell, variable expansion) are detected.
- Every action is recorded in an immutable, hash-chained audit trail.
- Audit integrity is cryptographically verifiable.

Target audience: teams of 5-50, startups with security requirements,
organizations adopting operational AI agents.

### 8.4 NL Protocol Advanced (Levels 1-7)

**Requirements:** Levels 1-7 fully implemented. Third-party certification
REQUIRED.
**Verification:** Automated test suite + independent security audit +
certification.

Additional guarantees (beyond Standard):
- Attacks are detected, classified, scored, and responded to automatically.
- Honeypot tokens detect exfiltration attempts.
- Agents can delegate scoped authority to sub-agents via delegation tokens.
- Cross-organization federation without secret exposure.
- Audit trails can be linked across organizations.

Target audience: enterprises with compliance requirements (SOC 2, ISO 27001),
organizations running autonomous agents in production, multi-organization
agent ecosystems.

---

## 9. Relationship to Existing Standards

The NL Protocol does not replace existing security standards. It complements
them by addressing the unique threat model of AI agents interacting with
secrets.

| Standard | Relationship to NL Protocol |
|----------|---------------------------|
| **OAuth 2.0** (RFC 6749) | OAuth authenticates users and authorizes applications. NL Protocol governs how an already-authenticated agent interacts with secrets. An NL-compliant system MAY use OAuth tokens as one form of agent credential, but the protocol's scope begins after authentication. |
| **Model Context Protocol (MCP)** | MCP defines how agents discover and invoke tools. NL Protocol defines how those tool invocations interact with secrets safely. An MCP server MAY implement the NL Protocol for its secret-dependent tools. The `{{nl:...}}` placeholder syntax is designed to coexist with MCP's tool parameter passing. An NL-compliant MCP server MUST NOT expose tools that return secret values (e.g., `vault_get_value`); it MUST only expose action-based tools (e.g., `vault_inject`). The MCP transport binding is defined in [Chapter 08](08-wire-protocol.md). An NL-compliant MCP server SHOULD expose public resources documenting the NL Protocol rules so that agents learn the protocol before authenticating. |
| **Agent2Agent Protocol (A2A)** | A2A defines inter-agent communication. NL Protocol's Level 7 (Cross-Agent Trust) complements A2A by ensuring that secrets never flow through inter-agent messages, only delegation tokens and results. |
| **SPIFFE/SPIRE** | SPIFFE defines workload identity (`spiffe://` URIs). NL Protocol's Agent URI (`nl://`) follows a similar pattern for agent identity. Implementations MAY bridge SPIFFE identities to NL Agent URIs. |
| **OWASP Top 10 for LLMs** | OWASP identifies risks (prompt injection, insecure output handling). NL Protocol provides specification-level mitigations for risks related to secret exposure specifically. |
| **OWASP Top 10 for MCP** (2025) | OWASP MCP01 (Token Mismanagement & Secret Exposure) is the #1 MCP vulnerability. NL Protocol directly addresses MCP01 through action-based access (Level 2): secrets never enter the agent context. Level 4 addresses MCP tool poisoning. Level 6 addresses rug-pull attacks where tools change behavior after initial approval. |
| **OWASP Top 10 for Agentic Applications** (2026) | NL Protocol mitigates Agent Goal Hijack (Level 4 pre-execution defense, Level 6 attack detection), Excessive Agency (Level 2 scope grants with least-privilege conditions), Tool Misuse (Level 4 command interception), and Rogue Agents (Level 1 identity with revocation, Level 6 anomaly detection). |
| **NIST AI RMF** | NIST provides a governance framework. NL Protocol provides implementable technical controls that map to NIST's governance categories. |
| **Zero Trust Architecture** (NIST 800-207) | NL Protocol applies zero-trust principles specifically to the agent-secret interaction boundary: never trust the agent's context, always verify at execution time. |
| **OpenTelemetry** | OpenTelemetry defines observability standards. NL Protocol's audit records (Level 5) MAY be exported in OpenTelemetry-compatible formats for integration with existing observability infrastructure. |

---

## 10. Version History

| Version | Date | Status | Changes |
|---------|------|--------|---------|
| 1.0.0-draft | 2026-02-08 | Draft | Initial specification covering all 7 levels. |

---

## 11. References

### Normative References

- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) -- Key words for use
  in RFCs to Indicate Requirement Levels
- [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519) -- JSON Web Token (JWT)
- [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515) -- JSON Web Signature (JWS)

### Informative References

- [SPIFFE](https://spiffe.io/) -- Secure Production Identity Framework for
  Everyone
- [Model Context Protocol](https://modelcontextprotocol.io/) -- Anthropic's
  protocol for agent-tool interaction
- [A2A Protocol](https://github.com/google/A2A) -- Google's Agent-to-Agent
  protocol
- [OAuth 2.0](https://www.rfc-editor.org/rfc/rfc6749) -- The OAuth 2.0
  Authorization Framework
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [OWASP Top 10 for MCP](https://owasp.org/www-project-mcp-top-10/) --
  Model Context Protocol security risks
- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) --
  Security risks in autonomous AI agent systems
- [NIST AI Risk Management Framework](https://www.nist.gov/artificial-intelligence/ai-risk-management-framework)
- [NIST SP 800-207](https://csrc.nist.gov/publications/detail/sp/800-207/final) --
  Zero Trust Architecture
- [OpenTelemetry](https://opentelemetry.io/) -- Observability framework

---

*Copyright 2026 Braincol. This specification is licensed under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).*
