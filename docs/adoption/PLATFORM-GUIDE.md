# How to Implement the NL Protocol

> **Disclaimer:** This guide describes how platform providers can implement the NL Protocol specification. It is implementation-agnostic. Examples use the protocol's Action Request JSON format, not any specific CLI or product. For a list of known implementations, see [IMPLEMENTATIONS.md](../IMPLEMENTATIONS.md).

**Audience:** Platform providers -- cloud vendors, API platforms, secret managers, and agent frameworks.

**Last Updated:** 2026-02-08

---

## Table of Contents

1. [Why Implement NL Protocol](#1-why-implement-nl-protocol)
2. [Conformance Levels](#2-conformance-levels)
3. [Implementation Checklist](#3-implementation-checklist)
4. [Integration Patterns](#4-integration-patterns)
5. [Example: Stripe Implementing NL Protocol](#5-example-stripe-implementing-nl-protocol)
6. [Example: AWS Implementing NL Protocol](#6-example-aws-implementing-nl-protocol)
7. [Certification Process](#7-certification-process)

---

## 1. Why Implement NL Protocol

Every day, AI agents access your platform using credentials that sit exposed in LLM context windows. Your customers' API keys are being sent to cloud inference providers, persisted in conversation logs, and stored in memory alongside untrusted prompt content. This is not a theoretical risk -- it is the default behavior of every major agent framework today.

Implementing the NL Protocol eliminates this exposure for your customers. Here is why it matters to your business.

### Customer Demand

Security-conscious customers are already asking how to use AI agents without exposing credentials. Enterprises with SOC 2, PCI DSS, and ISO 27001 requirements cannot adopt agent workflows that put secrets in LLM context windows. NL Protocol gives these customers a compliant path to agent adoption -- on your platform.

### Compliance Advantage

Regulatory frameworks increasingly require demonstrable control over credential access. NL Protocol provides:

- Auditable proof that secrets never enter agent context.
- Cryptographically signed audit trails for every action.
- Fine-grained access control that maps cleanly to compliance requirements.

Platforms that implement NL Protocol can offer their customers compliance-ready agent integration out of the box.

### Competitive Differentiation

The first platforms to support NL Protocol will be the default choice for organizations deploying AI agents in production. In a market where every competitor's agent integration has the same secret-leakage vulnerability, NL Protocol conformance is a clear differentiator.

### Ecosystem Network Effects

NL Protocol is an open standard. Every platform that adopts it makes the protocol more valuable for every other platform. An agent that can securely interact with Stripe through NL Protocol can also securely interact with AWS, GitHub, and any other conforming platform -- without the developer changing anything. Adoption compounds.

---

## 2. Conformance Levels

NL Protocol defines three conformance levels. Each level adds additional security capabilities on top of the previous one.

### Basic (Levels 1-3)

The minimum bar. An implementation at Basic conformance ensures that **secrets never enter the agent's LLM context**.

| Requirement | What It Means for Your Platform |
|-------------|-------------------------------|
| **L1: Agent Identity** | Your platform can identify and authenticate the agent making requests. You know *who* is acting. |
| **L2: Action-Based Access** | Agents request actions (e.g., "charge this customer"), not secrets (e.g., "give me the API key"). Your platform resolves credentials internally. |
| **L3: Execution Isolation** | Actions execute in an environment isolated from the agent's context. Secrets are injected at runtime and never returned to the agent. |

**Target audience:** Startups, developer tools, platforms wanting a fast path to NL Protocol support.

### Standard (Levels 1-5)

Adds auditability and pre-execution defense. Required for platforms serving regulated industries.

| Additional Requirement | What It Means for Your Platform |
|-----------------------|-------------------------------|
| **L4: Pre-Execution Defense** | Your platform inspects action requests for injection attacks, exfiltration patterns, and policy violations before execution. |
| **L5: Audit & Integrity** | Every action produces a tamper-evident, cryptographically chained audit record. Your customers can prove exactly what agents did. |

**Target audience:** SaaS platforms, fintech, healthtech, any platform where customers need audit trails.

### Advanced (Levels 1-7)

The full specification. Required for platforms operating in multi-agent environments.

| Additional Requirement | What It Means for Your Platform |
|-----------------------|-------------------------------|
| **L6: Attack Detection** | Your platform detects anomalous agent behavior in real time and can revoke sessions or rotate credentials automatically. |
| **L7: Cross-Agent Trust** | Your platform supports secure delegation between agents, including agents on different platforms, with trust attenuation. |

**Target audience:** Enterprises, multi-agent orchestration platforms, cloud providers serving large organizations.

---

## 3. Implementation Checklist

Use these checklists to track your progress toward each conformance level.

### Basic Conformance Checklist

- [ ] **Agent Identity (L1)**
  - [ ] Accept and validate Agent Identity Documents (AIDs) in requests.
  - [ ] Verify AID attestation signatures against known issuers.
  - [ ] Check AID validity period and revocation status.
  - [ ] Reject requests from agents with invalid or expired AIDs.
  - [ ] Log the agent ID for every request.

- [ ] **Action-Based Access (L2)**
  - [ ] Define an action manifest listing operations agents can perform on your platform.
  - [ ] Accept action requests (not credential requests) from agents.
  - [ ] Implement scope evaluation: check granted actions, resource constraints, and time windows.
  - [ ] Enforce deny-by-default: reject any action not explicitly permitted by an active scope.
  - [ ] Support secret reference syntax (`{{nl:path/SECRET_NAME}}`) in action templates.

- [ ] **Execution Isolation (L3)**
  - [ ] Execute actions in an isolated environment (separate process, container, or serverless function).
  - [ ] Inject secrets as environment variables within the isolated environment only.
  - [ ] Strip secrets from the environment after execution completes.
  - [ ] Sanitize action output to detect and remove accidentally leaked secret values.
  - [ ] Return only the action result to the agent -- never the secret itself.

### Standard Conformance Checklist (in addition to Basic)

- [ ] **Pre-Execution Defense (L4)**
  - [ ] Inspect action requests for command injection patterns.
  - [ ] Detect exfiltration attempts (base64-encoded secrets, DNS tunneling, data in URL parameters).
  - [ ] Validate action requests against the agent's authorized action set.
  - [ ] Reject requests that fail any defense check, with a descriptive error (no secret values in error messages).

- [ ] **Audit & Integrity (L5)**
  - [ ] Generate a structured audit record for every action execution.
  - [ ] Include agent ID, action, resource, timestamp, authorization decision, and result status in each record.
  - [ ] Sign each audit record cryptographically.
  - [ ] Chain audit records so that tampering with any record invalidates the chain.
  - [ ] Provide an API or export mechanism for customers to retrieve their audit records.

### Advanced Conformance Checklist (in addition to Standard)

- [ ] **Attack Detection (L6)**
  - [ ] Monitor agent behavior for anomalies (unusual action patterns, frequency spikes, out-of-scope access attempts).
  - [ ] Implement automated responses: session revocation, credential rotation, operator alerting.
  - [ ] Support circuit breaker patterns to halt agent sessions on high-confidence attack signals.

- [ ] **Cross-Agent Trust (L7)**
  - [ ] Support trust delegation tokens with scope attenuation.
  - [ ] Validate delegation chains and enforce maximum depth limits.
  - [ ] Enable cross-platform federation: accept delegated trust from agents on other NL-conforming platforms.
  - [ ] Automatically revoke derived scopes when parent scopes are revoked.

---

## 4. Integration Patterns

There are three primary patterns for integrating the NL Protocol into your platform, depending on how agents interact with you.

### 4.1 MCP Server Pattern

**For:** Platforms that expose tools to AI agents via the Model Context Protocol (MCP).

In this pattern, your platform provides an MCP server that agents connect to. Instead of returning secrets through MCP tool responses, the server accepts action requests and resolves secrets internally.

```
Agent (MCP Client)                    Your Platform (MCP Server)
       |                                        |
       |--- action_request(charge_customer) --->|
       |                                        |-- resolve secret internally
       |                                        |-- execute charge
       |<-- action_result(success, receipt) ----|
       |                                        |
       |  Secret never leaves your server.      |
```

**Implementation notes:**

- Define your MCP tools as NL Protocol actions, not credential-returning endpoints.
- Use the NL action manifest format to declare what operations are available.
- Validate the agent's AID before processing any tool call.
- Return structured results, never raw credentials.

### 4.2 REST API Pattern

**For:** Cloud vendors and API platforms that expose HTTP endpoints.

In this pattern, your platform exposes NL-compatible REST endpoints that accept action requests. The agent sends a structured action request; your API resolves the credential and executes the operation.

```
Agent                                 Your Platform (REST API)
  |                                        |
  |--- POST /nl/actions/s3.upload -------->|
  |    {                                   |
  |      "agentId": "nl://...",           |
  |      "params": {                       |-- resolve IAM role
  |        "bucket": "my-bucket",          |-- execute S3 upload
  |        "key": "report.pdf",            |
  |        "body": "<base64>"              |
  |      },                                |
  |      "signature": "..."                |
  |    }                                   |
  |<--- 200 { "result": "uploaded" } ------|
  |                                        |
  |  Credential resolved via IAM role.     |
  |  Agent never sees AWS_SECRET_ACCESS_KEY.|
```

**Implementation notes:**

- Add an `/nl/actions/` endpoint namespace to your existing API.
- Accept AID-signed requests. Verify identity before execution.
- Map NL actions to your internal API operations.
- Issue scoped action tokens instead of long-lived API keys.

### 4.3 SDK Pattern

**For:** Client libraries that developers use in their applications.

In this pattern, your SDK handles secret resolution transparently. The developer configures the SDK with a secret reference (not a plaintext secret), and the SDK resolves it at runtime through an NL-compatible vault.

```python
# OLD: Secret in code, exposed to any agent that reads this file.
import stripe
stripe.api_key = "sk_live_abc123..."

# NL PROTOCOL: Secret reference, resolved at runtime.
import stripe
from nl_protocol import SecretRef

stripe.api_key = SecretRef("{{nl:stripe/API_KEY}}")
# The SDK resolves this through an NL-compliant vault at call time.
# The plaintext key never appears in source code, logs, or agent context.
# See IMPLEMENTATIONS.md for available NL Protocol libraries.
```

**Implementation notes:**

- Accept `SecretRef` objects wherever your SDK currently accepts string credentials.
- Resolve secret references at the moment of use, not at configuration time.
- Ensure resolved secrets are held only in memory for the duration of the API call.
- Never log, serialize, or return resolved secret values.

---

## 5. Example: Stripe Implementing NL Protocol

### The Problem Today

When an AI agent needs to process a payment through Stripe, it reads the Stripe secret key into its context:

```bash
# Agent reads the Stripe key from the environment or a vault.
export STRIPE_KEY=$(vault get stripe/secret_key)
# STRIPE_KEY = "sk_live_abc123def456..."
# This value is now in the LLM context window.
# It has been sent to the inference provider.
# It may appear in logs and conversation history.

curl https://api.stripe.com/v1/charges \
  -u "$STRIPE_KEY:" \
  -d amount=2000 \
  -d currency=usd \
  -d customer=cus_ABC123
```

The agent now possesses the full secret key. It could inadvertently leak it in a response, a log, or a subsequent API call to a different service.

### The NL Protocol Solution

With NL Protocol, the agent requests an *action*, not a secret. The agent submits a structured Action Request:

```json
{
  "action": "api.charges.create",
  "agentId": "nl://com.acme/agents/billing-bot",
  "params": {
    "amount": 2000,
    "currency": "usd",
    "customer": "cus_ABC123"
  },
  "secretRefs": {
    "apiKey": "{{nl:stripe/SECRET_KEY}}"
  },
  "scope": "scope-abc-123",
  "signature": "MEQCIG...base64..."
}
```

The NL-compliant implementation:

1. Validates the agent's identity and scope.
2. Resolves `{{nl:stripe/SECRET_KEY}}` from the configured vault.
3. Executes the Stripe API call in an isolated environment, injecting the secret at runtime.
4. Returns only the result to the agent. The secret value never enters the agent's context.

```json
{
  "result": {
    "id": "ch_1ABC",
    "amount": 2000,
    "currency": "usd",
    "status": "succeeded"
  }
}
```

### What Stripe Would Build

To natively support NL Protocol, Stripe would:

1. **Publish an NL action manifest** defining permitted operations:

```json
{
  "platform": "stripe",
  "version": "2026-02-08",
  "actions": [
    {
      "action": "api.charges.create",
      "description": "Create a new charge",
      "parameters": {
        "amount": { "type": "integer", "required": true },
        "currency": { "type": "string", "required": true },
        "customer": { "type": "string", "required": true }
      }
    },
    {
      "action": "api.customers.retrieve",
      "description": "Retrieve a customer by ID",
      "parameters": {
        "customer_id": { "type": "string", "required": true }
      }
    }
  ]
}
```

2. **Expose NL-compatible endpoints** that accept action requests:

```
POST /nl/actions/api.charges.create
{
  "agentId": "nl://com.acme/agents/billing-bot",
  "params": { "amount": 2000, "currency": "usd", "customer": "cus_ABC123" },
  "scope": "scope-abc-123",
  "signature": "MEQCIG...base64..."
}
```

3. **Resolve the credential internally.** The Stripe backend maps the authenticated action request to the merchant's API key via their existing authentication infrastructure. The agent never touches `sk_live_*`.

4. **Return only the result:**

```json
{
  "result": {
    "id": "ch_1ABC",
    "amount": 2000,
    "currency": "usd",
    "status": "succeeded"
  }
}
```

### Business Impact for Stripe

- Enterprise customers can deploy AI billing agents without exposing Stripe keys.
- Reduced credential leakage incidents (fewer support tickets, fewer emergency rotations).
- Compliance teams can approve agent-based workflows because audit trails prove secrets stayed internal.
- Competitive advantage: "The only payment platform where AI agents never see your keys."

---

## 6. Example: AWS Implementing NL Protocol

### The Problem Today

When an AI agent needs to upload a file to S3, the agent reads AWS credentials:

```bash
# Agent reads AWS credentials.
export AWS_ACCESS_KEY_ID=$(vault get aws/access_key)
export AWS_SECRET_ACCESS_KEY=$(vault get aws/secret_key)
# Both values are now in the LLM context window.

aws s3 cp report.pdf s3://my-bucket/reports/report.pdf
```

The agent now holds long-lived AWS credentials in its context. These credentials typically have broad permissions. A single exfiltration event compromises the entire AWS account.

### The NL Protocol Solution

The agent submits a structured Action Request instead of handling credentials directly:

```json
{
  "action": "s3.object.upload",
  "agentId": "nl://com.acme/agents/report-generator",
  "params": {
    "bucket": "my-bucket",
    "key": "reports/report.pdf",
    "body": "<base64-encoded content>"
  },
  "secretRefs": {
    "accessKey": "{{nl:aws/ACCESS_KEY}}",
    "secretKey": "{{nl:aws/SECRET_KEY}}"
  },
  "scope": "scope-xyz-789",
  "signature": "MEQCIG...base64..."
}
```

The NL-compliant implementation:

1. Validates the agent's identity and scope.
2. Resolves both secret references from the configured vault.
3. Injects credentials into an isolated execution environment.
4. Executes the S3 upload operation.
5. Returns only the result to the agent.
6. Scrubs all secret material from the environment after execution.

```json
{
  "result": {
    "status": "uploaded",
    "bucket": "my-bucket",
    "key": "reports/report.pdf",
    "etag": "\"d41d8cd98f00b204e9800998ecf8427e\""
  }
}
```

### What AWS Would Build

For native NL Protocol support, AWS would:

1. **Define NL action manifests** for core services:

```json
{
  "platform": "aws",
  "service": "s3",
  "actions": [
    {
      "action": "s3.object.upload",
      "description": "Upload an object to S3",
      "parameters": {
        "bucket": { "type": "string", "required": true },
        "key": { "type": "string", "required": true },
        "body": { "type": "binary", "required": true }
      }
    },
    {
      "action": "s3.object.download",
      "description": "Download an object from S3",
      "parameters": {
        "bucket": { "type": "string", "required": true },
        "key": { "type": "string", "required": true }
      }
    }
  ]
}
```

2. **Expose NL action endpoints** that resolve credentials via IAM roles:

```
POST /nl/actions/s3.object.upload
{
  "agentId": "nl://com.acme/agents/report-generator",
  "params": { "bucket": "my-bucket", "key": "reports/report.pdf", "body": "<base64>" },
  "roleArn": "arn:aws:iam::123456789:role/nl-agent-upload",
  "signature": "MEQCIG...base64..."
}
```

3. **Resolve credentials internally.** AWS assumes the specified IAM role, generates short-lived STS credentials, executes the S3 operation, and returns only the result. The agent never sees `AWS_SECRET_ACCESS_KEY`.

4. **Leverage existing IAM infrastructure.** NL Protocol maps naturally to AWS IAM roles and policies. The IAM policy attached to the role defines exactly what the agent can do -- no broader access is possible.

### Business Impact for AWS

- Customers can deploy AI agents in AWS environments without distributing long-lived access keys.
- IAM role-based credential resolution aligns with AWS's existing security model.
- Reduced blast radius from agent compromise: credentials are short-lived and scoped to the specific action.
- Enterprise customers with strict compliance requirements can adopt agent workflows.

---

## 7. Certification Process

Platforms that implement NL Protocol can be officially certified, demonstrating to customers that their integration has been independently verified.

### Steps to Certification

1. **Choose your target conformance level** (Basic, Standard, or Advanced).

2. **Implement the requirements** using the checklists in Section 3.

3. **Run the conformance test suite.** The NL Protocol project provides an open-source test suite that validates each level. Run it against your implementation and collect the results.

```bash
# Example: Run Basic conformance tests against your platform.
nl-conformance test --level basic --target https://your-platform.com/nl/
```

4. **Submit your application.** Provide:
   - Conformance test results (automated report from the test suite).
   - Architecture documentation describing how your platform implements each required level.
   - Contact information for the engineering team responsible for the integration.

5. **Review.** NL Protocol maintainers review your submission. They may request additional information, run supplementary tests, or ask for clarifications. The review process targets a 30-day turnaround.

6. **Certification issued.** Upon successful review:
   - You receive the "NL Protocol Certified" badge for your conformance level.
   - Your platform is listed in the official NL Protocol certified directory.
   - The certificate is valid for one year from the date of issue.

7. **Annual renewal.** Re-run the conformance tests annually and submit updated results. If the specification has been updated, you may need to implement new requirements to maintain certification.

### Certification Levels and Badges

| Level | Badge | Meaning |
|-------|-------|---------|
| Basic | NL Protocol Certified -- Basic | Secrets never enter agent context. Agent identity verified. Execution isolated. |
| Standard | NL Protocol Certified -- Standard | Basic + pre-execution defense + tamper-evident audit trail. |
| Advanced | NL Protocol Certified -- Advanced | Full specification compliance including attack detection and cross-agent trust. |

### For More Information

See [CERTIFICATION.md](../governance/CERTIFICATION.md) for the complete certification program details, including pricing and the process for agent providers.

---

<p align="center">
  <sub>Your platform holds your customers' secrets. NL Protocol ensures AI agents never do.</sub>
</p>
