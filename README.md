<p align="center">
  <a href="https://neverleakprotocol.org">
    <img src="website/public/favicon.svg" alt="Never-Leak Protocol" width="100" />
  </a>
</p>

<h1 align="center"><a href="https://neverleakprotocol.org">Never-Leak Protocol</a></h1>

<p align="center">
  <strong>The open standard for AI agent secret governance.</strong><br />
  <em>Agents request actions, not secrets.</em>
</p>

<p align="center">
  <a href="https://pypi.org/project/nl-protocol/"><img src="https://img.shields.io/pypi/v/nl-protocol?style=flat&label=pypi" alt="PyPI" /></a>
  &nbsp;
  <a href="https://neverleakprotocol.org"><img src="https://img.shields.io/badge/neverleakprotocol.org-059669?style=flat&logo=googlechrome&logoColor=white" alt="neverleakprotocol.org" /></a>
  &nbsp;
  <a href="specification/v1.0/"><img src="https://img.shields.io/badge/spec-v1.0-3b82f6?style=flat" alt="Specification v1.0" /></a>
  &nbsp;
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-6b7280?style=flat" alt="Apache 2.0" /></a>
</p>

<br />

<table>
<tr>
<td width="60" align="center">
  <a href="https://github.com/braincol/braincol-vault">
    <img src="website/public/braincol-vault.svg" alt="Braincol Vault" width="40" />
  </a>
</td>
<td>
  <strong>Looking for the implementation?</strong> <a href="https://github.com/braincol/braincol-vault"><strong>Braincol Vault</strong></a> is the first open-source implementation of the NL Protocol — a local-first secret manager with MCP server, so your AI agents can use secrets without ever seeing them. <strong>Available February 14, 2026.</strong>
</td>
</tr>
</table>

<br />

> **NL Protocol is a specification, not a product.** This repository contains
> the protocol definition, governance documents, and conformance requirements.
> For implementations, see [Implementations](#implementations).

---

## Install the Reference Implementation

The Python SDK implements all 7 security levels and is available on [PyPI](https://pypi.org/project/nl-protocol/):

```bash
pip install nl-protocol
```

---

## The Problem

AI agents are the most powerful development tool ever created — and the most dangerous secret-leaking vector the industry has ever seen.

Every major agent framework today shares the same flaw: **when an agent needs a secret, it reads that secret directly into the LLM context window.** From that moment, the plaintext travels to cloud providers, persists in logs, and sits exposed in memory.

This is not a bug — it's a structural flaw. The industry needs a **protocol** that redefines how agents interact with secrets.

```
TODAY:    Agent requests secret  →  receives plaintext  →  value enters LLM context  ⚠️
                                                           Visible to cloud provider,
                                                           stored in logs, impossible to revoke.

NL:       Agent requests ACTION  →  secret injected in    →  agent receives RESULT only  ✓
                                    isolated process          Secret never enters context.
```

**The core insight:** agents don't need secrets — they need the *results* of actions that use secrets.

---

## Seven Levels of Defense

Each level addresses a distinct attack surface. Adopt incrementally.

| Level | Name | What It Does |
|:-----:|------|-------------|
| **1** | **Agent Identity** | Cryptographic identity (JWT), agent URIs (`nl://vendor/agent/version`), trust levels L0–L3 |
| **2** | **Action-Based Access** | Agents request actions, not secrets. Opaque handles (`{{nl:...}}`), scoped grants, rotation propagation |
| **3** | **Execution Isolation** | Isolated subprocess execution, environment scrubbing, output sanitization, memory wipe |
| **4** | **Pre-Execution Defense** | Command interception, injection detection, exfiltration pattern matching |
| **5** | **Audit & Integrity** | SHA-256 hash-chained, HMAC-signed, tamper-evident audit records |
| **6** | **Attack Detection** | Behavioral anomaly detection, prompt injection detection, circuit breakers |
| **7** | **Cross-Agent Trust** | Delegation tokens, scope attenuation, result-only propagation across agent boundaries |

> **Level 2 is the core innovation.** Instead of "give me the database password," an agent requests "execute this SQL query against production." The secret is resolved and injected by a trusted layer the agent cannot observe.

---

## Conformance Tiers

| Tier | Levels | For |
|------|--------|-----|
| **Basic** | L1 – L3 | Individual developers, startups — *"My agent never sees my secrets"* |
| **Standard** | L1 – L5 | Engineering teams, SaaS — *"Auditable secret governance for our agents"* |
| **Advanced** | L1 – L7 | Enterprise, regulated industries — *"Full defense-in-depth with cross-agent trust"* |

---

## Quick Example

<table>
<tr>
<th>❌ How agents work today</th>
<th>✅ With NL Protocol</th>
</tr>
<tr>
<td>

```bash
# Secret enters LLM context
export API_KEY=$(vault get my-api-key)
curl -H "Authorization: Bearer $API_KEY" \
  https://api.example.com/data
# sk-live-abc123... now in context window
```

</td>
<td>

```json
{
  "type": "action_request",
  "agent_id": "nl://anthropic/claude-code/4.0.0",
  "action": {
    "type": "exec",
    "template": "curl -H 'Authorization: Bearer {{nl:api/API_KEY}}' https://api.example.com/data",
    "purpose": "Fetch data from API"
  }
}
```

</td>
</tr>
</table>

The system **verifies** identity → **resolves** the handle → **executes** in isolation → **sanitizes** output → **returns** only the result. The secret never enters the LLM context.

---

## Specification

The full technical specification — 9 chapters, covering all 7 levels plus wire protocol:

| # | Chapter | |
|:-:|---------|---|
| 00 | [Overview, Goals, Architecture](specification/v1.0/00-overview.md) | Design principles, conformance tiers, standards alignment |
| 01 | [Agent Identity](specification/v1.0/01-agent-identity.md) | AID schema, trust levels, lifecycle management |
| 02 | [Action-Based Access](specification/v1.0/02-action-based-access.md) | Action types, opaque handles, scope grants |
| 03 | [Execution Isolation](specification/v1.0/03-execution-isolation.md) | Subprocess isolation, scrubbing, sanitization |
| 04 | [Pre-Execution Defense](specification/v1.0/04-pre-execution-defense.md) | Injection detection, exfiltration matching |
| 05 | [Audit & Integrity](specification/v1.0/05-audit-integrity.md) | Hash chains, HMAC signatures, verification |
| 06 | [Attack Detection](specification/v1.0/06-attack-detection.md) | Anomaly detection, circuit breakers |
| 07 | [Cross-Agent Trust](specification/v1.0/07-cross-agent-trust.md) | Delegation tokens, federation |
| 08 | [Wire Protocol](specification/v1.0/08-wire-protocol.md) | JSON format, HTTP/stdio/WebSocket bindings |

---

## Standards Alignment

| Standard | Relationship |
|----------|-------------|
| **OWASP Top 10 for LLMs** | Mitigates Sensitive Information Disclosure (LLM06) |
| **OWASP Top 10 for MCP** | Addresses Token Mismanagement (MCP01) |
| **OWASP Top 10 for Agentic Apps** | Mitigates Agent Goal Hijack, Excessive Agency, Tool Misuse |
| **RFC 2119** | Requirement levels follow RFC 2119 semantics |
| **RFC 7519 (JWT)** | Agent attestation tokens use JWT format |
| **RFC 9180 (HPKE)** | Delegation token encryption (Level 7) |

---

## Implementations

| Name | Conformance | Language | Description |
|------|-------------|----------|-------------|
| [**NL Protocol Reference SDK**](reference/python/) | Advanced (L1-L7) | Python | Canonical reference implementation. 49 modules, 907 tests, full 7-level pipeline. |
| [**Braincol Vault**](https://github.com/braincol/braincol-vault) | Standard (L1-L5) | Python | Local-first secret manager with MCP server. Available February 14, 2026. |

NL Protocol is an open specification — anyone can build a conforming implementation.
See [IMPLEMENTATIONS.md](IMPLEMENTATIONS.md) for details and guidance.

---

## Contributing

Whether you're a security researcher, agent framework developer, or platform provider — contributions are welcome.

- **Specification feedback** → [Open an issue](https://github.com/braincol/never-leak-protocol/issues/new?template=spec_feedback.md)
- **Conformance tests** → Submit test cases that validate implementation correctness
- **Security vulnerabilities** → See [SECURITY.md](SECURITY.md) for responsible disclosure
- **Implementations** → Build one and submit to [IMPLEMENTATIONS.md](IMPLEMENTATIONS.md)

Please read the [Contributing Guidelines](CONTRIBUTING.md) and our [Code of Conduct](CODE_OF_CONDUCT.md) before submitting.

See [docs/governance/](docs/governance/) for the governance model.

---

## License

[Apache License 2.0](LICENSE) — free to implement, extend, and distribute in both open-source and commercial products.

---

<p align="center">
  <a href="https://braincol.com">
    <img src="website/public/braincol-logo.png" alt="Braincol" width="40" />
  </a><br />
  <sub>Created by <a href="https://braincol.com">Braincol</a></sub>
</p>
