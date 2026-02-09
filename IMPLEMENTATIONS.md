# NL Protocol Implementations

NL Protocol is an **open specification** licensed under [Apache 2.0](LICENSE). Anyone can build a conforming implementation -- open-source or commercial -- without royalty or restriction, subject to the terms of the license.

This file lists known implementations that conform to (or are working toward conformance with) the NL Protocol specification. For the full protocol definition, see the [specification](specification/v1.0/) and the [README](README.md).

---

## Known Implementations

| Name | Maintainer | Conformance Level | Language | License | Link |
|---|---|---|---|---|---|
| [NL Protocol Reference SDK](reference/python/) | [Braincol](https://braincol.com) | Advanced (L1-L7) | Python | Apache 2.0 | [reference/python/](reference/python/) |
| [Braincol Vault](https://github.com/braincol/braincol-vault) | [Braincol](https://braincol.com) | Standard (L1-L5) | Python | Apache 2.0 + BSAL | [github.com/braincol/braincol-vault](https://github.com/braincol/braincol-vault) |

> **Note:** Conformance levels are defined in the [NL Protocol specification](specification/v1.0/). The three tiers are **Basic** (Levels 1--3), **Standard** (Levels 1--5), and **Advanced** (Levels 1--7). An entry marked "(target)" indicates the implementation is actively working toward that conformance level but has not yet completed formal conformance testing.

### NL Protocol Reference SDK

The [Reference SDK](reference/python/) is the canonical Python implementation of the NL Protocol, maintained alongside the specification in this repository. It implements all 7 security levels at **Advanced** conformance.

Current capabilities:

- **Advanced conformance (L1--L7)**: All 7 security levels fully integrated in the `NLProvider` orchestrator.
- **907 tests** (718 unit + 189 conformance) covering all levels.
- **49 source modules**, ~11,100 lines of implementation.
- **Protocol-based interfaces** (`SecretStore`, `AuditStore`, `AgentRegistry`, `ScopeGrantStore`, `NonceStore`, `DelegationStore`) with in-memory implementations for testing.
- **3 usage examples**: quickstart, full pipeline (7-level demo), and attestation/lifecycle.

### Braincol Vault

[Braincol Vault](https://github.com/braincol/braincol-vault) is a production implementation of the NL Protocol. The core is licensed under Apache 2.0; enterprise features are available under the Braincol Source-Available License (BSAL v1.0).

Current capabilities:

- **Standard conformance (L1--L5)**: Agent Identity, Action-Based Access, Execution Isolation, Pre-Execution Defense, and Audit Integrity.
- **MCP server** implementing the Opaque Proxy Pattern (agents interact with secrets through tool calls; secrets never enter agent context).
- **7 AI agent configurations** with ready-to-use instruction files for Claude Code, Cursor, Copilot, Codex, Windsurf, Aider, and a generic template.
- **1,051 tests** including 133 security-specific tests.
- **Interfaces:** CLI, REST API, Web Dashboard, and MCP Server.
- **Placeholder syntax:** `{{nl:...}}` (NL Protocol standard) and `{{vault:...}}` (Braincol Vault backward-compatible alias).

---

## Building Your Own Implementation

NL Protocol is designed to be platform-agnostic and implementation-independent. You are encouraged to build your own conforming implementation in any language, for any platform.

To get started:

- **Specification:** Read the full protocol definition in [`specification/v1.0/`](specification/v1.0/). This is the authoritative source for all protocol requirements, schemas, and behaviors.
- **Conformance Test Suite:** A conformance test suite with 189 tests is available at [`reference/python/conformance/`](reference/python/conformance/). It validates all MUST requirements across all 7 levels and wire protocol.
- **Certification Program:** A formal certification program for NL Protocol conformance is planned. Certified implementations will be listed with a verified conformance badge. Details will be published in this repository as the program launches.

The minimum bar for any NL Protocol implementation is **Basic** conformance (Levels 1--3): agent identity, action-based access with `{{nl:...}}` secret references, and execution isolation. An implementation that achieves Basic conformance can truthfully state: "Secrets never enter the LLM context."

---

## Submitting Your Implementation

If you have built an implementation that conforms to NL Protocol (at any conformance level), you can get it listed here by opening a pull request against this repository.

Your PR should:

1. Add a row to the **Known Implementations** table above with the following information:
   - **Name:** The name of your implementation (linked to its homepage or repository).
   - **Maintainer:** The person or organization maintaining the implementation.
   - **Conformance Level:** The conformance tier your implementation targets or has achieved (Basic, Standard, or Advanced). Append "(target)" if conformance testing is not yet complete.
   - **Language:** The primary implementation language.
   - **License:** The license under which your implementation is distributed.
   - **Link:** A direct link to the source repository or project page.

2. Include evidence of conformance (test results, self-assessment, or a description of which protocol levels are implemented) in the PR description.

For questions about conformance, the specification, or the submission process, open an issue in this repository or see [CONTRIBUTING.md](CONTRIBUTING.md).

---

<p align="center">
  <sub>NL Protocol is a specification, not a product. Implementations are maintained independently by their respective authors.</sub>
</p>
