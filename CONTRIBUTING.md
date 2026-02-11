# Contributing to NL Protocol

Thank you for your interest in contributing to the Never-Leak Protocol. Whether you are a security researcher, agent framework developer, platform provider, or community member, your contributions help strengthen the standard that keeps secrets out of AI agent context windows.

---

## Table of Contents

1. [Ways to Contribute](#ways-to-contribute)
2. [Getting Started](#getting-started)
3. [Contributing with AI Agents](#contributing-with-ai-agents)
4. [Specification Contributions](#specification-contributions)
5. [Conformance Test Contributions](#conformance-test-contributions)
6. [Website & Documentation](#website--documentation)
7. [Implementation Listings](#implementation-listings)
8. [Pull Request Process](#pull-request-process)
9. [Style Guide](#style-guide)
10. [Community](#community)

---

## Ways to Contribute

| Type | Description | Where |
|------|-------------|-------|
| **Specification feedback** | Report ambiguities, edge cases, or gaps in the spec | [Open an issue](https://github.com/braincol/never-leak-protocol/issues/new?template=spec_feedback.md) |
| **Security research** | Report attack vectors, threat model gaps, or vulnerabilities | See [SECURITY.md](SECURITY.md) |
| **Conformance tests** | Submit test cases that validate implementation correctness | `conformance/` directory |
| **Documentation** | Improve guides, fix typos, clarify explanations | `docs/` and `website/` |
| **Implementations** | Build an NL-conforming implementation and list it | [IMPLEMENTATIONS.md](IMPLEMENTATIONS.md) |
| **Proposals** | Propose new features or protocol extensions | `proposals/` directory |

---

## Getting Started

1. **Read the specification.** Start with [00-overview.md](specification/v1.0/00-overview.md) to understand the protocol architecture and design principles.

2. **Fork the repository.**

   ```bash
   git clone https://github.com/braincol/never-leak-protocol.git
   cd never-leak-protocol
   ```

3. **Create a branch** from `main` for your contribution.

   ```bash
   git checkout -b your-branch-name
   ```

4. **Make your changes**, following the guidelines below.

5. **Submit a pull request** against the `main` branch.

---

## Contributing with AI Agents

We welcome contributions made with the assistance of AI coding agents (Claude Code, Cursor, Copilot, Codex, Windsurf, Aider, and others). AI agents are powerful tools -- but unscoped agent contributions can overwhelm a project. To keep the quality bar high for everyone, follow these rules.

### Requirements for agent-assisted contributions

1. **An issue must exist first.** Every agent-assisted PR must reference an existing, open issue. Do not let an agent scan the repo and generate unsolicited changes. If you see something worth fixing, open an issue first, discuss it, and then use your agent to implement the agreed-upon change.

2. **One focused change per PR.** Agents are good at touching many files at once -- resist that urge. A PR that fixes a typo in Chapter 02 should not also "improve" the wording in Chapter 05. If the agent suggests additional changes, open separate issues for them.

3. **No unsolicited refactoring.** Do not submit PRs that "clean up" code, restructure documentation, rename files, add comments, or "improve readability" unless a maintainer has explicitly requested it in an issue. Drive-by improvements, no matter how well-intentioned, create review burden.

4. **No bulk or batch PRs.** Do not use agents to generate multiple PRs in quick succession. One PR at a time. Wait for review before submitting the next one.

5. **Human review before submission.** A human must review and understand every line of the PR before submitting. "My agent wrote it" is not a justification for incorrect or low-quality changes. You are responsible for what you submit.

6. **Disclose agent usage.** All agent-assisted PRs must check the "AI-assisted contribution" box in the pull request template and identify the agent used. This is not a penalty -- it helps reviewers calibrate their review.

### What agents should NOT do

| Action | Why |
|--------|-----|
| Scan the repo and open issues autonomously | Creates noise, duplicates, and low-quality issues |
| Submit spec changes without human judgment | RFC 2119 keywords require deliberate, contextual decisions |
| Rewrite sections "for clarity" without an issue | Subjective changes waste reviewer time |
| Add boilerplate (comments, docstrings, type hints) to files they did not modify | Adds noise to git history |
| Generate proposals without domain expertise | Protocol extensions require deep understanding of the threat model |
| Submit multiple PRs in parallel | Overwhelms the review queue |

### What agents CAN do well

- Fix specific, well-defined bugs referenced in an issue.
- Add conformance tests for a specific MUST requirement (referenced by spec section).
- Fix typos or broken links identified in an issue.
- Implement a clearly scoped proposal that has been approved by maintainers.
- Help draft documentation for a section that a maintainer has flagged as needing work.

### For agent developers

If you are building an agent that interacts with the NL Protocol repository, the documentation website provides machine-readable context at:

- `https://neverleakprotocol.org/llms.txt` -- project overview and structure.
- `https://neverleakprotocol.org/llms-full.txt` -- full specification content.

These files follow the [llms.txt](https://llmstxt.org/) convention. Use them to give your agent context about the protocol before contributing.

### Enforcement

PRs that do not follow these guidelines will be closed without review and tagged `agent-spam`. Repeated violations may result in the contributor being blocked from the repository. We value quality over quantity.

---

## Specification Contributions

The specification lives in `specification/v1.0/`. Changes to the spec have a high impact and require careful review.

### What makes a good spec contribution

- **Clarity improvements.** If a requirement is ambiguous, propose clearer language.
- **Edge cases.** If you identify a scenario the spec does not cover, document it and propose how the spec should handle it.
- **Security considerations.** If you find a gap in the threat model, describe the attack vector and propose a mitigation.
- **Alignment.** If the spec conflicts with or could better align with existing standards (OWASP, NIST, RFCs), propose the alignment.

### What to avoid

- Do not propose changes that break backwards compatibility without a compelling security reason.
- Do not add requirements that are implementation-specific rather than protocol-level.
- Do not remove MUST/REQUIRED provisions without a detailed justification.

### RFC 2119 keywords

The specification uses [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) keywords. When writing or modifying spec text:

- **MUST / REQUIRED / SHALL** -- absolute requirement.
- **SHOULD / RECOMMENDED** -- strong recommendation with valid exceptions.
- **MAY / OPTIONAL** -- truly optional behavior.

Use these keywords deliberately. Every MUST adds an implementation burden; every MAY creates interoperability risk.

---

## Conformance Test Contributions

Conformance tests live in `reference/python/conformance/` (189 tests covering all 7 levels + wire protocol). These tests validate that an implementation correctly follows the specification.

### Guidelines

- Each test should target a specific MUST or SHOULD requirement from the specification.
- Reference the specification section and requirement in the test description.
- Tests should be deterministic and reproducible.
- Include both positive tests (correct behavior) and negative tests (correct rejection of invalid input).

---

## Website & Documentation

The documentation website is built with [Astro](https://astro.build/) and lives in `website/`.

### Local development

```bash
cd website
npm install
npm run dev
```

The site will be available at `http://localhost:4321`.

### Documentation guidelines

- Write in clear, direct language.
- Use concrete examples over abstract descriptions.
- Keep paragraphs short.
- Use tables for structured comparisons.

---

## Implementation Listings

If you have built an NL Protocol-conforming implementation, you can submit it for listing in [IMPLEMENTATIONS.md](IMPLEMENTATIONS.md).

### Requirements for listing

1. The implementation must be publicly available (open source or commercial with public documentation).
2. The implementation must declare its conformance level (Basic, Standard, or Advanced).
3. The listing must include: name, conformance level, language, and a brief description.
4. The implementation should include documentation on how to run the conformance test suite against it.

Submit a pull request adding your implementation to the table in `IMPLEMENTATIONS.md`.

---

## Pull Request Process

1. **One concern per PR.** Keep pull requests focused on a single change. A spec clarification and a website fix should be separate PRs.

2. **Describe the change.** Use the pull request template. Explain *what* you changed and *why*.

3. **Reference issues.** If your PR addresses an open issue, reference it with `Closes #123` or `Relates to #123`.

4. **Expect review.** All contributions require review by at least one maintainer. Spec changes require review by at least two maintainers.

5. **Be responsive.** If reviewers request changes, address them promptly or explain why you disagree.

6. **Sign-off.** By submitting a pull request, you agree that your contribution is licensed under the [Apache License 2.0](LICENSE).

---

## Style Guide

### Markdown

- Use ATX-style headers (`#`, `##`, `###`).
- Use fenced code blocks with language identifiers.
- Use `|` tables for structured data.
- One sentence per line in specification text (for cleaner diffs).
- No trailing whitespace.

### Commit messages

- Use [Conventional Commits](https://www.conventionalcommits.org/) format.
- Prefix with scope when relevant: `spec`, `docs`, `website`, `conformance`.

  ```
  spec(L2): clarify opaque handle resolution order
  docs: fix typo in developer guide
  website: update hero section copy
  conformance: add L3 isolation boundary test
  ```

---

## Community

- **Issues** -- For questions, feedback, and discussion: [GitHub Issues](https://github.com/braincol/never-leak-protocol/issues)
- **Security** -- For vulnerability reports: see [SECURITY.md](SECURITY.md)
- **Governance** -- For certification and governance: see [docs/governance/](docs/governance/)

---

<p align="center">
  <sub>NL Protocol is maintained by <a href="https://braincol.com">Braincol</a>.</sub>
</p>
