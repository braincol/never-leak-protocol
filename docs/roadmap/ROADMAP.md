# NL Protocol Development Roadmap

**Last Updated:** 2026-02-09
**Status:** Active

---

## Vision

The Never-Leak Protocol will become the industry standard for secure secret governance in AI agent systems. This roadmap outlines the path from initial specification draft to a self-sustaining ecosystem of conforming implementations, certified platforms, and an independent governance body.

Each phase builds on the previous one. No phase is skipped. The protocol earns adoption through technical merit, not marketing -- every milestone listed here produces a concrete, testable artifact.

---

## Phase 1: Foundation (Q1-Q2 2026)

**Objective:** Publish a complete, implementable specification and prove it works with a reference implementation.

### Milestones

| # | Milestone | Target Date | Status |
|---|-----------|------------|--------|
| 1.1 | v1.0 specification published (Levels 1-7 + Wire Protocol) | 2026-02-09 | Complete |
| 1.2 | Reference implementation -- Advanced conformance (L1-L7) | 2026-02-09 | Complete |
| 1.3 | Conformance test suite -- Advanced level (L1-L7, 189 tests) | 2026-02-09 | Complete |
| 1.4 | IMPLEMENTATIONS.md with reference SDK + Braincol Vault | 2026-02-09 | Complete |
| 1.5 | Error codes specification (40+ codes, NL-E100 through NL-E806) | 2026-02-09 | Complete |
| 1.6 | Wire protocol / transport specification (Chapter 08) | 2026-02-09 | Complete |
| 1.7 | GitHub Discussions enabled for community feedback | 2026-02-15 | Planned |
| 1.8 | Community feedback period opens (60 days) | 2026-04-01 | Planned |
| 1.9 | First public demonstration (blog post + video walkthrough) | 2026-05-15 | Planned |

### Deliverables

- Complete specification documents for all seven levels + wire protocol (9 chapters, 10,734 lines, 1,232 requirements).
- Reference Python SDK with Advanced conformance (L1-L7) -- 49 modules, 907 tests.
- 40+ structured error codes (NL-E100 through NL-E806).
- Wire protocol / transport specification (Chapter 08) with NDJSON and HTTP bindings.
- Conformance test suite (189 tests) covering all MUST requirements across all 7 levels.
- Public GitHub repository with Issues, contribution guidelines, and documentation website.

### Success Metrics

| Metric | Target |
|--------|--------|
| Specification chapters complete | 9/9 (7 levels + overview + wire protocol) |
| Conformance tests passing (Advanced) | 189/189 (100%) |
| GitHub stars | 200+ |
| Community feedback submissions | 25+ issues or discussion threads |
| External contributors | 5+ |

---

## Phase 2: Validation (Q3-Q4 2026)

**Objective:** Validate the specification through community review, a second independent implementation, and a formal security audit. Produce a release candidate.

### Milestones

| # | Milestone | Target Date | Status |
|---|-----------|------------|--------|
| 2.1 | Community feedback period closes; triage complete | 2026-07-15 | Planned |
| 2.2 | Specification revisions incorporated | 2026-08-01 | Planned |
| 2.3 | v1.0-rc1 specification published | 2026-08-15 | Planned |
| 2.4 | Second independent implementation (community-driven) | 2026-09-15 | Planned |
| 2.5 | Conformance test suite -- Standard level (L1-L5) | 2026-09-15 | Planned |
| 2.6 | Security audit of specification (external firm) | 2026-10-31 | Planned |
| 2.7 | Outreach to agent providers initiated | 2026-08-01 | Planned |
| 2.8 | v1.0-rc2 specification (post-audit fixes) | 2026-12-01 | Planned |

### Deliverables

- Revised specification incorporating community and security audit feedback.
- At least two independent implementations passing Basic conformance tests (tracked in IMPLEMENTATIONS.md).
- Standard-level conformance test suite (L1-L5).
- Security audit report (published publicly).
- Formal outreach documents sent to Anthropic, OpenAI, Google DeepMind, and Microsoft.

### Success Metrics

| Metric | Target |
|--------|--------|
| Community feedback items resolved | 80%+ |
| Independent implementations (Basic conformance) | 2+ |
| Security audit critical findings | 0 unresolved |
| Agent provider conversations initiated | 3+ |
| Conformance tests (Standard level) | 100% passing on reference implementation |
| Contributors | 15+ |

---

## Phase 3: Standardization (2027 H1)

**Objective:** Finalize the v1.0 specification, begin the formal standards process, launch the certification program, and ship production-quality SDKs.

### Milestones

| # | Milestone | Target Date | Status |
|---|-----------|------------|--------|
| 3.1 | v1.0 final specification published | 2027-01-15 | Planned |
| 3.2 | IETF Internet-Draft submission (or Linux Foundation project proposal) | 2027-02-15 | Planned |
| 3.3 | Certification program launch (Basic + Standard) | 2027-03-01 | Planned |
| 3.4 | Protocol SDK -- Python | 2027-03-15 | Planned |
| 3.5 | Protocol SDK -- TypeScript | 2027-04-15 | Planned |
| 3.6 | Conformance test suite -- Advanced level (L1-L7) | 2027-05-01 | Planned |
| 3.7 | Multiple conforming implementations (3+) | 2027-05-15 | Planned |
| 3.8 | First certified platform announced | 2027-06-01 | Planned |
| 3.9 | v1.0.1 specification (errata and clarifications) | 2027-06-30 | Planned |

### Deliverables

- Final, stable v1.0 specification with no outstanding critical issues.
- IETF Internet-Draft or Linux Foundation project charter, initiating the formal standardization process.
- Operational certification program with self-assessment tooling, application portal, and review process.
- Production-quality Python and TypeScript protocol SDKs with pip/npm packages.
- Full conformance test suite covering all three levels (Basic, Standard, Advanced).
- At least three independent conforming implementations (tracked in IMPLEMENTATIONS.md).

### Success Metrics

| Metric | Target |
|--------|--------|
| Specification stability | No breaking changes after v1.0 final |
| Formal standards body engagement | Active Internet-Draft or LF project |
| Certified implementations | 1+ |
| SDK downloads (combined) | 1,000+ |
| Conforming implementations | 3+ |
| Agent providers with active integration plans | 1+ |
| GitHub stars | 2,000+ |

---

## Phase 4: Ecosystem (2027 H2 - 2028)

**Objective:** Grow the NL Protocol from a specification into a thriving ecosystem with cloud vendor integrations, a formal working group, and an independent governance foundation.

### Milestones

| # | Milestone | Target Date | Status |
|---|-----------|------------|--------|
| 4.1 | v1.1 specification (incorporating real-world learnings) | 2027-Q3 | Planned |
| 4.2 | First cloud vendor integration (NL-compatible action endpoints) | 2027-Q4 | Planned |
| 4.3 | Second cloud vendor integration | 2028-Q1 | Planned |
| 4.4 | NL Protocol Working Group formation | 2028-Q1 | Planned |
| 4.5 | Advanced certification (L1-L7) fully operational | 2028-Q1 | Planned |
| 4.6 | Third cloud vendor integration | 2028-Q2 | Planned |
| 4.7 | First Annual NL Protocol Summit | 2028-Q2 | Planned |
| 4.8 | Governance transition to independent foundation | 2028-Q3 | Planned |
| 4.9 | v1.2 specification planning begins | 2028-Q4 | Planned |

### Deliverables

- v1.1 specification addressing gaps discovered during production deployments.
- Native NL Protocol support in at least two major cloud platforms.
- NL Protocol Working Group with representatives from multiple organizations, operating under a published charter.
- Annual summit bringing together implementors, platform providers, security researchers, and agent framework developers.
- Independent foundation (or sub-foundation within an existing body such as the Linux Foundation) governing the protocol's future development.

### Success Metrics

| Metric | Target |
|--------|--------|
| Cloud vendor integrations | 2+ |
| Agent frameworks with native NL support | 2+ |
| Certified implementations | 10+ |
| Working Group member organizations | 5+ |
| Summit attendees | 100+ |
| SDK downloads (combined, cumulative) | 25,000+ |
| Production deployments using NL Protocol | 100+ |
| Foundation governance operational | Yes |

---

## How to Contribute to the Roadmap

This roadmap is a living document. If you believe a milestone is missing, a target is unrealistic, or a phase should be restructured, open an issue or start a GitHub Discussion.

Contributions that directly advance roadmap milestones:

- **Specification feedback**: Open an issue tagged `spec-feedback` during the community feedback period.
- **New implementation**: Build an independent NL Protocol implementation and submit it for conformance testing and inclusion in IMPLEMENTATIONS.md.
- **Security review**: Review the specification for vulnerabilities and submit findings.
- **SDK contributions**: Contribute to the Python or TypeScript protocol SDK development.
- **Platform integration**: If you work at a cloud vendor or agent framework company, reach out to discuss integration.

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for detailed contribution guidelines.

---

## Roadmap Changelog

| Date | Change |
|------|--------|
| 2026-02-08 | Initial roadmap published. |
| 2026-02-08 | Adjusted timelines for realism; replaced product-specific references with protocol-generic language; added spec milestones (Appendix A, Chapter 08, IMPLEMENTATIONS.md); made success metrics more conservative. |
| 2026-02-09 | Updated Phase 1 milestones 1.1-1.6 to Complete. Spec v1.0 finalized (9 chapters, 10,734 lines). Reference Python SDK at Advanced conformance (907 tests). |

---

<p align="center">
  <sub>The best time to fix secret leakage was before agents existed. The second best time is now.</sub>
</p>
