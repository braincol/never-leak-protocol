# Changelog

All notable changes to the NL Protocol specification will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) for specification releases.

---

## [1.0.0-alpha] - 2026-02-09

### Specification

- NL Protocol specification v1.0 -- 9 chapters, 10,734 lines, 1,232 requirements covering all 7 defense levels plus wire protocol.
- **Chapter 00 -- Overview:** Design principles, conformance tiers, architecture, and standards alignment (OWASP, RFC 2119, RFC 7519).
- **Chapter 01 -- Agent Identity:** AID schema, agent URIs (`nl://vendor/agent/version`), trust levels L0-L3, lifecycle management.
- **Chapter 02 -- Action-Based Access:** Action types, opaque handles (`{{nl:...}}`), scoped grants, rotation propagation.
- **Chapter 03 -- Execution Isolation:** Subprocess isolation, environment scrubbing, output sanitization, memory wipe.
- **Chapter 04 -- Pre-Execution Defense:** Command interception, injection detection, exfiltration pattern matching.
- **Chapter 05 -- Audit & Integrity:** SHA-256 hash-chained, HMAC-signed, tamper-evident audit records.
- **Chapter 06 -- Attack Detection:** Behavioral anomaly detection, prompt injection detection, circuit breakers.
- **Chapter 07 -- Cross-Agent Trust:** Delegation tokens, scope attenuation, result-only propagation.
- **Chapter 08 -- Wire Protocol:** JSON message format, HTTP/stdio/WebSocket transport bindings.

### Reference Implementation (Python)

- Canonical Python SDK at `reference/python/` -- Advanced conformance (L1-L7).
- 49 source modules, ~11,100 lines of implementation.
- 907 tests (718 unit + 189 conformance), all passing.
- `NLProvider` orchestrator wiring all 7 security levels.
- Protocol-based interfaces with in-memory implementations for all 6 backend stores.
- 3 usage examples: quickstart, full 7-level pipeline, and attestation/lifecycle.

### Documentation

- Documentation website at [neverleakprotocol.org](https://neverleakprotocol.org).
- Developer Guide (`docs/adoption/DEVELOPER-GUIDE.md`).
- Platform Guide (`docs/adoption/PLATFORM-GUIDE.md`).
- Certification Program (`docs/governance/CERTIFICATION.md`).
- Community roadmap (`ROADMAP.md`).

---

<p align="center">
  <sub>NL Protocol is maintained by <a href="https://braincol.com">Braincol</a>.</sub>
</p>
