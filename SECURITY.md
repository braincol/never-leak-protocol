# Security Policy

The NL Protocol is a security specification. We take security issues in the protocol itself, the conformance test suite, and the documentation website seriously.

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please report vulnerabilities via one of the following channels:

- **Email:** [security@braincol.com](mailto:security@braincol.com)
- **GitHub Security Advisories:** [Report a vulnerability](https://github.com/braincol/never-leak-protocol/security/advisories/new)

### What to include

- A description of the vulnerability and its potential impact.
- Steps to reproduce, if applicable.
- The specification section(s) affected (e.g., "Level 2, Section 2.3.4 -- Opaque Handle Resolution").
- Your assessment of severity (Critical, High, Medium, Low).
- Any suggested mitigation or fix.

### What to expect

| Step | Timeline |
|------|----------|
| Acknowledgment of your report | Within **48 hours** |
| Initial assessment and severity classification | Within **5 business days** |
| Resolution or mitigation plan communicated to you | Within **30 calendar days** |
| Public disclosure (coordinated with reporter) | After fix is published |

We follow coordinated disclosure. We will work with you on timing and credit.

---

## Scope

### In scope

- **Specification vulnerabilities.** Flaws in the protocol design that could allow an attacker to extract secrets from an NL-conforming implementation.
- **Threat model gaps.** Attack vectors not addressed by the specification's seven defense levels.
- **Conformance test suite issues.** Tests that incorrectly validate insecure behavior or fail to detect non-conformance.
- **Website vulnerabilities.** Security issues in the NL Protocol documentation website (XSS, injection, etc.).

### Out of scope

- **Vulnerabilities in specific implementations.** If you find a vulnerability in an implementation (e.g., Braincol Vault), report it to that project's security contact, not here.
- **Social engineering or phishing attacks** against maintainers or contributors.
- **Denial of service** against project infrastructure.

---

## Specification Security Considerations

The NL Protocol specification includes security considerations in each chapter. Key areas of focus:

| Level | Primary Security Concern |
|-------|------------------------|
| L1 -- Agent Identity | Identity spoofing, token forgery, trust level escalation |
| L2 -- Action-Based Access | Handle prediction, scope escalation, unauthorized action execution |
| L3 -- Execution Isolation | Isolation escape, environment leakage, output contamination |
| L4 -- Pre-Execution Defense | Injection bypass, exfiltration pattern evasion |
| L5 -- Audit & Integrity | Audit log tampering, hash chain manipulation |
| L6 -- Attack Detection | Detection evasion, false positive flooding |
| L7 -- Cross-Agent Trust | Delegation token forgery, scope amplification, federation trust abuse |

If you discover a vulnerability that crosses multiple levels, note all affected levels in your report.

---

## Recognition

We maintain a security acknowledgments section for researchers who responsibly disclose vulnerabilities. If you would like to be credited, let us know in your report.

---

<p align="center">
  <sub>NL Protocol is maintained by <a href="https://braincol.com">Braincol</a>.</sub>
</p>
