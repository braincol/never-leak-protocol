# NL Protocol Specification v1.0 -- Chapter 05: Audit Integrity

**Status:** 1.0
**Version:** 1.0.0
**Date:** 2026-02-08

> **Note:** This document is a SPECIFICATION. It defines required behaviors,
> data formats, and protocols — not specific products or CLI commands.
> For implementations of this specification, see [IMPLEMENTATIONS.md](../../IMPLEMENTATIONS.md).

## 1. Introduction

This chapter defines the Audit Integrity layer of the NL Protocol. Every interaction between an agent and a secret -- whether the interaction succeeds, is denied, or is blocked -- MUST produce a tamper-evident audit record. The audit trail provides the cryptographic proof required to answer four fundamental questions:

1. **What did Agent X do?** (agent attribution)
2. **Who accessed Secret Y?** (secret access history)
3. **What happened between T1 and T2?** (temporal analysis)
4. **Can I prove this log has not been tampered with?** (integrity verification)

The audit trail is the foundation for compliance, forensic analysis, and anomaly detection. If an attacker can modify, delete, or reorder audit records undetected, every other security layer becomes unverifiable. The hash chain defined in this chapter ensures that any tampering is mathematically detectable.

### 1.1 Critical Constraint: No Secret Values in Audit Records

Secret VALUES MUST NEVER appear in audit entries -- not in plaintext, not encoded, not hashed in a way that is reversible or subject to brute-force. Audit entries record WHAT was done (the action), TO WHAT (the secret's name or reference), and BY WHOM (the agent), but NEVER the secret's content. If audit records contained secret values, the audit log itself would become an exfiltration vector.

### 1.2 Multi-Platform Scope

The audit schema and integrity mechanisms defined in this chapter are designed to be implementable across any platform:

- Local vaults (file-based, SQLite-based)
- Cloud secret managers (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault)
- SaaS platforms (Stripe, GitHub, Twilio)
- CI/CD systems (GitHub Actions, GitLab CI, Jenkins)
- Custom agent orchestration frameworks

Each platform produces audit entries in the schema defined here. Cross-platform correlation is achieved through shared `correlation_id` values (Section 8).

## 2. Audit Entry Schema

### 2.1 Required Fields

Every audit entry MUST contain the following fields:

```json
{
  "entry_id": "01953f2a-7b3c-7def-8a12-4b5c6d7e8f90",
  "sequence": 1,
  "timestamp": "2026-02-08T10:30:00.000Z",
  "nl_version": "1.0",
  "agent": {
    "uri": "nl://anthropic.com/claude-code/1.5.2",
    "organization_id": "org_example",
    "session_id": "session_abc123"
  },
  "delegated_by": "human:admin@example.com",
  "action": "exec",
  "target": "api/API_KEY",
  "result": "success",
  "secrets_used": ["api/API_KEY"],
  "correlation_id": "req-abc-123",
  "platform": "acme-secrets",
  "chain": {
    "prev_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    "hash": "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    "hmac": "sha256:f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5"
  }
}
```

### 2.2 Field Definitions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `entry_id` | string | MUST | A globally unique identifier. UUID v7 is RECOMMENDED for time-ordered uniqueness. |
| `sequence` | integer | MUST | A monotonically increasing integer starting at 1. Each new entry MUST have a sequence number exactly one greater than the previous entry. Gaps indicate deletion. |
| `timestamp` | string | MUST | ISO 8601 timestamp with millisecond precision and UTC timezone (e.g., `2026-02-08T10:30:00.000Z`). Implementations MUST use synchronized time sources (NTP). See Clock Requirements below. |
| `nl_version` | string | MUST | The version of the NL Protocol specification this entry conforms to (e.g., `"1.0"`). |
| `agent` | object | MUST | The agent that performed the action. See Section 2.3. |
| `delegated_by` | string | MUST | The principal (human or agent) who authorized the agent to act. Format: `human:<email>` or `agent:<agent_uri>`. |
| `action` | string | MUST | The action type performed. One of: `exec`, `template`, `inject_stdin`, `inject_tempfile`, `list`, `search`, `create`, `update`, `delete`, `rotate`, `blocked`, `denied`, `verify`. |
| `target` | string | MUST | The secret reference or resource that was the target of the action. MUST be the secret's name or path, NEVER its value. Format: `<name>` or `<category>/<name>` or `<project>/<environment>/<name>`. |
| `result` | string | MUST | The outcome. One of: `success`, `denied`, `blocked`, `error`, `timeout`. |
| `secrets_used` | string[] | MUST | List of secret references used in this action. MUST contain only names or paths, NEVER values. Empty array `[]` for actions that do not involve secrets. |
| `correlation_id` | string | MUST | A unique identifier linking related actions across platforms and systems. Used for cross-platform tracing. |
| `platform` | string | MUST | The platform or system that produced this audit entry (e.g., `acme-vault`, `aws-secrets-manager`, `braincol-vault`, `stripe-proxy`). |
| `chain` | object | MUST | Hash chain integrity data. See Section 3. |

**Clock Requirements:**
1. Audit record timestamps MUST use UTC wall clock time in ISO 8601 format
2. The `sequence` field MUST be a monotonically increasing integer (never decreasing, regardless of clock adjustments)
3. If a wall clock adjustment causes `timestamp[n] < timestamp[n-1]`, the implementation MUST still increment the sequence number and record the adjusted time. The hash chain remains valid because it chains on `sequence + content`, not on timestamp ordering.
4. Implementations SHOULD use NTP with authentication (NTS, RFC 8915) to minimize clock drift
5. Cross-organization audit correlation MUST allow up to 30 seconds of clock skew (not 5 seconds as for intra-system)

**NTP Synchronization Failure Behavior:**

If the NTP source becomes unreachable, the system MUST continue operating using the local clock but MUST log a WARNING event every 60 seconds until NTP sync is restored. If the local clock drifts by more than 30 seconds from the last known NTP time (as estimated by monotonic clock comparison), the system MUST log a CRITICAL event and SHOULD alert administrators immediately. Audit records written during an NTP outage MUST include the flag `"clock_synced": false` in the entry's `metadata` object. The system MUST NOT stop writing audit records due to NTP failure -- availability of the audit trail takes precedence over timestamp precision. When NTP sync is restored, if the clock adjustment exceeds 5 seconds, the system MUST write a `clock_adjustment` audit record containing the old timestamp, the new timestamp, and the delta in milliseconds. This record MUST be chained into the hash chain like any other audit entry and MUST use `action: "clock_adjustment"`.

### 2.3 Agent Object

The `agent` field MUST contain:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `uri` | string | MUST | The agent's NL Protocol identity URI (Chapter 01). Format: `nl://<authority>/<path>`. |
| `organization_id` | string | MUST | The organization the agent belongs to. |
| `session_id` | string | MUST | A unique identifier for the agent's current session. Sessions are bounded by authentication events. |

### 2.4 Optional Fields

Implementations MAY include additional fields in audit entries:

| Field | Type | Description |
|-------|------|-------------|
| `detail` | string | Additional human-readable detail about the action (e.g., "Command executed: curl -H 'Auth: Bearer {{nl:API_KEY}}' ..."). Secret values MUST NOT appear. |
| `source_ip` | string | The IP address from which the action originated. |
| `user_agent` | string | The user agent or client identifier. |
| `duration_ms` | integer | Execution duration in milliseconds (for `exec` and similar actions). |
| `rule_id` | string | For `blocked` results, the ID of the deny rule that triggered the block (Chapter 04). |
| `error_code` | string | For `error` results, a machine-readable error code. |
| `scope_id` | string | The scope ID under which the action was authorized (Chapter 02). |
| `metadata` | object | An extensible key-value map for implementation-specific data. MUST NOT contain secret values. |

### 2.5 Prohibited Content

The following MUST NOT appear in any field of an audit entry:

1. Secret values in any encoding (plaintext, base64, hex, URL-encoded, hashed with weak algorithms).
2. Passwords, tokens, API keys, certificates, or private keys.
3. Partial secret values (e.g., first/last N characters).
4. Data that could be used to reconstruct or brute-force a secret value.

Implementations MUST scan audit entries for potential secret leakage before writing them to storage. If a secret value is detected in an audit entry, the entry MUST be sanitized (value replaced with `[REDACTED]`) and a security incident MUST be logged.

## 3. Hash Chain

### 3.1 Purpose

The hash chain provides cryptographic proof that audit entries have not been modified, deleted, or reordered after they were written. Each entry includes the hash of the previous entry, creating a chain where any alteration to a single entry invalidates all subsequent entries.

### 3.2 Chain Object

The `chain` field in each audit entry MUST contain:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `prev_hash` | string | MUST | The `hash` value of the immediately preceding entry. For the genesis entry (sequence 1), this MUST be `sha256:` followed by 64 zeros. |
| `hash` | string | MUST | The SHA-256 hash of this entry's canonical content. See Section 3.3 for the hash calculation. |
| `hmac` | string | SHOULD | An HMAC-SHA256 of this entry's `hash`, keyed with the vault's HMAC key. Provides additional integrity assurance. See Section 3.5. |

### 3.3 Hash Calculation

The `hash` field is calculated as follows:

```
hash = SHA-256(canonical_input)
```

Where `canonical_input` is the concatenation of the following fields, separated by the newline character (`\n`), in the exact order specified:

```
<sequence>\n<timestamp>\n<agent.uri>\n<action>\n<target>\n<result>\n<prev_hash>
```

**Example calculation:**

```
Input:
  sequence    = 1
  timestamp   = 2026-02-08T10:30:00.000Z
  agent.uri   = nl://anthropic.com/claude-code/1.5.2
  action      = exec
  target      = api/API_KEY
  result      = success
  prev_hash   = sha256:0000000000000000000000000000000000000000000000000000000000000000

Canonical string:
  "1\n2026-02-08T10:30:00.000Z\nnl://anthropic.com/claude-code/1.5.2\nexec\napi/API_KEY\nsuccess\nsha256:0000000000000000000000000000000000000000000000000000000000000000"

hash = SHA-256(canonical_string)
     = sha256:a1b2c3...  (64 hex characters)
```

Implementations MUST prefix hash values with `sha256:` to indicate the algorithm used. This enables future algorithm agility.

Audit record canonicalization MUST follow RFC 8785 (JCS - JSON Canonicalization Scheme).

**Requirements:**
1. All audit records MUST be serialized using RFC 8785 before hashing
2. This ensures two independent implementations produce identical hashes for the same logical record
3. Key ordering MUST be lexicographic (Unicode code point order)
4. Numbers MUST use the shortest representation without trailing zeros
5. Strings MUST use the minimal UTF-8 encoding

Implementations that do not support RFC 8785 MAY use `JSON.stringify()` with sorted keys as a fallback, but MUST document this deviation. Interoperability between RFC 8785 and sorted-key implementations is NOT guaranteed.

#### 3.3.1 Canonical JSON Test Vectors

The following test vectors define the expected output of a conformant RFC 8785 canonicalization implementation. Implementations MUST produce byte-identical output for all test vectors. Failure to match any test vector indicates a non-compliant canonicalization implementation.

**Test Vector 1 -- Field ordering:**

```
Input:     {"zebra": 1, "alpha": 2}
Canonical: {"alpha":2,"zebra":1}
SHA-256:   b38943f3398f7057224689aa44865d70c1143669a51b010f27e8495094c97b6e
```

**Test Vector 2 -- Nested objects:**

```
Input:     {"b": {"z": 1, "a": 2}, "a": 3}
Canonical: {"a":3,"b":{"a":2,"z":1}}
SHA-256:   b375125e33a203b70f14be432a2d7b0823e92ae82f505063e8b21ca5b7a73f42
```

**Test Vector 3 -- Unicode escaping:**

```
Input:     {"key": "café"}
Canonical: {"key":"café"}    (UTF-8 preserved, no escape)
SHA-256:   6f0a62bb4f435d032b67c7a8719afe68a157bfa0a90897f977ba38dbd9be9d8e
```

**Test Vector 4 -- Numbers:**

```
Input:     {"val": 1.0, "big": 1e2}
Canonical: {"big":100,"val":1}    (integers normalized, no trailing zeros)
SHA-256:   c2ee8c03a063b35bf4b71b34c34508544022597b6b06f0990f0cc592b91a1ab6
```

**Test Vector 5 -- Null and boolean:**

```
Input:     {"n": null, "t": true, "f": false}
Canonical: {"f":false,"n":null,"t":true}
SHA-256:   22e00dc2f7b01420f940fbdbfbdf34fa0667cc6500186495023ba37722cbd05e
```

> **Conformance note:** Implementations MUST produce byte-identical output for all test vectors above. A canonicalization implementation that fails to match any single test vector MUST NOT be used for audit record hashing. Implementers SHOULD use these vectors as part of their automated test suite.

### Algorithm Agility

The current version of this specification requires SHA-256 for hash chains and HMAC.

**Migration Path:**
1. Hash references are prefixed with algorithm identifier: `sha256:abc123...`
2. Future versions MAY introduce additional algorithms (e.g., `sha3-256:`, `blake3:`)
3. When a new algorithm is adopted, implementations MUST support a transition period where BOTH old and new algorithms are accepted for verification
4. New audit entries MUST use the new algorithm; verification MUST accept either
5. The transition period MUST be at least 90 days
6. The discovery document (Chapter 08) MUST advertise supported hash algorithms in `capabilities.hash_algorithms` array

#### Hash Algorithm Migration Procedure

To ensure long-term protocol durability, implementations MUST support algorithm migration using the following procedure:

1. **Algorithm Identification**: Every audit record MUST include a `hash_algorithm` field identifying the algorithm used (e.g., `"sha256"`). This field enables future readers to verify records signed with different algorithms.

2. **Migration Announcement**: A new algorithm is announced via a protocol version update. The announcement MUST specify:
   - The new algorithm identifier
   - The sunset date for the old algorithm (minimum 2 years from announcement)
   - The transition period during which both algorithms are accepted

3. **Transition Period**: During the transition period:
   - New audit records MUST be signed with the new algorithm
   - New audit records SHOULD also include a secondary hash using the old algorithm (`legacy_hash` field) for backward verification
   - Verification of existing records MUST accept both old and new algorithms
   - The hash chain continues: each record's `previous_hash` references the prior record using whatever algorithm that record used

4. **Post-Sunset**: After the sunset date:
   - New records MUST use only the new algorithm
   - Old records remain verifiable using their declared `hash_algorithm`
   - Implementations MUST retain support for verifying deprecated algorithms indefinitely (read-only)
   - The `legacy_hash` field is no longer required

5. **Emergency Migration**: If an algorithm is found to be critically compromised:
   - The sunset period MAY be shortened to 90 days
   - A `chain_migration_checkpoint` record MUST be created, signed with the new algorithm, referencing the last record of the old chain
   - This checkpoint acts as a trust anchor for the new chain segment

**Algorithm Registry**:

| Identifier | Algorithm | Status | Notes |
|---|---|---|---|
| `sha256` | SHA-256 | Active | Current default |
| `sha384` | SHA-384 | Reserved | For future use |
| `sha3_256` | SHA3-256 | Reserved | Post-quantum candidate |

### 3.4 Genesis Entry

The first entry in the audit chain (sequence = 1) is the genesis entry. Its `prev_hash` MUST be:

```
sha256:0000000000000000000000000000000000000000000000000000000000000000
```

This is a string of 64 ASCII zeros, prefixed with `sha256:`. The genesis entry establishes the root of the hash chain.

### 3.5 HMAC Calculation

The optional `hmac` field provides an additional layer of integrity by signing the hash with a key that is not stored alongside the audit log. This prevents an attacker who gains write access to the audit log from rewriting the hash chain with valid hashes.

```
hmac = HMAC-SHA256(key=vault_hmac_key, message=hash)
```

Where:

- `vault_hmac_key` is a secret key managed by the vault or audit system. This key MUST be stored separately from the audit log.
- `hash` is the `chain.hash` value of the current entry (including the `sha256:` prefix).

The HMAC value MUST be prefixed with `sha256:` to indicate the algorithm.

Implementations that support HMAC SHOULD store the HMAC key in an HSM or key management service. The HMAC key MUST be rotated periodically (RECOMMENDED: every 90 days). When the HMAC key is rotated, the audit entry at the rotation point MUST include a `metadata.hmac_key_rotated` flag set to `true`.

#### 3.5.1 HMAC Key Rotation Procedure

When the HMAC key is rotated, the old key MUST be retained for a minimum of 90 days to allow verification of historical audit records that were signed with that key. The system MUST maintain a key registry that maps each `key_id` to its corresponding key material and the time range during which it was active. Each audit record SHOULD include a `chain.hmac_key_id` field identifying the `key_id` used to compute its HMAC, enabling verifiers to select the correct key.

During rotation, a transition period of at least 24 hours MUST be observed during which both the old and new keys are accepted for verification. New audit records written during the transition period MUST use the new key, but verification of records signed with the old key MUST continue to succeed.

If the old key is compromised or lost, historical records signed with that key become unverifiable. In such an event, the system MUST log a CRITICAL security event indicating which `key_id` was lost and the range of audit records affected (by sequence number). The unverifiable records MUST be flagged with `metadata.hmac_unverifiable: true` but MUST NOT be deleted -- the hash chain integrity (via `chain.hash` and `chain.prev_hash`) remains valid independently of HMAC verification.

Key storage: HMAC keys MUST be stored in a separate key store from the audit data store. Compromise of the audit data store alone MUST NOT compromise the HMAC keys. Implementations SHOULD use an HSM, a cloud KMS (e.g., AWS KMS, GCP Cloud KMS, Azure Key Vault), or an encrypted key store with access controls independent of the audit log storage.

### 3.6 Hash Chain Continuity Across Log Rotation

When audit logs are rotated (Section 7), the hash chain MUST continue across rotations:

1. The last entry in the old log file has hash `H_last`.
2. The first entry in the new log file MUST have `prev_hash = H_last`.
3. The rotation event itself SHOULD be recorded as an audit entry with `action = "log_rotation"`.

This ensures that the hash chain is a single, continuous sequence across all log files.

## 4. Tamper Detection

### 4.1 Types of Tampering

The hash chain is designed to detect four types of tampering:

#### 4.1.1 Modification

An attacker modifies the content of an existing audit entry (e.g., changing `result` from `"blocked"` to `"success"`).

**Detection:** Recalculate the hash of the modified entry from its fields. The recalculated hash will not match the stored `chain.hash`. Additionally, all subsequent entries will have invalid `prev_hash` references.

#### 4.1.2 Deletion

An attacker deletes one or more audit entries from the log.

**Detection:** A gap in the `sequence` field indicates deletion. If entry with sequence N exists and the next entry has sequence N+2, an entry has been deleted. Additionally, the `prev_hash` of entry N+2 will not match the `hash` of entry N.

#### 4.1.3 Reordering

An attacker changes the order of audit entries (e.g., to make a blocked action appear to have occurred after an authorization change).

**Detection:** Reordering breaks the hash chain because each entry's hash is calculated using `prev_hash`, which depends on the previous entry's content and position. Swapping two entries invalidates the hashes of both entries and all subsequent entries.

#### 4.1.4 Truncation

An attacker deletes the most recent entries from the end of the log to remove evidence of recent actions.

**Detection:** The last known sequence number (from checkpoints or external references) is compared against the current last sequence number. A decrease indicates truncation. External checkpoints (Section 4.4) provide an independent anchor for this comparison.

### 4.2 Chain Reconstruction Attack

A sophisticated attacker with write access to the audit log could delete entries and then recalculate the hash chain to produce valid hashes. This attack is mitigated by:

1. **HMAC protection** (Section 3.5): Without the HMAC key, the attacker cannot produce valid HMAC values, even if they can recalculate SHA-256 hashes.
2. **External checkpoints** (Section 4.4): Checkpoint hashes published to an external, append-only store cannot be retroactively modified.
3. **Sequence number gaps**: Even with a reconstructed chain, gaps in sequence numbers reveal deletion.

### 4.3 Hash Chain Fork Detection

A hash chain fork occurs when two audit records claim the same `prev_hash`. Implementations MUST detect forks by maintaining an index of `prev_hash` values.

On fork detection, the system MUST: (a) halt new audit writes, (b) generate a CRITICAL alert, (c) preserve both branches for forensic analysis.

### 4.4 External Checkpoints

Implementations SHOULD publish periodic checkpoints to an external, append-only store that is independent of the audit log. Checkpoints provide an independent anchor that an attacker cannot modify even if they compromise the audit system.

A checkpoint MUST contain:

```json
{
  "checkpoint_id": "chk-2026-02-08-001",
  "timestamp": "2026-02-08T11:00:00.000Z",
  "last_sequence": 1247,
  "last_hash": "sha256:a1b2c3d4...",
  "last_hmac": "sha256:f6e5d4c3...",
  "entry_count": 1247,
  "platform": "acme-vault",
  "signature": "ES256:MEUCIQDf...base64..."
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `checkpoint_id` | string | MUST | Unique identifier for the checkpoint. |
| `timestamp` | string | MUST | ISO 8601 timestamp of checkpoint creation. |
| `last_sequence` | integer | MUST | The sequence number of the last entry included in this checkpoint. |
| `last_hash` | string | MUST | The `chain.hash` of the last entry. |
| `last_hmac` | string | SHOULD | The `chain.hmac` of the last entry. |
| `entry_count` | integer | MUST | Total number of entries in the chain at checkpoint time. |
| `platform` | string | MUST | The platform that produced the checkpoint. |
| `signature` | string | MUST | A digital signature over the checkpoint, produced by the audit system's signing key. |

**Checkpoint Signature Format:**

- Checkpoint signatures MUST use the format: `<algorithm>:<base64url-encoded-signature>`
- Supported algorithms: `ES256`, `ES384`, `RS256`
- The signing key MUST be different from the HMAC key used for audit records
- Checkpoint signing keys SHOULD be stored in an HSM. If not, they MUST be stored with filesystem permissions restricting access to the NL Provider process only.

Checkpoint publication targets MAY include:

- Append-only databases or ledgers
- Signed timestamping services (RFC 3161)
- Transparency logs (Certificate Transparency-style)
- Immutable cloud storage (e.g., AWS S3 Object Lock, Azure Immutable Blob Storage)
- Version control systems (as signed commits)

Checkpoint frequency MUST be at least once per hour during active operation. Implementations SHOULD support configurable checkpoint intervals.

## 5. Verification Protocol

### 5.1 Full Chain Verification

Full verification recalculates the entire hash chain from the genesis entry. This is the most thorough verification method but is also the most computationally expensive.

**Procedure:**

1. Load all audit entries, ordered by `sequence`.
2. Verify that entry with sequence 1 has `prev_hash` equal to the genesis value (64 zeros).
3. For each entry from sequence 1 to N:
   a. Reconstruct the canonical input string from the entry's fields.
   b. Calculate `expected_hash = SHA-256(canonical_input)`.
   c. Compare `expected_hash` with the stored `chain.hash`. If they differ, the entry has been modified. Report the sequence number and stop.
   d. If the entry has sequence > 1, verify that `chain.prev_hash` equals the `chain.hash` of the previous entry. If they differ, the chain has been broken at this point. Report and stop.
   e. If HMAC is present, verify the HMAC using the vault's HMAC key. If it does not match, report and stop.
4. Verify that the sequence numbers are contiguous (no gaps).
5. If all checks pass, the chain is verified as intact.

**Result schema:**

```json
{
  "verification": "full",
  "status": "valid",
  "entries_verified": 1247,
  "first_sequence": 1,
  "last_sequence": 1247,
  "timestamp": "2026-02-08T12:00:00.000Z",
  "duration_ms": 340
}
```

**Failure result schema:**

```json
{
  "verification": "full",
  "status": "tampered",
  "entries_verified": 892,
  "tamper_detected_at": {
    "sequence": 893,
    "type": "hash_mismatch",
    "expected_hash": "sha256:a1b2c3...",
    "actual_hash": "sha256:d4e5f6...",
    "detail": "Entry content has been modified after writing."
  },
  "timestamp": "2026-02-08T12:00:00.000Z",
  "duration_ms": 210
}
```

### 5.2 Incremental Verification

Incremental verification starts from the last known-good entry and verifies only entries added since then. This is suitable for periodic verification and is significantly faster than full verification for large audit logs.

**Procedure:**

1. Load the last verification result to determine the `last_verified_sequence` and `last_verified_hash`.
2. Load all entries with sequence > `last_verified_sequence`, ordered by sequence.
3. Verify that the first new entry's `chain.prev_hash` equals `last_verified_hash`.
4. For each new entry, apply the same verification steps as full verification (Section 5.1, step 3).
5. If all checks pass, update the last verification result.

Incremental verification SHOULD be performed automatically at a configurable interval (RECOMMENDED: every 5 minutes during active operation).

### 5.3 Cross-Platform Verification

When actions span multiple platforms (e.g., an agent uses an NL Provider to inject a secret into an AWS Lambda function), the audit entries on each platform are linked by `correlation_id`. Cross-platform verification ensures that the entries are consistent.

**Procedure:**

1. Given a `correlation_id`, retrieve all audit entries with that `correlation_id` from all participating platforms.
2. Verify that the entries form a logically consistent sequence:
   a. Timestamps are in plausible order (allowing for clock skew up to a configurable tolerance, RECOMMENDED: 5 seconds).
   b. The agent URI is consistent across entries.
   c. The action types form a valid workflow (e.g., an `exec` on the vault corresponds to an invocation on the target platform).
3. Verify the hash chain integrity on each individual platform (per Sections 5.1 or 5.2).
4. Report any inconsistencies.

**Cross-platform verification result:**

```json
{
  "verification": "cross_platform",
  "correlation_id": "req-abc-123",
  "status": "consistent",
  "platforms": [
    {
      "platform": "acme-vault",
      "entries": 1,
      "chain_status": "valid"
    },
    {
      "platform": "aws-lambda-proxy",
      "entries": 1,
      "chain_status": "valid"
    }
  ],
  "timestamp": "2026-02-08T12:05:00.000Z"
}
```

### 5.4 Verification Triggers

Implementations MUST support the following verification triggers:

| Trigger | Verification Type | Required |
|---------|------------------|----------|
| On-demand by administrator | Full or incremental | MUST |
| Scheduled (periodic) | Incremental | SHOULD |
| After log rotation | Full (on rotated log) | SHOULD |
| After checkpoint publication | Incremental (since last checkpoint) | SHOULD |
| After security incident | Full | SHOULD |
| Via API endpoint | Full or incremental | SHOULD |

## 6. Audit Queries

### 6.1 Query Capabilities

Implementations MUST support querying the audit log by the following dimensions:

#### 6.1.1 By Agent

"What did Agent X do?"

```json
{
  "query": "by_agent",
  "agent_uri": "nl://anthropic.com/claude-code/1.5.2",
  "time_range": {
    "from": "2026-02-08T00:00:00.000Z",
    "to": "2026-02-08T23:59:59.999Z"
  },
  "results": [
    {
      "sequence": 42,
      "timestamp": "2026-02-08T10:30:00.000Z",
      "action": "exec",
      "target": "api/API_KEY",
      "result": "success"
    },
    {
      "sequence": 57,
      "timestamp": "2026-02-08T11:15:00.000Z",
      "action": "exec",
      "target": "database/DB_PASSWORD",
      "result": "blocked",
      "detail": "Direct secret access attempted (NL-4-DENY-001)"
    }
  ]
}
```

#### 6.1.2 By Secret

"Who accessed Secret Y?"

```json
{
  "query": "by_secret",
  "target": "api/API_KEY",
  "time_range": {
    "from": "2026-02-01T00:00:00.000Z",
    "to": "2026-02-08T23:59:59.999Z"
  },
  "results": [
    {
      "sequence": 42,
      "timestamp": "2026-02-08T10:30:00.000Z",
      "agent_uri": "nl://anthropic.com/claude-code/1.5.2",
      "action": "exec",
      "result": "success"
    },
    {
      "sequence": 103,
      "timestamp": "2026-02-08T14:20:00.000Z",
      "agent_uri": "nl://example.com/deploy-bot/2.0.0",
      "action": "inject_stdin",
      "result": "success"
    }
  ]
}
```

#### 6.1.3 By Time Range

"What happened between T1 and T2?"

```json
{
  "query": "by_time",
  "time_range": {
    "from": "2026-02-08T10:00:00.000Z",
    "to": "2026-02-08T10:30:00.000Z"
  },
  "results": [
    {
      "sequence": 40,
      "timestamp": "2026-02-08T10:05:12.000Z",
      "agent_uri": "nl://anthropic.com/claude-code/1.5.2",
      "action": "list",
      "target": "project:myapp/env:production",
      "result": "success"
    },
    {
      "sequence": 41,
      "timestamp": "2026-02-08T10:15:33.000Z",
      "agent_uri": "nl://anthropic.com/claude-code/1.5.2",
      "action": "exec",
      "target": "api/STRIPE_KEY",
      "result": "blocked"
    },
    {
      "sequence": 42,
      "timestamp": "2026-02-08T10:30:00.000Z",
      "agent_uri": "nl://anthropic.com/claude-code/1.5.2",
      "action": "exec",
      "target": "api/API_KEY",
      "result": "success"
    }
  ]
}
```

#### 6.1.4 By Correlation ID

"Trace the full chain for request Z across all platforms."

```json
{
  "query": "by_correlation",
  "correlation_id": "req-abc-123",
  "results": [
    {
      "platform": "acme-vault",
      "sequence": 42,
      "timestamp": "2026-02-08T10:30:00.000Z",
      "agent_uri": "nl://anthropic.com/claude-code/1.5.2",
      "action": "exec",
      "target": "api/API_KEY",
      "result": "success"
    },
    {
      "platform": "aws-lambda-proxy",
      "sequence": 891,
      "timestamp": "2026-02-08T10:30:00.150Z",
      "agent_uri": "nl://anthropic.com/claude-code/1.5.2",
      "action": "api_call",
      "target": "https://api.stripe.com/v1/charges",
      "result": "success"
    }
  ]
}
```

#### 6.1.5 By Result

"Show all blocked actions" or "Show all denied access attempts."

```json
{
  "query": "by_result",
  "result": "blocked",
  "time_range": {
    "from": "2026-02-08T00:00:00.000Z",
    "to": "2026-02-08T23:59:59.999Z"
  },
  "count": 7,
  "results": [
    {
      "sequence": 41,
      "timestamp": "2026-02-08T10:15:33.000Z",
      "agent_uri": "nl://anthropic.com/claude-code/1.5.2",
      "action": "exec",
      "target": "api/STRIPE_KEY",
      "result": "blocked",
      "rule_id": "NL-4-DENY-001"
    }
  ]
}
```

### 6.2 Query Requirements

| Requirement | Level |
|------------|-------|
| Query by agent URI | MUST |
| Query by secret target | MUST |
| Query by time range | MUST |
| Query by correlation ID | MUST |
| Query by result type | MUST |
| Pagination support for large result sets | MUST |
| Query by platform | SHOULD |
| Full-text search on `detail` field | MAY |
| Cross-platform aggregated query | MAY (see Section 8.2) |

### 6.3 Query Access Control

Access to audit queries MUST be controlled:

1. Agents MUST NOT be able to query their own audit entries (to prevent them from understanding what is and is not being logged, which could inform evasion strategies).
2. Human administrators MUST be able to query all audit entries within their organizational scope.
3. Query access MUST be governed by the same RBAC model as other vault operations.
4. Audit query actions themselves MUST be logged in the audit trail (meta-auditing).

## 7. Log Rotation

### 7.1 Rotation Policy

Audit logs MUST support rotation to manage storage and ensure performance. Rotation MUST NOT break the hash chain (see Section 3.6).

### 7.2 Rotation Triggers

Rotation SHOULD be triggered by one or more of the following conditions:

| Trigger | Default | Configurable |
|---------|---------|-------------|
| File size | 10 MB | MUST |
| Entry count | 100,000 entries | SHOULD |
| Time period | 30 days | SHOULD |
| Manual trigger | N/A | MUST |

### 7.3 Rotation Procedure

When a log rotation is triggered:

1. Write a rotation marker entry to the current log:
   ```json
   {
     "entry_id": "...",
     "sequence": 1248,
     "timestamp": "2026-02-08T12:00:00.000Z",
     "nl_version": "1.0",
     "agent": {
       "uri": "nl://system/audit-manager",
       "organization_id": "org_example",
       "session_id": "system"
     },
     "delegated_by": "system:audit-rotation",
     "action": "log_rotation",
     "target": "audit-log-2026-02-08-001.json",
     "result": "success",
     "secrets_used": [],
     "correlation_id": "rotation-2026-02-08-001",
     "platform": "example-sm",
     "chain": {
       "prev_hash": "sha256:...",
       "hash": "sha256:...",
       "hmac": "sha256:..."
     }
   }
   ```
2. Close the current log file and mark it as read-only.
3. Create a new log file.
4. The first entry in the new log file MUST have `chain.prev_hash` equal to the `chain.hash` of the rotation marker entry.
5. Publish a checkpoint for the rotated log file.

### 7.4 Rotated Log Naming

Rotated log files SHOULD follow the naming convention:

```
audit-<platform>-<start_sequence>-<end_sequence>-<date>.json
```

Example: `audit-example-sm-0001-1248-2026-02-08.json`

### 7.5 Rotated Log Access

Rotated log files MUST remain accessible for the duration of the retention period (Section 8). They MAY be compressed (gzip RECOMMENDED) and MAY be moved to archival storage after a configurable period (RECOMMENDED: 30 days of hot storage, then cold storage for the remainder of retention).

## 8. Retention and Federation

### 8.1 Retention Requirements

Audit records MUST be retained for a minimum period determined by the deployment's conformance level and compliance requirements:

| Conformance Level | Minimum Retention | Description |
|------------------|-------------------|-------------|
| NL Protocol Basic (Levels 1-3) | 90 days | Suitable for development teams and small organizations. |
| NL Protocol Standard (Levels 1-5) | 1 year | Suitable for organizations with security policies and regulatory requirements. |
| NL Protocol Advanced (Levels 1-7) | 7 years | Suitable for enterprises with SOC2, ISO 27001, HIPAA, or GDPR compliance requirements. |

Retention periods are minimums. Organizations MAY retain records for longer periods based on their compliance requirements.

Records MUST be retrievable throughout the retention period. Archived records MUST be restorable within a defined SLA (RECOMMENDED: 24 hours for cold storage).

### 8.2 Federation

Federation enables audit entries from multiple platforms to be correlated and queried as a unified dataset. This is essential for organizations that use multiple secret managers, cloud platforms, or agent orchestration systems.

#### 8.2.1 Standard Federation (via Correlation ID)

At the Standard conformance level, federation is achieved through `correlation_id`:

1. When an agent initiates an action that spans multiple platforms, a single `correlation_id` is generated and propagated to all platforms.
2. Each platform records its own audit entries with the shared `correlation_id`.
3. Querying by `correlation_id` on each platform independently reveals the cross-platform trace.

This approach requires no centralized infrastructure. Each platform maintains its own audit log with its own hash chain.

**Example flow:**

```
Agent -> NL Provider (correlation_id: req-abc-123)
                |
                v
         Resolve {{nl:API_KEY}} -> Execute curl -> Stripe API
                |                                     |
                v                                     v
         Audit entry on                        Audit entry on
         acme-vault                            stripe-proxy
         (correlation_id: req-abc-123)         (correlation_id: req-abc-123)
```

#### 8.2.2 Advanced Federation (Centralized Audit Aggregator)

At the Advanced conformance level, organizations MAY deploy a centralized audit aggregator that:

1. **Collects** audit entries from all participating platforms via push (webhook) or pull (API polling).
2. **Indexes** entries by `correlation_id`, `agent.uri`, `target`, `timestamp`, and `platform`.
3. **Provides unified queries** across all platforms through a single API.
4. **Verifies chain integrity** independently for each platform's chain.
5. **Detects cross-platform anomalies** (e.g., an action recorded on platform A with no corresponding entry on platform B).

Aggregator entry format:

```json
{
  "aggregator_id": "agg-entry-001",
  "source_platform": "acme-vault",
  "source_entry_id": "01953f2a-7b3c-7def-8a12-4b5c6d7e8f90",
  "source_sequence": 42,
  "received_at": "2026-02-08T10:30:01.000Z",
  "chain_verified": true,
  "entry": { "...": "full audit entry from source platform" }
}
```

The aggregator MUST NOT modify source entries. It MUST store the original entry alongside its own metadata.

#### 8.2.3 Correlation ID Generation

Correlation IDs MUST be:

1. **Globally unique**: UUIDs or ULID format RECOMMENDED.
2. **Propagated**: When an action on platform A triggers an action on platform B, the same `correlation_id` MUST be used on both platforms.
3. **Immutable**: Once generated, a `correlation_id` MUST NOT be changed.
4. **Non-secret**: Correlation IDs MUST NOT contain secret values or information that could be used to derive secrets.

Correlation ID format: `req-<uuid>` (e.g., `req-7f3a2b1c-d4e5-6f78-9a0b-c1d2e3f4a5b6`).

## 9. Compliance Mapping

### 9.1 Purpose

The NL Protocol audit trail is designed to support compliance with major security and privacy frameworks. This section maps the audit capabilities to specific compliance requirements.

### 9.2 SOC 2

| SOC 2 Trust Service Criteria | NL Protocol Audit Mapping |
|-----------------------------|---------------------------|
| **CC6.1**: Logical access security | Agent identity (Chapter 01) recorded in every audit entry via `agent.uri`. Scope-based access control (Chapter 02) recorded via `scope_id` and `result`. |
| **CC6.2**: Restricting access to system resources | `result: "denied"` and `result: "blocked"` entries demonstrate access restriction enforcement. |
| **CC6.3**: Restricting access to infrastructure | Platform integration (Chapter 04, Section 10) demonstrates infrastructure-level access control. |
| **CC7.1**: Detecting unauthorized activities | `result: "blocked"` entries with deny rule IDs (Chapter 04) demonstrate detection of unauthorized activities. Threat scoring (Chapter 06) provides risk assessment. |
| **CC7.2**: Monitoring system activities | Continuous audit logging with hash chain integrity provides tamper-evident monitoring of all system activities. |
| **CC7.3**: Evaluating detected security events | Cross-platform correlation (`correlation_id`) and audit queries (Section 6) enable evaluation of security events. |
| **CC8.1**: Managing changes | `action: "create"`, `action: "update"`, `action: "delete"`, and `action: "rotate"` entries track all changes to secrets. |

### 9.3 ISO 27001

| ISO 27001 Control | NL Protocol Audit Mapping |
|-------------------|---------------------------|
| **A.8.15**: Logging | All agent actions are logged with timestamps, agent identity, action type, target, and result. |
| **A.8.16**: Monitoring activities | Hash chain integrity verification (Section 5) provides continuous monitoring of log integrity. |
| **A.8.17**: Clock synchronization | `timestamp` field requires UTC with millisecond precision from NTP-synchronized sources. |
| **A.5.23**: Information security for cloud services | Platform integration points (Chapter 04, Section 10) cover AWS, GCP, and Azure. Federation (Section 8.2) provides cross-platform visibility. |
| **A.8.4**: Access to source code | Audit entries for `action: "exec"` with code-related targets provide source code access tracking. |
| **A.8.10**: Information deletion | Retention policies (Section 8.1) define minimum retention periods and controlled deletion procedures. |

### 9.4 GDPR

| GDPR Article | NL Protocol Audit Mapping |
|-------------|---------------------------|
| **Article 5(2)**: Accountability | The hash-chained audit trail provides provable, tamper-evident records of all data processing activities involving secrets. |
| **Article 30**: Records of processing activities | Audit entries document what processing occurred (`action`), on what data (`target`), by whom (`agent.uri`), and when (`timestamp`). |
| **Article 32**: Security of processing | The hash chain, HMAC, and external checkpoints demonstrate integrity measures for the processing activity log. |
| **Article 33**: Notification of data breach | `result: "blocked"` and security incident entries provide evidence for breach detection and notification timeline reconstruction. |
| **Article 35**: Data protection impact assessment | Audit queries by agent, secret, and time range support impact assessment of any data processing operation. |

### 9.5 Additional Frameworks

The audit data model is extensible via the `metadata` field to support additional compliance frameworks, including but not limited to:

- **HIPAA**: Use `metadata.phi_involved: true` to flag entries involving protected health information.
- **PCI DSS**: Use `metadata.cardholder_data: true` to flag entries involving payment card data.
- **FedRAMP**: Use `metadata.impact_level: "high"` to categorize entries by FIPS 199 impact level.

## 10. Audit Entry Examples

### 10.1 Successful Secret Injection

An agent successfully injects a secret into a command execution:

```json
{
  "entry_id": "01953f2a-7b3c-7def-8a12-4b5c6d7e8f90",
  "sequence": 42,
  "timestamp": "2026-02-08T10:30:00.000Z",
  "nl_version": "1.0",
  "agent": {
    "uri": "nl://anthropic.com/claude-code/1.5.2",
    "organization_id": "org_braincol",
    "session_id": "session_abc123"
  },
  "delegated_by": "human:andre@braincol.com",
  "action": "exec",
  "target": "api/API_KEY",
  "result": "success",
  "secrets_used": ["api/API_KEY"],
  "correlation_id": "req-7f3a2b1c-d4e5-6f78-9a0b-c1d2e3f4a5b6",
  "platform": "braincol-vault",
  "detail": "Command: curl -H 'Authorization: Bearer {{nl:api/API_KEY}}' https://api.stripe.com/v1/charges",
  "duration_ms": 1250,
  "chain": {
    "prev_hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "hash": "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    "hmac": "sha256:f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5"
  }
}
```

Note: The `detail` field shows the command template with the placeholder `{{nl:api/API_KEY}}`, NOT the resolved secret value.

### 10.2 Blocked Action

An agent attempts a direct secret retrieval and is blocked by the pre-execution interceptor:

```json
{
  "entry_id": "01953f2a-8c4d-7abc-9012-5d6e7f8a9b0c",
  "sequence": 43,
  "timestamp": "2026-02-08T10:32:15.000Z",
  "nl_version": "1.0",
  "agent": {
    "uri": "nl://anthropic.com/claude-code/1.5.2",
    "organization_id": "org_acme",
    "session_id": "session_abc123"
  },
  "delegated_by": "human:admin@acme.com",
  "action": "blocked",
  "target": "api/API_KEY",
  "result": "blocked",
  "secrets_used": [],
  "correlation_id": "req-8g4b3c2d-e5f6-7a89-0b1c-d2e3f4a5b6c7",
  "platform": "acme-vault",
  "detail": "Blocked command: vault get API_KEY (rule: NL-4-DENY-001, category: direct_secret_access)",
  "rule_id": "NL-4-DENY-001",
  "chain": {
    "prev_hash": "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    "hash": "sha256:b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3",
    "hmac": "sha256:e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4"
  }
}
```

### 10.3 Denied Access

An agent attempts to access a secret outside its scope:

```json
{
  "entry_id": "01953f2a-9d5e-7bcd-0123-6e7f8a9b0c1d",
  "sequence": 44,
  "timestamp": "2026-02-08T10:35:00.000Z",
  "nl_version": "1.0",
  "agent": {
    "uri": "nl://example.com/ci-pipeline/3.1.0",
    "organization_id": "org_example",
    "session_id": "session_def456"
  },
  "delegated_by": "agent:nl://example.com/orchestrator/1.0.0",
  "action": "exec",
  "target": "production/database/DB_ADMIN_PASSWORD",
  "result": "denied",
  "secrets_used": [],
  "correlation_id": "req-9h5c4d3e-f6a1-8b90-1c2d-e3f4a5b6c7d8",
  "platform": "example-sm",
  "detail": "Agent scope limited to environment:staging. Requested resource is in environment:production.",
  "scope_id": "scope-ci-staging-001",
  "chain": {
    "prev_hash": "sha256:b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3",
    "hash": "sha256:c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    "hmac": "sha256:d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3"
  }
}
```

### 10.4 Multiple Secrets in a Single Action

An agent injects multiple secrets into a single command:

```json
{
  "entry_id": "01953f2a-ae6f-7cde-1234-7f8a9b0c1d2e",
  "sequence": 45,
  "timestamp": "2026-02-08T10:40:00.000Z",
  "nl_version": "1.0",
  "agent": {
    "uri": "nl://anthropic.com/claude-code/1.5.2",
    "organization_id": "org_example",
    "session_id": "session_abc123"
  },
  "delegated_by": "human:admin@example.com",
  "action": "exec",
  "target": "database/DB_USER,database/DB_PASSWORD",
  "result": "success",
  "secrets_used": ["database/DB_USER", "database/DB_PASSWORD"],
  "correlation_id": "req-0i6d5e4f-a1b2-9c01-2d3e-f4a5b6c7d8e9",
  "platform": "example-sm",
  "detail": "Command: psql 'postgresql://{{nl:database/DB_USER}}:{{nl:database/DB_PASSWORD}}@localhost/mydb'",
  "duration_ms": 3400,
  "chain": {
    "prev_hash": "sha256:c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    "hash": "sha256:d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5",
    "hmac": "sha256:c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2"
  }
}
```

### 10.5 Evasion Attempt

An agent attempts to evade deny rules using base64 encoding:

```json
{
  "entry_id": "01953f2a-bf70-7def-2345-8a9b0c1d2e3f",
  "sequence": 46,
  "timestamp": "2026-02-08T10:45:00.000Z",
  "nl_version": "1.0",
  "agent": {
    "uri": "nl://anthropic.com/claude-code/1.5.2",
    "organization_id": "org_acme",
    "session_id": "session_abc123"
  },
  "delegated_by": "human:admin@acme.com",
  "action": "blocked",
  "target": "unknown",
  "result": "blocked",
  "secrets_used": [],
  "correlation_id": "req-1j7e6f5a-b2c3-0d12-3e4f-a5b6c7d8e9f0",
  "platform": "acme-vault",
  "detail": "Evasion attempt detected: base64-encoded command piped to shell (rule: NL-4-DENY-030, category: encoding_evasion)",
  "rule_id": "NL-4-DENY-030",
  "metadata": {
    "evasion_type": "base64_decode_pipe_shell",
    "threat_score_delta": "+10"
  },
  "chain": {
    "prev_hash": "sha256:d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5",
    "hash": "sha256:e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6",
    "hmac": "sha256:b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1"
  }
}
```

## 11. Security Considerations

- **The audit system is a high-value target.** Compromise of the audit system undermines every other security layer because actions can no longer be verified. Implementations MUST treat the audit system as critical infrastructure with its own access controls, monitoring, and redundancy.

- **Hash chaining detects tampering but does not prevent it.** An attacker with write access can modify the log and rewrite the chain. HMAC protection (Section 3.5) and external checkpoints (Section 4.4) provide additional layers that make undetected tampering significantly harder.

- **Clock accuracy is critical.** Audit records with inaccurate timestamps undermine temporal analysis and cross-platform correlation. Implementations MUST use NTP-synchronized time sources and SHOULD monitor for clock skew. Clock skew greater than 1 second SHOULD trigger an alert.

- **Secret values in audit entries.** The prohibition on secret values in audit entries (Section 2.5) is the most critical constraint in this chapter. Implementations MUST scan entries before writing them and MUST sanitize any detected secret content. A leaked secret in the audit log is worse than no audit log at all, because it creates a persistent, searchable record of the secret.

- **Audit log storage exhaustion.** If the audit log storage is full and a new record cannot be written, the system MUST block the triggering action (fail-closed). The system MUST NOT execute actions that cannot be audited. Implementations SHOULD monitor disk usage and alert at 80% capacity.

- **Audit log as a denial-of-service vector.** A compromised agent could generate a high volume of actions to fill the audit log, triggering rotation and potentially consuming storage. Implementations SHOULD apply rate limiting to audit entry generation and SHOULD alert on unusual audit volume.

- **Query side channels.** Audit query patterns themselves can reveal sensitive information (e.g., which secrets are accessed most frequently). Query access MUST be controlled (Section 6.3) and query activity MUST be logged.

- **Retention and data minimization.** Long retention periods increase the value of the audit log as a target. Organizations MUST balance compliance retention requirements against the risk of storing a detailed record of all secret access activity. Encryption at rest for audit log storage is RECOMMENDED.

## 12. Conformance Requirements

An implementation conforms to NL Protocol Level 5 if it satisfies all MUST-level requirements. Full conformance includes satisfying all MUST and SHOULD requirements.

| Requirement ID | Description | Level |
|---------------|-------------|-------|
| NL-5.1 | Every action produces an audit entry with all required fields (Section 2) | MUST |
| NL-5.2 | Audit entries are linked in a SHA-256 hash chain (Section 3) | MUST |
| NL-5.3 | Genesis entry uses the defined prev_hash value (Section 3.4) | MUST |
| NL-5.4 | Secret values NEVER appear in audit entries (Section 2.5) | MUST |
| NL-5.5 | Hash chain integrity is verifiable on demand (Section 5) | MUST |
| NL-5.6 | Tamper detection covers modification, deletion, reordering, and truncation (Section 4) | MUST |
| NL-5.7 | Sequence numbers are monotonically increasing with no gaps (Section 2.2) | MUST |
| NL-5.8 | Audit entries use UTC timestamps with millisecond precision from NTP-synchronized sources (Section 2.2) | MUST |
| NL-5.9 | Agents cannot modify or delete their own audit entries (Section 6.3) | MUST |
| NL-5.10 | Audit queries by agent, secret, time, correlation ID, and result are supported (Section 6) | MUST |
| NL-5.11 | Log rotation does not break the hash chain (Section 7) | MUST |
| NL-5.12 | Minimum retention periods are enforced per conformance level (Section 8.1) | MUST |
| NL-5.13 | HMAC-SHA256 is supported for additional integrity (Section 3.5) | SHOULD |
| NL-5.14 | External checkpoints are published periodically (Section 4.4) | SHOULD |
| NL-5.15 | Incremental verification runs automatically on a schedule (Section 5.2) | SHOULD |
| NL-5.16 | Cross-platform correlation via correlation_id is supported (Section 8.2.1) | SHOULD |
| NL-5.17 | Audit entries are scanned for secret leakage before writing (Section 2.5) | SHOULD |
| NL-5.18 | Centralized audit aggregator for cross-platform queries (Section 8.2.2) | MAY |
| NL-5.19 | Compliance mapping metadata extensions are supported (Section 9.5) | MAY |
| NL-5.20 | Full-text search on audit entry detail field (Section 6.2) | MAY |

## 13. References

- [RFC 2119 -- Key words for use in RFCs](https://www.rfc-editor.org/rfc/rfc2119)
- [RFC 6234 -- US Secure Hash Algorithms (SHA and SHA-based HMAC and HKDF)](https://www.rfc-editor.org/rfc/rfc6234)
- [RFC 8785 -- JSON Canonicalization Scheme (JCS)](https://www.rfc-editor.org/rfc/rfc8785)
- [RFC 8915 -- Network Time Security for the Network Time Protocol](https://www.rfc-editor.org/rfc/rfc8915)
- [RFC 3161 -- Internet X.509 PKI Time-Stamp Protocol (TSP)](https://www.rfc-editor.org/rfc/rfc3161)
- [NIST SP 800-92 -- Guide to Computer Security Log Management](https://csrc.nist.gov/publications/detail/sp/800-92/final)
- [SOC 2 Trust Service Criteria](https://us.aicpa.org/interestareas/frc/assuranceadvisoryservices/trustservicescriteria)
- [ISO/IEC 27001:2022 -- Information Security Management Systems](https://www.iso.org/isoiec-27001-information-security.html)
- [GDPR -- General Data Protection Regulation](https://gdpr.eu/)
