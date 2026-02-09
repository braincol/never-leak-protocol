# NL Protocol Specification v1.0 -- Chapter 08: Wire Protocol, Transport & Error Handling

**Status:** 1.0
**Version:** 1.0.0
**Date:** 2026-02-08

> **Note:** This document is a SPECIFICATION. It defines required behaviors,
> data formats, and protocols — not specific products or CLI commands.
> For implementations of this specification, see [IMPLEMENTATIONS.md](../../IMPLEMENTATIONS.md).

---

## 1. Introduction

Chapters 01 through 07 of the NL Protocol define **what** components communicate:
agent identities, action requests, scope grants, audit records, delegation tokens,
and revocation signals. This chapter defines **how** those messages are transported
between components -- the wire format, transport bindings, API surface, error
taxonomy, service discovery, and operational mechanisms that enable interoperability
between independently developed NL-compliant implementations.

Without a wire protocol specification, two implementations that both conform to
Chapters 01-07 may be unable to communicate. Implementation A might encode
messages as Protocol Buffers over gRPC while Implementation B expects JSON over
REST. Implementation A might return errors as HTTP 500 with plain text bodies while
Implementation B expects structured error objects with machine-readable codes.
This chapter eliminates such incompatibilities.

### 1.1 Goals

This chapter aims to:

1. **Enable interoperability.** Two NL-compliant systems from different vendors
   MUST be able to exchange messages without vendor-specific adaptation.
2. **Define a canonical message format.** All NL Protocol messages MUST have a
   single, unambiguous JSON representation.
3. **Standardize error handling.** Every failure mode in the protocol MUST map to
   a well-defined error code with consistent structure.
4. **Support multiple transports.** The protocol MUST work over local IPC, HTTP,
   and within the MCP ecosystem.
5. **Enable discovery.** NL-compliant systems MUST be discoverable through a
   well-known endpoint.

### 1.2 Relationship to Other Chapters

This chapter is a cross-cutting concern that touches every other chapter:

- **Chapter 01 (Agent Identity)**: Defines the registration and identity
  verification API endpoints and message formats.
- **Chapter 02 (Action-Based Access)**: Defines the action request/response
  wire format and the scope grant management API.
- **Chapter 03 (Execution Isolation)**: Transport is orthogonal to isolation;
  the isolation boundary exists within the NL Provider regardless of transport.
- **Chapter 04 (Pre-Execution Defense)**: Error codes for blocked actions are
  defined here.
- **Chapter 05 (Audit Integrity)**: Defines the audit query API endpoint and
  audit export format.
- **Chapter 06 (Attack Detection)**: Error codes for detected attacks are
  defined here.
- **Chapter 07 (Cross-Agent Trust)**: Defines the delegation and revocation API
  endpoints and the federated transport requirements (mTLS).

---

## 2. Transport Bindings

The NL Protocol is transport-agnostic at its core: the message semantics defined
in Chapters 01-07 are independent of how messages move between components.
However, to ensure interoperability, this section defines standard transport
bindings with specific requirements for each.

### 2.1 Transport Overview

```
+========================================================================+
|                      NL PROTOCOL TRANSPORT BINDINGS                     |
+========================================================================+
|                                                                        |
|  LOCAL (Same-Host) Transports                                          |
|  +------------------------------------------------------------------+ |
|  | Unix Domain Sockets   | RECOMMENDED for local agent-to-provider  | |
|  | stdin/stdout Pipes    | MUST for MCP-style subprocess servers    | |
|  | Local HTTP (loopback) | MAY for development and debugging        | |
|  +------------------------------------------------------------------+ |
|                                                                        |
|  Network Transports                                                    |
|  +------------------------------------------------------------------+ |
|  | HTTPS (TLS 1.2+)     | MUST for all network communication       | |
|  | mTLS                  | MUST for cross-organization federation   | |
|  | gRPC over TLS         | MAY as an alternative to HTTP/JSON       | |
|  +------------------------------------------------------------------+ |
|                                                                        |
|  Agent Framework Integration                                           |
|  +------------------------------------------------------------------+ |
|  | MCP (stdio transport) | RECOMMENDED for AI agent ecosystems      | |
|  | MCP (SSE transport)   | MAY for web-based agent frontends        | |
|  | A2A Protocol          | MAY for inter-agent delegation messages  | |
|  +------------------------------------------------------------------+ |
|                                                                        |
+========================================================================+
```

### 2.2 Local Transport: Unix Domain Sockets

Unix domain sockets are the RECOMMENDED transport for same-host communication
between an agent process and an NL Provider process.

**Socket path convention:**

```
/tmp/nl-protocol/<organization_id>/<provider_id>.sock
```

Or, using the XDG runtime directory when available:

```
$XDG_RUNTIME_DIR/nl-protocol/<provider_id>.sock
```

**Requirements:**

| Requirement | Level | Description |
|-------------|-------|-------------|
| Socket permissions | MUST | The socket file MUST have permissions `0o660` (owner and group read/write). |
| Message framing | MUST | Messages MUST be framed using newline-delimited JSON (NDJSON). Each message is a single line of JSON followed by `\n` (0x0A). |
| Content type | MUST | Messages MUST be valid NL Protocol JSON (Section 3). |
| Authentication | MUST | The connecting process MUST authenticate using the agent credential (Chapter 01, Section 9.4). The credential MUST be passed as the first message in the connection (a `handshake` message type). |
| Connection lifecycle | SHOULD | Connections SHOULD be persistent for the duration of an agent session. Implementations SHOULD support connection pooling. |

**Handshake message:**

```json
{
  "nl_version": "1.0",
  "message_type": "handshake",
  "message_id": "msg_550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2026-02-08T10:00:00.000Z",
  "payload": {
    "agent_uri": "nl://anthropic.com/claude-code/1.5.2",
    "instance_id": "550e8400-e29b-41d4-a716-446655440000",
    "credential": "nlk_live_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
    "attestation": "eyJhbGciOiJFUzI1NiIs..."
  }
}
```

**Handshake response:**

```json
{
  "nl_version": "1.0",
  "message_type": "handshake_ack",
  "message_id": "msg_660f9511-f30c-52e5-b827-557766551111",
  "timestamp": "2026-02-08T10:00:00.050Z",
  "payload": {
    "status": "authenticated",
    "session_id": "sess_770a0622-a41d-63f6-c938-668877662222",
    "server_capabilities": {
      "nl_version": "1.0",
      "action_types": ["exec", "template", "inject_stdin", "inject_tempfile", "sdk_proxy"],
      "max_message_size_bytes": 1048576,
      "rate_limit": {
        "requests_per_minute": 120
      }
    }
  }
}
```

### 2.3 Local Transport: stdin/stdout Pipes

The stdin/stdout transport is REQUIRED for implementations that integrate with
the Model Context Protocol (MCP) using the stdio transport. In this model, the
NL Provider runs as a subprocess of the agent host, and communication occurs
through the process's standard streams.

**Requirements:**

| Requirement | Level | Description |
|-------------|-------|-------------|
| Message framing | MUST | Messages MUST be framed using newline-delimited JSON (NDJSON) on stdout. Each message is a single line of JSON followed by `\n`. |
| Input format | MUST | Requests MUST be written to the subprocess's stdin as NDJSON. |
| Stderr usage | MUST NOT | Stderr MUST NOT be used for protocol messages. Implementations MAY use stderr for diagnostic logging, but diagnostic output MUST NOT contain secret values. |
| Content type | MUST | Messages MUST be valid NL Protocol JSON (Section 3). |
| Authentication | MUST | The agent credential MUST be passed via environment variable (e.g., `NL_AGENT_CREDENTIAL`) at process startup, NOT through stdin. |

**NDJSON Message Framing Requirements:**

JSON messages transmitted over stdio MUST NOT contain unescaped newline characters (`\n`) within string values. Newlines in strings MUST be escaped as `\\n`. Each complete JSON message MUST be followed by exactly one newline character (`\n`). Implementations MUST buffer partial reads until a complete JSON object followed by newline is received. Maximum message size over stdio: 1 MiB. Messages exceeding this MUST be rejected with error NL-E800.

**Additional NDJSON framing requirements:**

1. **Control character escaping**: All ASCII control characters (U+0000 through U+001F) except the newline delimiter (`\n`, U+000A) between messages MUST be escaped using JSON escape sequences (`\uXXXX`) within string values. This includes but is not limited to: null (U+0000), tab (U+0009), carriage return (U+000D), and form feed (U+000C). Unescaped control characters within JSON string values MUST cause the message to be rejected with error `NL-E800`.

2. **Binary data prohibition**: Binary data (non-UTF-8 bytes) MUST NOT appear in NL Protocol messages. If a secret value or action result contains non-UTF-8 bytes, it MUST be Base64-encoded before inclusion in the message, and the corresponding field MUST be annotated with `"encoding": "base64"` to signal the receiver to decode it. Receivers MUST check the `encoding` field and decode Base64 content before use.

3. **Partial message timeout**: Partial messages (incomplete JSON objects resulting from fragmented reads) MUST be buffered with a timeout. If a complete message (a valid JSON object followed by `\n`) is not received within 30 seconds (configurable via provider settings), the partial buffer MUST be discarded and the connection SHOULD be reset. Implementations MUST log partial message timeouts as diagnostic events (not security incidents) for troubleshooting.

4. **Empty line handling**: Empty lines (bare `\n` characters, i.e., zero-length lines between messages) MUST be silently ignored by receivers. Senders SHOULD NOT emit empty lines, but receivers MUST tolerate them to support interoperability with implementations that may insert whitespace between messages.

**Example interaction (stdin/stdout):**

```
--> stdin:  {"nl_version":"1.0","message_type":"action_request","message_id":"msg_001",...}\n
<-- stdout: {"nl_version":"1.0","message_type":"action_response","message_id":"msg_002",...}\n
```

### 2.4 Local Transport: HTTP over Loopback

Implementations MAY support HTTP over the loopback interface (`127.0.0.1` or
`::1`) for local development and debugging. This binding follows the same API
surface as the network HTTP binding (Section 5) but operates over unencrypted
HTTP on loopback only.

**Requirements:**

| Requirement | Level | Description |
|-------------|-------|-------------|
| Binding address | MUST | The server MUST bind to loopback only (`127.0.0.1` or `::1`). It MUST NOT bind to `0.0.0.0` or any non-loopback address without TLS. |
| Port | SHOULD | Default port SHOULD be `9741` (the letters "NL" on a phone keypad: 6-5, reversed and padded). Implementations MUST support configurable port numbers. |
| TLS | MAY | TLS is OPTIONAL for loopback-only bindings. |

### 2.5 Network Transport: HTTPS

HTTPS is the REQUIRED transport for all network communication between
NL-compliant systems that are not on the same host.

**Requirements:**

| Requirement | Level | Description |
|-------------|-------|-------------|
| TLS version | MUST | TLS 1.2 or higher. TLS 1.3 is RECOMMENDED. |
| Certificate validation | MUST | Server certificates MUST be validated against trusted certificate authorities. Self-signed certificates MUST NOT be accepted in production. |
| Cipher suites | SHOULD | Implementations SHOULD prefer AEAD cipher suites (e.g., `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`). |
| Content-Type | MUST | Requests and responses MUST use `Content-Type: application/nl-protocol+json` (Section 3.2). |
| Authentication | MUST | Requests MUST include authentication via the `Authorization` header using Bearer token scheme: `Authorization: Bearer <agent_credential>`. |
| HSTS | SHOULD | Servers SHOULD send the `Strict-Transport-Security` header. |

### 2.6 Network Transport: mTLS

Mutual TLS (mTLS) is the REQUIRED transport for cross-organization
federation (Chapter 07, Section 6). In mTLS, both the client and server present
certificates, providing mutual authentication at the transport layer.

**Requirements:**

| Requirement | Level | Description |
|-------------|-------|-------------|
| Client certificate | MUST | The client MUST present a valid X.509 certificate during the TLS handshake. |
| Certificate chain | MUST | The certificate chain MUST be rooted in a CA that the federation partner trusts, as configured in the Federation Agreement Document (Chapter 07, Section 6.2.3). |
| Subject validation | MUST | The server MUST verify that the client certificate's Subject Alternative Name (SAN) matches the expected federation partner domain. |
| Certificate rotation | SHOULD | Implementations SHOULD support automated certificate rotation with overlap periods to avoid service disruption. |

### 2.7 Network Transport: gRPC

Implementations MAY support gRPC as an alternative to HTTP/JSON for
high-throughput or latency-sensitive deployments.

**Requirements (when gRPC is supported):**

| Requirement | Level | Description |
|-------------|-------|-------------|
| TLS | MUST | gRPC connections MUST use TLS. Plaintext gRPC MUST NOT be used in production. |
| Message format | MUST | gRPC messages MUST use Protocol Buffers v3 with a schema that maps 1:1 to the canonical JSON format (Section 3). |
| Reflection | SHOULD | gRPC servers SHOULD support server reflection for tooling compatibility. |
| Compatibility | MUST | Implementations that support gRPC MUST also support HTTP/JSON. gRPC is an additional binding, not a replacement. |

### 2.8 MCP Integration

The Model Context Protocol (MCP) is the primary mechanism by which AI agents
discover and invoke tools. NL Protocol operations SHOULD be exposed as MCP
tools so that NL-compliant systems integrate naturally into the AI agent
ecosystem.

**MCP tool mapping:**

| MCP Tool Name | NL Protocol Operation | Chapter |
|---------------|----------------------|---------|
| `nl_execute_action` | Submit action request | 02 |
| `nl_register_agent` | Register agent | 01 |
| `nl_get_agent` | Get agent identity | 01 |
| `nl_create_delegation` | Create delegation token | 07 |
| `nl_revoke_delegation` | Revoke delegation token | 07 |
| `nl_query_audit` | Query audit log | 05 |
| `nl_revoke_agent` | Revoke agent/scope | 07 |
| `nl_discover` | Discovery | 08 |

**MCP tool definition example (`nl_execute_action`):**

```json
{
  "name": "nl_execute_action",
  "description": "Execute an action that requires secrets. Secrets are referenced using {{nl:...}} placeholders and are NEVER returned to the agent. Only the action result is returned.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "action_type": {
        "type": "string",
        "enum": ["exec", "template", "inject_stdin", "inject_tempfile", "sdk_proxy", "delegate"],
        "description": "The type of action to perform."
      },
      "template": {
        "type": "string",
        "description": "Command template with {{nl:...}} placeholders for secrets."
      },
      "context": {
        "type": "object",
        "properties": {
          "project": { "type": "string" },
          "environment": { "type": "string" }
        }
      },
      "purpose": {
        "type": "string",
        "description": "Why this action is needed. Recorded in audit trail."
      },
      "timeout_ms": {
        "type": "integer",
        "default": 30000,
        "description": "Maximum execution time in milliseconds."
      },
      "dry_run": {
        "type": "boolean",
        "default": false,
        "description": "Validate permissions without executing."
      }
    },
    "required": ["action_type", "template"]
  }
}
```

#### MCP Tool: `nl_execute_action`

```json
{
  "name": "nl_execute_action",
  "description": "Execute an action with NL Protocol secret resolution",
  "inputSchema": {
    "type": "object",
    "properties": {
      "action_type": { "type": "string", "enum": ["exec", "template", "inject_stdin", "inject_tempfile"] },
      "template": { "type": "string", "description": "Command template with {{nl:...}} placeholders" },
      "purpose": { "type": "string", "description": "Human-readable purpose for audit" },
      "scope": { "type": "object", "properties": { "project": { "type": "string" }, "environment": { "type": "string" } } },
      "dry_run": { "type": "boolean", "default": false }
    },
    "required": ["action_type", "template", "purpose"]
  }
}
```

#### MCP Tool: `nl_list_secrets`

```json
{
  "name": "nl_list_secrets",
  "description": "List available secret names (not values) for the current agent",
  "inputSchema": {
    "type": "object",
    "properties": {
      "scope": { "type": "object", "properties": { "project": { "type": "string" }, "environment": { "type": "string" } } }
    }
  }
}
```

#### MCP Tool: `nl_check_access`

```json
{
  "name": "nl_check_access",
  "description": "Check if the agent has access to a specific secret",
  "inputSchema": {
    "type": "object",
    "properties": {
      "secret_name": { "type": "string" },
      "action_type": { "type": "string", "enum": ["exec", "template", "inject_stdin", "inject_tempfile"] }
    },
    "required": ["secret_name"]
  }
}
```

**MCP integration requirements:**

| Requirement | Level | Description |
|-------------|-------|-------------|
| Tool naming | SHOULD | MCP tools implementing NL Protocol operations SHOULD use the `nl_` prefix. |
| Agent identity | MUST | The agent's identity MUST be established during MCP server initialization (via environment variables or configuration), not per-tool-call. |
| Secret protection | MUST | MCP tool responses MUST NOT contain secret values. The same sanitization requirements as Chapter 02, Section 9 apply. |
| Error mapping | MUST | NL Protocol errors (Section 6) MUST be mapped to MCP tool error responses with the full error structure preserved in the error content. |

---

## 3. Message Format

### 3.1 Canonical Encoding

JSON is the canonical encoding for all NL Protocol messages. Every NL-compliant
system MUST support JSON encoding. Systems that additionally support other
encodings (Protocol Buffers, MessagePack, CBOR) MUST ensure lossless
round-trip conversion to and from JSON.

**Requirements:**

| Requirement | Level | Description |
|-------------|-------|-------------|
| JSON support | MUST | All implementations MUST support JSON (RFC 8259) as the message encoding. |
| UTF-8 | MUST | JSON messages MUST be encoded as UTF-8. No BOM. |
| Canonical form | SHOULD | For signature computation and hash chain integrity, implementations SHOULD use JSON Canonicalization Scheme (JCS, RFC 8785). |
| Maximum size | SHOULD | Implementations SHOULD support messages up to 1 MiB (1,048,576 bytes). Messages exceeding this size SHOULD be rejected with error `NL-E800`. |
| Pretty printing | MAY | Implementations MAY accept pretty-printed JSON but MUST accept minified JSON. |

### 3.2 Media Type

The NL Protocol defines a custom media type for its messages:

```
application/nl-protocol+json
```

This media type MUST be used in the `Content-Type` header for HTTP requests and
responses carrying NL Protocol messages. Implementations MUST also accept
`application/json` for backward compatibility, but SHOULD prefer the custom
media type.

**Registration details (per RFC 6838):**

| Field | Value |
|-------|-------|
| Type name | `application` |
| Subtype name | `nl-protocol+json` |
| Required parameters | None |
| Optional parameters | `version` (e.g., `version=1.0`) |
| Encoding | UTF-8 |
| Structured suffix | `+json` (RFC 6839) |

### 3.3 Message Envelope

Every NL Protocol message -- regardless of transport -- MUST be wrapped in a
standard envelope:

```json
{
  "nl_version": "1.0",
  "message_type": "<type>",
  "message_id": "<uuid-v4>",
  "timestamp": "<ISO-8601 UTC with milliseconds>",
  "payload": { }
}
```

**Envelope field definitions:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `nl_version` | string | MUST | The NL Protocol version. MUST be `"1.0"` for this specification. |
| `message_type` | string | MUST | The type of message. See Section 3.4 for the complete list. |
| `message_id` | string | MUST | A globally unique identifier for this message. UUID v4 is RECOMMENDED. Used for correlation, idempotency, and replay prevention. |
| `timestamp` | string | MUST | ISO 8601 timestamp with millisecond precision in UTC (e.g., `"2026-02-08T10:30:00.000Z"`). |
| `payload` | object | MUST | The message-type-specific payload. The schema depends on `message_type`. |

### 3.4 Message Types

The following message types are defined by the NL Protocol v1.0:

```
+==========================================================================+
|                        NL PROTOCOL MESSAGE TYPES                          |
+==========================================================================+
|                                                                          |
|  Identity & Registration (Chapter 01)                                    |
|  +--------------------------------------------------------------------+ |
|  | handshake              | Initial connection authentication          | |
|  | handshake_ack          | Server acknowledgment of handshake        | |
|  | agent_register         | Register a new agent                      | |
|  | agent_register_ack     | Registration response with AID            | |
|  | agent_get              | Retrieve agent identity                   | |
|  | agent_get_response     | Agent identity document                   | |
|  +--------------------------------------------------------------------+ |
|                                                                          |
|  Action Lifecycle (Chapters 02, 03, 04)                                  |
|  +--------------------------------------------------------------------+ |
|  | action_request         | Submit an action for execution             | |
|  | action_response        | Action result (success, denied, error)     | |
|  +--------------------------------------------------------------------+ |
|                                                                          |
|  Delegation & Revocation (Chapter 07)                                    |
|  +--------------------------------------------------------------------+ |
|  | delegation_request     | Request a delegation token                 | |
|  | delegation_response    | Delegation token reference                 | |
|  | delegation_revoke      | Revoke a delegation token                  | |
|  | delegation_revoke_ack  | Revocation acknowledgment                  | |
|  | revocation_request     | Revoke an agent or scope                   | |
|  | revocation_response    | Revocation result                          | |
|  +--------------------------------------------------------------------+ |
|                                                                          |
|  Audit (Chapter 05)                                                      |
|  +--------------------------------------------------------------------+ |
|  | audit_query            | Query the audit log                        | |
|  | audit_query_response   | Audit query results                        | |
|  +--------------------------------------------------------------------+ |
|                                                                          |
|  Discovery & Operational (Chapter 08)                                    |
|  +--------------------------------------------------------------------+ |
|  | discovery_request      | Request server capabilities                | |
|  | discovery_response     | Server capabilities and endpoints          | |
|  | error                  | Standalone error message                   | |
|  | rotation_notification  | Secret rotation notification               | |
|  +--------------------------------------------------------------------+ |
|                                                                          |
|  Federation (Chapter 07)                                                 |
|  +--------------------------------------------------------------------+ |
|  | federated_action       | Cross-organization action request          | |
|  | federated_response     | Cross-organization action response         | |
|  | federation_revocation  | Cross-organization revocation propagation  | |
|  | federation_revocation_ack | Revocation propagation acknowledgment   | |
|  +--------------------------------------------------------------------+ |
|                                                                          |
+==========================================================================+
```

**Payload schemas:** Each message type's payload schema is defined in the
chapter that governs the corresponding operation. The following table maps
message types to their payload schemas:

| Message Type | Payload Schema Reference | Chapter |
|-------------|--------------------------|---------|
| `handshake` | Section 2.2 of this chapter | 08 |
| `handshake_ack` | Section 2.2 of this chapter | 08 |
| `agent_register` | Chapter 01, Section 9.2 | 01 |
| `agent_register_ack` | Chapter 01, Section 9.3 | 01 |
| `agent_get` | `{ "agent_uri": "...", "instance_id": "..." }` | 01 |
| `agent_get_response` | Chapter 01, Section 4.2 (AID) | 01 |
| `action_request` | Chapter 02, Section 6.1 | 02 |
| `action_response` | Chapter 02, Section 7.1 | 02 |
| `delegation_request` | Chapter 07, Section 3.1 (token request) | 07 |
| `delegation_response` | `{ "token_id": "...", "expires_at": "..." }` | 07 |
| `delegation_revoke` | `{ "token_id": "...", "reason": "..." }` | 07 |
| `delegation_revoke_ack` | `{ "token_id": "...", "status": "revoked" }` | 07 |
| `revocation_request` | Chapter 07, Section 7.2 | 07 |
| `revocation_response` | Chapter 07, Section 7.6 | 07 |
| `audit_query` | Chapter 05, Section 6.1 | 05 |
| `audit_query_response` | Chapter 05, Section 6.1 (result format) | 05 |
| `discovery_request` | Section 7.1 of this chapter | 08 |
| `discovery_response` | Section 7.2 of this chapter | 08 |
| `error` | Section 6.2 of this chapter | 08 |
| `rotation_notification` | Section 8.4 of this chapter | 08 |
| `federated_action` | Chapter 07, Section 6.3 | 07 |
| `federated_response` | Chapter 07, Section 6.3 (response) | 07 |
| `federation_revocation` | Chapter 07, Section 7.2 | 07 |
| `federation_revocation_ack` | Chapter 07, Section 7.6 | 07 |

### 3.5 Message ID Requirements

Message IDs serve three purposes: correlation, idempotency, and replay
prevention.

1. **Correlation:** A response message SHOULD include a `correlation_id` field
   in its payload that references the `message_id` of the request it responds to.

2. **Idempotency:** If a sender retransmits a message with the same
   `message_id`, the receiver MUST return the same response without
   re-executing the operation. Implementations MUST maintain an idempotency
   cache for at least 5 minutes.

3. **Replay prevention:** Receivers MUST reject messages with a `message_id`
   that has already been processed (within the idempotency window). The
   rejection MUST use error code `NL-E802`.

### 3.6 Timestamp Requirements

All timestamps in NL Protocol messages MUST conform to:

- ISO 8601 format with millisecond precision.
- UTC timezone (indicated by trailing `Z`).
- Example: `"2026-02-08T10:30:00.000Z"`.

Implementations MUST reject messages with timestamps more than 5 minutes in the
future (allowing for clock skew). Implementations SHOULD reject messages with
timestamps more than 5 minutes in the past for real-time transports (not
applicable to audit queries).

---

## 4. Full Message Examples

### 4.1 Action Request (Complete Wire Format)

```json
{
  "nl_version": "1.0",
  "message_type": "action_request",
  "message_id": "msg_550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2026-02-08T14:30:00.000Z",
  "payload": {
    "agent": {
      "agent_uri": "nl://anthropic.com/claude-code/1.5.2",
      "instance_id": "550e8400-e29b-41d4-a716-446655440000",
      "attestation": "eyJhbGciOiJFUzI1NiIs..."
    },
    "action": {
      "type": "exec",
      "template": "curl -H 'Authorization: Bearer {{nl:api/GITHUB_TOKEN}}' https://api.github.com/user",
      "context": {
        "project": "braincol",
        "environment": "development"
      },
      "purpose": "Verify GitHub API access for CI setup",
      "timeout_ms": 30000,
      "dry_run": false
    }
  }
}
```

### 4.2 Action Response (Success)

```json
{
  "nl_version": "1.0",
  "message_type": "action_response",
  "message_id": "msg_660f9511-f30c-52e5-b827-557766551111",
  "timestamp": "2026-02-08T14:30:00.250Z",
  "payload": {
    "correlation_id": "msg_550e8400-e29b-41d4-a716-446655440000",
    "request_id": "req_550e8400-e29b-41d4-a716-446655440000",
    "action_id": "act_660f9511-f30c-52e5-b827-557766551111",
    "status": "success",
    "result": {
      "stdout": "{\"login\":\"acme-bot\",\"id\":12345}",
      "stderr": "",
      "exit_code": 0
    },
    "secrets_used": ["api/GITHUB_TOKEN"],
    "redacted": false,
    "redacted_count": 0,
    "audit_ref": "aud_770a0622-a41d-63f6-c938-668877662222",
    "timing": {
      "received_at": "2026-02-08T14:30:00.000Z",
      "resolved_at": "2026-02-08T14:30:00.050Z",
      "executed_at": "2026-02-08T14:30:00.055Z",
      "completed_at": "2026-02-08T14:30:00.250Z",
      "total_ms": 250
    }
  }
}
```

### 4.3 Action Response (Error)

```json
{
  "nl_version": "1.0",
  "message_type": "action_response",
  "message_id": "msg_770a0622-a41d-63f6-c938-668877662222",
  "timestamp": "2026-02-08T14:30:00.050Z",
  "payload": {
    "correlation_id": "msg_550e8400-e29b-41d4-a716-446655440000",
    "status": "denied",
    "error": {
      "code": "NL-E200",
      "message": "No active Scope Grant covers secret 'production/DB_PASSWORD' for action type 'exec'.",
      "detail": {
        "secret_ref": "production/DB_PASSWORD",
        "action_type": "exec",
        "agent_scope": {
          "environments": ["development", "staging"]
        },
        "required_scope": {
          "environments": ["production"]
        }
      },
      "resolution": "Request a Scope Grant for the 'production' environment from your administrator.",
      "doc_url": "https://nlprotocol.org/docs/errors/NL-E200"
    },
    "secrets_used": [],
    "redacted": false,
    "audit_ref": "aud_880b1733-b52e-74a7-d049-779988773333"
  }
}
```

### 4.4 Delegation Request

```json
{
  "nl_version": "1.0",
  "message_type": "delegation_request",
  "message_id": "msg_880b1733-b52e-74a7-d049-779988773333",
  "timestamp": "2026-02-08T14:35:00.000Z",
  "payload": {
    "issuer": "nl://anthropic.com/claude-code/1.5.2",
    "issuer_instance_id": "550e8400-e29b-41d4-a716-446655440000",
    "subject": "nl://acme.corp/deploy-bot/2.1.0",
    "scope": {
      "secrets": ["k8s/DEPLOY_TOKEN"],
      "actions": ["exec"],
      "max_uses": 1,
      "resource_constraints": {
        "exec": {
          "allowed_commands": ["kubectl apply *"]
        }
      }
    },
    "ttl_seconds": 300
  }
}
```

### 4.5 Rotation Notification

```json
{
  "nl_version": "1.0",
  "message_type": "rotation_notification",
  "message_id": "msg_990c2844-c63f-85b8-e150-880099884444",
  "timestamp": "2026-02-08T15:00:00.000Z",
  "payload": {
    "secret_ref": "api/GITHUB_TOKEN",
    "previous_version": "v3",
    "new_version": "v4",
    "rotation_id": "rot_aa0d3955-d740-96c9-f261-991100995555",
    "grace_period_ends": "2026-02-08T16:00:00.000Z",
    "reason": "scheduled_rotation"
  }
}
```

---

## 5. API Endpoints (HTTP/REST Binding)

For the HTTP transport binding, the NL Protocol defines a RESTful API surface.
All endpoints are relative to a base URL that is advertised through the
discovery mechanism (Section 7).

### 5.1 Base URL Convention

```
https://<host>:<port>/nl/v1
```

The version segment (`v1`) corresponds to the major version of the NL Protocol.
When a new major version is released, a new base path (`/nl/v2`) MUST be used.

### 5.2 Version Negotiation

Clients MUST include `nl_version` in the request envelope. If the server does not support the requested version, it MUST respond with error NL-E801 and include `supported_versions` array in the error detail. The client MAY retry with a supported version from the list. Major version changes (v1->v2) require separate API paths: `/nl/v1/...` and `/nl/v2/...`. Minor version changes within the same major version MUST be backward compatible.

### 5.3 Endpoint Summary

```
+==========================================================================+
|                        NL PROTOCOL API ENDPOINTS                          |
+==========================================================================+
|                                                                          |
|  Identity & Registration                                                 |
|  +--------------------------------------------------------------------+ |
|  | POST   /nl/v1/agents/register     | Register a new agent           | |
|  | GET    /nl/v1/agents/{agent_id}    | Get agent identity document    | |
|  +--------------------------------------------------------------------+ |
|                                                                          |
|  Actions                                                                 |
|  +--------------------------------------------------------------------+ |
|  | POST   /nl/v1/actions              | Submit an action request       | |
|  +--------------------------------------------------------------------+ |
|                                                                          |
|  Delegation & Revocation                                                 |
|  +--------------------------------------------------------------------+ |
|  | POST   /nl/v1/delegations          | Create a delegation token      | |
|  | DELETE /nl/v1/delegations/{id}     | Revoke a delegation token      | |
|  | POST   /nl/v1/revocations          | Revoke an agent or scope       | |
|  +--------------------------------------------------------------------+ |
|                                                                          |
|  Audit                                                                   |
|  +--------------------------------------------------------------------+ |
|  | GET    /nl/v1/audit                | Query audit log                | |
|  +--------------------------------------------------------------------+ |
|                                                                          |
|  Discovery & Health                                                      |
|  +--------------------------------------------------------------------+ |
|  | GET    /.well-known/nl-protocol    | Discovery endpoint             | |
|  | GET    /nl/v1/health               | Health check                   | |
|  +--------------------------------------------------------------------+ |
|                                                                          |
+==========================================================================+
```

### 5.4 Endpoint Specifications

#### 5.4.1 POST /nl/v1/agents/register

Register a new agent with the NL-compliant system.

| Property | Value |
|----------|-------|
| **Method** | `POST` |
| **Path** | `/nl/v1/agents/register` |
| **Authentication** | Admin credential (Bearer token) or organization API key |
| **Content-Type** | `application/nl-protocol+json` |
| **Request body** | Chapter 01, Section 9.2 (Registration Request) |
| **Success response** | `201 Created` with Chapter 01, Section 9.3 (Registration Response) |
| **Error responses** | `400 Bad Request` (NL-E800), `401 Unauthorized` (NL-E100), `409 Conflict` (agent already registered) |
| **Rate limit** | 10 requests per minute per organization |
| **Idempotent** | No. Each call creates a new agent instance. |

#### 5.4.2 GET /nl/v1/agents/{agent_id}

Retrieve the Agent Identity Document for a registered agent.

| Property | Value |
|----------|-------|
| **Method** | `GET` |
| **Path** | `/nl/v1/agents/{agent_id}` where `agent_id` is the `instance_id` (UUID) |
| **Authentication** | Agent credential or admin credential (Bearer token) |
| **Success response** | `200 OK` with AID (Chapter 01, Section 4.2). The credential field MUST NOT be included. |
| **Error responses** | `401 Unauthorized` (NL-E100), `404 Not Found` (NL-E100 with detail) |
| **Rate limit** | 60 requests per minute per agent |
| **Idempotent** | Yes |

#### 5.4.3 POST /nl/v1/actions

Submit an action request for execution.

| Property | Value |
|----------|-------|
| **Method** | `POST` |
| **Path** | `/nl/v1/actions` |
| **Authentication** | Agent credential (Bearer token) |
| **Content-Type** | `application/nl-protocol+json` |
| **Request body** | Chapter 02, Section 6.1 (Action Request) |
| **Success response** | `200 OK` with Chapter 02, Section 7.1 (Action Response) |
| **Error responses** | `400 Bad Request` (NL-E800, NL-E300, NL-E301), `401 Unauthorized` (NL-E100, NL-E101), `403 Forbidden` (NL-E200, NL-E201, NL-E202, NL-E400, NL-E401), `404 Not Found` (NL-E302), `408 Request Timeout` (NL-E303), `429 Too Many Requests` (NL-E202) |
| **Rate limit** | 120 requests per minute per agent (configurable via Scope Grant) |
| **Idempotent** | Yes (same `request_id` returns cached response) |

#### 5.4.4 POST /nl/v1/delegations

Create a delegation token.

| Property | Value |
|----------|-------|
| **Method** | `POST` |
| **Path** | `/nl/v1/delegations` |
| **Authentication** | Agent credential of the delegating agent (Bearer token) |
| **Content-Type** | `application/nl-protocol+json` |
| **Request body** | Delegation token request (Chapter 07, Section 3) |
| **Success response** | `201 Created` with `{ "token_id": "...", "expires_at": "..." }` |
| **Error responses** | `400 Bad Request` (NL-E800), `401 Unauthorized` (NL-E100), `403 Forbidden` (NL-E200, subset rule violation), `422 Unprocessable Entity` (invalid delegation constraints) |
| **Rate limit** | 30 requests per minute per agent |
| **Idempotent** | No. Each call creates a new delegation token. |

#### 5.4.5 DELETE /nl/v1/delegations/{token_id}

Revoke a delegation token.

| Property | Value |
|----------|-------|
| **Method** | `DELETE` |
| **Path** | `/nl/v1/delegations/{token_id}` where `token_id` is the delegation token UUID |
| **Authentication** | Agent credential of the issuer, or admin credential (Bearer token) |
| **Success response** | `200 OK` with `{ "token_id": "...", "status": "revoked", "cascade_count": <N> }` |
| **Error responses** | `401 Unauthorized` (NL-E100), `403 Forbidden` (not the issuer or admin), `404 Not Found` (NL-E700) |
| **Rate limit** | 60 requests per minute |
| **Idempotent** | Yes. Revoking an already-revoked token returns success. |

#### 5.4.6 GET /nl/v1/audit

Query the audit log.

| Property | Value |
|----------|-------|
| **Method** | `GET` |
| **Path** | `/nl/v1/audit` |
| **Authentication** | Admin credential (Bearer token). Agents MUST NOT query their own audit entries (Chapter 05, Section 6.3). |
| **Query parameters** | `agent_uri`, `target`, `from` (ISO 8601), `to` (ISO 8601), `correlation_id`, `result`, `platform`, `page`, `page_size` (max 100, default 50) |
| **Success response** | `200 OK` with paginated audit entries (Chapter 05, Section 6.1) |
| **Error responses** | `401 Unauthorized` (NL-E100), `403 Forbidden` (NL-E500), `400 Bad Request` (invalid query parameters) |
| **Rate limit** | 30 requests per minute |
| **Idempotent** | Yes |

#### 5.4.7 POST /nl/v1/revocations

Revoke an agent or scope.

| Property | Value |
|----------|-------|
| **Method** | `POST` |
| **Path** | `/nl/v1/revocations` |
| **Authentication** | Admin credential (Bearer token) |
| **Content-Type** | `application/nl-protocol+json` |
| **Request body** | Chapter 07, Section 7.2 (Revocation Request) |
| **Success response** | `200 OK` with Chapter 07, Section 7.6 (Revocation Response) |
| **Error responses** | `401 Unauthorized` (NL-E100), `403 Forbidden` (insufficient privileges), `404 Not Found` (agent not found) |
| **Rate limit** | 10 requests per minute |
| **Idempotent** | Yes. Re-revoking a revoked agent returns success. |

#### 5.4.8 GET /.well-known/nl-protocol

Discovery endpoint. See Section 7 for full specification.

| Property | Value |
|----------|-------|
| **Method** | `GET` |
| **Path** | `/.well-known/nl-protocol` |
| **Authentication** | None required (public endpoint) |
| **Success response** | `200 OK` with discovery document (Section 7.2) |
| **Error responses** | `503 Service Unavailable` |
| **Rate limit** | 60 requests per minute (per source IP) |
| **Idempotent** | Yes |
| **Cache** | Response SHOULD include `Cache-Control: max-age=3600` |

#### 5.4.9 GET /nl/v1/health

Health check endpoint for load balancers and monitoring.

| Property | Value |
|----------|-------|
| **Method** | `GET` |
| **Path** | `/nl/v1/health` |
| **Authentication** | None required |
| **Success response** | `200 OK` with `{ "status": "healthy", "nl_version": "1.0", "timestamp": "..." }` |
| **Error responses** | `503 Service Unavailable` with `{ "status": "unhealthy", "reason": "..." }` |
| **Rate limit** | 300 requests per minute |

### 5.6 Content-Type Handling

Servers MUST reject requests with `Content-Type` other than `application/json` or `application/nl-protocol+json` with HTTP 415 (Unsupported Media Type).

### 5.7 Common HTTP Headers

All HTTP requests to the NL Protocol API MUST include:

| Header | Required | Description |
|--------|----------|-------------|
| `Content-Type` | MUST (for POST/PUT) | `application/nl-protocol+json` |
| `Accept` | SHOULD | `application/nl-protocol+json` |
| `Authorization` | MUST (except discovery and health) | `Bearer <credential>` |
| `X-NL-Request-ID` | SHOULD | UUID matching the `message_id`. Enables log correlation across proxy layers. |
| `X-NL-Agent-URI` | SHOULD | The agent's URI. Informational; not used for authentication. |

All HTTP responses from the NL Protocol API MUST include:

| Header | Required | Description |
|--------|----------|-------------|
| `Content-Type` | MUST | `application/nl-protocol+json` |
| `X-NL-Request-ID` | MUST | Echo of the request's `X-NL-Request-ID`, or a server-generated UUID if the request did not include one. |
| `X-NL-RateLimit-Limit` | SHOULD | Maximum requests per window (Section 9). |
| `X-NL-RateLimit-Remaining` | SHOULD | Remaining requests in the current window. |
| `X-NL-RateLimit-Reset` | SHOULD | Unix timestamp when the rate limit window resets. |

---

## 6. Error Handling

### 6.1 Design Principles

Error handling in the NL Protocol follows three principles:

1. **Structured and machine-readable.** Every error response MUST be a valid
   JSON object with a consistent schema. Agents and automation MUST be able to
   parse and act on error responses programmatically.

2. **Informative and educational.** Error responses MUST include a human-readable
   message, a machine-readable code, and a resolution suggestion. Following the
   design philosophy of Chapter 04 (Pre-Execution Defense): "Educate, do not
   merely block."

3. **No secret leakage.** Error responses MUST NOT contain secret values, even
   when the error is related to secret resolution or access. Error messages
   MUST reference secrets by name or path, NEVER by value.

### 6.2 Error Response Format

All error responses MUST conform to the following structure, which is inspired
by RFC 7807 (Problem Details for HTTP APIs):

```json
{
  "error": {
    "code": "NL-EXXX",
    "message": "Human-readable error description.",
    "detail": {
    },
    "resolution": "Suggested action to resolve the error.",
    "doc_url": "https://nlprotocol.org/docs/errors/NL-EXXX"
  }
}
```

**Error object field definitions:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `code` | string | MUST | The NL Protocol error code (see Section 6.3). Format: `NL-EXXX` where XXX is a three-digit number. |
| `message` | string | MUST | A human-readable description of the error. MUST NOT contain secret values. |
| `detail` | object | SHOULD | A machine-readable object with additional context specific to the error code. Schema varies by error code. |
| `resolution` | string | SHOULD | A suggested action the agent or operator can take to resolve the error. |
| `doc_url` | string | MAY | A URL pointing to documentation for this error code. |

When an error occurs within an action response, the error object is embedded in
the action response payload (as shown in Chapter 02, Section 7.4). When an error
occurs outside of an action context (e.g., malformed request, authentication
failure), the error is returned as a standalone message with `message_type: "error"`.

### 6.3 Error Code Taxonomy

The NL Protocol defines a hierarchical error code taxonomy. Error codes are
organized by category, with each category corresponding to a protocol layer.

```
+==========================================================================+
|                    NL PROTOCOL ERROR CODE TAXONOMY                        |
+==========================================================================+
|                                                                          |
|  NL-E1xx  Authentication & Identity Errors        (Chapter 01)           |
|  NL-E2xx  Authorization & Scope Errors            (Chapter 02)           |
|  NL-E3xx  Action Execution Errors                 (Chapters 02, 03)      |
|  NL-E4xx  Defense & Interception Errors           (Chapter 04)           |
|  NL-E5xx  Audit Errors                            (Chapter 05)           |
|  NL-E6xx  Detection & Threat Errors               (Chapter 06)           |
|  NL-E7xx  Federation & Delegation Errors          (Chapter 07)           |
|  NL-E8xx  Transport & Protocol Errors             (Chapter 08)           |
|                                                                          |
+==========================================================================+
```

### 6.4 NL-E1xx: Authentication & Identity Errors

| Code | HTTP Status | Name | Description | Resolution |
|------|-------------|------|-------------|------------|
| NL-E100 | 401 | Invalid Agent | The agent identity could not be verified. The credential is missing, malformed, or does not match any registered agent. | Verify the agent credential is correct and the agent is registered. |
| NL-E101 | 401 | Expired Attestation | The agent's attestation JWT has expired. The `exp` claim is in the past. | Obtain a fresh attestation JWT from the platform provider. |
| NL-E102 | 403 | Trust Level Insufficient | The agent's trust level does not meet the minimum required for the requested operation. | Upgrade the agent's trust level by obtaining vendor attestation or third-party certification. |
| NL-E103 | 403 | Agent Suspended | The agent's lifecycle state is `suspended`. Suspended agents cannot perform actions. | Contact the administrator to reactivate the agent. |
| NL-E104 | 403 | Agent Revoked | The agent's lifecycle state is `revoked`. Revoked agents are permanently disabled. | Register a new agent instance. |
| NL-E105 | 401 | AID Expired | The agent identity document has expired (`expires_at` is in the past). | Re-register or renew the agent identity. |
| NL-E106 | 401 | Attestation Signature Invalid | The attestation JWT's signature could not be verified against the platform provider's public key. | Ensure the attestation was signed by the correct platform provider key. |
| NL-E107 | 401 | Replay Detected | The attestation JWT's `jti` has already been used. This may indicate a replay attack. | Generate a new attestation with a fresh `jti`. |
| NL-E108 | 403 | Capability Not Granted | The agent's AID does not include the requested action type in its `capabilities` list. | Request the capability be added to the agent's registration. |

### 6.5 NL-E2xx: Authorization & Scope Errors

| Code | HTTP Status | Name | Description | Resolution |
|------|-------------|------|-------------|------------|
| NL-E200 | 403 | No Scope Grant | No active Scope Grant covers the requested secret for the requested action type. | Request a Scope Grant from the administrator. |
| NL-E201 | 403 | Scope Expired | The Scope Grant that would authorize this action has expired (`valid_until` is in the past). | Request a new Scope Grant with an updated validity window. |
| NL-E202 | 429 | Use Limit Exceeded | The Scope Grant's `max_uses` limit has been reached. No further actions are authorized under this grant. | Request a new Scope Grant or contact the administrator to increase the limit. |
| NL-E203 | 403 | Environment Restricted | The Scope Grant does not include the target environment. | Request a Scope Grant that includes the target environment. |
| NL-E204 | 403 | Human Approval Required | The Scope Grant requires `require_human_approval: true` and no approval has been obtained for this action. | Request human approval through the approval workflow. |
| NL-E205 | 403 | Context Mismatch | The Scope Grant's `allowed_contexts` do not match the agent's current session context. | Verify you are operating in the correct repository, branch, or workspace. |
| NL-E206 | 403 | Concurrent Limit | The Scope Grant's `max_concurrent` limit has been reached. | Wait for in-flight actions to complete before submitting new ones. |

### 6.6 NL-E3xx: Action Execution Errors

| Code | HTTP Status | Name | Description | Resolution |
|------|-------------|------|-------------|------------|
| NL-E300 | 400 | Unknown Action Type | The `action.type` field contains an unrecognized action type. | Use one of the supported action types: `exec`, `template`, `inject_stdin`, `inject_tempfile`, `sdk_proxy`, `delegate`. |
| NL-E301 | 400 | Invalid Placeholder | A `{{nl:...}}` placeholder in the action template is malformed or does not conform to the grammar (Chapter 02, Section 4.1). | Verify the placeholder syntax matches the ABNF grammar. |
| NL-E302 | 404 | Secret Not Found | The referenced secret does not exist in any accessible scope. | Verify the secret name and path. Use a fully qualified reference to avoid ambiguity. |
| NL-E303 | 408 | Execution Timeout | The action execution exceeded the configured timeout (`timeout_ms`). The process has been terminated. | Increase the timeout or optimize the command. Maximum timeout is 600000 ms (10 minutes). |
| NL-E304 | 400 | Ambiguous Reference | A simple secret reference matched multiple secrets across accessible scopes. | Use a categorized, scoped, or fully qualified reference to disambiguate. |
| NL-E305 | 502 | Provider Unavailable | The cross-provider secret backend (e.g., AWS Secrets Manager) is unavailable. | Retry after a delay. Check the status of the external secret provider. |
| NL-E306 | 400 | Provider Not Configured | The cross-provider reference targets a provider that is not configured. | Configure the secret provider bridge or use a local secret reference. |
| NL-E307 | 500 | Isolation Failure | The isolated execution environment could not be established. | This is an internal error. Contact the system administrator. |
| NL-E308 | 500 | Sanitization Failure | Output sanitization failed. The response has been withheld to prevent potential secret leakage. | This is an internal error. The action may have succeeded, but the result cannot be safely returned. |

### 6.7 NL-E4xx: Defense & Interception Errors

| Code | HTTP Status | Name | Description | Resolution |
|------|-------------|------|-------------|------------|
| NL-E400 | 403 | Action Blocked | The action was blocked by a deny rule in the Pre-Execution Defense layer (Chapter 04). | Review the deny rule and use the NL Protocol-compliant alternative described in the `detail.alternative` field. |
| NL-E401 | 403 | Evasion Detected | The action contains patterns consistent with an attempt to evade deny rules (encoding bypass, indirect execution, shell expansion). | Use the action-based access model (Chapter 02). Do not attempt to circumvent security controls. |
| NL-E402 | 403 | Interceptor Unavailable | The Pre-Execution Interceptor is unavailable and the system is configured to fail closed. | The interceptor must be restored before actions can be processed. Contact the administrator. |

### 6.8 NL-E5xx: Audit Errors

| Code | HTTP Status | Name | Description | Resolution |
|------|-------------|------|-------------|------------|
| NL-E500 | 500 | Chain Integrity Failure | The audit hash chain has detected a potential integrity issue. The system is operating in a degraded security state. | Initiate a full chain verification (Chapter 05, Section 5.1). Contact the security team. |
| NL-E501 | 403 | Audit Query Denied | The requester does not have permission to query the audit log. Agents are prohibited from querying their own audit entries. | Audit queries must be performed by authorized administrators. |
| NL-E502 | 500 | Audit Write Failure | The audit entry could not be written. The action has been blocked to maintain audit integrity. | This is an internal error. The audit subsystem must be operational for actions to proceed. |

### 6.9 NL-E6xx: Detection & Threat Errors

| Code | HTTP Status | Name | Description | Resolution |
|------|-------------|------|-------------|------------|
| NL-E600 | 403 | Threat Level Exceeded | The agent's cumulative threat score has exceeded the threshold for the requested action type. | The agent's behavior has triggered anomaly detection. Reduce the threat score by operating within normal parameters, or contact the administrator for review. |
| NL-E601 | 403 | Agent Revoked By Detection | The agent has been automatically revoked by the attack detection system in response to a confirmed or high-confidence attack. | A new agent instance must be registered after security review. |
| NL-E602 | 403 | Honeypot Triggered | The agent accessed a honeypot token (Chapter 06). This indicates a potential exfiltration attempt. | This event has been flagged as a security incident. Contact the security team. |

### 6.10 NL-E7xx: Federation & Delegation Errors

| Code | HTTP Status | Name | Description | Resolution |
|------|-------------|------|-------------|------------|
| NL-E700 | 404 | Unknown Trust Domain | The federated secret reference targets a trust domain that is not registered as a federation partner. | Establish a federation agreement with the target organization (Chapter 07, Section 6.2). |
| NL-E701 | 403 | Federation Agreement Expired | The federation agreement with the target organization has expired. | Renew the federation agreement. |
| NL-E702 | 403 | Delegation Subset Violation | The requested delegation scope is not a strict subset of the delegator's scope. | Narrow the delegation scope to fit within your current permissions. |
| NL-E703 | 403 | Delegation Depth Exceeded | The maximum delegation chain depth has been reached. Further re-delegation is not permitted. | The delegate must execute the action directly, without further delegation. |
| NL-E704 | 400 | Invalid Delegation Token | The delegation token is malformed, has an invalid signature, or references an unknown issuer. | Verify the delegation token was issued by a valid, registered agent. |
| NL-E705 | 403 | Delegation Token Expired | The delegation token has expired (`expires_at` is in the past). | Request a new delegation token from the delegator. |
| NL-E706 | 429 | Delegation Use Limit | The delegation token's `max_uses` limit has been reached. | Request a new delegation token. |
| NL-E707 | 403 | Delegation Token Revoked | The delegation token has been explicitly revoked by the issuer or an ancestor in the chain. | Request a new delegation token. |
| NL-E708 | 502 | Federation Partner Unavailable | The federated partner's NL Provider is not reachable. | Retry after a delay. Check the partner's NL Provider status. |
| NL-E709 | 403 | Federation Action Not Allowed | The requested action type is not permitted by the federation agreement policy. | Review the federation agreement's `allowed_action_types`. |

### 6.11 NL-E8xx: Transport & Protocol Errors

| Code | HTTP Status | Name | Description | Resolution |
|------|-------------|------|-------------|------------|
| NL-E800 | 400 | Malformed Message | The request body is not valid JSON or does not conform to the NL Protocol message envelope schema. | Verify the message is valid JSON and includes all required envelope fields (`nl_version`, `message_type`, `message_id`, `timestamp`, `payload`). |
| NL-E801 | 400 | Version Mismatch | The `nl_version` field specifies a version that is not supported by this server. | Use a supported NL Protocol version. Query the discovery endpoint to determine supported versions. |
| NL-E802 | 409 | Replay Detected | A message with this `message_id` has already been processed. | Generate a new `message_id` (UUID v4) for each unique request. |
| NL-E803 | 413 | Message Too Large | The request body exceeds the maximum allowed message size. | Reduce the message size. The maximum is advertised in the discovery document. |
| NL-E804 | 415 | Unsupported Media Type | The `Content-Type` header is not `application/nl-protocol+json` or `application/json`. | Set the `Content-Type` header to `application/nl-protocol+json`. |
| NL-E805 | 400 | Invalid Timestamp | The message timestamp is too far in the future or too far in the past. | Synchronize the client clock using NTP. Timestamps must be within 5 minutes of server time. |
| NL-E806 | 400 | Unknown Message Type | The `message_type` field is not a recognized NL Protocol message type. | Use a valid message type from the list in Section 3.4. |

### 6.12 Error Code Convention

Error codes follow the convention `NL-E{L}XX` where `{L}` is the protocol level (1-8) and `XX` is a sequential number within that level. The level corresponds to the chapter that governs the error's domain:

| Level | Chapter | Error Domain |
|-------|---------|--------------|
| 1 | Chapter 01 | Authentication & Identity |
| 2 | Chapter 02 | Authorization & Scope |
| 3 | Chapters 02, 03 | Action Execution |
| 4 | Chapter 04 | Defense & Interception |
| 5 | Chapter 05 | Audit |
| 6 | Chapter 06 | Detection & Threat |
| 7 | Chapter 07 | Federation & Delegation |
| 8 | Chapter 08 | Transport & Protocol |

Implementations MUST return the `code` field as a string (e.g., `"NL-E100"`, not the integer `100`). Implementations MAY include additional vendor-specific error codes prefixed with `NL-EX` (e.g., `NL-EX01`). Vendor-specific codes MUST follow the same error response format defined in Section 6.2 and MUST NOT conflict with any code in the `NL-E1xx` through `NL-E8xx` ranges reserved by this specification.

---

## 7. Discovery Protocol

### 7.1 Purpose

The discovery protocol enables agents and other NL-compliant systems to discover
the capabilities, endpoints, and configuration of an NL Provider without prior
knowledge of its specific implementation. This follows the pattern established by
RFC 8615 (Well-Known URIs).

### 7.2 Well-Known URL

Every NL-compliant system that exposes an HTTP transport MUST serve a discovery
document at:

```
GET /.well-known/nl-protocol
```

The discovery endpoint MUST be served over HTTPS. HTTP requests MUST be rejected or redirected to HTTPS with a 301 response. Implementations MUST NOT serve the discovery document over unencrypted HTTP, even in development environments. TLS 1.2 is the minimum required version. TLS 1.3 SHOULD be preferred.

The discovery document MUST be served without authentication. It MUST NOT
contain secret values or sensitive configuration details.

**Discovery document schema:**

```json
{
  "nl_protocol": {
    "versions": ["1.0"],
    "preferred_version": "1.0"
  },
  "provider": {
    "name": "Braincol NL Provider",
    "vendor": "braincol.com",
    "version": "0.1.0",
    "documentation_url": "https://docs.braincol.com/nl-protocol"
  },
  "endpoints": {
    "base_url": "https://nl.braincol.com/nl/v1",
    "actions": "/nl/v1/actions",
    "agents_register": "/nl/v1/agents/register",
    "agents_get": "/nl/v1/agents/{agent_id}",
    "delegations": "/nl/v1/delegations",
    "delegations_revoke": "/nl/v1/delegations/{token_id}",
    "revocations": "/nl/v1/revocations",
    "audit": "/nl/v1/audit",
    "health": "/nl/v1/health"
  },
  "capabilities": {
    "conformance_level": "standard",
    "supported_levels": [1, 2, 3, 4, 5],
    "action_types": ["exec", "template", "inject_stdin", "inject_tempfile", "sdk_proxy"],
    "trust_levels": ["L0", "L1", "L2"],
    "credential_types": ["api_key", "bearer_token"],
    "max_message_size_bytes": 1048576,
    "max_timeout_ms": 600000,
    "supports_delegation": true,
    "supports_federation": false,
    "supports_dry_run": true,
    "supports_batch_actions": false
  },
  "security": {
    "jwks_uri": "https://nl.braincol.com/.well-known/nl-protocol/jwks.json",
    "attestation_issuers": [
      {
        "issuer": "anthropic.com",
        "jwks_uri": "https://anthropic.com/.well-known/nl-protocol/jwks.json"
      },
      {
        "issuer": "openai.com",
        "jwks_uri": "https://openai.com/.well-known/nl-protocol/jwks.json"
      }
    ],
    "rate_limiting": {
      "enabled": true,
      "default_requests_per_minute": 120
    }
  },
  "federation": {
    "enabled": false,
    "trust_domain": "nl://braincol.com",
    "partners": []
  }
}
```

### 7.3 Discovery Document Field Definitions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `nl_protocol.versions` | string[] | MUST | List of NL Protocol versions supported by this server. |
| `nl_protocol.preferred_version` | string | MUST | The preferred version for new connections. |
| `provider.name` | string | MUST | Human-readable name of the NL Provider implementation. |
| `provider.vendor` | string | MUST | Domain of the organization that operates this provider. |
| `provider.version` | string | SHOULD | Implementation version string. |
| `provider.documentation_url` | string | MAY | URL to implementation-specific documentation. |
| `endpoints.base_url` | string | MUST | The base URL for all API endpoints. |
| `endpoints.*` | string | MUST | Relative or absolute paths for each supported endpoint. |
| `capabilities.conformance_level` | string | MUST | One of: `"basic"`, `"standard"`, `"advanced"`. |
| `capabilities.supported_levels` | integer[] | MUST | List of NL Protocol levels (1-7) that are implemented. |
| `capabilities.action_types` | string[] | MUST | List of supported action types. |
| `capabilities.trust_levels` | string[] | MUST | List of supported trust levels. |
| `capabilities.credential_types` | string[] | MUST | List of supported credential types. |
| `capabilities.max_message_size_bytes` | integer | SHOULD | Maximum accepted message size. |
| `capabilities.max_timeout_ms` | integer | SHOULD | Maximum allowed action timeout. |
| `capabilities.supports_delegation` | boolean | MUST | Whether delegation tokens are supported. |
| `capabilities.supports_federation` | boolean | MUST | Whether cross-organization federation is supported. |
| `capabilities.supports_dry_run` | boolean | SHOULD | Whether dry run mode is supported. |
| `capabilities.supports_batch_actions` | boolean | MAY | Whether batch action requests are supported. |
| `security.jwks_uri` | string | SHOULD | URL to the provider's JSON Web Key Set for token verification. |
| `security.attestation_issuers` | array | SHOULD | List of trusted attestation issuers with their JWKS URIs. |
| `security.rate_limiting.enabled` | boolean | SHOULD | Whether rate limiting is active. |
| `federation.enabled` | boolean | MUST (if Level 7 supported) | Whether federation is active. |
| `federation.trust_domain` | string | MUST (if federation enabled) | This provider's trust domain identifier. |
| `federation.partners` | string[] | MAY | List of federated partner domains (if publicly disclosed). |

### 7.4 Discovery Caching

Discovery documents SHOULD be cached by clients. The server SHOULD include
appropriate HTTP caching headers:

```
Cache-Control: public, max-age=3600
ETag: "v1-2026020801"
```

Clients SHOULD refresh the discovery document:
- At least once per hour during active operation.
- Immediately when an `NL-E801` (version mismatch) error is received.
- Immediately when a connection to a new NL Provider is established.

---

## 8. Secret Rotation & Versioning

### 8.1 Secret Version Syntax

The NL Protocol supports versioned secret references to enable safe rotation.
The version suffix is appended to the standard placeholder syntax:

```
{{nl:path/SECRET_NAME@version}}
```

**Version formats:**

| Format | Meaning | Example |
|--------|---------|---------|
| `@latest` | Resolve to the current (newest) version. This is the default when no version is specified. | `{{nl:api/TOKEN@latest}}` |
| `@v<N>` | Resolve to a specific numbered version. | `{{nl:api/TOKEN@v3}}` |
| `@previous` | Resolve to the version immediately before `@latest`. Useful during rotation grace periods. | `{{nl:api/TOKEN@previous}}` |
| (no suffix) | Equivalent to `@latest`. | `{{nl:api/TOKEN}}` |

**Requirements:**

| Requirement | Level | Description |
|-------------|-------|-------------|
| Version syntax | MUST | Implementations MUST support the `@latest` and `@v<N>` version suffixes. |
| Default version | MUST | When no version suffix is specified, `@latest` MUST be assumed. |
| Previous version | SHOULD | Implementations SHOULD support the `@previous` suffix. |
| Version immutability | MUST | Once a version number is assigned, its value MUST NOT change. New values MUST receive new version numbers. |

### 8.2 Rotation Protocol

Secret rotation follows a defined protocol to ensure continuity of service:

```
+==============================================================================+
|                       SECRET ROTATION LIFECYCLE                               |
+==============================================================================+
|                                                                              |
|  Phase 1: NEW VERSION CREATED                                                |
|  +------------------------------------------------------------------------+  |
|  | - New secret value is stored as version v(N+1)                         |  |
|  | - @latest now resolves to v(N+1)                                       |  |
|  | - @previous resolves to v(N)                                           |  |
|  | - v(N) remains accessible by explicit reference (@v<N>)                |  |
|  +------------------------------------------------------------------------+  |
|                                                                              |
|  Phase 2: NOTIFICATION                                                       |
|  +------------------------------------------------------------------------+  |
|  | - rotation_notification message is sent to all subscribed agents        |  |
|  | - Notification includes: secret_ref, previous_version, new_version,    |  |
|  |   grace_period_ends                                                     |  |
|  +------------------------------------------------------------------------+  |
|                                                                              |
|  Phase 3: GRACE PERIOD                                                       |
|  +------------------------------------------------------------------------+  |
|  | - Both v(N) and v(N+1) are accessible                                  |  |
|  | - Agents using @latest automatically get v(N+1)                         |  |
|  | - Agents using @v<N> explicitly still get the old value                 |  |
|  | - RECOMMENDED grace period: 1 hour (configurable)                       |  |
|  +------------------------------------------------------------------------+  |
|                                                                              |
|  Phase 4: OLD VERSION DEPRECATED                                             |
|  +------------------------------------------------------------------------+  |
|  | - v(N) is marked as deprecated                                         |  |
|  | - Access to v(N) is still possible but generates a WARNING audit entry  |  |
|  | - RECOMMENDED deprecation period: 24 hours after grace period           |  |
|  +------------------------------------------------------------------------+  |
|                                                                              |
|  Phase 5: OLD VERSION REMOVED                                                |
|  +------------------------------------------------------------------------+  |
|  | - v(N) is removed from the secret store                                |  |
|  | - Access attempts for v(N) return NL-E302 (Secret Not Found)           |  |
|  | - Removal is recorded in the audit trail                               |  |
|  +------------------------------------------------------------------------+  |
|                                                                              |
+==============================================================================+
```

### 8.3 Rotation Notification Delivery

Rotation notifications can be delivered through two models:

**Webhook (push) model:**

The NL Provider sends a `rotation_notification` message to registered webhook
endpoints when a secret is rotated.

```
POST https://agent-service.example.com/nl/webhooks
Content-Type: application/nl-protocol+json
X-NL-Signature: sha256=<HMAC-SHA256 of request body using webhook secret>

{
  "nl_version": "1.0",
  "message_type": "rotation_notification",
  "message_id": "msg_990c2844-c63f-85b8-e150-880099884444",
  "timestamp": "2026-02-08T15:00:00.000Z",
  "payload": {
    "secret_ref": "api/GITHUB_TOKEN",
    "previous_version": "v3",
    "new_version": "v4",
    "rotation_id": "rot_aa0d3955-d740-96c9-f261-991100995555",
    "grace_period_ends": "2026-02-08T16:00:00.000Z",
    "reason": "scheduled_rotation"
  }
}
```

**Polling model:**

Agents or agent services poll the NL Provider for rotation events:

```
GET /nl/v1/rotations?since=2026-02-08T14:00:00.000Z&secrets=api/*
Authorization: Bearer <credential>
```

**Requirements:**

| Requirement | Level | Description |
|-------------|-------|-------------|
| Notification mechanism | MUST | Implementations MUST support at least one notification mechanism (webhook or polling). |
| Webhook signature | MUST | Webhook notifications MUST include an HMAC-SHA256 signature in the `X-NL-Signature` header for verification. |
| Grace period | MUST | Implementations MUST support a configurable grace period during which both old and new versions are accessible. |
| Audit | MUST | All rotation events MUST be recorded in the audit trail, including the rotation ID, secret reference, and the identity of the initiator. |

### 8.4 Rotation Audit Requirements

Every phase of the rotation lifecycle MUST produce an audit entry:

| Phase | Audit Action | Audit Detail |
|-------|-------------|--------------|
| New version created | `rotate` | `{"secret_ref": "...", "new_version": "v4", "initiated_by": "..."}` |
| Notification sent | `rotation_notification` | `{"secret_ref": "...", "recipients_notified": 3}` |
| Grace period ended | `rotation_grace_expired` | `{"secret_ref": "...", "deprecated_version": "v3"}` |
| Old version removed | `rotation_cleanup` | `{"secret_ref": "...", "removed_version": "v3"}` |

---

## 9. Rate Limiting & Backpressure

### 9.1 Purpose

Rate limiting protects NL-compliant systems from abuse, denial of service, and
resource exhaustion. Rate limits are enforced at multiple granularities: per
agent, per scope grant, and per source IP.

### 9.2 Rate Limit Headers

All HTTP responses SHOULD include the following rate limit headers:

| Header | Type | Description |
|--------|------|-------------|
| `X-NL-RateLimit-Limit` | integer | The maximum number of requests allowed in the current window. |
| `X-NL-RateLimit-Remaining` | integer | The number of requests remaining in the current window. |
| `X-NL-RateLimit-Reset` | integer | Unix timestamp (seconds since epoch) when the current rate limit window resets. |

### 9.3 Rate Limit Response (429)

When a rate limit is exceeded, the server MUST respond with HTTP status `429
Too Many Requests` and the following body:

```json
{
  "error": {
    "code": "NL-E202",
    "message": "Rate limit exceeded. Maximum 120 requests per minute for this agent.",
    "detail": {
      "limit": 120,
      "window_seconds": 60,
      "reset_at": "2026-02-08T14:31:00.000Z",
      "retry_after_seconds": 15,
      "scope": "per_agent"
    },
    "resolution": "Wait 15 seconds before retrying. Consider batching actions if supported."
  }
}
```

The response MUST also include the `Retry-After` HTTP header:

```
HTTP/1.1 429 Too Many Requests
Retry-After: 15
X-NL-RateLimit-Limit: 120
X-NL-RateLimit-Remaining: 0
X-NL-RateLimit-Reset: 1738936260
Content-Type: application/nl-protocol+json
```

### 9.4 Rate Limit Algorithm

Rate limiting MUST use a sliding window algorithm (not fixed window) to prevent burst attacks at window boundaries. The window size is 60 seconds by default. When multiple rate limit categories apply (per-agent AND per-org), the most restrictive limit takes precedence. Failed requests (4xx/5xx responses) DO count toward rate limits.

### 9.5 Rate Limit Granularity

| Scope | Granularity | Default Limit | Configurable |
|-------|-------------|---------------|-------------|
| Per agent | By `instance_id` | 120 requests/minute | MUST |
| Per scope grant | By `grant_id` | Defined in `max_uses` and `max_concurrent` | MUST |
| Per source IP | By client IP address | 600 requests/minute | SHOULD |
| Per organization | By `organization_id` | 1000 requests/minute | SHOULD |
| Per endpoint | By API path | Varies (see Section 5.4) | MAY |

### 9.6 Backpressure Signaling

When an NL Provider is experiencing high load but has not yet reached hard rate
limits, it SHOULD signal backpressure to clients:

```
HTTP/1.1 200 OK
X-NL-RateLimit-Remaining: 5
X-NL-Backpressure: true
X-NL-Suggested-Delay-Ms: 500
```

Clients that receive `X-NL-Backpressure: true` SHOULD introduce a delay of at
least `X-NL-Suggested-Delay-Ms` milliseconds before the next request. Clients
MUST NOT be required to honor backpressure signals, but implementations that
do not honor them MAY be subject to hard rate limiting.

---

## 10. Conformance Requirements

The following conformance requirements apply to implementations of this chapter.
Each requirement is identified by a unique ID and specifies a compliance level
using RFC 2119 language.

| Requirement ID | Description | Level |
|---------------|-------------|-------|
| NL-8.1 | All NL Protocol messages MUST be encoded as JSON (Section 3.1). | MUST |
| NL-8.2 | All messages MUST use the standard envelope format (Section 3.3). | MUST |
| NL-8.3 | All message types defined in Section 3.4 that correspond to implemented levels MUST be supported. | MUST |
| NL-8.4 | Message IDs MUST be globally unique (UUID v4 RECOMMENDED) and MUST be used for idempotency and replay prevention (Section 3.5). | MUST |
| NL-8.5 | Timestamps MUST conform to ISO 8601 with millisecond precision in UTC (Section 3.6). | MUST |
| NL-8.6 | HTTP transport MUST use TLS 1.2 or higher for non-loopback connections (Section 2.5). | MUST |
| NL-8.7 | HTTP transport MUST use `Content-Type: application/nl-protocol+json` (Section 3.2). | MUST |
| NL-8.8 | HTTP transport MUST authenticate requests using Bearer token in the `Authorization` header (Section 2.5). | MUST |
| NL-8.9 | All error responses MUST conform to the error response format (Section 6.2). | MUST |
| NL-8.10 | All error codes from the taxonomy (Section 6.3) that correspond to implemented levels MUST be used. | MUST |
| NL-8.11 | Error responses MUST NOT contain secret values (Section 6.1). | MUST |
| NL-8.12 | The `/.well-known/nl-protocol` discovery endpoint MUST be served for HTTP transport (Section 7.2). | MUST |
| NL-8.13 | The discovery document MUST include all required fields (Section 7.3). | MUST |
| NL-8.14 | Secret version syntax (`@latest`, `@v<N>`) MUST be supported (Section 8.1). | MUST |
| NL-8.15 | Secret rotation MUST include a configurable grace period (Section 8.2). | MUST |
| NL-8.16 | All rotation events MUST be recorded in the audit trail (Section 8.4). | MUST |
| NL-8.17 | Rate limiting MUST be supported per agent (Section 9.4). | MUST |
| NL-8.18 | Rate limit exceeded responses MUST use HTTP 429 with `Retry-After` header and structured error body (Section 9.3). | MUST |
| NL-8.19 | The stdin/stdout pipe transport MUST use NDJSON framing (Section 2.3). | MUST |
| NL-8.20 | mTLS MUST be used for cross-organization federation (Section 2.6). | MUST |
| NL-8.21 | NL Protocol operations SHOULD be exposed as MCP tools with the `nl_` prefix (Section 2.8). | SHOULD |
| NL-8.22 | Rate limit headers SHOULD be included in all HTTP responses (Section 9.2). | SHOULD |
| NL-8.23 | Discovery documents SHOULD be cached with appropriate HTTP headers (Section 7.4). | SHOULD |
| NL-8.24 | Webhook rotation notifications SHOULD include HMAC-SHA256 signatures (Section 8.3). | SHOULD |
| NL-8.25 | The `@previous` version suffix SHOULD be supported (Section 8.1). | SHOULD |
| NL-8.26 | Backpressure signaling SHOULD be supported under high load (Section 9.5). | SHOULD |
| NL-8.27 | JSON Canonicalization Scheme (JCS, RFC 8785) SHOULD be used for signature and hash computations (Section 3.1). | SHOULD |
| NL-8.28 | gRPC MAY be supported as an additional transport binding (Section 2.7). | MAY |
| NL-8.29 | Batch action requests MAY be supported (discovery document advertises this capability). | MAY |
| NL-8.30 | Implementations MAY support Protocol Buffers as an additional encoding, but MUST also support JSON. | MAY |
| NL-8.31 | All error codes defined in Section 6 (NL-E1xx through NL-E8xx) MUST be implemented by providers claiming conformance to the corresponding level. | MUST |
| NL-8.32 | Vendor-specific error codes MUST use the `NL-EX` prefix and MUST NOT conflict with reserved ranges (NL-E100 through NL-E899). | MUST |

---

## 11. Security Considerations

### 11.1 Transport Security

All NL Protocol communication over a network MUST be encrypted using TLS 1.2 or
higher. Plaintext HTTP MUST NOT be used for non-loopback connections. This
requirement applies to all transport bindings: HTTPS, mTLS, gRPC, and WebSocket.

For local transports (Unix domain sockets, stdin/stdout pipes), encryption is
not required because communication does not traverse a network. However, Unix
domain socket permissions MUST be set to restrict access to authorized processes
only (Section 2.2).

### 11.2 Replay Protection

NL Protocol messages include both a `message_id` and a `timestamp`. Together,
these provide replay protection:

1. **Message ID uniqueness:** Each message MUST have a unique `message_id`.
   Receivers MUST maintain a set of recently seen message IDs (minimum retention:
   5 minutes) and MUST reject duplicates with error `NL-E802`.

2. **Timestamp freshness:** Messages with timestamps more than 5 minutes in
   the future or past MUST be rejected with error `NL-E805`.

3. **Attestation nonce:** Attestation JWTs include a `jti` (JWT ID) that
   provides additional replay protection at the identity level (Chapter 01,
   Section 8.3).

```
REPLAY PROTECTION LAYERS:

  Layer 1: Transport (TLS)
  +---------------------------------------------------------------+
  | TLS protects against network-level replay by encrypting and   |
  | authenticating each connection with fresh session keys.       |
  +---------------------------------------------------------------+

  Layer 2: Message ID
  +---------------------------------------------------------------+
  | Each message has a unique message_id. The receiver maintains  |
  | a rolling window of seen IDs and rejects duplicates.          |
  +---------------------------------------------------------------+

  Layer 3: Timestamp
  +---------------------------------------------------------------+
  | Messages must be fresh (within 5-minute window). Stale        |
  | messages are rejected even if their message_id is novel.      |
  +---------------------------------------------------------------+

  Layer 4: Attestation JTI (for identity-level operations)
  +---------------------------------------------------------------+
  | Attestation JWTs include a jti claim that is tracked          |
  | independently for the JWT's lifetime.                         |
  +---------------------------------------------------------------+
```

### 11.3 Message Integrity

For HTTP transports, TLS provides message integrity at the transport layer.
For higher assurance, implementations SHOULD sign critical messages (delegation
tokens, revocation requests, federation messages) using JWS (RFC 7515). The
signature covers the canonical JSON (RFC 8785) representation of the message
payload.

For the Unix domain socket and stdin/stdout transports, message integrity relies
on the OS-level guarantee that local IPC is not subject to man-in-the-middle
attacks. However, implementations SHOULD still validate message structure and
reject malformed messages.

### 11.4 Credential Security in Transit

Agent credentials MUST be transmitted only over encrypted channels. For HTTP
transport, the credential is carried in the `Authorization: Bearer` header,
which is protected by TLS. For stdin/stdout transport, the credential is passed
via environment variable at process startup, which does not traverse a network.

Credentials MUST NOT be included in:
- URL query strings (which may be logged by proxies and web servers).
- Message payloads (except during the handshake for Unix domain sockets).
- Log messages or diagnostic output.

### 11.5 Error Message Information Disclosure

Error messages MUST NOT reveal information that could aid an attacker:

1. Error messages MUST NOT contain secret values.
2. Error messages MUST NOT reveal the internal structure of the secret store
   (e.g., file paths, database table names).
3. Error messages MUST NOT reveal which specific validation step failed in a way
   that enables enumeration attacks (e.g., "agent not found" vs. "password
   incorrect" -- both should return `NL-E100`).
4. The `detail` object in error responses MUST be limited to information that
   the requester is authorized to see based on their authenticated identity.

### 11.6 Denial of Service Mitigation

Rate limiting (Section 9) is the primary defense against denial of service.
Additional mitigations:

1. **Message size limits:** Implementations MUST reject messages exceeding the
   configured maximum size (default: 1 MiB) with error `NL-E803`.
2. **Connection limits:** Implementations SHOULD limit the number of concurrent
   connections per agent and per source IP.
3. **Timeout enforcement:** All operations MUST have timeouts. Idle connections
   SHOULD be closed after a configurable period (RECOMMENDED: 5 minutes).
4. **Slowloris protection:** HTTP servers SHOULD enforce minimum data rates on
   incoming requests to prevent slow-read attacks.

### 11.7 Federation Security

Cross-organization federation introduces additional security considerations:

1. **mTLS authentication:** Federation partners MUST authenticate using mTLS
   (Section 2.6). This provides mutual authentication at the transport layer.
2. **Request signing:** Federated action requests SHOULD be signed by the
   requesting NL Provider's key for non-repudiation.
3. **Rate limiting:** Federation endpoints SHOULD have separate, more
   restrictive rate limits than local endpoints.
4. **Response validation:** Responses from federation partners MUST be validated
   for well-formedness and MUST be subject to output sanitization before
   returning to the requesting agent.

---

## 12. References

### Normative References

- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) -- Key words for use in
  RFCs to Indicate Requirement Levels
- [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515) -- JSON Web Signature (JWS)
- [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519) -- JSON Web Token (JWT)
- [RFC 7807](https://www.rfc-editor.org/rfc/rfc7807) -- Problem Details for
  HTTP APIs
- [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259) -- The JavaScript Object
  Notation (JSON) Data Interchange Format
- [RFC 8615](https://www.rfc-editor.org/rfc/rfc8615) -- Well-Known Uniform
  Resource Identifiers (URIs)
- [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) -- JSON Canonicalization
  Scheme (JCS)
- [RFC 6838](https://www.rfc-editor.org/rfc/rfc6838) -- Media Type
  Specifications and Registration Procedures
- [RFC 6839](https://www.rfc-editor.org/rfc/rfc6839) -- Additional Media Type
  Structured Syntax Suffixes

### Informative References

- [Model Context Protocol](https://modelcontextprotocol.io/) -- Anthropic's
  protocol for agent-tool interaction
- [gRPC](https://grpc.io/) -- A high-performance, open-source universal RPC
  framework
- [NDJSON](https://github.com/ndjson/ndjson-spec) -- Newline Delimited JSON
  specification
- [A2A Protocol](https://github.com/google/A2A) -- Google's Agent-to-Agent
  protocol

### NL Protocol References

- [00-overview.md](00-overview.md) -- NL Protocol Overview
- [01-agent-identity.md](01-agent-identity.md) -- Level 1: Agent Identity
- [02-action-based-access.md](02-action-based-access.md) -- Level 2: Action-Based Access
- [03-execution-isolation.md](03-execution-isolation.md) -- Level 3: Execution Isolation
- [04-pre-execution-defense.md](04-pre-execution-defense.md) -- Level 4: Pre-Execution Defense
- [05-audit-integrity.md](05-audit-integrity.md) -- Level 5: Audit Integrity
- [06-attack-detection.md](06-attack-detection.md) -- Level 6: Attack Detection & Response
- [07-cross-agent-trust.md](07-cross-agent-trust.md) -- Level 7: Cross-Agent Trust & Federation

---

*Copyright 2026 Braincol. This specification is licensed under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).*
