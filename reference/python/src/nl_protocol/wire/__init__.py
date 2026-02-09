"""NL Protocol wire-protocol subpackage -- message framing, serialisation, and transport.

This subpackage implements the wire protocol layer defined in Chapter 08
of the NL Protocol specification.  It provides:

* **Message models** -- envelope, error payloads, serialisation, and
  validation helpers (:mod:`~nl_protocol.wire.messages`).
* **NDJSON transport** -- reader, writer, and stdio transport for the
  stdin/stdout binding (:mod:`~nl_protocol.wire.ndjson`).
* **HTTP transport** -- client and server-side handler for the HTTP
  binding (:mod:`~nl_protocol.wire.http`).
* **Discovery** -- ``/.well-known/nl-protocol`` document creation and
  serialisation (:mod:`~nl_protocol.wire.discovery`).
"""
from __future__ import annotations

# -- Discovery --------------------------------------------------------------
from nl_protocol.wire.discovery import (
    DiscoveryDocument,
    create_discovery_document,
    serialize_discovery,
)

# -- HTTP transport ---------------------------------------------------------
from nl_protocol.wire.http import (
    HTTPTransport,
    create_http_handler,
)

# -- Messages (existing) ---------------------------------------------------
from nl_protocol.wire.messages import (
    NL_CONTENT_TYPE,
    NL_CONTENT_TYPE_COMPAT,
    NL_PROTOCOL_VERSION,
    VALID_MESSAGE_TYPES,
    ErrorPayload,
    ErrorResponse,
    MessageEnvelope,
    format_error_dict,
    format_error_response,
    negotiate_version,
    parse_message,
    serialize_message,
    validate_content_type,
    validate_timestamp,
)

# -- NDJSON transport -------------------------------------------------------
from nl_protocol.wire.ndjson import (
    DEFAULT_MAX_MESSAGE_SIZE,
    DEFAULT_PARTIAL_TIMEOUT,
    NDJSONReader,
    NDJSONWriter,
    StdioTransport,
)

__all__ = [
    # Messages
    "NL_CONTENT_TYPE",
    "NL_CONTENT_TYPE_COMPAT",
    "NL_PROTOCOL_VERSION",
    "VALID_MESSAGE_TYPES",
    "MessageEnvelope",
    "ErrorPayload",
    "ErrorResponse",
    "format_error_response",
    "format_error_dict",
    "parse_message",
    "serialize_message",
    "negotiate_version",
    "validate_content_type",
    "validate_timestamp",
    # NDJSON
    "DEFAULT_MAX_MESSAGE_SIZE",
    "DEFAULT_PARTIAL_TIMEOUT",
    "NDJSONReader",
    "NDJSONWriter",
    "StdioTransport",
    # HTTP
    "HTTPTransport",
    "create_http_handler",
    # Discovery
    "DiscoveryDocument",
    "create_discovery_document",
    "serialize_discovery",
]
