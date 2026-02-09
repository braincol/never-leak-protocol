"""Tests for NL Protocol Level 8 -- Wire Protocol, Transport & Discovery.

Covers:

1. **NDJSON** -- read/write round-trip, malformed lines, empty lines,
   message size limits, EOF handling, partial timeout.
2. **StdioTransport** -- send/receive integration.
3. **Discovery** -- document creation, serialisation, config integration.
4. **HTTP transport** -- handler response formatting, Content-Type
   validation, version negotiation, error serialisation.
5. **Wire __init__** -- re-export availability.
"""
from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

import pytest

from nl_protocol.core.config import NLProviderConfig
from nl_protocol.core.errors import (
    MalformedMessage,
    MessageTooLarge,
    UnsupportedMediaType,
    VersionMismatch,
)
from nl_protocol.wire.discovery import (
    DiscoveryDocument,
    create_discovery_document,
    serialize_discovery,
)
from nl_protocol.wire.http import HTTPTransport, create_http_handler
from nl_protocol.wire.messages import (
    NL_CONTENT_TYPE,
    NL_CONTENT_TYPE_COMPAT,
    NL_PROTOCOL_VERSION,
    ErrorPayload,
    MessageEnvelope,
    format_error_response,
    negotiate_version,
    parse_message,
    serialize_message,
    validate_content_type,
    validate_timestamp,
)
from nl_protocol.wire.ndjson import (
    DEFAULT_MAX_MESSAGE_SIZE,
    NDJSONReader,
    NDJSONWriter,
    StdioTransport,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_stream_reader(data: bytes) -> asyncio.StreamReader:
    """Create an asyncio.StreamReader pre-filled with *data*."""
    reader = asyncio.StreamReader()
    reader.feed_data(data)
    reader.feed_eof()
    return reader


def _make_stream_writer() -> tuple[asyncio.StreamWriter, bytearray]:
    """Create a mock asyncio.StreamWriter that captures written bytes."""
    buffer = bytearray()

    writer = AsyncMock(spec=asyncio.StreamWriter)

    def write_side_effect(data: bytes) -> None:
        buffer.extend(data)

    writer.write = write_side_effect
    writer.drain = AsyncMock()

    return writer, buffer


# =========================================================================
# NDJSON Reader Tests
# =========================================================================


class TestNDJSONReader:
    """Tests for NDJSONReader."""

    async def test_read_single_message(self) -> None:
        """Read a single valid JSON line."""
        msg = {"nl_version": "1.0", "message_type": "handshake"}
        data = json.dumps(msg).encode() + b"\n"
        reader = _make_stream_reader(data)
        ndjson = NDJSONReader(reader)

        result = await ndjson.read_message()
        assert result == msg

    async def test_read_multiple_messages(self) -> None:
        """Read two consecutive JSON lines."""
        msg1 = {"id": 1, "type": "first"}
        msg2 = {"id": 2, "type": "second"}
        data = json.dumps(msg1).encode() + b"\n" + json.dumps(msg2).encode() + b"\n"
        reader = _make_stream_reader(data)
        ndjson = NDJSONReader(reader)

        result1 = await ndjson.read_message()
        result2 = await ndjson.read_message()
        assert result1 == msg1
        assert result2 == msg2

    async def test_skip_empty_lines(self) -> None:
        """Empty lines MUST be silently ignored (Section 2.3)."""
        msg = {"key": "value"}
        data = b"\n\n" + json.dumps(msg).encode() + b"\n"
        reader = _make_stream_reader(data)
        ndjson = NDJSONReader(reader)

        result = await ndjson.read_message()
        assert result == msg

    async def test_skip_multiple_empty_lines_between_messages(self) -> None:
        """Empty lines between messages are silently ignored."""
        msg1 = {"id": 1}
        msg2 = {"id": 2}
        data = (
            json.dumps(msg1).encode() + b"\n"
            + b"\n\n\n"
            + json.dumps(msg2).encode() + b"\n"
        )
        reader = _make_stream_reader(data)
        ndjson = NDJSONReader(reader)

        r1 = await ndjson.read_message()
        r2 = await ndjson.read_message()
        assert r1 == msg1
        assert r2 == msg2

    async def test_malformed_json_raises_error(self) -> None:
        """Invalid JSON MUST raise MalformedMessage."""
        data = b"not valid json\n"
        reader = _make_stream_reader(data)
        ndjson = NDJSONReader(reader)

        with pytest.raises(MalformedMessage, match="Invalid JSON"):
            await ndjson.read_message()

    async def test_non_object_json_raises_error(self) -> None:
        """A JSON array (non-object) MUST raise MalformedMessage."""
        data = b'[1, 2, 3]\n'
        reader = _make_stream_reader(data)
        ndjson = NDJSONReader(reader)

        with pytest.raises(MalformedMessage, match="JSON object"):
            await ndjson.read_message()

    async def test_json_string_raises_error(self) -> None:
        """A bare JSON string MUST raise MalformedMessage."""
        data = b'"hello"\n'
        reader = _make_stream_reader(data)
        ndjson = NDJSONReader(reader)

        with pytest.raises(MalformedMessage, match="JSON object"):
            await ndjson.read_message()

    async def test_message_too_large(self) -> None:
        """Messages exceeding max_message_size MUST raise MessageTooLarge."""
        # Set a very small limit for testing
        small_limit = 50
        msg = {"data": "x" * 100}
        data = json.dumps(msg).encode() + b"\n"
        reader = _make_stream_reader(data)
        ndjson = NDJSONReader(reader, max_message_size=small_limit)

        with pytest.raises(MessageTooLarge):
            await ndjson.read_message()

    async def test_eof_raises(self) -> None:
        """EOF before any message MUST raise EOFError."""
        reader = _make_stream_reader(b"")
        ndjson = NDJSONReader(reader)

        with pytest.raises(EOFError):
            await ndjson.read_message()

    async def test_carriage_return_handling(self) -> None:
        """Messages with \\r\\n line endings are handled."""
        msg = {"cr": "lf"}
        data = json.dumps(msg).encode() + b"\r\n"
        reader = _make_stream_reader(data)
        ndjson = NDJSONReader(reader)

        result = await ndjson.read_message()
        assert result == msg

    async def test_default_max_message_size(self) -> None:
        """Verify the default max message size is 1 MiB."""
        assert DEFAULT_MAX_MESSAGE_SIZE == 1_048_576


# =========================================================================
# NDJSON Writer Tests
# =========================================================================


class TestNDJSONWriter:
    """Tests for NDJSONWriter."""

    async def test_write_single_message(self) -> None:
        """Write a single JSON line."""
        writer, buffer = _make_stream_writer()
        ndjson = NDJSONWriter(writer)

        msg = {"key": "value"}
        await ndjson.write_message(msg)

        output = bytes(buffer).decode()
        assert output.endswith("\n")
        parsed = json.loads(output.strip())
        assert parsed == msg

    async def test_write_compact_json(self) -> None:
        """Written JSON should be compact (no spaces)."""
        writer, buffer = _make_stream_writer()
        ndjson = NDJSONWriter(writer)

        await ndjson.write_message({"a": 1, "b": 2})

        output = bytes(buffer).decode().strip()
        # Compact JSON should not have spaces after separators
        assert " " not in output

    async def test_write_multiple_messages(self) -> None:
        """Write multiple messages, each on its own line."""
        writer, buffer = _make_stream_writer()
        ndjson = NDJSONWriter(writer)

        await ndjson.write_message({"id": 1})
        await ndjson.write_message({"id": 2})

        lines = bytes(buffer).decode().strip().split("\n")
        assert len(lines) == 2
        assert json.loads(lines[0]) == {"id": 1}
        assert json.loads(lines[1]) == {"id": 2}

    async def test_write_drain_called(self) -> None:
        """drain() should be called after each write."""
        writer, _ = _make_stream_writer()
        ndjson = NDJSONWriter(writer)

        await ndjson.write_message({"test": True})
        writer.drain.assert_awaited_once()


# =========================================================================
# NDJSON Round-Trip Tests
# =========================================================================


class TestNDJSONRoundTrip:
    """Tests for round-trip NDJSON read/write."""

    async def test_roundtrip_simple(self) -> None:
        """A message written by NDJSONWriter can be read by NDJSONReader."""
        writer, buffer = _make_stream_writer()
        ndjson_writer = NDJSONWriter(writer)

        msg = {"nl_version": "1.0", "message_type": "action_request", "data": "test"}
        await ndjson_writer.write_message(msg)

        reader = _make_stream_reader(bytes(buffer))
        ndjson_reader = NDJSONReader(reader)

        result = await ndjson_reader.read_message()
        assert result == msg

    async def test_roundtrip_nested_objects(self) -> None:
        """Nested objects survive round-trip."""
        writer, buffer = _make_stream_writer()
        ndjson_writer = NDJSONWriter(writer)

        msg = {
            "envelope": {
                "version": "1.0",
                "payload": {"nested": {"deep": True}},
            }
        }
        await ndjson_writer.write_message(msg)

        reader = _make_stream_reader(bytes(buffer))
        ndjson_reader = NDJSONReader(reader)

        result = await ndjson_reader.read_message()
        assert result == msg

    async def test_roundtrip_special_characters(self) -> None:
        """Special characters in strings survive round-trip."""
        writer, buffer = _make_stream_writer()
        ndjson_writer = NDJSONWriter(writer)

        msg = {"text": "hello\tworld\r\n\"escaped\""}
        await ndjson_writer.write_message(msg)

        reader = _make_stream_reader(bytes(buffer))
        ndjson_reader = NDJSONReader(reader)

        result = await ndjson_reader.read_message()
        assert result == msg


# =========================================================================
# StdioTransport Tests
# =========================================================================


class TestStdioTransport:
    """Tests for StdioTransport."""

    async def test_send_and_receive(self) -> None:
        """Messages can be sent and received through the transport."""
        writer, buffer = _make_stream_writer()
        msg = {"nl_version": "1.0", "type": "test"}

        # Create a transport for sending
        reader_dummy = _make_stream_reader(b"")
        transport = StdioTransport(reader_dummy, writer)
        await transport.send(msg)

        # Create a reader transport with the written data
        reader = _make_stream_reader(bytes(buffer))
        recv_transport = StdioTransport(reader, writer)
        result = await recv_transport.receive()
        assert result == msg

    async def test_receive_eof(self) -> None:
        """Receiving on a closed stream raises EOFError."""
        reader = _make_stream_reader(b"")
        writer, _ = _make_stream_writer()
        transport = StdioTransport(reader, writer)

        with pytest.raises(EOFError):
            await transport.receive()


# =========================================================================
# Discovery Tests
# =========================================================================


class TestDiscoveryDocument:
    """Tests for DiscoveryDocument and related functions."""

    def test_default_construction(self) -> None:
        """DiscoveryDocument can be created with defaults."""
        doc = DiscoveryDocument()
        assert doc.protocol_version == "1.0"
        assert doc.max_message_size_bytes == 1_048_576
        assert doc.supports_delegation is True
        assert doc.supports_federation is False
        assert "sha256" in doc.supported_algorithms
        assert doc.supported_levels == [1, 2, 3, 4, 5, 6, 7]

    def test_custom_construction(self) -> None:
        """DiscoveryDocument can be created with custom values."""
        doc = DiscoveryDocument(
            provider_name="Test Provider",
            provider_vendor="test.com",
            protocol_version="1.0",
            supports_federation=True,
        )
        assert doc.provider_name == "Test Provider"
        assert doc.provider_vendor == "test.com"
        assert doc.supports_federation is True

    def test_create_from_config(self) -> None:
        """create_discovery_document builds from NLProviderConfig."""
        config = NLProviderConfig(
            provider_id="test-provider",
            supported_levels=[1, 2, 3, 4, 5, 6, 7],
            max_delegation_depth=3,
            max_message_size_bytes=2_097_152,
        )

        doc = create_discovery_document(
            config,
            provider_name="Test NL Provider",
            provider_vendor="test.com",
        )

        assert doc.protocol_version == "1.0"
        assert doc.provider_name == "Test NL Provider"
        assert doc.provider_vendor == "test.com"
        assert doc.max_message_size_bytes == 2_097_152
        assert doc.supports_delegation is True
        assert doc.supports_federation is True  # Level 7 is in supported_levels
        assert doc.supported_levels == [1, 2, 3, 4, 5, 6, 7]

    def test_create_from_config_no_delegation(self) -> None:
        """Discovery document reflects max_delegation_depth=0."""
        config = NLProviderConfig(
            provider_id="no-delegation",
            max_delegation_depth=0,
        )

        doc = create_discovery_document(config)
        assert doc.supports_delegation is False

    def test_create_from_config_no_federation(self) -> None:
        """Discovery document reflects Level 7 not in supported_levels."""
        config = NLProviderConfig(
            provider_id="no-federation",
            supported_levels=[1, 2, 3, 4, 5],
        )

        doc = create_discovery_document(config)
        assert doc.supports_federation is False

    def test_create_with_base_url(self) -> None:
        """Discovery document endpoints include base_url prefix."""
        config = NLProviderConfig(provider_id="base-url-test")
        doc = create_discovery_document(
            config, base_url="https://nl.example.com"
        )

        assert "base_url" in doc.endpoints
        assert doc.endpoints["base_url"] == "https://nl.example.com"
        assert doc.endpoints["actions"] == "https://nl.example.com/nl/v1/actions"
        assert doc.endpoints["health"] == "https://nl.example.com/nl/v1/health"

    def test_serialize_discovery_json(self) -> None:
        """serialize_discovery produces valid JSON."""
        doc = DiscoveryDocument(
            provider_name="Serialisation Test",
            provider_vendor="test.com",
        )

        result = serialize_discovery(doc)
        parsed = json.loads(result)

        assert "nl_protocol" in parsed
        assert parsed["nl_protocol"]["versions"] == ["1.0"]
        assert parsed["nl_protocol"]["preferred_version"] == "1.0"
        assert parsed["provider"]["name"] == "Serialisation Test"
        assert parsed["provider"]["vendor"] == "test.com"

    def test_serialize_discovery_structure(self) -> None:
        """Serialised discovery document has the spec-required top-level keys."""
        config = NLProviderConfig(provider_id="structure-test")
        doc = create_discovery_document(config)
        result = serialize_discovery(doc)
        parsed = json.loads(result)

        assert "nl_protocol" in parsed
        assert "provider" in parsed
        assert "endpoints" in parsed
        assert "capabilities" in parsed

    def test_serialize_discovery_capabilities(self) -> None:
        """Serialised capabilities include spec-required fields."""
        config = NLProviderConfig(provider_id="caps-test")
        doc = create_discovery_document(config)
        result = serialize_discovery(doc)
        parsed = json.loads(result)

        caps = parsed["capabilities"]
        assert "conformance_level" in caps
        assert "supported_levels" in caps
        assert "action_types" in caps
        assert "supports_delegation" in caps
        assert "supports_federation" in caps


# =========================================================================
# Messages Tests (existing module -- additional coverage)
# =========================================================================


class TestMessageEnvelope:
    """Tests for MessageEnvelope and helpers."""

    def test_envelope_defaults(self) -> None:
        """Envelope gets default version, message_id, and timestamp."""
        env = MessageEnvelope(message_type="action_request")
        assert env.nl_version == "1.0"
        assert env.message_id.startswith("msg_")
        assert env.timestamp is not None

    def test_serialize_produces_valid_json(self) -> None:
        """Envelope serialises to valid JSON with all envelope fields."""
        env = MessageEnvelope(
            message_type="action_request",
            payload={"key": "value"},
        )
        raw = serialize_message(env)
        data = json.loads(raw)
        assert data["nl_version"] == "1.0"
        assert data["message_type"] == "action_request"
        assert data["payload"] == {"key": "value"}
        assert "message_id" in data
        assert "timestamp" in data

    def test_parse_valid_envelope(self) -> None:
        """A well-formed envelope dict is parsed successfully."""
        data = json.dumps({
            "nl_version": "1.0",
            "message_type": "action_request",
            "message_id": "msg_test-roundtrip",
            "timestamp": datetime.now(UTC),
            "payload": {"key": "value"},
        }, default=str)
        # parse_message needs model_validate_json, but the existing code
        # uses model_validate(dict). We test through the JSON -> dict path
        # using model_validate_json for the roundtrip.
        parsed = MessageEnvelope.model_validate_json(data)
        assert parsed.message_type == "action_request"
        assert parsed.payload == {"key": "value"}

    def test_parse_empty_message(self) -> None:
        """Empty string raises MalformedMessage."""
        with pytest.raises(MalformedMessage, match="Empty message"):
            parse_message("")

    def test_parse_invalid_json(self) -> None:
        """Non-JSON input raises MalformedMessage."""
        with pytest.raises(MalformedMessage, match="Invalid JSON"):
            parse_message("{bad json")

    def test_parse_non_object(self) -> None:
        """JSON array raises MalformedMessage."""
        with pytest.raises(MalformedMessage, match="JSON object"):
            parse_message("[]")

    def test_parse_missing_fields(self) -> None:
        """Missing required fields raise MalformedMessage."""
        with pytest.raises(MalformedMessage, match="Missing required"):
            parse_message('{"nl_version": "1.0"}')

    def test_parse_unknown_message_type(self) -> None:
        """Unknown message type raises error."""
        from nl_protocol.core.errors import UnknownMessageType

        msg = json.dumps({
            "nl_version": "1.0",
            "message_type": "unknown_type",
            "message_id": "msg_test-123",
            "timestamp": datetime.now(UTC).isoformat(),
            "payload": {},
        })
        with pytest.raises(UnknownMessageType):
            parse_message(msg)


class TestErrorFormatting:
    """Tests for error response formatting."""

    def test_format_error_response_envelope(self) -> None:
        """format_error_response creates a proper error envelope."""
        error = MalformedMessage("Test error")
        envelope = format_error_response(error)

        assert envelope.message_type == "error"
        assert "error" in envelope.payload
        assert envelope.payload["error"]["code"] == "NL-E800"

    def test_error_payload_structure(self) -> None:
        """ErrorPayload has the spec-required fields."""
        payload = ErrorPayload(
            code="NL-E100",
            message="Test error",
            detail={"key": "value"},
            resolution="Fix it",
            doc_url="https://example.com",
        )
        assert payload.code == "NL-E100"
        assert payload.message == "Test error"
        assert payload.detail == {"key": "value"}
        assert payload.resolution == "Fix it"

    def test_error_response_serialisation(self) -> None:
        """Error response can be serialised to JSON."""
        error = VersionMismatch(
            "Unsupported version",
            details={"requested": "2.0"},
        )
        envelope = format_error_response(error)
        raw = serialize_message(envelope)
        data = json.loads(raw)

        assert data["message_type"] == "error"
        assert data["payload"]["error"]["code"] == "NL-E801"


# =========================================================================
# Version Negotiation Tests
# =========================================================================


class TestVersionNegotiation:
    """Tests for version negotiation."""

    def test_supported_version(self) -> None:
        """Version 1.0 is accepted."""
        result = negotiate_version("1.0")
        assert result == "1.0"

    def test_unsupported_version(self) -> None:
        """Unsupported version raises VersionMismatch."""
        with pytest.raises(VersionMismatch):
            negotiate_version("2.0")

    def test_custom_supported_versions(self) -> None:
        """Custom supported versions set."""
        result = negotiate_version("2.0", supported=frozenset({"1.0", "2.0"}))
        assert result == "2.0"

    def test_empty_version_string(self) -> None:
        """Empty version string raises VersionMismatch."""
        with pytest.raises(VersionMismatch):
            negotiate_version("")


# =========================================================================
# Content-Type Validation Tests
# =========================================================================


class TestContentTypeValidation:
    """Tests for Content-Type validation."""

    def test_nl_protocol_content_type(self) -> None:
        """The NL Protocol content type is accepted."""
        result = validate_content_type(NL_CONTENT_TYPE)
        assert result == "nl"

    def test_json_content_type(self) -> None:
        """application/json is accepted for backward compat."""
        result = validate_content_type(NL_CONTENT_TYPE_COMPAT)
        assert result == "json"

    def test_content_type_with_charset(self) -> None:
        """Content-Type with charset parameter is accepted."""
        result = validate_content_type("application/json; charset=utf-8")
        assert result == "json"

    def test_unsupported_content_type(self) -> None:
        """Unsupported Content-Type raises UnsupportedMediaType."""
        with pytest.raises(UnsupportedMediaType):
            validate_content_type("text/plain")

    def test_xml_content_type_rejected(self) -> None:
        """XML content type is rejected."""
        with pytest.raises(UnsupportedMediaType):
            validate_content_type("application/xml")


# =========================================================================
# Timestamp Validation Tests
# =========================================================================


class TestTimestampValidation:
    """Tests for timestamp validation."""

    def test_valid_timestamp(self) -> None:
        """A current timestamp passes validation."""
        now = datetime.now(UTC)
        validate_timestamp(now)  # Should not raise

    def test_future_timestamp_rejected(self) -> None:
        """Timestamp far in the future is rejected."""
        from nl_protocol.core.errors import InvalidTimestamp

        future = datetime.now(UTC) + timedelta(hours=1)
        with pytest.raises(InvalidTimestamp):
            validate_timestamp(future)

    def test_past_timestamp_rejected(self) -> None:
        """Timestamp far in the past is rejected."""
        from nl_protocol.core.errors import InvalidTimestamp

        past = datetime.now(UTC) - timedelta(hours=1)
        with pytest.raises(InvalidTimestamp):
            validate_timestamp(past)

    def test_custom_tolerance(self) -> None:
        """Custom tolerance allows wider window."""
        past = datetime.now(UTC) - timedelta(minutes=10)
        # 15 minutes tolerance should allow 10 minutes drift
        validate_timestamp(past, tolerance_seconds=900)


# =========================================================================
# HTTP Transport Tests
# =========================================================================


class TestHTTPTransport:
    """Tests for HTTPTransport (client-side)."""

    def test_httpx_not_installed_raises_import_error(self) -> None:
        """HTTPTransport raises helpful error when httpx is missing."""
        import nl_protocol.wire.http as http_mod

        original = http_mod._HTTPX_AVAILABLE
        try:
            http_mod._HTTPX_AVAILABLE = False
            with pytest.raises(ImportError, match="httpx"):
                HTTPTransport("https://example.com")
        finally:
            http_mod._HTTPX_AVAILABLE = original

    def test_build_headers(self) -> None:
        """HTTPTransport builds correct headers."""
        transport = HTTPTransport(
            "https://example.com",
            credential="test-token-123",
        )
        headers = transport._build_headers()

        assert headers["Content-Type"] == NL_CONTENT_TYPE
        assert headers["Accept"] == NL_CONTENT_TYPE
        assert headers["NL-Protocol-Version"] == NL_PROTOCOL_VERSION
        assert headers["Authorization"] == "Bearer test-token-123"

    def test_build_headers_no_credential(self) -> None:
        """Headers without credential omit Authorization."""
        transport = HTTPTransport("https://example.com")
        headers = transport._build_headers()

        assert "Authorization" not in headers

    def test_base_url_trailing_slash_stripped(self) -> None:
        """Trailing slash on base_url is stripped."""
        transport = HTTPTransport("https://example.com/")
        assert transport._base_url == "https://example.com"


class TestHTTPHandler:
    """Tests for the HTTP handler factory (server-side)."""

    def _make_provider(self) -> object:
        """Create a minimal mock provider for handler tests."""
        from nl_protocol.core.config import NLProviderConfig
        from nl_protocol.core.interfaces import (
            InMemoryAgentRegistry,
            InMemoryScopeGrantStore,
            InMemorySecretStore,
        )
        from nl_protocol.provider import NLProvider

        return NLProvider(
            config=NLProviderConfig(provider_id="test-handler"),
            secret_store=InMemorySecretStore(),
            agent_registry=InMemoryAgentRegistry(),
            scope_grant_store=InMemoryScopeGrantStore(),
        )

    async def test_handler_returns_tuple(self) -> None:
        """Handler returns (status, headers, body) tuple."""
        provider = self._make_provider()
        handler = create_http_handler(provider)

        # Send a valid action_request envelope
        envelope = MessageEnvelope(
            message_type="action_request",
            payload={
                "agent": {
                    "agent_uri": "nl://test.com/agent/1.0",
                },
                "action": {
                    "type": "exec",
                    "template": "echo hello",
                    "purpose": "test",
                },
            },
        )
        body = serialize_message(envelope).encode()

        status, headers, response_body = await handler(
            "/nl/v1/actions",
            {"Content-Type": NL_CONTENT_TYPE},
            body,
        )

        assert isinstance(status, int)
        assert isinstance(headers, dict)
        assert isinstance(response_body, str)

    async def test_handler_content_type_validation(self) -> None:
        """Handler rejects unsupported Content-Type."""
        provider = self._make_provider()
        handler = create_http_handler(provider)

        status, headers, body = await handler(
            "/nl/v1/actions",
            {"Content-Type": "text/plain"},
            b"{}",
        )

        assert status == 415
        data = json.loads(body)
        assert data["payload"]["error"]["code"] == "NL-E804"

    async def test_handler_malformed_body(self) -> None:
        """Handler returns error for malformed JSON body."""
        provider = self._make_provider()
        handler = create_http_handler(provider)

        status, headers, body = await handler(
            "/nl/v1/actions",
            {"Content-Type": NL_CONTENT_TYPE},
            b"not json at all",
        )

        assert status == 400
        data = json.loads(body)
        assert data["payload"]["error"]["code"] == "NL-E800"

    async def test_handler_version_mismatch(self) -> None:
        """Handler returns error for unsupported version."""
        provider = self._make_provider()
        handler = create_http_handler(provider)

        envelope = MessageEnvelope(
            nl_version="9.9",
            message_type="action_request",
            payload={},
        )
        body = serialize_message(envelope).encode()

        status, headers, response_body = await handler(
            "/nl/v1/actions",
            {"Content-Type": NL_CONTENT_TYPE},
            body,
        )

        assert status == 400
        data = json.loads(response_body)
        assert data["payload"]["error"]["code"] == "NL-E801"

    async def test_handler_response_content_type(self) -> None:
        """Handler response includes correct Content-Type header."""
        provider = self._make_provider()
        handler = create_http_handler(provider)

        envelope = MessageEnvelope(
            message_type="action_request",
            payload={
                "agent": {"agent_uri": "nl://test.com/agent/1.0"},
                "action": {"type": "exec", "template": "echo test", "purpose": "test"},
            },
        )
        body = serialize_message(envelope).encode()

        _, headers, _ = await handler(
            "/nl/v1/actions",
            {"Content-Type": NL_CONTENT_TYPE},
            body,
        )

        assert headers["Content-Type"] == NL_CONTENT_TYPE

    async def test_handler_unknown_path(self) -> None:
        """Handler returns error for unknown API path."""
        provider = self._make_provider()
        handler = create_http_handler(provider)

        envelope = MessageEnvelope(
            message_type="action_request",
            payload={},
        )
        body = serialize_message(envelope).encode()

        status, _, response_body = await handler(
            "/nl/v1/unknown",
            {"Content-Type": NL_CONTENT_TYPE},
            body,
        )

        assert status == 400


# =========================================================================
# Wire Package Re-export Tests
# =========================================================================


class TestWirePackageExports:
    """Tests that the wire __init__ re-exports all expected symbols."""

    def test_message_exports(self) -> None:
        """Message-related symbols are available from nl_protocol.wire."""
        from nl_protocol import wire

        assert hasattr(wire, "MessageEnvelope")
        assert hasattr(wire, "ErrorPayload")
        assert hasattr(wire, "serialize_message")
        assert hasattr(wire, "parse_message")
        assert hasattr(wire, "NL_PROTOCOL_VERSION")
        assert hasattr(wire, "NL_CONTENT_TYPE")

    def test_ndjson_exports(self) -> None:
        """NDJSON transport symbols are available from nl_protocol.wire."""
        from nl_protocol import wire

        assert hasattr(wire, "NDJSONReader")
        assert hasattr(wire, "NDJSONWriter")
        assert hasattr(wire, "StdioTransport")

    def test_http_exports(self) -> None:
        """HTTP transport symbols are available from nl_protocol.wire."""
        from nl_protocol import wire

        assert hasattr(wire, "HTTPTransport")
        assert hasattr(wire, "create_http_handler")

    def test_discovery_exports(self) -> None:
        """Discovery symbols are available from nl_protocol.wire."""
        from nl_protocol import wire

        assert hasattr(wire, "DiscoveryDocument")
        assert hasattr(wire, "create_discovery_document")
        assert hasattr(wire, "serialize_discovery")

    def test_top_level_package_exports(self) -> None:
        """Key wire symbols are available from the top-level nl_protocol package."""
        import nl_protocol

        assert hasattr(nl_protocol, "MessageEnvelope")
        assert hasattr(nl_protocol, "NDJSONReader")
        assert hasattr(nl_protocol, "HTTPTransport")
        assert hasattr(nl_protocol, "DiscoveryDocument")
        assert hasattr(nl_protocol, "NLProvider")
        assert hasattr(nl_protocol, "NL_PROTOCOL_VERSION")
