"""Level 8 -- Wire Protocol & Transport conformance tests.

Verifies Chapter 08 requirements: NDJSON framing, message envelope
structure, version negotiation, content-type validation, and
discovery document format.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from nl_protocol.core.config import NLProviderConfig
from nl_protocol.core.errors import (
    MalformedMessage,
    NLProtocolError,
    UnsupportedMediaType,
    VersionMismatch,
)
from nl_protocol.wire.discovery import (
    create_discovery_document,
    serialize_discovery,
)
from nl_protocol.wire.messages import (
    NL_PROTOCOL_VERSION,
    MessageEnvelope,
    format_error_response,
    negotiate_version,
    parse_message,
    serialize_message,
    validate_content_type,
)

# ===================================================================
# Section 3.3 -- Message envelope structure
# ===================================================================

class TestMessageEnvelope:
    """Spec Section 3.3: every message MUST use the standard envelope."""

    def test_MUST_include_required_fields(self) -> None:
        """Envelope MUST have nl_version, message_type, message_id, timestamp."""
        env = MessageEnvelope(
            message_type="action_request",
            payload={"agent_id": "nl://test/agent/1.0.0"},
        )
        assert env.nl_version == NL_PROTOCOL_VERSION
        assert env.message_type == "action_request"
        assert env.message_id is not None
        assert env.timestamp is not None

    def test_MUST_default_version_to_1_0(self) -> None:
        """Default nl_version MUST be '1.0'."""
        env = MessageEnvelope(message_type="action_request")
        assert env.nl_version == "1.0"

    def test_MUST_auto_generate_message_id(self) -> None:
        """message_id MUST be auto-generated when not provided."""
        env = MessageEnvelope(message_type="action_request")
        assert env.message_id.startswith("msg_")

    def test_MUST_serialize_to_json(self) -> None:
        """Envelope MUST serialize to valid JSON."""
        env = MessageEnvelope(
            message_type="action_request",
            payload={"key": "value"},
        )
        raw = serialize_message(env)
        parsed = json.loads(raw)
        assert parsed["message_type"] == "action_request"
        assert parsed["nl_version"] == "1.0"


# ===================================================================
# Section 3.3 -- Message parsing
# ===================================================================

class TestMessageParsing:
    """Spec Section 3.3: parsing MUST validate the envelope structure."""

    def test_MUST_parse_valid_message(self) -> None:
        """A well-formed JSON message MUST parse successfully."""
        # Build via MessageEnvelope + serialize to guarantee valid format
        original = MessageEnvelope(
            message_type="action_request",
            payload={"agent_id": "nl://test/agent/1.0.0"},
        )
        raw = serialize_message(original)
        env = parse_message(raw)
        assert env.message_type == "action_request"

    def test_MUST_reject_empty_message(self) -> None:
        """An empty string MUST raise MalformedMessage."""
        with pytest.raises(MalformedMessage):
            parse_message("")

    def test_MUST_reject_non_json(self) -> None:
        """Non-JSON content MUST raise MalformedMessage."""
        with pytest.raises(MalformedMessage):
            parse_message("not json at all")

    def test_MUST_reject_missing_nl_version(self) -> None:
        """Missing nl_version field MUST raise MalformedMessage."""
        msg = json.dumps({
            "message_type": "action_request",
            "message_id": "msg_test",
            "timestamp": datetime.now(UTC).isoformat(),
            "payload": {},
        })
        with pytest.raises(MalformedMessage):
            parse_message(msg)

    def test_MUST_reject_missing_message_type(self) -> None:
        """Missing message_type MUST raise MalformedMessage."""
        msg = json.dumps({
            "nl_version": "1.0",
            "message_id": "msg_test",
            "timestamp": datetime.now(UTC).isoformat(),
            "payload": {},
        })
        with pytest.raises(MalformedMessage):
            parse_message(msg)

    def test_MUST_reject_unknown_message_type(self) -> None:
        """An unrecognized message_type MUST be rejected."""
        msg = json.dumps({
            "nl_version": "1.0",
            "message_type": "unknown_type_xyz",
            "message_id": "msg_test",
            "timestamp": datetime.now(UTC).isoformat(),
            "payload": {},
        })
        with pytest.raises((MalformedMessage, NLProtocolError)):
            parse_message(msg)

    def test_MUST_accept_bytes_input(self) -> None:
        """parse_message MUST accept bytes as well as str."""
        original = MessageEnvelope(
            message_type="action_request",
            payload={"agent_id": "nl://test/agent/1.0.0"},
        )
        raw_bytes = serialize_message(original).encode("utf-8")
        env = parse_message(raw_bytes)
        assert env.message_type == "action_request"


# ===================================================================
# Section 3.5 -- Version negotiation
# ===================================================================

class TestVersionNegotiation:
    """Spec Section 3.5: version negotiation MUST validate supported versions."""

    def test_MUST_accept_supported_version(self) -> None:
        """Version '1.0' MUST be accepted."""
        result = negotiate_version("1.0")
        assert result == "1.0"

    def test_MUST_reject_unsupported_version(self) -> None:
        """An unsupported version MUST raise VersionMismatch."""
        with pytest.raises(VersionMismatch):
            negotiate_version("2.0")

    def test_MUST_reject_empty_version(self) -> None:
        """An empty version string MUST raise VersionMismatch."""
        with pytest.raises(VersionMismatch):
            negotiate_version("")

    def test_MUST_support_custom_version_sets(self) -> None:
        """Custom version sets MUST be usable for negotiation."""
        result = negotiate_version("2.0", supported=frozenset({"1.0", "2.0"}))
        assert result == "2.0"


# ===================================================================
# Section 3.2 -- Content-Type validation
# ===================================================================

class TestContentTypeValidation:
    """Spec Section 3.2: Content-Type MUST be validated."""

    def test_MUST_accept_nl_protocol_json(self) -> None:
        """application/nl-protocol+json MUST be accepted."""
        result = validate_content_type("application/nl-protocol+json")
        assert result == "nl"

    def test_MUST_accept_application_json(self) -> None:
        """application/json MUST be accepted (backward compat)."""
        result = validate_content_type("application/json")
        assert result == "json"

    def test_MUST_accept_with_charset(self) -> None:
        """Content-Type with charset parameter MUST be accepted."""
        result = validate_content_type(
            "application/nl-protocol+json; charset=utf-8"
        )
        assert result == "nl"

    def test_MUST_reject_text_plain(self) -> None:
        """text/plain MUST be rejected."""
        with pytest.raises(UnsupportedMediaType):
            validate_content_type("text/plain")

    def test_MUST_reject_text_html(self) -> None:
        """text/html MUST be rejected."""
        with pytest.raises(UnsupportedMediaType):
            validate_content_type("text/html")


# ===================================================================
# Section 6.2 -- Error response formatting
# ===================================================================

class TestErrorFormatting:
    """Spec Section 6.2: error responses MUST use the standard format."""

    def test_MUST_wrap_error_in_envelope(self) -> None:
        """NLProtocolError MUST be formatted as a message envelope."""
        error = MalformedMessage("Test error")
        envelope = format_error_response(error)
        assert envelope.message_type == "error"
        assert "error" in envelope.payload
        assert envelope.payload["error"]["code"] == "NL-E800"

    def test_MUST_include_error_code(self) -> None:
        """Error response MUST include the NL Protocol error code."""
        error = VersionMismatch("Unsupported")
        envelope = format_error_response(error)
        assert envelope.payload["error"]["code"] == "NL-E801"


# ===================================================================
# Section 7 -- Discovery document
# ===================================================================

class TestDiscoveryDocument:
    """Spec Section 7: discovery document MUST describe provider capabilities."""

    def test_MUST_include_protocol_version(self) -> None:
        """Discovery document MUST include the NL Protocol version."""
        config = NLProviderConfig(provider_id="test-provider")
        doc = create_discovery_document(config)
        assert doc.protocol_version == "1.0"

    def test_MUST_include_endpoints(self) -> None:
        """Discovery document MUST list available endpoints."""
        config = NLProviderConfig(provider_id="test-provider")
        doc = create_discovery_document(config)
        assert "actions" in doc.endpoints
        assert "agents_register" in doc.endpoints

    def test_MUST_include_supported_levels(self) -> None:
        """Discovery document MUST list supported protocol levels."""
        config = NLProviderConfig(provider_id="test-provider")
        doc = create_discovery_document(config)
        assert len(doc.supported_levels) > 0

    def test_MUST_serialize_to_valid_json(self) -> None:
        """Serialized discovery document MUST be valid JSON."""
        config = NLProviderConfig(provider_id="test-provider")
        doc = create_discovery_document(config)
        raw = serialize_discovery(doc)
        parsed = json.loads(raw)
        assert "nl_protocol" in parsed
        assert "provider" in parsed
        assert "endpoints" in parsed
        assert "capabilities" in parsed

    def test_MUST_include_nl_protocol_versions(self) -> None:
        """Discovery JSON MUST include nl_protocol.versions list."""
        config = NLProviderConfig(provider_id="test-provider")
        doc = create_discovery_document(config)
        raw = serialize_discovery(doc)
        parsed = json.loads(raw)
        assert "1.0" in parsed["nl_protocol"]["versions"]

    def test_MUST_include_provider_info(self) -> None:
        """Discovery JSON MUST include provider name and vendor."""
        config = NLProviderConfig(provider_id="test-provider")
        doc = create_discovery_document(
            config, provider_name="My Provider", provider_vendor="my.org"
        )
        raw = serialize_discovery(doc)
        parsed = json.loads(raw)
        assert parsed["provider"]["name"] == "My Provider"
        assert parsed["provider"]["vendor"] == "my.org"
