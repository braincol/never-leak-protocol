"""HTTP transport binding for the NL Protocol.

This module implements the HTTP transport binding defined in Chapter 08,
Section 2.5 and Section 5 of the NL Protocol specification.  It provides:

* **HTTPTransport** -- async HTTP client for sending action requests to a
  remote NL Provider (requires the optional ``httpx`` dependency).
* **create_http_handler** -- factory that creates an async request handler
  suitable for use in ASGI applications or test harnesses.

The ``httpx`` dependency is optional.  If it is not installed, the
:class:`HTTPTransport` class will raise :exc:`ImportError` on instantiation
while the handler factory remains fully functional.
"""
from __future__ import annotations

import json
from collections.abc import Callable, Coroutine
from typing import TYPE_CHECKING, Any

from nl_protocol.core.errors import (
    MalformedMessage,
    NLProtocolError,
    UnsupportedMediaType,
)
from nl_protocol.wire.messages import (
    NL_CONTENT_TYPE,
    NL_PROTOCOL_VERSION,
    MessageEnvelope,
    format_error_response,
    negotiate_version,
    serialize_message,
    validate_content_type,
)

# Optional httpx import -- guarded per project conventions.
try:
    import httpx

    _HTTPX_AVAILABLE = True
except ImportError:  # pragma: no cover
    _HTTPX_AVAILABLE = False

if TYPE_CHECKING:
    from nl_protocol.provider import NLProvider


# ---------------------------------------------------------------------------
# HTTPTransport (client)
# ---------------------------------------------------------------------------


class HTTPTransport:
    """HTTP client transport for sending NL Protocol requests.

    Sends action requests to a remote NL Provider over HTTP/HTTPS with
    proper headers and content-type handling per the specification.

    Parameters
    ----------
    base_url:
        The base URL of the remote NL Provider (e.g. ``https://nl.example.com``).
    credential:
        The agent credential for the ``Authorization: Bearer`` header.
    timeout:
        Request timeout in seconds (default: 30).

    Raises
    ------
    ImportError
        If ``httpx`` is not installed.
    """

    def __init__(
        self,
        base_url: str,
        *,
        credential: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        if not _HTTPX_AVAILABLE:
            msg = (
                "httpx is required for HTTPTransport. "
                "Install it with: pip install nl-protocol[http]"
            )
            raise ImportError(msg)

        self._base_url = base_url.rstrip("/")
        self._credential = credential
        self._timeout = timeout

    def _build_headers(self) -> dict[str, str]:
        """Build the standard NL Protocol HTTP headers."""
        headers: dict[str, str] = {
            "Content-Type": NL_CONTENT_TYPE,
            "Accept": NL_CONTENT_TYPE,
            "NL-Protocol-Version": NL_PROTOCOL_VERSION,
        }
        if self._credential:
            headers["Authorization"] = f"Bearer {self._credential}"
        return headers

    async def send_request(
        self,
        path: str,
        envelope: MessageEnvelope,
    ) -> dict[str, Any]:
        """Send an NL Protocol message to the remote provider.

        Parameters
        ----------
        path:
            The API path (e.g. ``/nl/v1/actions``).
        envelope:
            The :class:`MessageEnvelope` to send.

        Returns
        -------
        dict[str, Any]
            The parsed JSON response body.

        Raises
        ------
        MalformedMessage
            If the response body is not valid JSON.
        NLProtocolError
            If the server returns an NL Protocol error.
        """
        url = f"{self._base_url}{path}"
        body = serialize_message(envelope)
        headers = self._build_headers()

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            response = await client.post(url, content=body, headers=headers)

        # Parse the response body
        try:
            data: dict[str, Any] = response.json()
        except (json.JSONDecodeError, ValueError) as exc:
            raise MalformedMessage(
                f"Invalid JSON in HTTP response: {exc}",
                details={"status_code": response.status_code},
            ) from exc

        return data

    async def send_action(
        self,
        envelope: MessageEnvelope,
    ) -> dict[str, Any]:
        """Send an action request to ``POST /nl/v1/actions``.

        Convenience wrapper around :meth:`send_request` for the most
        common operation.

        Parameters
        ----------
        envelope:
            The action request wrapped in a :class:`MessageEnvelope`.

        Returns
        -------
        dict[str, Any]
            The parsed action response.
        """
        return await self.send_request("/nl/v1/actions", envelope)


# ---------------------------------------------------------------------------
# HTTP Handler Factory (server-side)
# ---------------------------------------------------------------------------

# Type alias for an async handler function.
HTTPHandler = Callable[
    [str, dict[str, str], bytes],
    Coroutine[Any, Any, tuple[int, dict[str, str], str]],
]


def create_http_handler(
    provider: NLProvider,
) -> HTTPHandler:
    """Create an async HTTP request handler for an NL Provider.

    The returned handler function accepts an HTTP request and returns
    a tuple of ``(status_code, headers, body)``.  This can be integrated
    into an ASGI framework, a test harness, or any custom HTTP server.

    The handler supports:

    * ``POST /nl/v1/actions`` -- submit an action request.
    * Content-Type validation (Section 5.6).
    * NL Protocol version negotiation (Section 5.2).
    * Structured error responses per Section 6.2.

    Parameters
    ----------
    provider:
        The :class:`NLProvider` instance to route requests to.

    Returns
    -------
    HTTPHandler
        An async function with signature:
        ``(path, headers, body) -> (status_code, response_headers, response_body)``
    """

    async def handler(
        path: str,
        headers: dict[str, str],
        body: bytes,
    ) -> tuple[int, dict[str, str], str]:
        """Process an HTTP request to the NL Protocol API."""
        response_headers: dict[str, str] = {
            "Content-Type": NL_CONTENT_TYPE,
        }

        try:
            # -- Validate Content-Type for POST requests --
            content_type = headers.get("content-type", headers.get("Content-Type", ""))
            if content_type:
                validate_content_type(content_type)

            # -- Parse the request body --
            # Use model_validate_json for correct datetime coercion from
            # JSON strings (model_validate with strict=True rejects string
            # timestamps, but model_validate_json handles them correctly).
            from pydantic import ValidationError as _PydanticValidationError

            raw_str = body.decode("utf-8") if isinstance(body, bytes) else body
            raw_str = raw_str.strip()
            if not raw_str:
                raise MalformedMessage("Empty message")

            # Pre-validate the JSON structure
            try:
                data = json.loads(raw_str)
            except json.JSONDecodeError as exc:
                raise MalformedMessage(f"Invalid JSON: {exc}") from exc

            if not isinstance(data, dict):
                raise MalformedMessage("Message must be a JSON object")

            # Check required fields before model validation
            for field_name in ("nl_version", "message_type", "message_id", "timestamp"):
                if field_name not in data:
                    raise MalformedMessage(
                        f"Missing required envelope field: {field_name}"
                    )

            try:
                envelope = MessageEnvelope.model_validate_json(raw_str)
            except _PydanticValidationError as exc:
                raise MalformedMessage(
                    f"Envelope validation failed: {exc}"
                ) from exc

            # -- Version negotiation --
            negotiate_version(envelope.nl_version)

            # -- Route to the appropriate handler --
            if path == "/nl/v1/actions" and envelope.message_type == "action_request":
                # Import here to avoid circular dependency at module level
                from nl_protocol.core.types import ActionPayload, ActionRequest, ActionType

                # Build an ActionRequest from the envelope payload
                payload = envelope.payload
                action_data = payload.get("action", {})
                action_payload = ActionPayload(
                    type=ActionType(action_data.get("type", "exec")),
                    template=action_data.get("template", ""),
                    purpose=action_data.get("purpose", ""),
                    timeout=action_data.get("timeout", 30),
                )

                agent_data = payload.get("agent", {})
                request = ActionRequest(
                    agent_uri=agent_data.get("agent_uri", "nl://unknown/agent/0.0.0"),
                    action=action_payload,
                )

                response = await provider.process_action(request)
                response_envelope = MessageEnvelope(
                    message_type="action_response",
                    payload=response.model_dump(),
                )

                return (
                    200,
                    response_headers,
                    serialize_message(response_envelope),
                )

            # Unknown path or message type
            error_envelope = format_error_response(
                MalformedMessage(
                    f"Unsupported path or message type: {path}",
                    details={"path": path, "message_type": envelope.message_type},
                )
            )
            return (400, response_headers, serialize_message(error_envelope))

        except UnsupportedMediaType as exc:
            error_envelope = format_error_response(exc)
            return (exc.http_status, response_headers, serialize_message(error_envelope))

        except NLProtocolError as exc:
            error_envelope = format_error_response(exc)
            return (exc.http_status, response_headers, serialize_message(error_envelope))

        except Exception as exc:
            fallback = MalformedMessage(
                f"Internal server error: {type(exc).__name__}",
                details={"exception_type": type(exc).__name__},
            )
            error_envelope = format_error_response(fallback)
            return (500, response_headers, serialize_message(error_envelope))

    return handler
