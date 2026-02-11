"""NDJSON (Newline-Delimited JSON) framing for the stdio transport.

This module implements the stdin/stdout transport binding defined in
Chapter 08, Section 2.3 of the NL Protocol specification.  It provides:

* **NDJSONReader** -- reads NDJSON messages from an async stream (stdin).
* **NDJSONWriter** -- writes NDJSON messages to an async stream (stdout).
* **StdioTransport** -- bidirectional NDJSON transport wrapping stdin/stdout.

NDJSON requirements from the spec:
- Each message is a single line of JSON followed by ``\\n`` (0x0A).
- Empty lines (bare ``\\n``) MUST be silently ignored.
- Maximum message size: 1 MiB.
- Partial message timeout: 30 seconds (configurable).
"""
from __future__ import annotations

import asyncio
import json
from typing import Any

from nl_protocol.core.errors import MalformedMessage, MessageTooLarge

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_MAX_MESSAGE_SIZE: int = 1_048_576  # 1 MiB (Section 2.3)
DEFAULT_PARTIAL_TIMEOUT: float = 30.0  # seconds (Section 2.3)


# ---------------------------------------------------------------------------
# NDJSONReader
# ---------------------------------------------------------------------------


class NDJSONReader:
    """Reads NDJSON messages from an async stream.

    Parameters
    ----------
    reader:
        An :class:`asyncio.StreamReader` (typically ``stdin``).
    max_message_size:
        Maximum allowed message size in bytes.  Messages exceeding
        this limit are rejected with ``NL-E803``.
    partial_timeout:
        Maximum time in seconds to wait for a complete message
        before discarding the partial buffer.
    """

    def __init__(
        self,
        reader: asyncio.StreamReader,
        *,
        max_message_size: int = DEFAULT_MAX_MESSAGE_SIZE,
        partial_timeout: float = DEFAULT_PARTIAL_TIMEOUT,
    ) -> None:
        self._reader = reader
        self._max_message_size = max_message_size
        self._partial_timeout = partial_timeout

    async def read_message(self) -> dict[str, Any]:
        """Read one NDJSON message from the stream.

        Reads lines until a non-empty line containing valid JSON is found.
        Empty lines are silently ignored per the spec.

        Returns
        -------
        dict[str, Any]
            The parsed JSON object.

        Raises
        ------
        MalformedMessage
            If the line contains invalid JSON or is not a JSON object.
        MessageTooLarge
            If the line exceeds *max_message_size* bytes.
        EOFError
            If the stream is closed before a complete message is received.
        asyncio.TimeoutError
            If a complete message is not received within *partial_timeout*.
        """
        while True:
            try:
                line = await asyncio.wait_for(
                    self._reader.readline(),
                    timeout=self._partial_timeout,
                )
            except TimeoutError:
                raise

            # EOF -- stream closed
            if not line:
                raise EOFError("Stream closed before a complete message was received")

            # Strip the trailing newline and any carriage return
            stripped = line.rstrip(b"\r\n")

            # Empty lines MUST be silently ignored (Section 2.3)
            if not stripped:
                continue

            # Check message size limit
            if len(stripped) > self._max_message_size:
                raise MessageTooLarge(
                    f"Message size {len(stripped)} bytes exceeds maximum "
                    f"{self._max_message_size} bytes",
                    details={
                        "size": len(stripped),
                        "max_size": self._max_message_size,
                    },
                )

            # Parse JSON
            try:
                data = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise MalformedMessage(
                    f"Invalid JSON in NDJSON line: {exc}",
                    details={"raw_length": len(stripped)},
                ) from exc

            if not isinstance(data, dict):
                raise MalformedMessage(
                    "NDJSON message must be a JSON object",
                    details={"type": type(data).__name__},
                )

            return data


# ---------------------------------------------------------------------------
# NDJSONWriter
# ---------------------------------------------------------------------------


class NDJSONWriter:
    """Writes NDJSON messages to an async stream.

    Parameters
    ----------
    writer:
        An :class:`asyncio.StreamWriter` (typically ``stdout``).
    """

    def __init__(self, writer: asyncio.StreamWriter) -> None:
        self._writer = writer

    async def write_message(self, msg: dict[str, Any]) -> None:
        """Write one NDJSON message to the stream.

        The message is serialised as compact JSON (no embedded newlines)
        followed by a single ``\\n`` character.

        Parameters
        ----------
        msg:
            A JSON-serialisable dictionary.
        """
        # separators=(',', ':') produces compact JSON without spaces
        line = json.dumps(msg, separators=(",", ":"), default=str)
        self._writer.write(line.encode("utf-8") + b"\n")
        await self._writer.drain()


# ---------------------------------------------------------------------------
# StdioTransport
# ---------------------------------------------------------------------------


class StdioTransport:
    """Bidirectional NDJSON transport over stdin/stdout.

    This implements the stdio transport binding from Section 2.3 of the
    NL Protocol specification.  It wraps a reader (stdin) and writer
    (stdout) into a single transport with ``send`` and ``receive`` methods.

    Parameters
    ----------
    reader:
        An :class:`asyncio.StreamReader` for incoming messages.
    writer:
        An :class:`asyncio.StreamWriter` for outgoing messages.
    max_message_size:
        Maximum allowed message size in bytes.
    partial_timeout:
        Maximum wait time for a complete message in seconds.
    """

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        *,
        max_message_size: int = DEFAULT_MAX_MESSAGE_SIZE,
        partial_timeout: float = DEFAULT_PARTIAL_TIMEOUT,
    ) -> None:
        self._ndjson_reader = NDJSONReader(
            reader,
            max_message_size=max_message_size,
            partial_timeout=partial_timeout,
        )
        self._ndjson_writer = NDJSONWriter(writer)

    async def send(self, message: dict[str, Any]) -> None:
        """Send a message through the transport.

        Parameters
        ----------
        message:
            A JSON-serialisable dictionary representing the NL Protocol message.
        """
        await self._ndjson_writer.write_message(message)

    async def receive(self) -> dict[str, Any]:
        """Receive a message from the transport.

        Returns
        -------
        dict[str, Any]
            The parsed NL Protocol message.

        Raises
        ------
        MalformedMessage
            If the received line is not valid JSON.
        MessageTooLarge
            If the received line exceeds the size limit.
        EOFError
            If the stream is closed.
        """
        return await self._ndjson_reader.read_message()
