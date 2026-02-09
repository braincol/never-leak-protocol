"""NL Protocol Level 2 -- Output sanitization.

**THIS IS CRITICAL SECURITY CODE.**

This module implements the output sanitization algorithm defined in
Chapter 02, Section 9 of the NL Protocol specification.  Output
sanitization is the *last line of defence*: it scans stdout/stderr for
any secret values that were used in an action and redacts them before
the output reaches the agent.

The scanning algorithm checks four encodings of each secret:

1. **Plaintext** -- direct string match.
2. **Base64** -- ``base64.b64encode(value.encode()).decode()``.
3. **URL-encoded** -- ``urllib.parse.quote(value, safe="")``.
4. **Hex-encoded** -- ``value.encode().hex()``.

Per specification:

* Secrets shorter than 4 characters are skipped (NL-2.6.5) to avoid
  excessive false positives.
* Binary null bytes are stripped before scanning (NL-2.6.10).
* Multi-line secrets are matched as a single string (NL-2.6.11).
* Every occurrence of a leaked secret is redacted (NL-2.6.9).
* The redaction marker format is ``[NL-REDACTED:name]`` for plaintext
  and ``[NL-REDACTED:name:encoding]`` for encoded matches (NL-2.6.2,
  NL-2.6.4).

This module is referenced by Chapter 06 (Attack Detection) for hash-based
detection.  Implementations MUST use a single sanitization implementation
for both output sanitization and attack detection.
"""
from __future__ import annotations

import base64
import urllib.parse
from typing import TYPE_CHECKING

from nl_protocol.core.errors import SanitizationFailure

if TYPE_CHECKING:
    from nl_protocol.core.types import SecretValue

# Maximum output size in bytes (10 MiB default).
DEFAULT_MAX_OUTPUT_SIZE: int = 10 * 1024 * 1024

# Minimum secret length for scanning (NL-2.6.5).
MIN_SECRET_LENGTH: int = 4


class OutputSanitizer:
    """Scans action output for leaked secret values and redacts them.

    Per NL Protocol spec Chapter 02, Section 9, the sanitizer checks:

    1. Plaintext matches
    2. Base64-encoded matches
    3. URL-encoded matches
    4. Hex-encoded matches

    This class is stateless and thread-safe.

    Usage
    -----
    ::

        sanitizer = OutputSanitizer()
        cleaned, names = sanitizer.sanitize(output, {"api/TOKEN": token_value})
    """

    def sanitize(
        self,
        output: str,
        secrets: dict[str, SecretValue],
        max_size: int = DEFAULT_MAX_OUTPUT_SIZE,
    ) -> tuple[str, list[str]]:
        """Sanitize output by redacting any leaked secret values.

        Parameters
        ----------
        output:
            The raw output (stdout or stderr) from action execution.
        secrets:
            Mapping of ``{reference_name: SecretValue}`` for every secret
            that was resolved during the action.
        max_size:
            Maximum allowed output size in bytes.  Outputs exceeding this
            limit raise :class:`SanitizationFailure`.

        Returns
        -------
        tuple[str, list[str]]
            A 2-tuple of ``(sanitized_output, list_of_redacted_secret_names)``.
            The list contains each secret name that was found and redacted
            (no duplicates, preserves first-encounter order).

        Raises
        ------
        SanitizationFailure
            If the output exceeds *max_size*.
        """
        # Size guard
        if len(output.encode("utf-8", errors="replace")) > max_size:
            raise SanitizationFailure(
                f"Output size ({len(output.encode('utf-8', errors='replace'))} bytes) "
                f"exceeds maximum allowed size ({max_size} bytes)."
            )

        # Step 0: Strip binary null bytes (NL-2.6.10)
        result = output.replace("\x00", "")

        redacted: list[str] = []

        for name, secret in secrets.items():
            value = secret.expose()

            # Skip empty secrets and secrets shorter than 4 chars (NL-2.6.5)
            if not value or len(value) < MIN_SECRET_LENGTH:
                continue

            # 1. Plaintext match (NL-2.6.2, NL-2.6.9)
            if value in result:
                result = result.replace(value, f"[NL-REDACTED:{name}]")
                if name not in redacted:
                    redacted.append(name)

            # 2. Base64-encoded match (NL-2.6.3, NL-2.6.4)
            b64_value = base64.b64encode(value.encode("utf-8")).decode("ascii")
            if b64_value in result:
                result = result.replace(
                    b64_value, f"[NL-REDACTED:{name}:base64]"
                )
                if name not in redacted:
                    redacted.append(name)

            # 3. URL-encoded match (NL-2.6.3, NL-2.6.4)
            url_value = urllib.parse.quote(value, safe="")
            if url_value in result:
                result = result.replace(
                    url_value, f"[NL-REDACTED:{name}:url]"
                )
                if name not in redacted:
                    redacted.append(name)

            # 4. Hex-encoded match (NL-2.6.3, NL-2.6.4)
            hex_value = value.encode("utf-8").hex()
            if hex_value in result:
                result = result.replace(
                    hex_value, f"[NL-REDACTED:{name}:hex]"
                )
                if name not in redacted:
                    redacted.append(name)

        return result, redacted

    def sanitize_with_count(
        self,
        output: str,
        secrets: dict[str, SecretValue],
        max_size: int = DEFAULT_MAX_OUTPUT_SIZE,
    ) -> tuple[str, list[str], int]:
        """Sanitize output and also return the total redaction count.

        This extended variant counts *every individual replacement*
        (including multiple occurrences of the same secret), which is
        required for the ``redacted_count`` field in the action response
        (Section 7.2).

        Parameters
        ----------
        output:
            The raw output from action execution.
        secrets:
            Mapping of ``{reference_name: SecretValue}`` for resolved secrets.
        max_size:
            Maximum allowed output size in bytes.

        Returns
        -------
        tuple[str, list[str], int]
            A 3-tuple of ``(sanitized_output, redacted_names, total_redaction_count)``.

        Raises
        ------
        SanitizationFailure
            If the output exceeds *max_size*.
        """
        # Size guard
        if len(output.encode("utf-8", errors="replace")) > max_size:
            raise SanitizationFailure(
                f"Output size ({len(output.encode('utf-8', errors='replace'))} bytes) "
                f"exceeds maximum allowed size ({max_size} bytes)."
            )

        # Step 0: Strip binary null bytes (NL-2.6.10)
        result = output.replace("\x00", "")

        redacted: list[str] = []
        total_count = 0

        for name, secret in secrets.items():
            value = secret.expose()

            # Skip empty secrets and secrets shorter than 4 chars (NL-2.6.5)
            if not value or len(value) < MIN_SECRET_LENGTH:
                continue

            # 1. Plaintext match -- count all occurrences
            count = result.count(value)
            if count > 0:
                result = result.replace(value, f"[NL-REDACTED:{name}]")
                total_count += count
                if name not in redacted:
                    redacted.append(name)

            # 2. Base64-encoded match
            b64_value = base64.b64encode(value.encode("utf-8")).decode("ascii")
            count = result.count(b64_value)
            if count > 0:
                result = result.replace(
                    b64_value, f"[NL-REDACTED:{name}:base64]"
                )
                total_count += count
                if name not in redacted:
                    redacted.append(name)

            # 3. URL-encoded match
            url_value = urllib.parse.quote(value, safe="")
            count = result.count(url_value)
            if count > 0:
                result = result.replace(
                    url_value, f"[NL-REDACTED:{name}:url]"
                )
                total_count += count
                if name not in redacted:
                    redacted.append(name)

            # 4. Hex-encoded match
            hex_value = value.encode("utf-8").hex()
            count = result.count(hex_value)
            if count > 0:
                result = result.replace(
                    hex_value, f"[NL-REDACTED:{name}:hex]"
                )
                total_count += count
                if name not in redacted:
                    redacted.append(name)

        return result, redacted, total_count
