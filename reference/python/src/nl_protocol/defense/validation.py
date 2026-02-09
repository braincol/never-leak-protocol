"""NL Protocol Level 4 -- Command validation and evasion detection.

Implements the evasion detection countermeasures defined in Section 6 of
Chapter 04.  Covers:

* Unicode evasion (homoglyphs, zero-width chars, RTL overrides) -- Section 6.2.1
* Whitespace manipulation -- Section 6.2.2
* Shell metacharacter validation
* Command injection detection
* Template injection detection (Jinja2 ``{{ }}`` vs NL ``{{nl: }}``)
* Null byte injection detection
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

from nl_protocol.core.errors import EvasionDetected

# ---------------------------------------------------------------------------
# Unicode threat tables
# ---------------------------------------------------------------------------

# Bidirectional control characters (Section 6.2.1)
_BIDI_CONTROLS = frozenset(
    "\u200e\u200f"  # LRM, RLM
    "\u202a\u202b\u202c\u202d\u202e"  # LRE, RLE, PDF, LRO, RLO
    "\u2066\u2067\u2068\u2069"  # LRI, RLI, FSI, PDI
)

# Zero-width characters (Section 6.2.1)
_ZERO_WIDTH = frozenset(
    "\u200b"  # ZWSP
    "\u200c"  # ZWNJ
    "\u200d"  # ZWJ
    "\ufeff"  # BOM / ZWNBSP
)

# Common confusable characters (Latin look-alikes from Cyrillic, Greek, etc.)
# Subset of Unicode Confusables (UTS #39).
_CONFUSABLE_MAP: dict[str, str] = {
    # Cyrillic -> Latin
    "\u0410": "A",  # А
    "\u0412": "B",  # В
    "\u0421": "C",  # С
    "\u0415": "E",  # Е
    "\u041d": "H",  # Н
    "\u041a": "K",  # К
    "\u041c": "M",  # М
    "\u041e": "O",  # О
    "\u0420": "P",  # Р
    "\u0422": "T",  # Т
    "\u0425": "X",  # Х
    "\u0430": "a",  # а
    "\u0435": "e",  # е
    "\u043e": "o",  # о
    "\u0440": "p",  # р
    "\u0441": "c",  # с
    "\u0443": "y",  # у
    "\u0445": "x",  # х
    # Fullwidth Latin -> ASCII
    "\uff56": "v",  # ｖ
    "\uff41": "a",  # ａ
    "\uff55": "u",  # ｕ
    "\uff4c": "l",  # ｌ
    "\uff54": "t",  # ｔ
    "\uff47": "g",  # ｇ
    "\uff45": "e",  # ｅ
    "\uff53": "s",  # ｓ
    "\uff43": "c",  # ｃ
    "\uff52": "r",  # ｒ
}

# ---------------------------------------------------------------------------
# Regex patterns for evasion / injection detection
# ---------------------------------------------------------------------------

# Shell metacharacters that might enable injection
_SHELL_META_RE = re.compile(
    r"[;&|`$]"
    r"|>\s*/dev/tcp"
    r"|>\s*/dev/udp"
    r"|/dev/tcp/"
    r"|/dev/udp/"
)

# Command injection patterns (chaining, substitution, piping to shell)
_CMD_INJECTION_RE = re.compile(
    r";\s*\w"  # semicolon chaining
    r"|\|\|\s*\w"  # || chaining
    r"|&&\s*\w"  # && chaining
    r"|\$\([^)]*\)"  # command substitution
    r"|`[^`]+`"  # backtick substitution
)

# Template injection: Jinja2-style {{ }} that is NOT an NL placeholder
_TEMPLATE_INJECTION_RE = re.compile(
    r"\{\{(?!\s*nl:)[^}]*\}\}"
)

# Null byte
_NULL_BYTE_RE = re.compile(r"\x00")


# ---------------------------------------------------------------------------
# Evasion detection result
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class EvasionFinding:
    """A single evasion detection finding."""

    technique: str
    detail: str
    position: int | None = None


# ---------------------------------------------------------------------------
# CommandValidator
# ---------------------------------------------------------------------------

class CommandValidator:
    """Validates commands for evasion attempts and injection attacks.

    Implements countermeasures from Section 6 of Chapter 04:

    * Unicode normalization and confusable detection (6.2.1)
    * Zero-width and bidi character stripping (6.2.1)
    * Whitespace normalization (6.2.2)
    * Null byte detection
    * Shell metacharacter analysis
    * Command injection detection
    * Template injection detection
    """

    def __init__(self, *, strict: bool = True) -> None:
        self._strict = strict

    # -- public API ---------------------------------------------------------

    def normalize(self, text: str) -> str:
        """Normalize *text* for deny-rule matching (pre-processing step).

        Applies:
        1. NFC normalization (Section 6.2.1)
        2. Bidi control character removal (Section 6.2.1)
        3. Zero-width character removal (Section 6.2.1)
        4. Confusable character replacement (Section 6.2.1)
        5. Whitespace collapsing (Section 6.2.2)
        """
        # Step 1: NFC normalization
        result = unicodedata.normalize("NFC", text)

        # Step 2 & 3: Strip bidi controls and zero-width characters
        result = "".join(
            ch for ch in result if ch not in _BIDI_CONTROLS and ch not in _ZERO_WIDTH
        )

        # Step 4: Replace confusable characters
        result = "".join(_CONFUSABLE_MAP.get(ch, ch) for ch in result)

        # Step 5: Collapse whitespace and trim
        result = re.sub(r"\s+", " ", result).strip()

        return result

    def validate(self, template: str) -> list[EvasionFinding]:
        """Check *template* for evasion attempts.

        Returns a list of :class:`EvasionFinding` objects (empty if clean).
        Does NOT raise; use :meth:`validate_or_raise` if you want exceptions.
        """
        findings: list[EvasionFinding] = []

        # 1. Null byte injection
        for m in _NULL_BYTE_RE.finditer(template):
            findings.append(
                EvasionFinding("null_byte", "Null byte detected", m.start())
            )

        # 2. Unicode evasion
        findings.extend(self._check_unicode_evasion(template))

        # 3. Template injection (Jinja2 {{ }} without nl: prefix)
        for m in _TEMPLATE_INJECTION_RE.finditer(template):
            findings.append(
                EvasionFinding(
                    "template_injection",
                    f"Non-NL template expression: {m.group()}",
                    m.start(),
                )
            )

        return findings

    def validate_or_raise(self, template: str) -> str:
        """Validate *template* and raise :class:`EvasionDetected` on findings.

        Returns the normalized template if validation passes.
        """
        findings = self.validate(template)
        if findings:
            first = findings[0]
            raise EvasionDetected(
                f"Evasion detected: {first.technique} -- {first.detail}",
                details={
                    "technique": first.technique,
                    "detail": first.detail,
                    "position": first.position,
                    "total_findings": len(findings),
                },
            )
        return self.normalize(template)

    # -- detection for specific checks (public for testing) -----------------

    def has_null_bytes(self, text: str) -> bool:
        """Return ``True`` if *text* contains null bytes."""
        return "\x00" in text

    def has_bidi_controls(self, text: str) -> bool:
        """Return ``True`` if *text* contains bidirectional control characters."""
        return any(ch in _BIDI_CONTROLS for ch in text)

    def has_zero_width_chars(self, text: str) -> bool:
        """Return ``True`` if *text* contains zero-width characters."""
        return any(ch in _ZERO_WIDTH for ch in text)

    def has_confusable_chars(self, text: str) -> bool:
        """Return ``True`` if *text* contains Unicode confusable characters."""
        return any(ch in _CONFUSABLE_MAP for ch in text)

    def has_template_injection(self, text: str) -> bool:
        """Return ``True`` if *text* contains non-NL template expressions."""
        return _TEMPLATE_INJECTION_RE.search(text) is not None

    def detect_shell_metacharacters(self, text: str) -> list[str]:
        """Return a list of suspicious shell metacharacter patterns found."""
        return [m.group() for m in _SHELL_META_RE.finditer(text)]

    def detect_command_injection(self, text: str) -> list[str]:
        """Return a list of command injection patterns found."""
        return [m.group() for m in _CMD_INJECTION_RE.finditer(text)]

    # -- internal -----------------------------------------------------------

    def _check_unicode_evasion(self, text: str) -> list[EvasionFinding]:
        """Scan for Unicode-based evasion techniques."""
        findings: list[EvasionFinding] = []

        for i, ch in enumerate(text):
            if ch in _BIDI_CONTROLS:
                findings.append(
                    EvasionFinding(
                        "bidi_control",
                        f"Bidirectional control character U+{ord(ch):04X}",
                        i,
                    )
                )
            elif ch in _ZERO_WIDTH:
                findings.append(
                    EvasionFinding(
                        "zero_width",
                        f"Zero-width character U+{ord(ch):04X}",
                        i,
                    )
                )
            elif ch in _CONFUSABLE_MAP:
                findings.append(
                    EvasionFinding(
                        "homoglyph",
                        f"Confusable character U+{ord(ch):04X} "
                        f"(looks like '{_CONFUSABLE_MAP[ch]}')",
                        i,
                    )
                )

        return findings
