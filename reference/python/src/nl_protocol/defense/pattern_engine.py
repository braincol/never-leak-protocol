"""NL Protocol Level 4 -- Pattern matching engine.

Provides RE2-compatible pattern matching with graceful fallback to the
standard library ``re`` module when ``google-re2`` is not installed.

The spec (Section 3.2) requires:
* RE2-compatible regex semantics (linear-time matching, no ReDoS).
* Each pattern evaluation MUST complete within 100 ms wall-clock time.
* If a timeout is exceeded, the pattern MUST be treated as matched (fail-closed).
* Pattern compilation caching for performance.
"""
from __future__ import annotations

import re
import threading
from functools import lru_cache
from typing import Any

# ---------------------------------------------------------------------------
# Attempt to import google-re2; fall back to ``re`` if unavailable
# ---------------------------------------------------------------------------

_RE2_AVAILABLE = False
_re2_module: Any = None

try:
    import re2 as _re2_module  # type: ignore[no-redef]

    _RE2_AVAILABLE = True
except ImportError:
    pass


# ---------------------------------------------------------------------------
# Compiled pattern cache (module-level)
# ---------------------------------------------------------------------------

@lru_cache(maxsize=512)
def _compile_pattern(pattern: str, use_re2: bool) -> Any:
    """Compile and cache a regex pattern.

    Parameters
    ----------
    pattern:
        The RE2-compatible regex pattern string.
    use_re2:
        Whether to use the ``google-re2`` engine.

    Returns
    -------
    A compiled pattern object (``re2.Pattern`` or ``re.Pattern``).

    Raises
    ------
    re.error
        If the pattern is syntactically invalid.
    """
    if use_re2 and _RE2_AVAILABLE:
        return _re2_module.compile(pattern, _re2_module.IGNORECASE)
    return re.compile(pattern, re.IGNORECASE)


# ---------------------------------------------------------------------------
# PatternEngine
# ---------------------------------------------------------------------------

class PatternEngine:
    """RE2-compatible pattern matching engine with timeout support.

    Parameters
    ----------
    timeout_ms:
        Maximum wall-clock time in milliseconds for a single pattern
        evaluation.  Defaults to 100 ms per the spec (Section 3.2).
    prefer_re2:
        If ``True`` (the default), use ``google-re2`` when available.
    """

    def __init__(
        self,
        timeout_ms: float = 100.0,
        prefer_re2: bool = True,
    ) -> None:
        self._timeout_s = timeout_ms / 1000.0
        self._use_re2 = prefer_re2 and _RE2_AVAILABLE

    # -- public properties --------------------------------------------------

    @property
    def engine_name(self) -> str:
        """Return the name of the active regex engine."""
        return "google-re2" if self._use_re2 else "re (stdlib)"

    @property
    def timeout_ms(self) -> float:
        """Return the configured timeout in milliseconds."""
        return self._timeout_s * 1000.0

    # -- compilation --------------------------------------------------------

    def compile(self, pattern: str) -> Any:
        """Compile *pattern* with the active engine.

        Raises ``re.error`` (or ``re2.error``) if the pattern is invalid.
        Patterns are validated at load time per Section 3.2.
        """
        return _compile_pattern(pattern, self._use_re2)

    # -- matching -----------------------------------------------------------

    def match(self, pattern: str, text: str) -> bool:
        """Return ``True`` if *pattern* matches anywhere in *text*.

        On timeout, returns ``True`` (fail-closed per Section 3.2 requirement 5).
        """
        compiled = self.compile(pattern)
        return self._run_with_timeout(lambda: compiled.search(text) is not None)

    def find_all(self, pattern: str, text: str) -> list[str]:
        """Return all non-overlapping matches of *pattern* in *text*.

        On timeout, returns ``["<TIMEOUT>"]`` to signal a fail-closed match.
        """
        compiled = self.compile(pattern)
        result: list[str] | None = self._run_with_timeout_value(
            lambda: compiled.findall(text)
        )
        if result is None:
            return ["<TIMEOUT>"]
        return result

    # -- internal timeout helpers -------------------------------------------

    def _run_with_timeout(self, fn: Any) -> bool:
        """Execute *fn* with a wall-clock timeout.

        Returns ``True`` if the function times out (fail-closed).
        """
        result_box: list[bool] = [True]  # default: fail-closed
        exception_box: list[BaseException | None] = [None]

        def _worker() -> None:
            try:
                result_box[0] = fn()
            except Exception as exc:
                exception_box[0] = exc

        thread = threading.Thread(target=_worker, daemon=True)
        thread.start()
        thread.join(timeout=self._timeout_s)

        if thread.is_alive():
            # Timeout -- fail-closed: treat as matched
            return True

        if exception_box[0] is not None:
            raise exception_box[0]  # type: ignore[misc]

        return result_box[0]

    def _run_with_timeout_value(self, fn: Any) -> list[str] | None:
        """Execute *fn* with a wall-clock timeout, returning ``None`` on timeout."""
        result_box: list[list[str] | None] = [None]
        exception_box: list[BaseException | None] = [None]

        def _worker() -> None:
            try:
                result_box[0] = fn()
            except Exception as exc:
                exception_box[0] = exc

        thread = threading.Thread(target=_worker, daemon=True)
        thread.start()
        thread.join(timeout=self._timeout_s)

        if thread.is_alive():
            return None

        if exception_box[0] is not None:
            raise exception_box[0]  # type: ignore[misc]

        return result_box[0]

    # -- cache management ---------------------------------------------------

    @staticmethod
    def clear_cache() -> None:
        """Clear the compiled pattern cache."""
        _compile_pattern.cache_clear()

    @staticmethod
    def cache_info() -> Any:
        """Return cache statistics."""
        return _compile_pattern.cache_info()
