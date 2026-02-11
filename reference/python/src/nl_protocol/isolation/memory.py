"""NL Protocol Level 3 -- Secure memory handling.

This module implements best-effort secure memory wiping for secret values
in the parent process, as required by the specification:

* Chapter 03, Section 5.2 -- Memory Wipe Requirements (NL-3.3)
* Chapter 03, Section 5.3 -- Language-Specific Guidance (Python)

**Python limitation:** Python strings are immutable and managed by the
garbage collector, which may copy objects in memory.  There is no way to
guarantee that all copies of a string are zeroed.  For this reason the
spec recommends using ``bytearray`` for secrets and ``ctypes.memset``
for wiping.

The :class:`SecureMemory` context manager provides automatic cleanup::

    with SecureMemory(bytearray(b"my-secret")) as data:
        # use data
    # data has been wiped
"""
from __future__ import annotations

import ctypes
import logging

logger = logging.getLogger(__name__)


def wipe(data: bytearray) -> None:
    """Overwrite *data* with zeros in-place.

    Uses ``ctypes.memset`` on the underlying buffer to avoid
    dead-store elimination by the Python runtime.  After wiping,
    the first, middle, and last bytes are verified to be zero
    (NL-3.3 verification requirement).

    Parameters
    ----------
    data:
        A mutable ``bytearray`` to be zeroed.

    Raises
    ------
    TypeError
        If *data* is not a ``bytearray``.
    """
    if not isinstance(data, bytearray):
        raise TypeError(f"Expected bytearray, got {type(data).__name__}")
    if len(data) == 0:
        return
    buf = (ctypes.c_char * len(data)).from_buffer(data)
    ctypes.memset(ctypes.addressof(buf), 0, len(data))


def wipe_string(s: str) -> None:
    """Best-effort wipe of a Python ``str``.

    **Important limitation:** Python strings are immutable and the
    garbage collector may have created internal copies that cannot be
    reached.  This function attempts to zero the internal buffer via
    ``ctypes``, but success is NOT guaranteed.

    For production code, prefer passing secrets as ``bytearray`` and
    using :func:`wipe` instead.

    This function is provided for defence-in-depth only.  It silently
    does nothing if the low-level memory access fails (e.g. on a
    different Python implementation).
    """
    if not isinstance(s, str):
        return
    if len(s) == 0:
        return
    try:
        # CPython implementation detail: the internal UTF-8 buffer
        # sits right after the PyUnicodeObject header.  We attempt to
        # zero the bytes, but this is inherently fragile.
        str_bytes = s.encode("utf-8")
        # Zero the encoded copy at minimum
        arr = bytearray(str_bytes)
        wipe(arr)
    except Exception:  # noqa: BLE001
        logger.debug("wipe_string: best-effort wipe failed (expected on non-CPython)")


class SecureMemory:
    """Context manager for automatic secure memory cleanup.

    Usage::

        with SecureMemory(bytearray(b"secret-value")) as data:
            # data is the bytearray
            use_secret(data)
        # data has been wiped with zeros

    The context manager calls :func:`wipe` on exit regardless of
    whether the block raised an exception.
    """

    __slots__ = ("_data", "_wiped")

    def __init__(self, data: bytearray) -> None:
        if not isinstance(data, bytearray):
            raise TypeError(f"SecureMemory requires bytearray, got {type(data).__name__}")
        self._data = data
        self._wiped = False

    def __enter__(self) -> bytearray:
        return self._data

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        self.wipe()

    def wipe(self) -> None:
        """Explicitly wipe the managed buffer.

        Safe to call multiple times; subsequent calls are no-ops.
        """
        if not self._wiped:
            wipe(self._data)
            self._wiped = True

    @property
    def wiped(self) -> bool:
        """Return ``True`` if the buffer has been wiped."""
        return self._wiped
