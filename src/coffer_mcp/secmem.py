"""
Secure memory handling for credential secrets.

Python strings are immutable and may be interned by the interpreter,
making it impossible to reliably zero them from memory. This module
provides:

1. SecureBuffer — a bytearray wrapper that zeros its contents on
   close/del, minimizing the window where plaintext secrets exist
   in process memory.

2. wipe_entry() — zeros the secret fields on a CredentialEntry
   after they've been used (e.g., injected into HTTP headers).

3. harden_process() — disables core dumps and locks memory pages
   (where supported) to prevent secrets from leaking to disk.

Limitations:
- Python's str() still creates immutable copies during JSON parsing
  and header construction. These copies may linger in the garbage
  collector until overwritten by other allocations.
- mlock() only prevents swapping; it doesn't protect against a
  process memory dump by a same-user attacker with ptrace access.
- On Windows, VirtualLock has per-process working set limits.

Despite these limitations, these measures significantly reduce the
attack surface compared to leaving secrets in memory indefinitely.
"""

from __future__ import annotations

import ctypes
import sys
from typing import Any


class SecureBuffer:
    """
    A bytearray wrapper that zeros its contents when closed.

    Usage:
        with SecureBuffer(plaintext_bytes) as buf:
            data = json.loads(buf.decode("utf-8"))
        # buf is now zeroed

    The buffer is also zeroed on garbage collection (__del__) as a
    safety net, though deterministic cleanup via context manager or
    explicit close() is preferred.
    """

    __slots__ = ("_data", "_closed")

    def __init__(self, data: bytes | bytearray) -> None:
        self._data = bytearray(data)
        self._closed = False

    def __enter__(self) -> "SecureBuffer":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def close(self) -> None:
        """Zero the buffer contents."""
        if not self._closed:
            for i in range(len(self._data)):
                self._data[i] = 0
            self._closed = True

    def __del__(self) -> None:
        self.close()

    def __bytes__(self) -> bytes:
        if self._closed:
            raise ValueError("SecureBuffer has been closed")
        return bytes(self._data)

    def decode(self, encoding: str = "utf-8") -> str:
        """Decode the buffer as a string. The returned str is immutable."""
        if self._closed:
            raise ValueError("SecureBuffer has been closed")
        return self._data.decode(encoding)

    def __len__(self) -> int:
        return len(self._data)


def wipe_entry(entry: Any) -> None:
    """
    Best-effort zeroing of secret fields on a CredentialEntry.

    Overwrites the str references with empty strings. This doesn't
    guarantee the original string is freed (Python may intern it),
    but it ensures the CredentialEntry object no longer holds a
    reference, allowing the GC to collect the original sooner.
    """
    try:
        object.__setattr__(entry, "secret", "")
        object.__setattr__(entry, "username", "")
    except (AttributeError, TypeError):
        pass


def harden_process() -> dict[str, bool]:
    """
    Apply process-level memory protections. Call once at server startup.

    Returns a dict of which protections were successfully applied.

    Protections:
    - disable_core_dumps: Prevents secrets from being written to core
      dump files on crash (Linux/macOS via RLIMIT_CORE).
    - lock_memory: Prevents the OS from swapping memory pages to disk
      (Linux via mlockall, Windows via SetProcessWorkingSetSize hint).
    """
    results = {}
    results["disable_core_dumps"] = _disable_core_dumps()
    results["lock_future_memory"] = _lock_future_memory()
    return results


def _disable_core_dumps() -> bool:
    """Disable core dumps via RLIMIT_CORE (Unix only)."""
    if sys.platform == "win32":
        return False  # Windows doesn't use core dumps the same way

    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        return True
    except Exception:
        return False


def _lock_future_memory() -> bool:
    """
    Lock current and future memory pages to prevent swapping.

    - Linux: mlockall(MCL_CURRENT | MCL_FUTURE)
    - Windows: Hint via SetProcessWorkingSetSize (advisory only)
    - macOS: Not supported (mlockall exists but often fails without root)
    """
    if sys.platform == "linux":
        try:
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            MCL_CURRENT = 1  # noqa: N806
            MCL_FUTURE = 2  # noqa: N806
            result = libc.mlockall(MCL_CURRENT | MCL_FUTURE)
            return result == 0
        except Exception:
            return False
    elif sys.platform == "win32":
        try:
            # Hint to Windows to keep our working set in RAM
            # This is advisory — Windows may still page out under pressure
            kernel32 = ctypes.windll.kernel32
            process = kernel32.GetCurrentProcess()
            # Set min/max working set to 10MB/50MB
            kernel32.SetProcessWorkingSetSize(process, 10 * 1024 * 1024, 50 * 1024 * 1024)
            return True
        except Exception:
            return False
    return False  # macOS — mlockall usually requires root
