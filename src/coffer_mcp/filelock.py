"""
Cross-platform file locking for safe concurrent access.

Provides both cross-process file locking (via OS primitives) and
in-process threading locks. Used by EncryptedStore and AuditLogger
to prevent data corruption from concurrent CLI + MCP server access.
"""

from __future__ import annotations

import sys
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


class FileLock:
    """
    Cross-platform advisory file lock with in-process thread safety.

    Uses:
    - Windows: kernel32 LockFileEx/UnlockFileEx via ctypes
    - Unix/macOS: fcntl.flock (LOCK_EX)

    Also holds a threading.Lock so concurrent async tasks within the
    same process are serialised without needing asyncio.Lock (the
    protected I/O is synchronous and fast).
    """

    def __init__(self, path: Path) -> None:
        self._lock_path = path.with_suffix(path.suffix + ".lock")
        self._thread_lock = threading.Lock()

    @contextmanager
    def acquire(self) -> Iterator[None]:
        """Context manager that holds both the thread lock and file lock."""
        with self._thread_lock:
            self._lock_path.parent.mkdir(parents=True, exist_ok=True)
            if sys.platform == "win32":
                yield from self._acquire_windows()
            else:
                yield from self._acquire_unix()

    def _acquire_unix(self) -> Iterator[None]:
        """Unix/macOS file locking via fcntl."""
        import fcntl

        fd = open(self._lock_path, "w", encoding="utf-8")  # noqa: SIM115
        try:
            fcntl.flock(fd.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fd.fileno(), fcntl.LOCK_UN)
        finally:
            fd.close()

    def _acquire_windows(self) -> Iterator[None]:
        """Windows file locking via kernel32 LockFileEx with shared open."""
        import ctypes
        import ctypes.wintypes

        # OVERLAPPED structure — not in ctypes.wintypes, define manually
        class OVERLAPPED(ctypes.Structure):
            _fields_ = [
                ("Internal", ctypes.POINTER(ctypes.c_ulong)),
                ("InternalHigh", ctypes.POINTER(ctypes.c_ulong)),
                ("Offset", ctypes.wintypes.DWORD),
                ("OffsetHigh", ctypes.wintypes.DWORD),
                ("hEvent", ctypes.wintypes.HANDLE),
            ]

        GENERIC_READ = 0x80000000  # noqa: N806
        GENERIC_WRITE = 0x40000000  # noqa: N806
        FILE_SHARE_READ = 0x00000001  # noqa: N806
        FILE_SHARE_WRITE = 0x00000002  # noqa: N806
        OPEN_ALWAYS = 4  # noqa: N806
        FILE_ATTRIBUTE_NORMAL = 0x80  # noqa: N806
        LOCKFILE_EXCLUSIVE_LOCK = 0x02  # noqa: N806
        INVALID_HANDLE_VALUE = ctypes.wintypes.HANDLE(-1).value  # noqa: N806

        kernel32 = ctypes.windll.kernel32

        # Open with FILE_SHARE_READ|WRITE so other processes can also open
        handle = kernel32.CreateFileW(
            str(self._lock_path),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        if handle == INVALID_HANDLE_VALUE:
            raise OSError(f"Cannot open lock file: {self._lock_path}")

        try:
            overlapped = OVERLAPPED()
            # Lock the first byte exclusively (blocks until acquired)
            ok = kernel32.LockFileEx(
                ctypes.wintypes.HANDLE(handle),
                LOCKFILE_EXCLUSIVE_LOCK,  # exclusive, blocking
                0,  # reserved
                1,  # bytes to lock (low)
                0,  # bytes to lock (high)
                ctypes.byref(overlapped),
            )
            if not ok:
                raise OSError(f"LockFileEx failed: {ctypes.GetLastError()}")
            try:
                yield
            finally:
                kernel32.UnlockFileEx(
                    ctypes.wintypes.HANDLE(handle),
                    0,
                    1,
                    0,
                    ctypes.byref(overlapped),
                )
        finally:
            kernel32.CloseHandle(ctypes.wintypes.HANDLE(handle))
