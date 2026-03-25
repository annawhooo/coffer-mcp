"""
Cross-platform file and directory permission hardening.

Sets restrictive permissions (owner-only read/write) on sensitive files
like credentials.json, audit.jsonl, and backup files. On multi-user
systems this prevents other users from reading vault contents.

- Unix/macOS: chmod 0600 for files, 0700 for directories
- Windows: removes Everyone/Users group access via icacls
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path


def secure_file(path: Path) -> None:
    """
    Set owner-only read/write permissions on a file (0600).

    On Windows, removes broad group access (Everyone, Users, Authenticated Users)
    while preserving inherited owner/admin permissions. Falls back silently on
    failure — better to have the file with default permissions than to crash.
    """
    if not path.exists():
        return

    if sys.platform == "win32":
        _secure_windows(path)
    else:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0600


def secure_directory(path: Path) -> None:
    """
    Set owner-only read/write/execute permissions on a directory (0700).

    On Windows, removes broad group access while preserving owner permissions.
    """
    if not path.exists():
        return

    if sys.platform == "win32":
        _secure_windows(path)
    else:
        os.chmod(path, stat.S_IRWXU)  # 0700


def _secure_windows(path: Path) -> None:
    """
    Remove broad group access on Windows.

    Rather than stripping all inheritance (which can break access in temp
    directories and CI environments), we remove specific well-known groups
    that grant access to other users. Owner and SYSTEM access is preserved.

    Falls back silently on failure (e.g., network drives, FAT32, CI runners).
    """
    import subprocess

    try:
        # Remove broad groups that could give other users access
        for group in ("Everyone", "BUILTIN\\Users", "Authenticated Users"):
            subprocess.run(
                ["icacls", str(path), "/remove:g", group],
                capture_output=True,
                timeout=5,
            )
    except Exception:
        pass  # Best-effort on Windows
