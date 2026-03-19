"""
Master key management.

Retrieves or generates the master encryption key using (in priority order):
1. OS keyring (Windows Credential Manager / macOS Keychain / Linux Secret Service)
2. COFFER_MASTER_KEY environment variable
3. Auto-generated key stored in ~/.coffer/.master-key (fallback)
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path

import keyring

SERVICE_NAME = "coffer-mcp"
KEY_ACCOUNT = "master-key"


def get_master_key() -> bytes:
    """
    Retrieve the 32-byte master key.

    Priority:
        1. OS keyring
        2. COFFER_MASTER_KEY env var (hex-encoded)
        3. Auto-generated file at ~/.coffer/.master-key

    Returns:
        32-byte AES-256 key.
    """
    # 1. Try OS keyring
    stored = _get_from_keyring()
    if stored is not None:
        return stored

    # 2. Try environment variable
    env_key = os.environ.get("COFFER_MASTER_KEY")
    if env_key:
        return _derive_key_from_passphrase(env_key)

    # 3. Fallback: auto-generated file
    return _get_or_create_file_key()


def store_master_key_in_keyring(passphrase: str) -> bytes:
    """
    Derive a key from a passphrase and store it in the OS keyring.

    Uses a random salt stored alongside the derived key to prevent
    rainbow table attacks. The salt + derived key are stored together
    as a JSON object in the keyring.

    Args:
        passphrase: User-provided passphrase.

    Returns:
        The 32-byte derived key.
    """
    salt = os.urandom(16)
    key = _derive_key_from_passphrase(passphrase, salt)
    # Store salt + key together so we can re-derive on retrieval
    payload = json.dumps({"salt": salt.hex(), "key": key.hex()})
    keyring.set_password(SERVICE_NAME, KEY_ACCOUNT, payload)
    return key


def clear_keyring() -> None:
    """Remove the master key from the OS keyring."""
    try:
        keyring.delete_password(SERVICE_NAME, KEY_ACCOUNT)
    except keyring.errors.PasswordDeleteError:
        pass  # Already gone


def _get_from_keyring() -> bytes | None:
    """Try to retrieve the master key from the OS keyring."""
    try:
        stored = keyring.get_password(SERVICE_NAME, KEY_ACCOUNT)
        if stored:
            # Handle both old format (bare hex) and new format (JSON with salt)
            try:
                payload = json.loads(stored)
                return bytes.fromhex(payload["key"])
            except (json.JSONDecodeError, KeyError):
                # Legacy format: bare hex key (from before salt was added)
                return bytes.fromhex(stored)
    except Exception:
        pass
    return None


def _derive_key_from_passphrase(passphrase: str, salt: bytes | None = None) -> bytes:
    """
    Derive a 32-byte key from a passphrase using PBKDF2-HMAC-SHA256.

    Args:
        passphrase: User-provided passphrase.
        salt: 16-byte random salt. If None, generates a new one (for
              backward compat with env var path, which cannot store salt).
    """
    if salt is None:
        # Env var path: no place to store salt, so derive deterministically.
        # This is the known weaker path -- documented in SECURITY.md.
        salt = hashlib.sha256(SERVICE_NAME.encode()).digest()[:16]
    return hashlib.pbkdf2_hmac(
        "sha256",
        passphrase.encode("utf-8"),
        salt,
        iterations=600_000,  # OWASP 2023 recommendation
    )


def _get_or_create_file_key() -> bytes:
    """
    Get or create an auto-generated master key stored on disk.

    This is the least secure option -- used only as a last resort.
    On Windows, uses icacls to restrict access to the current user only
    (chmod 0o600 is a no-op on Windows).
    """
    key_path = Path.home() / ".coffer" / ".master-key"
    key_path.parent.mkdir(parents=True, exist_ok=True)

    if key_path.exists():
        return bytes.fromhex(key_path.read_text().strip())

    # Generate a new random key
    key = secrets.token_bytes(32)
    key_path.write_text(key.hex())

    # Restrict permissions
    if sys.platform == "win32":
        try:
            username = os.environ.get("USERNAME", "")
            if username:
                subprocess.run(
                    ["icacls", str(key_path), "/inheritance:r",
                     "/grant:r", f"{username}:(F)"],
                    capture_output=True, timeout=10,
                )
        except Exception:
            pass
    else:
        try:
            key_path.chmod(0o600)
        except OSError:
            pass

    return key
