"""
Master key management.

Retrieves or generates the master encryption key using (in priority order):
1. OS keyring (Windows Credential Manager / macOS Keychain / Linux Secret Service)
2. ALCOVE_MASTER_KEY environment variable
3. Auto-generated key stored in ~/.alcove/.master-key (fallback)
"""

from __future__ import annotations

import hashlib
import os
import secrets
from pathlib import Path

import keyring

SERVICE_NAME = "alcove-mcp"
KEY_ACCOUNT = "master-key"


def get_master_key() -> bytes:
    """
    Retrieve the 32-byte master key.

    Priority:
        1. OS keyring
        2. ALCOVE_MASTER_KEY env var (hex-encoded)
        3. Auto-generated file at ~/.alcove/.master-key

    Returns:
        32-byte AES-256 key.
    """
    # 1. Try OS keyring
    stored = _get_from_keyring()
    if stored is not None:
        return stored

    # 2. Try environment variable
    env_key = os.environ.get("ALCOVE_MASTER_KEY")
    if env_key:
        return _derive_key_from_passphrase(env_key)

    # 3. Fallback: auto-generated file
    return _get_or_create_file_key()


def store_master_key_in_keyring(passphrase: str) -> bytes:
    """
    Derive a key from a passphrase and store it in the OS keyring.

    Args:
        passphrase: User-provided passphrase.

    Returns:
        The 32-byte derived key.
    """
    key = _derive_key_from_passphrase(passphrase)
    keyring.set_password(SERVICE_NAME, KEY_ACCOUNT, key.hex())
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
            return bytes.fromhex(stored)
    except Exception:
        pass
    return None


def _derive_key_from_passphrase(passphrase: str) -> bytes:
    """
    Derive a 32-byte key from a passphrase using PBKDF2-HMAC-SHA256.

    Uses a fixed salt derived from the service name so the same passphrase
    always produces the same key on the same machine. This is a deliberate
    trade-off: the passphrase itself provides the entropy.
    """
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

    This is the least secure option â€” used only as a last resort.
    The file is created with restrictive permissions.
    """
    key_path = Path.home() / ".alcove" / ".master-key"
    key_path.parent.mkdir(parents=True, exist_ok=True)

    if key_path.exists():
        return bytes.fromhex(key_path.read_text().strip())

    # Generate a new random key
    key = secrets.token_bytes(32)
    key_path.write_text(key.hex())

    # Restrict permissions (best effort on Windows)
    try:
        key_path.chmod(0o600)
    except OSError:
        pass

    return key
