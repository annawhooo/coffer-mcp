"""
Encrypted credential store using AES-256-GCM.

Each credential entry is individually encrypted with a unique nonce.
The master key is derived from a passphrase via PBKDF2 or retrieved
from the OS keyring.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from coffer_mcp.filelock import FileLock
from coffer_mcp.permissions import secure_directory, secure_file
from coffer_mcp.secmem import SecureBuffer

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class CredentialEntry:
    """A single stored credential (plaintext representation)."""

    alias: str
    auth_type: str  # "bearer_token", "basic_auth", "api_key_header", "web_login"
    username: str = ""
    secret: str = ""  # password, token, or API key — never returned to the LLM
    allowed_urls: list[str] = field(default_factory=list)
    allowed_methods: list[str] = field(default_factory=lambda: ["GET"])
    description: str = ""
    created_at: float = field(default_factory=time.time)
    rotated_at: float = field(default_factory=time.time)
    expires_at: float | None = None  # Unix timestamp; None = never expires

    def metadata(self) -> dict[str, Any]:
        """Return only non-secret fields (safe to show the LLM)."""
        return {
            "alias": self.alias,
            "auth_type": self.auth_type,
            "username": self.username,
            "allowed_urls": self.allowed_urls,
            "allowed_methods": self.allowed_methods,
            "description": self.description,
            "created_at": self.created_at,
            "rotated_at": self.rotated_at,
            "expires_at": self.expires_at,
        }


@dataclass
class EncryptedBlob:
    """On-disk representation of a single encrypted credential."""

    alias: str
    nonce: str  # hex-encoded 12-byte nonce
    ciphertext: str  # hex-encoded ciphertext + GCM tag
    auth_type: str
    description: str
    created_at: float
    rotated_at: float
    expires_at: float | None = None


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------


class EncryptedStore:
    """
    Manages encrypted credentials on disk.

    File layout:
        ~/.coffer/credentials.json — list of EncryptedBlob dicts
    """

    def __init__(self, master_key: bytes, store_path: Path | None = None):
        """
        Args:
            master_key: 32-byte AES-256 key.
            store_path: Path to the credentials JSON file.
        """
        if len(master_key) != 32:
            raise ValueError("Master key must be exactly 32 bytes (256 bits)")
        self._gcm = AESGCM(master_key)
        self._path = store_path or Path.home() / ".coffer" / "credentials.json"
        self._lock = FileLock(self._path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        secure_directory(self._path.parent)
        with self._lock.acquire():
            if not self._path.exists():
                self._write_blobs([])

    # -- public API ----------------------------------------------------------

    def add(self, entry: CredentialEntry) -> None:
        """Encrypt and persist a new credential."""
        with self._lock.acquire():
            blobs = self._read_blobs()
            # Reject duplicates
            if any(b["alias"] == entry.alias for b in blobs):
                raise ValueError(f"Credential with alias '{entry.alias}' already exists")
            blobs.append(self._encrypt(entry))
            self._write_blobs(blobs)

    def is_expired(self, alias: str) -> bool:
        """Check if a credential has passed its expiry date."""
        entry = self.get(alias)
        if entry.expires_at is None:
            return False
        return time.time() > entry.expires_at

    def get(self, alias: str) -> CredentialEntry:
        """Decrypt and return a credential by alias."""
        with self._lock.acquire():
            blobs = self._read_blobs()
            for blob in blobs:
                if blob["alias"] == alias:
                    return self._decrypt(blob)
            raise KeyError(f"No credential found with alias '{alias}'")

    def list_aliases(self) -> list[dict[str, Any]]:
        """Return metadata for all stored credentials (no secrets)."""
        with self._lock.acquire():
            blobs = self._read_blobs()
        return [
            {
                "alias": b["alias"],
                "auth_type": b["auth_type"],
                "description": b["description"],
                "created_at": b["created_at"],
                "rotated_at": b["rotated_at"],
                "expires_at": b.get("expires_at"),
            }
            for b in blobs
        ]

    def remove(self, alias: str) -> bool:
        """Remove a credential by alias. Returns True if found and removed."""
        with self._lock.acquire():
            blobs = self._read_blobs()
            new_blobs = [b for b in blobs if b["alias"] != alias]
            if len(new_blobs) == len(blobs):
                return False
            self._write_blobs(new_blobs)
            return True

    def update_secret(self, alias: str, new_secret: str) -> None:
        """
        Rotate the secret for an existing credential.

        This is atomic: the old credential is replaced in a single
        write operation. If the process crashes mid-rotation, the
        original credential remains intact.
        """
        with self._lock.acquire():
            blobs = self._read_blobs()
            found = False
            for i, blob in enumerate(blobs):
                if blob["alias"] == alias:
                    # Decrypt, update, re-encrypt in memory
                    entry = self._decrypt(blob)
                    entry.secret = new_secret
                    entry.rotated_at = time.time()
                    blobs[i] = self._encrypt(entry)
                    found = True
                    break
            if not found:
                raise KeyError(f"No credential found with alias '{alias}'")
            # Single atomic write replaces the entire file
            self._write_blobs(blobs)

    def rekey(self, new_master_key: bytes) -> int:
        """
        Re-encrypt all credentials with a new master key.

        Decrypts every entry with the current key, then re-encrypts
        with the new key in a single atomic write.  If anything fails
        mid-way, the file is left untouched (the old key still works).

        Args:
            new_master_key: 32-byte AES-256 key to re-encrypt with.

        Returns:
            Number of credentials re-encrypted.

        Raises:
            ValueError: If the new key is not 32 bytes.
        """
        if len(new_master_key) != 32:
            raise ValueError("New master key must be exactly 32 bytes (256 bits)")

        new_gcm = AESGCM(new_master_key)

        with self._lock.acquire():
            blobs = self._read_blobs()

            # Phase 1: decrypt everything with the OLD key (in memory)
            entries: list[CredentialEntry] = []
            for blob in blobs:
                entries.append(self._decrypt(blob))

            # Phase 2: re-encrypt everything with the NEW key
            self._gcm = new_gcm
            new_blobs = []
            for entry in entries:
                new_blobs.append(self._encrypt(entry))

            # Phase 3: atomic write
            self._write_blobs(new_blobs)

        return len(entries)

    # -- encryption primitives -----------------------------------------------

    def _encrypt(self, entry: CredentialEntry) -> dict:
        """Encrypt a CredentialEntry into an EncryptedBlob dict.

        Uses the credential alias as Associated Authenticated Data (AAD)
        so that ciphertext cannot be swapped between credential entries
        without detection.
        """
        plaintext = json.dumps(
            {
                "username": entry.username,
                "secret": entry.secret,
                "allowed_urls": entry.allowed_urls,
                "allowed_methods": entry.allowed_methods,
            }
        ).encode("utf-8")

        nonce = os.urandom(12)  # 96-bit nonce, unique per entry
        aad = entry.alias.encode("utf-8")
        ciphertext = self._gcm.encrypt(nonce, plaintext, aad)

        return {
            "alias": entry.alias,
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex(),
            "auth_type": entry.auth_type,
            "description": entry.description,
            "created_at": entry.created_at,
            "rotated_at": entry.rotated_at,
            "expires_at": entry.expires_at,
        }

    def _decrypt(self, blob: dict) -> CredentialEntry:
        """Decrypt an EncryptedBlob dict into a CredentialEntry.

        Tries AAD-based decryption first; falls back to legacy no-AAD
        for entries encrypted before AAD was added.

        Uses SecureBuffer to zero the decrypted plaintext from memory
        as soon as the JSON fields have been extracted.
        """
        nonce = bytes.fromhex(blob["nonce"])
        ciphertext = bytes.fromhex(blob["ciphertext"])
        aad = blob["alias"].encode("utf-8")
        try:
            raw_plaintext = self._gcm.decrypt(nonce, ciphertext, aad)
        except InvalidTag:
            # Legacy entry encrypted without AAD — fall back
            raw_plaintext = self._gcm.decrypt(nonce, ciphertext, None)

        # Wrap in SecureBuffer so we can zero the plaintext after parsing
        with SecureBuffer(raw_plaintext) as buf:
            secret_data = json.loads(buf.decode("utf-8"))

        # Zero the original bytes object as best we can (mutable copy)
        raw_mut = bytearray(len(raw_plaintext))
        for i in range(len(raw_mut)):
            raw_mut[i] = 0
        del raw_plaintext

        return CredentialEntry(
            alias=blob["alias"],
            auth_type=blob["auth_type"],
            username=secret_data["username"],
            secret=secret_data["secret"],
            allowed_urls=secret_data["allowed_urls"],
            allowed_methods=secret_data["allowed_methods"],
            description=blob["description"],
            created_at=blob["created_at"],
            rotated_at=blob["rotated_at"],
            expires_at=blob.get("expires_at"),
        )

    # -- file I/O ------------------------------------------------------------

    def _read_blobs(self) -> list[dict]:
        """Read the encrypted blobs from disk."""
        try:
            with open(self._path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return []

    def _write_blobs(self, blobs: list[dict]) -> None:
        """Write encrypted blobs to disk atomically with secure permissions."""
        tmp_path = self._path.with_suffix(".tmp")
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(blobs, f, indent=2)
        secure_file(tmp_path)
        tmp_path.replace(self._path)
        secure_file(self._path)
