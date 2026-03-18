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
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

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


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------

class EncryptedStore:
    """
    Manages encrypted credentials on disk.

    File layout:
        ~/.krypteia/credentials.json — list of EncryptedBlob dicts
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
        self._path = store_path or Path.home() / ".krypteia" / "credentials.json"
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if not self._path.exists():
            self._write_blobs([])

    # -- public API ----------------------------------------------------------

    def add(self, entry: CredentialEntry) -> None:
        """Encrypt and persist a new credential."""
        blobs = self._read_blobs()
        # Reject duplicates
        if any(b["alias"] == entry.alias for b in blobs):
            raise ValueError(f"Credential with alias '{entry.alias}' already exists")
        blobs.append(self._encrypt(entry))
        self._write_blobs(blobs)

    def get(self, alias: str) -> CredentialEntry:
        """Decrypt and return a credential by alias."""
        blobs = self._read_blobs()
        for blob in blobs:
            if blob["alias"] == alias:
                return self._decrypt(blob)
        raise KeyError(f"No credential found with alias '{alias}'")

    def list_aliases(self) -> list[dict[str, Any]]:
        """Return metadata for all stored credentials (no secrets)."""
        blobs = self._read_blobs()
        return [
            {
                "alias": b["alias"],
                "auth_type": b["auth_type"],
                "description": b["description"],
                "created_at": b["created_at"],
                "rotated_at": b["rotated_at"],
            }
            for b in blobs
        ]

    def remove(self, alias: str) -> bool:
        """Remove a credential by alias. Returns True if found and removed."""
        blobs = self._read_blobs()
        new_blobs = [b for b in blobs if b["alias"] != alias]
        if len(new_blobs) == len(blobs):
            return False
        self._write_blobs(new_blobs)
        return True

    def update_secret(self, alias: str, new_secret: str) -> None:
        """Rotate the secret for an existing credential."""
        entry = self.get(alias)
        self.remove(alias)
        entry.secret = new_secret
        entry.rotated_at = time.time()
        self.add(entry)

    # -- encryption primitives -----------------------------------------------

    def _encrypt(self, entry: CredentialEntry) -> dict:
        """Encrypt a CredentialEntry into an EncryptedBlob dict."""
        plaintext = json.dumps({
            "username": entry.username,
            "secret": entry.secret,
            "allowed_urls": entry.allowed_urls,
            "allowed_methods": entry.allowed_methods,
        }).encode("utf-8")

        nonce = os.urandom(12)  # 96-bit nonce, unique per entry
        ciphertext = self._gcm.encrypt(nonce, plaintext, None)

        return {
            "alias": entry.alias,
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex(),
            "auth_type": entry.auth_type,
            "description": entry.description,
            "created_at": entry.created_at,
            "rotated_at": entry.rotated_at,
        }

    def _decrypt(self, blob: dict) -> CredentialEntry:
        """Decrypt an EncryptedBlob dict into a CredentialEntry."""
        nonce = bytes.fromhex(blob["nonce"])
        ciphertext = bytes.fromhex(blob["ciphertext"])
        plaintext = self._gcm.decrypt(nonce, ciphertext, None)
        secret_data = json.loads(plaintext.decode("utf-8"))

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
        """Write encrypted blobs to disk atomically."""
        tmp_path = self._path.with_suffix(".tmp")
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(blobs, f, indent=2)
        tmp_path.replace(self._path)
