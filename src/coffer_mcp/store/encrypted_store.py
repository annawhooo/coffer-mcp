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
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from coffer_mcp.filelock import FileLock
from coffer_mcp.permissions import secure_directory, secure_file
from coffer_mcp.secmem import SecureBuffer

STORE_VERSION = 2  # Bump when the on-disk format changes

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
    # coffer_exec allowlist: [{"argv": ["/abs/path/bin", "arg", ...], "cwd": "/abs/dir" | None}]
    # Exact-argv match only; argv[0] must be absolute. Fail-closed when empty.
    allowed_commands: list[dict] = field(default_factory=list)
    description: str = ""
    created_at: float = field(default_factory=time.time)
    rotated_at: float = field(default_factory=time.time)
    expires_at: float | None = None  # Unix timestamp; None = never expires

    def metadata(self) -> dict[str, Any]:
        """Return only non-secret fields (safe to show the LLM).

        Note: username is intentionally excluded because for many auth
        types it is half the credential (e.g., basic_auth, web_login).
        """
        return {
            "alias": self.alias,
            "auth_type": self.auth_type,
            "allowed_urls": self.allowed_urls,
            "allowed_methods": self.allowed_methods,
            "allowed_commands": self.allowed_commands,
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

    def add_allowed_command(self, alias: str, argv: list[str], cwd: str | None = None) -> int:
        """Append a command to a credential's coffer_exec allowlist.

        The allowlist lives inside the encrypted payload, so it is
        confidential and integrity-protected like the secret itself.

        Args:
            alias: The credential to modify.
            argv: Exact argument vector; argv[0] must be an absolute path.
            cwd: Optional fixed working directory (absolute) for the command.

        Returns:
            The new number of allowed commands for this credential.

        Raises:
            KeyError: If the alias doesn't exist.
            ValueError: If argv/cwd fail validation.
        """
        if not argv or not all(isinstance(a, str) and a for a in argv):
            raise ValueError("argv must be a non-empty list of non-empty strings")
        if not os.path.isabs(argv[0]):
            raise ValueError("argv[0] must be an absolute path (PATH lookup is not allowed)")
        if cwd is not None and not os.path.isabs(cwd):
            raise ValueError("cwd must be an absolute path when provided")

        with self._lock.acquire():
            blobs = self._read_blobs()
            for i, blob in enumerate(blobs):
                if blob["alias"] == alias:
                    entry = self._decrypt(blob)
                    command = {"argv": list(argv), "cwd": cwd}
                    if command not in entry.allowed_commands:
                        entry.allowed_commands.append(command)
                    blobs[i] = self._encrypt(entry)
                    self._write_blobs(blobs)
                    return len(entry.allowed_commands)
            raise KeyError(f"No credential found with alias '{alias}'")

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

    def migrate_aad(self) -> int:
        """Re-encrypt every entry with the current full-metadata AAD.

        Upgrades legacy entries (alias-only AAD or no AAD) so their
        plaintext metadata fields become integrity-protected (RR-H6).
        Atomic: if any entry fails to decrypt, nothing is written.

        Returns:
            Number of credentials re-encrypted.
        """
        with self._lock.acquire():
            blobs = self._read_blobs()
            entries = [self._decrypt(blob) for blob in blobs]
            new_blobs = [self._encrypt(entry) for entry in entries]
            self._write_blobs(new_blobs)
        return len(entries)

    # -- encryption primitives -----------------------------------------------

    @staticmethod
    def _metadata_aad(
        alias: str,
        auth_type: str,
        description: str,
        created_at: float,
        rotated_at: float,
        expires_at: float | None,
    ) -> bytes:
        """Canonical AAD covering all plaintext metadata fields (RR-H6).

        Binding these fields into the GCM authentication tag means an
        attacker with file write access cannot alter them (e.g., null out
        expires_at to disable expiry) without breaking decryption.
        """
        return json.dumps(
            {
                "alias": alias,
                "auth_type": auth_type,
                "description": description,
                "created_at": created_at,
                "rotated_at": rotated_at,
                "expires_at": expires_at,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def _encrypt(self, entry: CredentialEntry) -> dict:
        """Encrypt a CredentialEntry into an EncryptedBlob dict.

        All plaintext metadata fields are bound into the GCM tag as
        Associated Authenticated Data (AAD), so neither cross-entry
        ciphertext swaps nor metadata edits go undetected.
        """
        plaintext = json.dumps(
            {
                "username": entry.username,
                "secret": entry.secret,
                "allowed_urls": entry.allowed_urls,
                "allowed_methods": entry.allowed_methods,
                "allowed_commands": entry.allowed_commands,
            }
        ).encode("utf-8")

        nonce = os.urandom(12)  # 96-bit nonce, unique per entry
        aad = self._metadata_aad(
            entry.alias,
            entry.auth_type,
            entry.description,
            entry.created_at,
            entry.rotated_at,
            entry.expires_at,
        )
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
            "aad_version": 3,  # informational; tampering it has no effect
        }

    def _decrypt(self, blob: dict) -> CredentialEntry:
        """Decrypt an EncryptedBlob dict into a CredentialEntry.

        Tries full-metadata AAD first (current format), then falls back to
        alias-only AAD and finally no AAD for entries written by older
        versions. The fallbacks only succeed for blobs genuinely encrypted
        with the older constructions — a current blob with tampered
        metadata fails all three and raises InvalidTag (fail closed).
        Legacy successes emit a warning recommending migrate_aad().

        Uses SecureBuffer to zero the decrypted plaintext from memory
        as soon as the JSON fields have been extracted.
        """
        nonce = bytes.fromhex(blob["nonce"])
        ciphertext = bytes.fromhex(blob["ciphertext"])
        aad_full = self._metadata_aad(
            blob["alias"],
            blob["auth_type"],
            blob["description"],
            blob["created_at"],
            blob["rotated_at"],
            blob.get("expires_at"),
        )
        try:
            raw_plaintext = self._gcm.decrypt(nonce, ciphertext, aad_full)
        except InvalidTag:
            try:
                # Legacy: alias-only AAD (store format v2)
                raw_plaintext = self._gcm.decrypt(nonce, ciphertext, blob["alias"].encode("utf-8"))
            except InvalidTag:
                # Legacy: no AAD (store format v1). If this also fails,
                # InvalidTag propagates — tampered entry or wrong key.
                raw_plaintext = self._gcm.decrypt(nonce, ciphertext, None)
            warnings.warn(
                f"Credential '{blob['alias']}' uses a legacy AAD format; its "
                "metadata (expires_at, auth_type, ...) is not integrity-"
                "protected. Run migrate_aad() to upgrade.",
                UserWarning,
                stacklevel=3,
            )

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
            allowed_commands=secret_data.get("allowed_commands", []),
            description=blob["description"],
            created_at=blob["created_at"],
            rotated_at=blob["rotated_at"],
            expires_at=blob.get("expires_at"),
        )

    # -- file I/O ------------------------------------------------------------

    def _read_blobs(self) -> list[dict]:
        """Read the encrypted blobs from disk.

        Raises json.JSONDecodeError if the file exists but is corrupted,
        rather than silently returning an empty list (which would make
        all credentials appear to vanish).
        """
        try:
            with open(self._path, "r", encoding="utf-8") as f:
                content = f.read()
        except FileNotFoundError:
            return []

        if not content.strip():
            return []

        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            raise json.JSONDecodeError(
                f"Credential store is corrupted ({self._path}): {e.msg}",
                e.doc,
                e.pos,
            ) from e

        # Support both formats:
        #   v2+: {"version": N, "credentials": [...]}
        #   v1 (legacy): bare list [...]
        if isinstance(data, list):
            return data  # Legacy format
        if isinstance(data, dict) and "credentials" in data:
            return data["credentials"]
        return []

    def _write_blobs(self, blobs: list[dict]) -> None:
        """Write encrypted blobs to disk atomically with secure permissions."""
        tmp_path = self._path.with_suffix(".tmp")
        envelope = {"version": STORE_VERSION, "credentials": blobs}
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(envelope, f, indent=2)
        secure_file(tmp_path)
        tmp_path.replace(self._path)
        secure_file(self._path)
