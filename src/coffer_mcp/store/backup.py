"""
Encrypted backup and restore for the Coffer credential store.

Export produces a standalone encrypted file (using a separate passphrase)
that can be stored on a USB drive, cloud storage, etc.

Import decrypts the backup and re-adds all credentials to the vault.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from coffer_mcp.store.encrypted_store import CredentialEntry, EncryptedStore

BACKUP_VERSION = 1
BACKUP_MAGIC = "COFFER-BACKUP"


def _derive_backup_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a 32-byte key from a backup passphrase."""
    return hashlib.pbkdf2_hmac(
        "sha256",
        passphrase.encode("utf-8"),
        salt,
        iterations=600_000,
    )


def export_vault(
    store: EncryptedStore,
    passphrase: str,
    output_path: Path,
) -> dict[str, Any]:
    """
    Export all credentials to an encrypted backup file.

    The backup uses a separate passphrase (not the master key) so it
    can be safely stored independently.
    """
    aliases = store.list_aliases()
    entries = []
    for a in aliases:
        entry = store.get(a["alias"])
        entries.append(
            {
                "alias": entry.alias,
                "auth_type": entry.auth_type,
                "username": entry.username,
                "secret": entry.secret,
                "allowed_urls": entry.allowed_urls,
                "allowed_methods": entry.allowed_methods,
                "description": entry.description,
                "created_at": entry.created_at,
                "rotated_at": entry.rotated_at,
                "expires_at": entry.expires_at,
            }
        )

    salt = os.urandom(16)
    key = _derive_backup_key(passphrase, salt)
    gcm = AESGCM(key)
    nonce = os.urandom(12)

    payload = json.dumps(
        {
            "magic": BACKUP_MAGIC,
            "version": BACKUP_VERSION,
            "exported_at": time.time(),
            "credentials": entries,
        }
    ).encode("utf-8")

    aad = f"{BACKUP_MAGIC}:v{BACKUP_VERSION}".encode("utf-8")
    ciphertext = gcm.encrypt(nonce, payload, aad)

    backup_data = {
        "magic": BACKUP_MAGIC,
        "version": BACKUP_VERSION,
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "credential_count": len(entries),
    }
    output_path.write_text(
        json.dumps(backup_data, indent=2),
        encoding="utf-8",
    )
    return {
        "status": "ok",
        "count": len(entries),
        "path": str(output_path),
    }


def import_vault(
    store: EncryptedStore,
    passphrase: str,
    input_path: Path,
    overwrite: bool = False,
) -> dict[str, Any]:
    """
    Import credentials from an encrypted backup file.

    Args:
        store: The credential store to import into.
        passphrase: Passphrase used to encrypt the backup.
        input_path: Path to the backup file.
        overwrite: If True, overwrite existing credentials
                   with the same alias. If False, skip them.

    Returns:
        Dict with status, counts of imported/skipped credentials.
    """
    raw = json.loads(input_path.read_text(encoding="utf-8"))

    if raw.get("magic") != BACKUP_MAGIC:
        return {"status": "error", "message": "Not a valid Coffer backup file."}

    salt = bytes.fromhex(raw["salt"])
    nonce = bytes.fromhex(raw["nonce"])
    ciphertext = bytes.fromhex(raw["ciphertext"])

    key = _derive_backup_key(passphrase, salt)
    gcm = AESGCM(key)

    aad = f"{BACKUP_MAGIC}:v{raw.get('version', BACKUP_VERSION)}".encode("utf-8")
    try:
        plaintext = gcm.decrypt(nonce, ciphertext, aad)
    except Exception:
        # Fall back to legacy no-AAD for backups created before AAD was added
        try:
            plaintext = gcm.decrypt(nonce, ciphertext, None)
        except Exception:
            return {
                "status": "error",
                "message": "Decryption failed. Wrong passphrase?",
            }

    data = json.loads(plaintext.decode("utf-8"))
    entries = data.get("credentials", [])

    imported = 0
    skipped = 0
    errors = []

    for raw_entry in entries:
        alias = raw_entry["alias"]
        entry = CredentialEntry(
            alias=alias,
            auth_type=raw_entry["auth_type"],
            username=raw_entry.get("username", ""),
            secret=raw_entry["secret"],
            allowed_urls=raw_entry.get("allowed_urls", []),
            allowed_methods=raw_entry.get("allowed_methods", ["GET"]),
            description=raw_entry.get("description", ""),
            created_at=raw_entry.get("created_at", time.time()),
            rotated_at=raw_entry.get("rotated_at", time.time()),
            expires_at=raw_entry.get("expires_at"),
        )
        try:
            if overwrite:
                # Save the old entry before removing so we can roll back
                old_entry: CredentialEntry | None = None
                try:
                    old_entry = store.get(alias)
                except KeyError:
                    pass
                if old_entry is not None:
                    store.remove(alias)
                try:
                    store.add(entry)
                except Exception:
                    # Roll back: restore the old credential if add failed
                    if old_entry is not None:
                        try:
                            store.add(old_entry)
                        except Exception:
                            pass  # Best-effort restore
                    raise
            else:
                store.add(entry)
            imported += 1
        except ValueError:
            # Duplicate alias and overwrite=False
            skipped += 1
        except Exception as e:
            errors.append(f"{alias}: {e}")

    return {
        "status": "ok",
        "imported": imported,
        "skipped": skipped,
        "errors": errors,
        "total_in_backup": len(entries),
    }
