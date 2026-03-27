"""Tests for P0 fixes: file locking, AAD in AES-GCM, thread-safe globals."""

import asyncio
import json
import os
import threading
import time

import pytest

from coffer_mcp.audit.logger import AuditLogger
from coffer_mcp.filelock import FileLock
from coffer_mcp.store.backup import export_vault, import_vault
from coffer_mcp.store.encrypted_store import CredentialEntry, EncryptedStore

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def master_key():
    return os.urandom(32)


@pytest.fixture
def store(master_key, tmp_path):
    return EncryptedStore(master_key, tmp_path / "credentials.json")


@pytest.fixture
def sample_entry():
    return CredentialEntry(
        alias="test-api",
        auth_type="bearer_token",
        secret="super-secret-token-12345",
        allowed_urls=["https://api.example.com/*"],
    )


# ===========================================================================
# P0-1: File locking
# ===========================================================================


class TestFileLock:
    def test_basic_lock_unlock(self, tmp_path):
        """FileLock acquire/release should work without error."""
        lock = FileLock(tmp_path / "test.json")
        with lock.acquire():
            # Write something while holding the lock
            (tmp_path / "test.json").write_text("locked", encoding="utf-8")
        assert (tmp_path / "test.json").read_text(encoding="utf-8") == "locked"

    def test_lock_creates_lockfile(self, tmp_path):
        """Acquiring a lock should create a .lock file."""
        target = tmp_path / "data.json"
        target.write_text("{}", encoding="utf-8")
        lock = FileLock(target)
        with lock.acquire():
            assert target.with_suffix(".json.lock").exists()

    def test_reentrant_different_instances(self, tmp_path):
        """Two FileLock instances on the same path should serialise."""
        target = tmp_path / "shared.json"
        target.write_text("0", encoding="utf-8")

        results = []

        def writer(lock_inst, value, delay):
            with lock_inst.acquire():
                time.sleep(delay)
                target.write_text(str(value), encoding="utf-8")
                results.append(value)

        # Two threads, each with their own FileLock on the same path
        lock_a = FileLock(target)
        lock_b = FileLock(target)

        t1 = threading.Thread(target=writer, args=(lock_a, 1, 0.1))
        t2 = threading.Thread(target=writer, args=(lock_b, 2, 0.0))

        t1.start()
        time.sleep(0.02)  # Give t1 time to acquire
        t2.start()

        t1.join(timeout=5)
        t2.join(timeout=5)

        # Both should complete; t1 should finish first
        assert len(results) == 2
        assert results[0] == 1

    def test_concurrent_store_adds(self, master_key, tmp_path):
        """Concurrent adds to the same store should not lose entries."""
        store_path = tmp_path / "concurrent.json"
        errors = []

        def add_entry(i):
            try:
                s = EncryptedStore(master_key, store_path)
                entry = CredentialEntry(
                    alias=f"cred-{i}",
                    auth_type="bearer_token",
                    secret=f"secret-{i}",
                )
                s.add(entry)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=add_entry, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert not errors, f"Errors during concurrent adds: {errors}"

        # All 10 entries should be present
        s = EncryptedStore(master_key, store_path)
        aliases = s.list_aliases()
        assert len(aliases) == 10

    def test_concurrent_audit_logs(self, tmp_path):
        """Concurrent audit log writes should maintain chain integrity."""
        log_path = tmp_path / "audit.jsonl"
        hmac_key = os.urandom(32)
        errors = []

        def log_event(i):
            try:
                logger = AuditLogger(log_path, hmac_key=hmac_key)
                logger.log("credential.used", f"api-{i}")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=log_event, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert not errors, f"Errors during concurrent logging: {errors}"

        # All 10 events should be present
        verifier = AuditLogger(log_path, hmac_key=hmac_key)
        events = verifier.get_events(limit=100)
        assert len(events) == 10


# ===========================================================================
# P0-2: AAD in AES-GCM
# ===========================================================================


class TestAAD:
    def test_encrypt_decrypt_with_aad(self, store, sample_entry):
        """Basic roundtrip should still work with AAD enabled."""
        store.add(sample_entry)
        retrieved = store.get("test-api")
        assert retrieved.secret == sample_entry.secret
        assert retrieved.alias == sample_entry.alias

    def test_legacy_no_aad_still_decrypts(self, master_key, tmp_path):
        """Entries encrypted without AAD (legacy) should still decrypt."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        store_path = tmp_path / "legacy.json"
        gcm = AESGCM(master_key)

        # Manually create a legacy blob (no AAD)
        plaintext = json.dumps(
            {
                "username": "old-user",
                "secret": "old-secret",
                "allowed_urls": ["https://old.example.com/*"],
                "allowed_methods": ["GET"],
            }
        ).encode("utf-8")
        nonce = os.urandom(12)
        ciphertext = gcm.encrypt(nonce, plaintext, None)  # No AAD

        blobs = [
            {
                "alias": "legacy-cred",
                "nonce": nonce.hex(),
                "ciphertext": ciphertext.hex(),
                "auth_type": "bearer_token",
                "description": "Legacy credential",
                "created_at": time.time(),
                "rotated_at": time.time(),
                "expires_at": None,
            }
        ]
        store_path.write_text(json.dumps(blobs), encoding="utf-8")

        # New store should still decrypt the legacy entry
        store = EncryptedStore(master_key, store_path)
        entry = store.get("legacy-cred")
        assert entry.secret == "old-secret"
        assert entry.username == "old-user"

    def test_swapped_ciphertext_detected(self, master_key, tmp_path):
        """Swapping ciphertext between two AAD-protected entries should fail."""
        store_path = tmp_path / "swap.json"
        store = EncryptedStore(master_key, store_path)

        store.add(
            CredentialEntry(
                alias="cred-a",
                auth_type="bearer_token",
                secret="secret-a",
            )
        )
        store.add(
            CredentialEntry(
                alias="cred-b",
                auth_type="bearer_token",
                secret="secret-b",
            )
        )

        # Swap the ciphertext+nonce between the two entries
        raw = json.loads(store_path.read_text(encoding="utf-8"))
        # Handle both envelope format (v2) and bare list (v1)
        blobs = raw["credentials"] if isinstance(raw, dict) else raw
        blobs[0]["ciphertext"], blobs[1]["ciphertext"] = (
            blobs[1]["ciphertext"],
            blobs[0]["ciphertext"],
        )
        blobs[0]["nonce"], blobs[1]["nonce"] = (
            blobs[1]["nonce"],
            blobs[0]["nonce"],
        )
        if isinstance(raw, dict):
            raw["credentials"] = blobs
            store_path.write_text(json.dumps(raw), encoding="utf-8")
        else:
            store_path.write_text(json.dumps(blobs), encoding="utf-8")

        # Decryption should fail because AAD (alias) doesn't match
        store2 = EncryptedStore(master_key, store_path)
        with pytest.raises(Exception):
            store2.get("cred-a")

    def test_backup_roundtrip_with_aad(self, store, sample_entry, tmp_path, master_key):
        """Backup export/import should work with AAD."""
        store.add(sample_entry)
        backup_path = tmp_path / "backup.enc"

        result = export_vault(store, "test-pass", backup_path)
        assert result["status"] == "ok"

        new_store = EncryptedStore(master_key, tmp_path / "new.json")
        result = import_vault(new_store, "test-pass", backup_path)
        assert result["status"] == "ok"
        assert result["imported"] == 1

        restored = new_store.get("test-api")
        assert restored.secret == sample_entry.secret

    def test_legacy_backup_no_aad_still_imports(self, master_key, tmp_path):
        """Backups created without AAD (legacy) should still import."""
        import hashlib

        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        backup_path = tmp_path / "legacy_backup.enc"

        # Create a legacy backup (no AAD)
        salt = os.urandom(16)
        key = hashlib.pbkdf2_hmac("sha256", b"legacy-pass", salt, 600_000)
        gcm = AESGCM(key)
        nonce = os.urandom(12)

        payload = json.dumps(
            {
                "magic": "COFFER-BACKUP",
                "version": 1,
                "exported_at": time.time(),
                "credentials": [
                    {
                        "alias": "legacy-api",
                        "auth_type": "bearer_token",
                        "username": "",
                        "secret": "legacy-secret",
                        "allowed_urls": [],
                        "allowed_methods": ["GET"],
                        "description": "Legacy",
                        "created_at": time.time(),
                        "rotated_at": time.time(),
                        "expires_at": None,
                    }
                ],
            }
        ).encode("utf-8")

        ciphertext = gcm.encrypt(nonce, payload, None)  # No AAD

        backup_data = {
            "magic": "COFFER-BACKUP",
            "version": 1,
            "salt": salt.hex(),
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex(),
            "credential_count": 1,
        }
        backup_path.write_text(json.dumps(backup_data), encoding="utf-8")

        # Import should still work
        store = EncryptedStore(master_key, tmp_path / "store.json")
        result = import_vault(store, "legacy-pass", backup_path)
        assert result["status"] == "ok"
        assert result["imported"] == 1

        entry = store.get("legacy-api")
        assert entry.secret == "legacy-secret"


# ===========================================================================
# P0-3: Thread-safe global state
# ===========================================================================


class TestThreadSafeGlobals:
    def test_server_init_lock_exists(self):
        """server module should have an _init_lock."""
        from coffer_mcp import server

        assert hasattr(server, "_init_lock")
        assert isinstance(server._init_lock, type(threading.Lock()))

    def test_sessions_lock_exists(self):
        """vault_web_login module should have an _sessions_lock."""
        import importlib

        vwl_module = importlib.import_module("coffer_mcp.tools.vault_web_login")
        assert hasattr(vwl_module, "_sessions_lock")
        assert isinstance(vwl_module._sessions_lock, asyncio.Lock)

    def test_token_lock_exists(self):
        """oauth2 module should have a _token_lock."""
        from coffer_mcp.tools import oauth2

        assert hasattr(oauth2, "_token_lock")
        assert isinstance(oauth2._token_lock, asyncio.Lock)

    def test_clear_token_cache_is_async(self):
        """clear_token_cache should be an async function."""
        from coffer_mcp.tools.oauth2 import clear_token_cache

        assert asyncio.iscoroutinefunction(clear_token_cache)
