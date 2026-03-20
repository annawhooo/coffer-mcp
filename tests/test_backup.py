"""Tests for encrypted backup and restore."""

import os
import time

import pytest

from coffer_mcp.store.encrypted_store import CredentialEntry, EncryptedStore
from coffer_mcp.store.backup import export_vault, import_vault


@pytest.fixture
def master_key():
    return os.urandom(32)


@pytest.fixture
def store(master_key, tmp_path):
    return EncryptedStore(master_key, tmp_path / "credentials.json")


@pytest.fixture
def populated_store(store):
    """Store with 3 credentials of different types."""
    store.add(CredentialEntry(
        alias="api-1", auth_type="bearer_token",
        secret="token-111", description="API one",
        allowed_urls=["https://api1.example.com/*"],
    ))
    store.add(CredentialEntry(
        alias="web-1", auth_type="web_login",
        username="user@test.com", secret="pass123",
        description="Web login", expires_at=time.time() + 86400,
    ))
    store.add(CredentialEntry(
        alias="basic-1", auth_type="basic_auth",
        username="admin", secret="admin-pass",
        description="Basic auth", allowed_methods=["GET", "POST"],
    ))
    return store


class TestExportImport:
    def test_roundtrip(self, populated_store, tmp_path, master_key):
        """Export then import should reproduce all credentials exactly."""
        backup_path = tmp_path / "backup.enc"
        result = export_vault(populated_store, "backup-pass", backup_path)
        assert result["status"] == "ok"
        assert result["count"] == 3
        assert backup_path.exists()

        # Import into a fresh store
        new_store = EncryptedStore(master_key, tmp_path / "new_creds.json")
        result = import_vault(new_store, "backup-pass", backup_path)
        assert result["status"] == "ok"
        assert result["imported"] == 3
        assert result["skipped"] == 0

        # Verify all credentials match
        api = new_store.get("api-1")
        assert api.secret == "token-111"
        assert api.auth_type == "bearer_token"

        web = new_store.get("web-1")
        assert web.username == "user@test.com"
        assert web.secret == "pass123"
        assert web.expires_at is not None

        basic = new_store.get("basic-1")
        assert basic.username == "admin"
        assert basic.secret == "admin-pass"

    def test_wrong_passphrase_fails(self, populated_store, tmp_path, master_key):
        """Import with wrong passphrase should fail gracefully."""
        backup_path = tmp_path / "backup.enc"
        export_vault(populated_store, "correct-pass", backup_path)

        new_store = EncryptedStore(master_key, tmp_path / "new_creds.json")
        result = import_vault(new_store, "wrong-pass", backup_path)
        assert result["status"] == "error"
        assert "passphrase" in result["message"].lower() or "decryption" in result["message"].lower()

    def test_skip_duplicates(self, populated_store, tmp_path):
        """Import without overwrite should skip existing credentials."""
        backup_path = tmp_path / "backup.enc"
        export_vault(populated_store, "pass", backup_path)

        # Import into the SAME store (all 3 already exist)
        result = import_vault(populated_store, "pass", backup_path, overwrite=False)
        assert result["status"] == "ok"
        assert result["imported"] == 0
        assert result["skipped"] == 3

    def test_overwrite_replaces(self, populated_store, tmp_path, master_key):
        """Import with overwrite should replace existing credentials."""
        backup_path = tmp_path / "backup.enc"
        export_vault(populated_store, "pass", backup_path)

        # Change a secret in the original store
        populated_store.update_secret("api-1", "changed-secret")

        # Import with overwrite — should restore original secret
        result = import_vault(populated_store, "pass", backup_path, overwrite=True)
        assert result["status"] == "ok"
        assert result["imported"] == 3

        restored = populated_store.get("api-1")
        assert restored.secret == "token-111"  # Original from backup

    def test_empty_vault_export(self, store, tmp_path):
        """Exporting an empty vault should succeed with count 0."""
        backup_path = tmp_path / "empty.enc"
        result = export_vault(store, "pass", backup_path)
        assert result["status"] == "ok"
        assert result["count"] == 0

    def test_invalid_backup_file(self, store, tmp_path):
        """Importing a non-backup file should fail gracefully."""
        fake_path = tmp_path / "not_a_backup.json"
        fake_path.write_text('{"foo": "bar"}', encoding="utf-8")
        result = import_vault(store, "pass", fake_path)
        assert result["status"] == "error"
        assert "valid" in result["message"].lower() or "backup" in result["message"].lower()
