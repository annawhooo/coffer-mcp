"""Tests for file permission hardening."""

from __future__ import annotations

import os
import stat
import sys

import pytest

from coffer_mcp.permissions import secure_directory, secure_file
from coffer_mcp.store.encrypted_store import CredentialEntry, EncryptedStore


class TestSecureFile:
    """Test that secure_file sets restrictive permissions."""

    @pytest.mark.skipif(sys.platform == "win32", reason="Unix permission model")
    def test_file_permissions_0600_unix(self, tmp_path):
        """On Unix, secure_file should set 0600 (owner read/write only)."""
        test_file = tmp_path / "secret.json"
        test_file.write_text("sensitive data")

        # Ensure it starts with broader permissions
        os.chmod(test_file, 0o644)
        secure_file(test_file)

        mode = stat.S_IMODE(os.stat(test_file).st_mode)
        assert mode == 0o600

    @pytest.mark.skipif(sys.platform == "win32", reason="Unix permission model")
    def test_directory_permissions_0700_unix(self, tmp_path):
        """On Unix, secure_directory should set 0700 (owner rwx only)."""
        test_dir = tmp_path / "vault"
        test_dir.mkdir()

        os.chmod(test_dir, 0o755)
        secure_directory(test_dir)

        mode = stat.S_IMODE(os.stat(test_dir).st_mode)
        assert mode == 0o700

    def test_nonexistent_file_no_error(self, tmp_path):
        """secure_file on a nonexistent path should not raise."""
        secure_file(tmp_path / "does_not_exist.json")

    def test_nonexistent_dir_no_error(self, tmp_path):
        """secure_directory on a nonexistent path should not raise."""
        secure_directory(tmp_path / "does_not_exist")


class TestStorePermissions:
    """Test that EncryptedStore creates files with secure permissions."""

    @pytest.mark.skipif(sys.platform == "win32", reason="Unix permission model")
    def test_credentials_file_is_0600(self, tmp_path):
        """credentials.json should be created with 0600 permissions."""
        key = os.urandom(32)
        store_path = tmp_path / "vault" / "credentials.json"
        EncryptedStore(key, store_path)

        mode = stat.S_IMODE(os.stat(store_path).st_mode)
        assert mode == 0o600

    @pytest.mark.skipif(sys.platform == "win32", reason="Unix permission model")
    def test_vault_directory_is_0700(self, tmp_path):
        """The .coffer directory should be created with 0700 permissions."""
        key = os.urandom(32)
        vault_dir = tmp_path / "vault"
        EncryptedStore(key, vault_dir / "credentials.json")

        mode = stat.S_IMODE(os.stat(vault_dir).st_mode)
        assert mode == 0o700

    @pytest.mark.skipif(sys.platform == "win32", reason="Unix permission model")
    def test_permissions_maintained_after_write(self, tmp_path):
        """Permissions should stay 0600 after adding a credential."""
        key = os.urandom(32)
        store_path = tmp_path / "credentials.json"
        store = EncryptedStore(key, store_path)

        store.add(
            CredentialEntry(
                alias="test",
                auth_type="bearer_token",
                secret="s3cret",
                allowed_urls=["https://api.example.com/*"],
            )
        )

        mode = stat.S_IMODE(os.stat(store_path).st_mode)
        assert mode == 0o600

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_windows_store_no_crash(self, tmp_path):
        """On Windows, store creation should succeed without permission errors."""
        key = os.urandom(32)
        store = EncryptedStore(key, tmp_path / "credentials.json")
        store.add(
            CredentialEntry(
                alias="test",
                auth_type="bearer_token",
                secret="s3cret",
                allowed_urls=["https://api.example.com/*"],
            )
        )
        assert store.get("test").secret == "s3cret"


class TestBackupPermissions:
    """Test that backup files get secure permissions."""

    @pytest.mark.skipif(sys.platform == "win32", reason="Unix permission model")
    def test_backup_file_is_0600(self, tmp_path):
        """Exported backup files should have 0600 permissions."""
        from coffer_mcp.store.backup import export_vault

        key = os.urandom(32)
        store = EncryptedStore(key, tmp_path / "credentials.json")
        store.add(
            CredentialEntry(
                alias="test",
                auth_type="bearer_token",
                secret="s3cret",
                allowed_urls=["https://api.example.com/*"],
            )
        )

        backup_path = tmp_path / "backup.enc"
        export_vault(store, "pass123", backup_path)

        mode = stat.S_IMODE(os.stat(backup_path).st_mode)
        assert mode == 0o600
