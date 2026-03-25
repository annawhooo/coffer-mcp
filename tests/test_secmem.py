"""Tests for secure memory handling: SecureBuffer, wipe_entry, harden_process."""

from __future__ import annotations

import os

import pytest

from coffer_mcp.secmem import SecureBuffer, harden_process, wipe_entry
from coffer_mcp.store.encrypted_store import CredentialEntry, EncryptedStore


class TestSecureBuffer:
    """Test that SecureBuffer zeros its contents on close."""

    def test_buffer_readable_before_close(self):
        buf = SecureBuffer(b"secret-data")
        assert buf.decode() == "secret-data"
        assert bytes(buf) == b"secret-data"
        buf.close()

    def test_buffer_zeroed_after_close(self):
        """After close(), the internal bytearray should be all zeros."""
        buf = SecureBuffer(b"sensitive-secret")
        buf.close()
        # Access internal data directly to verify zeroing
        assert all(b == 0 for b in buf._data)

    def test_buffer_zeroed_after_context_manager(self):
        """Context manager exit should zero the buffer."""
        with SecureBuffer(b"my-password") as buf:
            assert buf.decode() == "my-password"
        assert all(b == 0 for b in buf._data)

    def test_buffer_raises_after_close(self):
        """Accessing a closed buffer should raise ValueError."""
        buf = SecureBuffer(b"data")
        buf.close()
        with pytest.raises(ValueError, match="closed"):
            buf.decode()
        with pytest.raises(ValueError, match="closed"):
            bytes(buf)

    def test_buffer_double_close_safe(self):
        """Closing twice should not raise."""
        buf = SecureBuffer(b"data")
        buf.close()
        buf.close()  # Should not raise

    def test_buffer_len(self):
        buf = SecureBuffer(b"12345")
        assert len(buf) == 5
        buf.close()

    def test_buffer_with_empty_data(self):
        with SecureBuffer(b"") as buf:
            assert buf.decode() == ""
        assert len(buf._data) == 0

    def test_buffer_with_unicode(self):
        secret = "pässwörd-日本語".encode("utf-8")
        with SecureBuffer(secret) as buf:
            assert buf.decode("utf-8") == "pässwörd-日本語"
        assert all(b == 0 for b in buf._data)

    def test_buffer_with_large_data(self):
        """Large buffers should also be properly zeroed."""
        data = os.urandom(10_000)
        with SecureBuffer(data) as buf:
            assert len(buf) == 10_000
        assert all(b == 0 for b in buf._data)


class TestWipeEntry:
    """Test that wipe_entry clears secret fields."""

    def test_wipe_clears_secret_and_username(self):
        entry = CredentialEntry(
            alias="test",
            auth_type="bearer_token",
            username="admin",
            secret="super-secret-key",
            allowed_urls=["https://api.example.com/*"],
        )
        wipe_entry(entry)
        assert entry.secret == ""
        assert entry.username == ""

    def test_wipe_preserves_non_secret_fields(self):
        entry = CredentialEntry(
            alias="test",
            auth_type="bearer_token",
            username="admin",
            secret="secret",
            allowed_urls=["https://api.example.com/*"],
            description="Test credential",
        )
        wipe_entry(entry)
        # Non-secret fields should be preserved
        assert entry.alias == "test"
        assert entry.auth_type == "bearer_token"
        assert entry.allowed_urls == ["https://api.example.com/*"]
        assert entry.description == "Test credential"

    def test_wipe_idempotent(self):
        """Wiping an already-wiped entry should not raise."""
        entry = CredentialEntry(alias="test", auth_type="bearer_token", secret="s")
        wipe_entry(entry)
        wipe_entry(entry)  # Should not raise
        assert entry.secret == ""

    def test_wipe_none_does_not_raise(self):
        """Wiping None or non-entry objects should not raise."""
        wipe_entry(None)
        wipe_entry("not an entry")
        wipe_entry(42)


class TestDecryptUsesSecureBuffer:
    """Test that the store's decrypt path uses SecureBuffer."""

    def test_decrypt_still_works(self, tmp_path):
        """Ensure decrypt returns correct data after SecureBuffer integration."""
        key = os.urandom(32)
        store = EncryptedStore(key, tmp_path / "creds.json")
        store.add(
            CredentialEntry(
                alias="test",
                auth_type="bearer_token",
                username="user",
                secret="my-secret-value-12345",
                allowed_urls=["https://api.example.com/*"],
            )
        )
        entry = store.get("test")
        assert entry.secret == "my-secret-value-12345"
        assert entry.username == "user"

    def test_decrypt_with_special_chars(self, tmp_path):
        """Secrets with special characters survive SecureBuffer path."""
        key = os.urandom(32)
        store = EncryptedStore(key, tmp_path / "creds.json")
        secret = 'p@ss\\"word\nwith\ttabs'
        store.add(
            CredentialEntry(
                alias="special",
                auth_type="bearer_token",
                secret=secret,
                allowed_urls=["https://api.example.com/*"],
            )
        )
        entry = store.get("special")
        assert entry.secret == secret


class TestHardenProcess:
    """Test process hardening."""

    def test_harden_returns_dict(self):
        """harden_process should return a dict of results."""
        results = harden_process()
        assert isinstance(results, dict)
        assert "disable_core_dumps" in results
        assert "lock_future_memory" in results

    def test_harden_idempotent(self):
        """Calling harden_process twice should not raise."""
        harden_process()
        harden_process()
