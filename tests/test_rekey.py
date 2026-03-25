"""Tests for master key rotation (rekey)."""

import os

import pytest

from coffer_mcp.store.encrypted_store import CredentialEntry, EncryptedStore


@pytest.fixture
def old_key():
    return os.urandom(32)


@pytest.fixture
def new_key():
    return os.urandom(32)


@pytest.fixture
def populated_store(old_key, tmp_path):
    """Store with 3 credentials encrypted under old_key."""
    store = EncryptedStore(old_key, tmp_path / "credentials.json")
    store.add(
        CredentialEntry(
            alias="api-1",
            auth_type="bearer_token",
            secret="secret-one",
            description="First API",
            allowed_urls=["https://api1.example.com/*"],
        )
    )
    store.add(
        CredentialEntry(
            alias="api-2",
            auth_type="basic_auth",
            username="admin",
            secret="secret-two",
            description="Second API",
            allowed_methods=["GET", "POST"],
        )
    )
    store.add(
        CredentialEntry(
            alias="api-3",
            auth_type="api_key_header",
            secret="X-Key: secret-three",
            description="Third API",
            expires_at=9999999999.0,
        )
    )
    return store


class TestRekey:
    def test_rekey_roundtrip(self, populated_store, new_key, tmp_path):
        """After rekey, new key decrypts all credentials correctly."""
        count = populated_store.rekey(new_key)
        assert count == 3

        # Open the same file with the NEW key
        new_store = EncryptedStore(new_key, tmp_path / "credentials.json")

        api1 = new_store.get("api-1")
        assert api1.secret == "secret-one"
        assert api1.auth_type == "bearer_token"
        assert api1.allowed_urls == ["https://api1.example.com/*"]

        api2 = new_store.get("api-2")
        assert api2.secret == "secret-two"
        assert api2.username == "admin"
        assert api2.allowed_methods == ["GET", "POST"]

        api3 = new_store.get("api-3")
        assert api3.secret == "X-Key: secret-three"
        assert api3.expires_at == 9999999999.0

    def test_old_key_fails_after_rekey(self, populated_store, old_key, new_key, tmp_path):
        """Old key should no longer decrypt credentials after rekey."""
        populated_store.rekey(new_key)

        old_store = EncryptedStore(old_key, tmp_path / "credentials.json")
        with pytest.raises(Exception):
            old_store.get("api-1")

    def test_rekey_preserves_metadata(self, populated_store, new_key, tmp_path):
        """Rekey should preserve all non-secret metadata."""
        # Capture metadata before rekey
        before = {a["alias"]: a for a in populated_store.list_aliases()}

        populated_store.rekey(new_key)

        new_store = EncryptedStore(new_key, tmp_path / "credentials.json")
        after = {a["alias"]: a for a in new_store.list_aliases()}

        for alias in before:
            assert before[alias]["auth_type"] == after[alias]["auth_type"]
            assert before[alias]["description"] == after[alias]["description"]
            assert before[alias]["created_at"] == after[alias]["created_at"]
            assert before[alias]["expires_at"] == after[alias]["expires_at"]

    def test_rekey_empty_vault(self, old_key, new_key, tmp_path):
        """Rekeying an empty vault should succeed with count 0."""
        store = EncryptedStore(old_key, tmp_path / "credentials.json")
        count = store.rekey(new_key)
        assert count == 0

    def test_rekey_invalid_key_length_rejected(self, populated_store):
        """Rekey with wrong key length should raise ValueError."""
        with pytest.raises(ValueError, match="32 bytes"):
            populated_store.rekey(b"too-short")

    def test_rekey_same_key(self, populated_store, old_key, tmp_path):
        """Rekeying with the same key should work (re-encrypts with new nonces)."""
        populated_store.rekey(old_key)

        store = EncryptedStore(old_key, tmp_path / "credentials.json")
        assert store.get("api-1").secret == "secret-one"

    def test_rekey_then_add(self, populated_store, new_key, tmp_path):
        """After rekey, adding new credentials with the new key should work."""
        populated_store.rekey(new_key)

        new_store = EncryptedStore(new_key, tmp_path / "credentials.json")
        new_store.add(
            CredentialEntry(
                alias="api-4",
                auth_type="bearer_token",
                secret="new-secret",
            )
        )

        assert len(new_store.list_aliases()) == 4
        assert new_store.get("api-4").secret == "new-secret"

    def test_rekey_then_update_secret(self, populated_store, new_key, tmp_path):
        """After rekey, rotating a secret with the new key should work."""
        populated_store.rekey(new_key)

        new_store = EncryptedStore(new_key, tmp_path / "credentials.json")
        new_store.update_secret("api-1", "rotated-secret")

        assert new_store.get("api-1").secret == "rotated-secret"

    def test_double_rekey(self, populated_store, tmp_path):
        """Rekeying twice in sequence should work."""
        key_b = os.urandom(32)
        key_c = os.urandom(32)

        populated_store.rekey(key_b)

        store_b = EncryptedStore(key_b, tmp_path / "credentials.json")
        store_b.rekey(key_c)

        store_c = EncryptedStore(key_c, tmp_path / "credentials.json")
        assert store_c.get("api-1").secret == "secret-one"
        assert store_c.get("api-2").secret == "secret-two"
        assert store_c.get("api-3").secret == "X-Key: secret-three"
