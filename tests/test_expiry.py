"""Tests for credential expiry feature."""

import os
import time

import pytest

from coffer_mcp.store.encrypted_store import CredentialEntry, EncryptedStore


@pytest.fixture
def master_key():
    return os.urandom(32)


@pytest.fixture
def store(master_key, tmp_path):
    return EncryptedStore(master_key, tmp_path / "credentials.json")


class TestCredentialExpiry:
    def test_expires_at_none_by_default(self):
        """New credentials should have no expiry by default."""
        entry = CredentialEntry(alias="test", auth_type="bearer_token", secret="s")
        assert entry.expires_at is None

    def test_expires_at_roundtrip(self, store):
        """expires_at should survive encrypt/decrypt cycle."""
        future = time.time() + 86400
        entry = CredentialEntry(
            alias="expiring",
            auth_type="bearer_token",
            secret="token123",
            expires_at=future,
        )
        store.add(entry)
        retrieved = store.get("expiring")
        assert retrieved.expires_at == pytest.approx(future, abs=1)

    def test_expires_at_none_roundtrip(self, store):
        """A credential with no expiry should stay None after roundtrip."""
        entry = CredentialEntry(
            alias="forever",
            auth_type="bearer_token",
            secret="eternal",
        )
        store.add(entry)
        retrieved = store.get("forever")
        assert retrieved.expires_at is None

    def test_is_expired_past(self, store):
        """A credential with expires_at in the past should be expired."""
        entry = CredentialEntry(
            alias="old",
            auth_type="bearer_token",
            secret="old-token",
            expires_at=time.time() - 3600,  # 1 hour ago
        )
        store.add(entry)
        assert store.is_expired("old") is True

    def test_is_expired_future(self, store):
        """A credential with expires_at in the future should not be expired."""
        entry = CredentialEntry(
            alias="fresh",
            auth_type="bearer_token",
            secret="fresh-token",
            expires_at=time.time() + 86400,  # 24 hours from now
        )
        store.add(entry)
        assert store.is_expired("fresh") is False

    def test_is_expired_none_means_never(self, store):
        """A credential with no expiry should never be expired."""
        entry = CredentialEntry(
            alias="forever",
            auth_type="bearer_token",
            secret="eternal",
            expires_at=None,
        )
        store.add(entry)
        assert store.is_expired("forever") is False

    def test_expires_at_in_metadata(self):
        """metadata() should include expires_at."""
        future = time.time() + 86400
        entry = CredentialEntry(
            alias="test",
            auth_type="bearer_token",
            secret="s",
            expires_at=future,
        )
        meta = entry.metadata()
        assert "expires_at" in meta
        assert meta["expires_at"] == future

    def test_expires_at_in_list_aliases(self, store):
        """list_aliases should include expires_at."""
        future = time.time() + 86400
        entry = CredentialEntry(
            alias="expiring",
            auth_type="bearer_token",
            secret="t",
            expires_at=future,
        )
        store.add(entry)
        aliases = store.list_aliases()
        assert aliases[0]["expires_at"] == pytest.approx(future, abs=1)

    def test_list_aliases_no_expiry_returns_none(self, store):
        """list_aliases should return None for expires_at when not set."""
        entry = CredentialEntry(
            alias="forever",
            auth_type="bearer_token",
            secret="t",
        )
        store.add(entry)
        aliases = store.list_aliases()
        assert aliases[0]["expires_at"] is None

    def test_update_secret_preserves_expiry(self, store):
        """Rotating a secret should preserve the expires_at value."""
        future = time.time() + 86400
        entry = CredentialEntry(
            alias="rotating",
            auth_type="bearer_token",
            secret="old",
            expires_at=future,
        )
        store.add(entry)
        store.update_secret("rotating", "new")
        retrieved = store.get("rotating")
        assert retrieved.secret == "new"
        assert retrieved.expires_at == pytest.approx(future, abs=1)
