"""Tests for vault_list expiry status annotations."""

import os
import time

import pytest

from coffer_mcp.audit.logger import AuditLogger
from coffer_mcp.store.encrypted_store import CredentialEntry, EncryptedStore
from coffer_mcp.tools.vault_list import vault_list


@pytest.fixture
def master_key():
    return os.urandom(32)


@pytest.fixture
def store(master_key, tmp_path):
    return EncryptedStore(master_key, tmp_path / "credentials.json")


@pytest.fixture
def audit(tmp_path):
    return AuditLogger(tmp_path / "audit.jsonl")


class TestVaultListStatus:
    def test_active_no_expiry(self, store, audit):
        """Credential with no expiry should show 'active' status."""
        store.add(CredentialEntry(
            alias="forever", auth_type="bearer_token", secret="t",
        ))
        result = vault_list(store, audit)
        assert result[0]["status"] == "active"

    def test_active_future_expiry(self, store, audit):
        """Credential expiring far in the future should show 'active'."""
        store.add(CredentialEntry(
            alias="future", auth_type="bearer_token", secret="t",
            expires_at=time.time() + 30 * 86400,  # 30 days out
        ))
        result = vault_list(store, audit)
        assert result[0]["status"] == "active"

    def test_expiring_soon_within_7_days(self, store, audit):
        """Credential expiring within 7 days should show 'EXPIRING_SOON'."""
        store.add(CredentialEntry(
            alias="soon", auth_type="bearer_token", secret="t",
            expires_at=time.time() + 3 * 86400,  # 3 days out
        ))
        result = vault_list(store, audit)
        assert result[0]["status"] == "EXPIRING_SOON"

    def test_expired(self, store, audit):
        """Credential past its expiry should show 'EXPIRED'."""
        store.add(CredentialEntry(
            alias="old", auth_type="bearer_token", secret="t",
            expires_at=time.time() - 3600,  # 1 hour ago
        ))
        result = vault_list(store, audit)
        assert result[0]["status"] == "EXPIRED"

    def test_mixed_statuses(self, store, audit):
        """Multiple credentials should each get their own status."""
        store.add(CredentialEntry(
            alias="active-cred", auth_type="bearer_token", secret="t1",
        ))
        store.add(CredentialEntry(
            alias="expiring-cred", auth_type="bearer_token", secret="t2",
            expires_at=time.time() + 2 * 86400,
        ))
        store.add(CredentialEntry(
            alias="expired-cred", auth_type="bearer_token", secret="t3",
            expires_at=time.time() - 86400,
        ))
        result = vault_list(store, audit)
        statuses = {r["alias"]: r["status"] for r in result}
        assert statuses["active-cred"] == "active"
        assert statuses["expiring-cred"] == "EXPIRING_SOON"
        assert statuses["expired-cred"] == "EXPIRED"

    def test_list_never_contains_secrets(self, store, audit):
        """vault_list should never return secrets regardless of status."""
        store.add(CredentialEntry(
            alias="secret-cred", auth_type="bearer_token",
            secret="super-secret-value", username="user@test.com",
        ))
        result = vault_list(store, audit)
        entry = result[0]
        assert "secret" not in entry
        assert "password" not in entry
        # username should also not be in list output
        assert entry.get("username") is None or "username" not in entry
