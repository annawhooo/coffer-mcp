"""Tests for the `coffer migrate` CLI command (RR-H6 follow-up)."""

import json
import os

import pytest
from click.testing import CliRunner

from coffer_mcp import cli
from coffer_mcp.audit.logger import AuditLogger
from coffer_mcp.store.encrypted_store import CredentialEntry, EncryptedStore


@pytest.fixture
def store(tmp_path):
    return EncryptedStore(os.urandom(32), store_path=tmp_path / "credentials.json")


@pytest.fixture
def audit(tmp_path):
    return AuditLogger(tmp_path / "audit.jsonl", hmac_key=os.urandom(32), source="cli")


@pytest.fixture
def runner(monkeypatch, store, audit):
    monkeypatch.setattr(cli, "_get_store", lambda: store)
    monkeypatch.setattr(cli, "_get_audit", lambda: audit)
    return CliRunner()


def _make_legacy_blob(store, alias="legacy-1"):
    """Write a blob encrypted with the old alias-only AAD directly to disk."""
    plaintext = json.dumps(
        {
            "username": "u",
            "secret": "s3cret",
            "allowed_urls": ["https://api.example.com/*"],
            "allowed_methods": ["GET"],
        }
    ).encode("utf-8")
    nonce = os.urandom(12)
    ciphertext = store._gcm.encrypt(nonce, plaintext, alias.encode("utf-8"))
    blob = {
        "alias": alias,
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "auth_type": "bearer_token",
        "description": "",
        "created_at": 1.0,
        "rotated_at": 1.0,
        "expires_at": None,
    }
    store._path.write_text(json.dumps({"version": 2, "credentials": [blob]}), encoding="utf-8")


class TestMigrateCommand:
    def test_empty_vault(self, runner):
        result = runner.invoke(cli.main, ["migrate"])
        assert result.exit_code == 0
        assert "nothing to migrate" in result.output

    def test_migrates_legacy_entries(self, runner, store, audit):
        _make_legacy_blob(store)

        result = runner.invoke(cli.main, ["migrate"])
        assert result.exit_code == 0
        assert "1 upgraded from a legacy AAD format" in result.output

        # Entry still decrypts, now without a legacy warning
        import warnings

        with warnings.catch_warnings():
            warnings.simplefilter("error")
            entry = store.get("legacy-1")
        assert entry.secret == "s3cret"

        # Migration was audited
        events = audit.get_events(limit=5)
        assert any(e["event_type"] == "vault.aad_migrated" for e in events)

    def test_current_entries_reported_as_current(self, runner, store):
        store.add(
            CredentialEntry(
                alias="fresh",
                auth_type="bearer_token",
                secret="x",
                allowed_urls=["https://api.example.com/*"],
            )
        )
        result = runner.invoke(cli.main, ["migrate"])
        assert result.exit_code == 0
        assert "all were already current" in result.output

    def test_migration_makes_metadata_tamper_evident(self, runner, store):
        from cryptography.exceptions import InvalidTag

        _make_legacy_blob(store)
        result = runner.invoke(cli.main, ["migrate"])
        assert result.exit_code == 0

        data = json.loads(store._path.read_text(encoding="utf-8"))
        data["credentials"][0]["expires_at"] = None  # no-op value...
        data["credentials"][0]["auth_type"] = "web_login"  # ...but this isn't
        store._path.write_text(json.dumps(data), encoding="utf-8")

        with pytest.raises(InvalidTag):
            store.get("legacy-1")
