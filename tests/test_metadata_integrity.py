"""Tests for RR-H6: plaintext metadata integrity via full-metadata AAD."""

import json
import os

import pytest
from cryptography.exceptions import InvalidTag

from coffer_mcp.store.encrypted_store import CredentialEntry, EncryptedStore


@pytest.fixture
def master_key():
    return os.urandom(32)


@pytest.fixture
def store(tmp_path, master_key):
    return EncryptedStore(master_key, store_path=tmp_path / "credentials.json")


@pytest.fixture
def entry():
    return CredentialEntry(
        alias="api-1",
        auth_type="bearer_token",
        username="user@example.com",
        secret="sk-live-abc123",
        allowed_urls=["https://api.example.com/*"],
        allowed_methods=["GET"],
        description="test credential",
        expires_at=4102444800.0,  # 2100-01-01
    )


def _load_blobs(store):
    data = json.loads(store._path.read_text(encoding="utf-8"))
    return data["credentials"] if isinstance(data, dict) else data


def _save_blobs(store, blobs):
    envelope = {"version": 2, "credentials": blobs}
    store._path.write_text(json.dumps(envelope), encoding="utf-8")


class TestMetadataIntegrity:
    def test_round_trip(self, store, entry):
        store.add(entry)
        got = store.get("api-1")
        assert got.secret == "sk-live-abc123"
        assert got.expires_at == entry.expires_at
        assert got.auth_type == "bearer_token"

    def test_tampered_expires_at_detected(self, store, entry):
        """Nulling out expires_at (disabling expiry) must break decryption."""
        store.add(entry)
        blobs = _load_blobs(store)
        blobs[0]["expires_at"] = None
        _save_blobs(store, blobs)

        with pytest.raises(InvalidTag):
            store.get("api-1")

    def test_tampered_auth_type_detected(self, store, entry):
        store.add(entry)
        blobs = _load_blobs(store)
        blobs[0]["auth_type"] = "api_key_header"
        _save_blobs(store, blobs)

        with pytest.raises(InvalidTag):
            store.get("api-1")

    def test_tampered_description_detected(self, store, entry):
        store.add(entry)
        blobs = _load_blobs(store)
        blobs[0]["description"] = "attacker-controlled"
        _save_blobs(store, blobs)

        with pytest.raises(InvalidTag):
            store.get("api-1")

    def test_tampered_timestamps_detected(self, store, entry):
        store.add(entry)
        blobs = _load_blobs(store)
        blobs[0]["rotated_at"] = blobs[0]["rotated_at"] + 1.0
        _save_blobs(store, blobs)

        with pytest.raises(InvalidTag):
            store.get("api-1")

    def test_is_expired_uses_protected_value(self, store, entry):
        """is_expired() goes through get(), so a tampered expires_at raises
        rather than silently reporting not-expired."""
        entry.expires_at = 1000.0  # long past
        store.add(entry)
        assert store.is_expired("api-1") is True

        blobs = _load_blobs(store)
        blobs[0]["expires_at"] = None
        _save_blobs(store, blobs)
        with pytest.raises(InvalidTag):
            store.is_expired("api-1")


class TestLegacyCompatibility:
    def _make_legacy_blob(self, store, entry, aad):
        """Encrypt an entry the way older store versions did."""
        plaintext = json.dumps(
            {
                "username": entry.username,
                "secret": entry.secret,
                "allowed_urls": entry.allowed_urls,
                "allowed_methods": entry.allowed_methods,
            }
        ).encode("utf-8")
        nonce = os.urandom(12)
        ciphertext = store._gcm.encrypt(nonce, plaintext, aad)
        return {
            "alias": entry.alias,
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex(),
            "auth_type": entry.auth_type,
            "description": entry.description,
            "created_at": entry.created_at,
            "rotated_at": entry.rotated_at,
            "expires_at": entry.expires_at,
        }

    def test_legacy_alias_aad_blob_still_decrypts(self, store, entry):
        blob = self._make_legacy_blob(store, entry, aad=entry.alias.encode("utf-8"))
        _save_blobs(store, [blob])

        with pytest.warns(UserWarning, match="legacy"):
            got = store.get("api-1")
        assert got.secret == entry.secret

    def test_legacy_no_aad_blob_still_decrypts(self, store, entry):
        blob = self._make_legacy_blob(store, entry, aad=None)
        _save_blobs(store, [blob])

        with pytest.warns(UserWarning, match="legacy"):
            got = store.get("api-1")
        assert got.secret == entry.secret

    def test_migrate_aad_upgrades_legacy_blobs(self, store, entry):
        blob = self._make_legacy_blob(store, entry, aad=entry.alias.encode("utf-8"))
        _save_blobs(store, [blob])

        migrated = store.migrate_aad()
        assert migrated == 1

        # After migration: no legacy warning, and tampering is detected
        import warnings

        with warnings.catch_warnings():
            warnings.simplefilter("error")
            got = store.get("api-1")
        assert got.secret == entry.secret

        blobs = _load_blobs(store)
        blobs[0]["expires_at"] = None
        _save_blobs(store, blobs)
        with pytest.raises(InvalidTag):
            store.get("api-1")

    def test_update_secret_upgrades_to_protected_aad(self, store, entry):
        """Rotation re-encrypts, so a rotated legacy blob gains protection."""
        blob = self._make_legacy_blob(store, entry, aad=None)
        _save_blobs(store, [blob])

        with pytest.warns(UserWarning, match="legacy"):
            store.update_secret("api-1", "new-secret")

        blobs = _load_blobs(store)
        blobs[0]["auth_type"] = "web_login"
        _save_blobs(store, blobs)
        with pytest.raises(InvalidTag):
            store.get("api-1")

    def test_wrong_key_still_fails(self, tmp_path, entry):
        """The legacy fallback chain must not turn wrong-key into success."""
        store_a = EncryptedStore(os.urandom(32), store_path=tmp_path / "a.json")
        store_a.add(entry)
        store_b = EncryptedStore(os.urandom(32), store_path=tmp_path / "a.json")
        with pytest.raises(InvalidTag):
            store_b.get("api-1")


class TestCiphertextSwap:
    def test_swap_between_entries_detected(self, store, entry):
        """Alias remains in the AAD, so cross-entry ciphertext swap fails."""
        store.add(entry)
        entry2 = CredentialEntry(
            alias="api-2",
            auth_type="bearer_token",
            secret="other-secret",
            allowed_urls=["https://other.example.com/*"],
        )
        store.add(entry2)

        blobs = _load_blobs(store)
        blobs[0]["ciphertext"], blobs[1]["ciphertext"] = (
            blobs[1]["ciphertext"],
            blobs[0]["ciphertext"],
        )
        blobs[0]["nonce"], blobs[1]["nonce"] = blobs[1]["nonce"], blobs[0]["nonce"]
        _save_blobs(store, blobs)

        with pytest.raises(InvalidTag):
            store.get("api-1")
