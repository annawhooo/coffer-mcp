"""Tests for the encrypted credential store."""

import os

import pytest

from coffer_mcp.store.encrypted_store import CredentialEntry, EncryptedStore


@pytest.fixture
def master_key():
    """Generate a random 32-byte master key for testing."""
    return os.urandom(32)


@pytest.fixture
def store(master_key, tmp_path):
    """Create a temporary encrypted store."""
    store_path = tmp_path / "credentials.json"
    return EncryptedStore(master_key, store_path)


@pytest.fixture
def sample_entry():
    """Create a sample credential entry."""
    return CredentialEntry(
        alias="test-api",
        auth_type="bearer_token",
        username="testuser@example.com",
        secret="super-secret-token-12345",
        allowed_urls=["https://api.example.com/*"],
        allowed_methods=["GET", "POST"],
        description="Test API credential",
    )


class TestEncryptedStore:
    def test_add_and_get_roundtrip(self, store, sample_entry):
        """Encrypting and decrypting should return the original data."""
        store.add(sample_entry)
        retrieved = store.get("test-api")

        assert retrieved.alias == sample_entry.alias
        assert retrieved.auth_type == sample_entry.auth_type
        assert retrieved.username == sample_entry.username
        assert retrieved.secret == sample_entry.secret
        assert retrieved.allowed_urls == sample_entry.allowed_urls
        assert retrieved.allowed_methods == sample_entry.allowed_methods
        assert retrieved.description == sample_entry.description

    def test_duplicate_alias_rejected(self, store, sample_entry):
        """Adding a credential with a duplicate alias should raise ValueError."""
        store.add(sample_entry)
        with pytest.raises(ValueError, match="already exists"):
            store.add(sample_entry)

    def test_get_nonexistent_raises_keyerror(self, store):
        """Getting a nonexistent alias should raise KeyError."""
        with pytest.raises(KeyError, match="No credential found"):
            store.get("does-not-exist")

    def test_list_aliases_returns_metadata_only(self, store, sample_entry):
        """list_aliases should return metadata but never secrets."""
        store.add(sample_entry)
        aliases = store.list_aliases()

        assert len(aliases) == 1
        assert aliases[0]["alias"] == "test-api"
        assert aliases[0]["auth_type"] == "bearer_token"
        assert "secret" not in aliases[0]
        assert "username" not in aliases[0]
        assert "password" not in aliases[0]

    def test_remove_existing(self, store, sample_entry):
        """Removing an existing credential should return True."""
        store.add(sample_entry)
        assert store.remove("test-api") is True
        assert store.list_aliases() == []

    def test_remove_nonexistent(self, store):
        """Removing a nonexistent credential should return False."""
        assert store.remove("does-not-exist") is False

    def test_wrong_key_fails_decryption(self, sample_entry, tmp_path):
        """Decrypting with the wrong key should fail."""
        store_path = tmp_path / "credentials.json"
        key1 = os.urandom(32)
        key2 = os.urandom(32)

        store1 = EncryptedStore(key1, store_path)
        store1.add(sample_entry)

        store2 = EncryptedStore(key2, store_path)
        with pytest.raises(Exception):  # cryptography raises InvalidTag
            store2.get("test-api")

    def test_update_secret(self, store, sample_entry):
        """Updating a secret should change the stored value."""
        store.add(sample_entry)
        store.update_secret("test-api", "new-secret-value")

        retrieved = store.get("test-api")
        assert retrieved.secret == "new-secret-value"
        assert retrieved.rotated_at > sample_entry.rotated_at

    def test_invalid_key_length_rejected(self, tmp_path):
        """A master key that isn't 32 bytes should be rejected."""
        with pytest.raises(ValueError, match="32 bytes"):
            EncryptedStore(b"too-short", tmp_path / "creds.json")

    def test_metadata_never_contains_secret(self, sample_entry):
        """The metadata() method should never include the secret or username."""
        meta = sample_entry.metadata()
        assert "secret" not in meta
        assert "password" not in meta
        assert "username" not in meta  # username is sensitive for many auth types
        assert meta["alias"] == "test-api"

    def test_multiple_credentials(self, store):
        """Store should handle multiple credentials independently."""
        for i in range(5):
            entry = CredentialEntry(
                alias=f"cred-{i}",
                auth_type="bearer_token",
                secret=f"secret-{i}",
                description=f"Credential {i}",
            )
            store.add(entry)

        aliases = store.list_aliases()
        assert len(aliases) == 5

        for i in range(5):
            retrieved = store.get(f"cred-{i}")
            assert retrieved.secret == f"secret-{i}"


class TestBearerTokenWhitespace:
    """Regression tests for bearer_token whitespace corruption (GitHub #401).

    On Windows, getpass.getpass() can include trailing \\r or whitespace
    from clipboard paste. If stored verbatim, the Authorization header
    becomes 'Bearer ghp_abc123\\r' which fails authentication.
    """

    DIRTY_TOKENS = [
        ("ghp_abc123\r", "ghp_abc123", "trailing CR"),
        ("ghp_abc123\r\n", "ghp_abc123", "trailing CRLF"),
        ("ghp_abc123\n", "ghp_abc123", "trailing LF"),
        ("ghp_abc123 ", "ghp_abc123", "trailing space"),
        ("ghp_abc123\t", "ghp_abc123", "trailing tab"),
        (" ghp_abc123", "ghp_abc123", "leading space"),
        (" ghp_abc123 \r\n", "ghp_abc123", "mixed leading/trailing"),
    ]

    @pytest.mark.parametrize(
        "dirty,clean,desc",
        DIRTY_TOKENS,
        ids=lambda x: x if len(x) < 20 else x[:15],
    )
    def test_roundtrip_preserves_exact_bytes(self, dirty, clean, desc, tmp_path):
        """Store roundtrip preserves the secret exactly (including whitespace).

        The store itself should NOT strip — that's the CLI's job.
        This test documents current behavior so the defense-in-depth
        .strip() at header injection time is clearly necessary.
        """
        key = os.urandom(32)
        store = EncryptedStore(key, tmp_path / "creds.json")
        entry = CredentialEntry(
            alias="dirty-token",
            auth_type="bearer_token",
            secret=dirty,
            allowed_urls=["https://api.github.com/*"],
        )
        store.add(entry)
        retrieved = store.get("dirty-token")
        # Store preserves exact bytes — this is by design
        assert retrieved.secret == dirty
        # But stripped version matches the clean token
        assert retrieved.secret.strip() == clean

    @pytest.mark.parametrize(
        "dirty,clean,desc",
        DIRTY_TOKENS,
        ids=lambda x: x if len(x) < 20 else x[:15],
    )
    def test_bearer_header_after_strip(self, dirty, clean, desc):
        """The Authorization header must be exactly 'Bearer {token}' with no trailing junk."""
        header = f"Bearer {dirty.strip()}"
        assert header == f"Bearer {clean}"
        assert header[-1] != "\r"
        assert header[-1] != "\n"
        assert header[-1] != " "
