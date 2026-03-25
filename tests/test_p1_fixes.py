"""Tests for P1 fixes: backup atomicity, expanded scrubbing, HMAC enforcement."""

import os
import warnings

import pytest

from coffer_mcp.audit.logger import AuditLogger
from coffer_mcp.security import sanitize_response
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
def entry_with_secret():
    """A credential with a realistic secret for scrubbing tests."""
    return CredentialEntry(
        alias="test-api",
        auth_type="bearer_token",
        username="admin",
        secret="sk-proj-abc123XYZ789",
        allowed_urls=["https://api.example.com/*"],
    )


# ===========================================================================
# P1-1: Backup import atomicity
# ===========================================================================


class TestBackupAtomicity:
    def test_overwrite_preserves_original_on_add_failure(
        self,
        store,
        tmp_path,
        master_key,
    ):
        """If add fails during overwrite import, the old credential is restored."""
        # Add an original credential
        original = CredentialEntry(
            alias="cred-1",
            auth_type="bearer_token",
            secret="original-secret",
        )
        store.add(original)

        # Export a backup with a different secret
        store2 = EncryptedStore(master_key, tmp_path / "creds2.json")
        store2.add(
            CredentialEntry(
                alias="cred-1",
                auth_type="bearer_token",
                secret="backup-secret",
            )
        )
        backup_path = tmp_path / "backup.enc"
        export_vault(store2, "pass", backup_path)

        # Monkey-patch store.add to fail on the first call (the import add),
        # but succeed on the second call (the rollback re-add).
        real_add = store.add
        call_count = [0]

        def failing_once_add(entry):
            call_count[0] += 1
            if call_count[0] == 1:
                raise RuntimeError("Simulated failure")
            return real_add(entry)

        store.add = failing_once_add

        result = import_vault(store, "pass", backup_path, overwrite=True)

        # Restore the real add to verify
        store.add = real_add

        # The original credential should have been restored by rollback
        retrieved = store.get("cred-1")
        assert retrieved.secret == "original-secret"
        assert len(result["errors"]) == 1

    def test_overwrite_with_nonexistent_original(
        self,
        store,
        tmp_path,
        master_key,
    ):
        """Overwrite import of a credential that doesn't exist yet should work."""
        store2 = EncryptedStore(master_key, tmp_path / "creds2.json")
        store2.add(
            CredentialEntry(
                alias="new-cred",
                auth_type="bearer_token",
                secret="new-secret",
            )
        )
        backup_path = tmp_path / "backup.enc"
        export_vault(store2, "pass", backup_path)

        result = import_vault(store, "pass", backup_path, overwrite=True)
        assert result["status"] == "ok"
        assert result["imported"] == 1

        retrieved = store.get("new-cred")
        assert retrieved.secret == "new-secret"


# ===========================================================================
# P1-2: Expanded credential scrubbing
# ===========================================================================


class TestExpandedScrubbing:
    def test_bearer_token_pattern_scrubbed(self, entry_with_secret):
        """Bearer <secret> pattern should be scrubbed."""
        text = f"Authorization: Bearer {entry_with_secret.secret}\nOK"
        result = sanitize_response(text, entry_with_secret)
        assert entry_with_secret.secret not in result
        assert "[REDACTED]" in result

    def test_token_equals_pattern_scrubbed(self, entry_with_secret):
        """token=<secret> pattern should be scrubbed."""
        text = f"callback?token={entry_with_secret.secret}&foo=bar"
        result = sanitize_response(text, entry_with_secret)
        assert entry_with_secret.secret not in result

    def test_access_token_json_scrubbed(self, entry_with_secret):
        """JSON "access_token": "<secret>" should be scrubbed."""
        text = f'{{"access_token": "{entry_with_secret.secret}", "type": "bearer"}}'
        result = sanitize_response(text, entry_with_secret)
        assert entry_with_secret.secret not in result

    def test_api_key_pattern_scrubbed(self, entry_with_secret):
        """api_key=<secret> pattern should be scrubbed."""
        text = f"api_key={entry_with_secret.secret}"
        result = sanitize_response(text, entry_with_secret)
        assert entry_with_secret.secret not in result

    def test_base64_standalone_scrubbed(self, entry_with_secret):
        """Base64-encoded standalone secret should be scrubbed."""
        import base64

        b64 = base64.b64encode(entry_with_secret.secret.encode()).decode()
        text = f"encoded: {b64}"
        result = sanitize_response(text, entry_with_secret)
        assert b64 not in result
        assert "[REDACTED]" in result

    def test_url_encoded_scrubbed(self, entry_with_secret):
        """URL-encoded secret should be scrubbed."""
        from urllib.parse import quote

        encoded = quote(entry_with_secret.secret, safe="")
        text = f"param={encoded}"
        result = sanitize_response(text, entry_with_secret)
        assert encoded not in result

    def test_basic_auth_still_scrubbed(self, entry_with_secret):
        """Base64 Basic auth (user:pass) should still be scrubbed."""
        import base64

        basic = base64.b64encode(
            f"{entry_with_secret.username}:{entry_with_secret.secret}".encode()
        ).decode()
        text = f"Authorization: Basic {basic}"
        result = sanitize_response(text, entry_with_secret)
        assert basic not in result

    def test_short_secret_not_scrubbed(self):
        """Secrets of 3 chars or fewer should not be scrubbed (false positive risk)."""
        entry = CredentialEntry(
            alias="short",
            auth_type="bearer_token",
            secret="abc",
        )
        text = "abc is a common word, abc appears in abcdefg"
        result = sanitize_response(text, entry)
        assert result == text  # unchanged

    def test_clean_response_unchanged(self, entry_with_secret):
        """Response without any secret traces should pass through unchanged."""
        text = "Everything is fine. Status 200 OK."
        result = sanitize_response(text, entry_with_secret)
        assert result == text


# ===========================================================================
# P1-3: HMAC enforcement warning
# ===========================================================================


class TestHmacEnforcement:
    def test_no_hmac_key_emits_warning(self, tmp_path):
        """AuditLogger without HMAC key should emit a warning on first log."""
        logger = AuditLogger(tmp_path / "audit.jsonl")
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            logger.log("credential.created", "api-1")
            assert len(w) == 1
            assert "no hmac key" in str(w[0].message).lower()
            assert issubclass(w[0].category, UserWarning)

    def test_warning_emitted_only_once(self, tmp_path):
        """The no-HMAC warning should only be emitted once per logger instance."""
        logger = AuditLogger(tmp_path / "audit.jsonl")
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            logger.log("credential.created", "api-1")
            logger.log("credential.used", "api-1")
            logger.log("credential.removed", "api-1")
            hmac_warnings = [x for x in w if "HMAC" in str(x.message)]
            assert len(hmac_warnings) == 1

    def test_hmac_key_present_no_warning(self, tmp_path):
        """AuditLogger with HMAC key should not emit a warning."""
        hmac_key = os.urandom(32)
        logger = AuditLogger(tmp_path / "audit.jsonl", hmac_key=hmac_key)
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            logger.log("credential.created", "api-1")
            hmac_warnings = [x for x in w if "HMAC" in str(x.message)]
            assert len(hmac_warnings) == 0

    def test_verify_chain_with_no_hmac_still_works(self, tmp_path):
        """Backward compat: no-HMAC chain should still verify (with warning)."""
        logger = AuditLogger(tmp_path / "audit.jsonl")
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            logger.log("credential.created", "api-1")
            logger.log("credential.used", "api-1")
            is_valid, count, _ = logger.verify_chain()
        assert is_valid is True
        assert count == 2
