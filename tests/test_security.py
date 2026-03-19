"""Tests for security utilities — URL allowlisting and response sanitization."""

import pytest

from coffer_mcp.security import check_method_allowed, check_url_allowed, sanitize_response
from coffer_mcp.store.encrypted_store import CredentialEntry


@pytest.fixture
def api_entry():
    """Credential with API-style allowlist."""
    return CredentialEntry(
        alias="test-api",
        auth_type="bearer_token",
        username="user@example.com",
        secret="sk-live-abc123xyz789",
        allowed_urls=["https://api.example.com/*", "https://api.example.com/v2/*"],
        allowed_methods=["GET", "POST"],
    )


@pytest.fixture
def empty_allowlist_entry():
    """Credential with no allowed URLs (should block everything)."""
    return CredentialEntry(
        alias="locked",
        auth_type="bearer_token",
        secret="secret123",
        allowed_urls=[],
        allowed_methods=[],
    )


class TestUrlAllowlist:
    def test_allowed_url_matches(self, api_entry):
        assert check_url_allowed(api_entry, "https://api.example.com/users") is True
        assert check_url_allowed(api_entry, "https://api.example.com/v2/data") is True

    def test_disallowed_url_blocked(self, api_entry):
        assert check_url_allowed(api_entry, "https://evil.com/steal") is False
        assert check_url_allowed(api_entry, "https://other-api.example.com/data") is False

    def test_empty_allowlist_blocks_all(self, empty_allowlist_entry):
        """Empty allowlist should block ALL URLs (fail-closed)."""
        assert check_url_allowed(empty_allowlist_entry, "https://api.example.com/data") is False
        assert check_url_allowed(empty_allowlist_entry, "https://localhost/test") is False

    def test_query_params_ignored_in_check(self, api_entry):
        """URL check should match on scheme + host + path, ignoring query params."""
        assert check_url_allowed(api_entry, "https://api.example.com/users?page=1") is True


class TestMethodAllowlist:
    def test_allowed_method(self, api_entry):
        assert check_method_allowed(api_entry, "GET") is True
        assert check_method_allowed(api_entry, "POST") is True

    def test_disallowed_method(self, api_entry):
        assert check_method_allowed(api_entry, "DELETE") is False
        assert check_method_allowed(api_entry, "PUT") is False

    def test_case_insensitive(self, api_entry):
        assert check_method_allowed(api_entry, "get") is True
        assert check_method_allowed(api_entry, "post") is True

    def test_empty_methods_blocks_all(self, empty_allowlist_entry):
        assert check_method_allowed(empty_allowlist_entry, "GET") is False


class TestResponseSanitization:
    def test_secret_scrubbed(self, api_entry):
        """The actual secret value should be replaced with [REDACTED]."""
        response = '{"token": "sk-live-abc123xyz789", "data": "hello"}'
        sanitized = sanitize_response(response, api_entry)
        assert "sk-live-abc123xyz789" not in sanitized
        assert "[REDACTED]" in sanitized
        assert '"data": "hello"' in sanitized

    def test_basic_auth_scrubbed(self):
        """Base64-encoded basic auth should be scrubbed."""
        import base64
        entry = CredentialEntry(
            alias="basic",
            auth_type="basic_auth",
            username="admin",
            secret="p@ssw0rd",
        )
        b64 = base64.b64encode(b"admin:p@ssw0rd").decode()
        response = f'{{"auth": "{b64}", "status": "ok"}}'
        sanitized = sanitize_response(response, entry)
        assert b64 not in sanitized
        assert "[REDACTED]" in sanitized

    def test_no_false_positives_on_short_secret(self):
        """Very short secrets (<=3 chars) should not trigger scrubbing to avoid false positives."""
        entry = CredentialEntry(alias="short", auth_type="bearer_token", secret="ab")
        response = "The alphabet starts with ab and continues with cd"
        sanitized = sanitize_response(response, entry)
        # Short secrets are intentionally not scrubbed
        assert sanitized == response

    def test_clean_response_unchanged(self, api_entry):
        """A response without any credentials should pass through unchanged."""
        response = '{"users": [{"name": "Alice"}, {"name": "Bob"}]}'
        sanitized = sanitize_response(response, api_entry)
        assert sanitized == response
