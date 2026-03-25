"""
Tests for OAuth2 access token sanitization in HTTP responses.

Verifies that OAuth2 access tokens (which are dynamically obtained and not
stored in the credential entry) are properly scrubbed from response bodies
via the extra_secrets parameter of sanitize_response().
"""

from __future__ import annotations

import base64

from coffer_mcp.security import sanitize_response
from coffer_mcp.store.encrypted_store import CredentialEntry


def _make_oauth2_entry() -> CredentialEntry:
    """Create a sample OAuth2 credential entry."""
    return CredentialEntry(
        alias="my-oauth-api",
        auth_type="oauth2_client_credentials",
        username="my_client_id|my_client_secret",
        secret="https://auth.example.com/token|read write",
        allowed_urls=["https://api.example.com/*"],
        allowed_methods=["GET", "POST"],
    )


def _make_bearer_entry() -> CredentialEntry:
    """Create a sample bearer token credential entry (non-OAuth2)."""
    return CredentialEntry(
        alias="my-api",
        auth_type="bearer_token",
        username="",
        secret="static-bearer-secret-token-12345",
        allowed_urls=["https://api.example.com/*"],
        allowed_methods=["GET"],
    )


class TestOAuth2TokenLiteralScrub:
    """OAuth2 access token appearing literally in response body is scrubbed."""

    def test_literal_token_in_body(self) -> None:
        entry = _make_oauth2_entry()
        access_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test-payload.signature"
        response_text = f'{{"data": "value", "leaked_token": "{access_token}"}}'

        result = sanitize_response(response_text, entry, extra_secrets=[access_token])

        assert access_token not in result
        assert "[REDACTED]" in result

    def test_literal_token_multiple_occurrences(self) -> None:
        entry = _make_oauth2_entry()
        access_token = "oauth2-access-token-abc123xyz"
        response_text = f"Token: {access_token}\nAgain: {access_token}"

        result = sanitize_response(response_text, entry, extra_secrets=[access_token])

        assert access_token not in result
        assert result.count("[REDACTED]") >= 2


class TestOAuth2TokenBearerPattern:
    """OAuth2 access token in Bearer pattern is scrubbed."""

    def test_bearer_prefix_scrubbed(self) -> None:
        entry = _make_oauth2_entry()
        access_token = "eyJhbGciOiJSUzI1NiJ9.oauth2-payload.sig"
        response_text = f"Authorization: Bearer {access_token}"

        result = sanitize_response(response_text, entry, extra_secrets=[access_token])

        assert access_token not in result
        assert "[REDACTED]" in result

    def test_access_token_json_field_scrubbed(self) -> None:
        entry = _make_oauth2_entry()
        access_token = "dynamic-oauth2-token-xyz789"
        response_text = f'{{"access_token": "{access_token}"}}'

        result = sanitize_response(response_text, entry, extra_secrets=[access_token])

        assert access_token not in result
        assert "[REDACTED]" in result


class TestOAuth2TokenBase64Scrub:
    """OAuth2 access token base64-encoded is scrubbed."""

    def test_base64_encoded_token_scrubbed(self) -> None:
        entry = _make_oauth2_entry()
        access_token = "oauth2-access-token-for-base64-test"
        b64_token = base64.b64encode(access_token.encode()).decode()
        response_text = f"encoded_value: {b64_token}"

        result = sanitize_response(response_text, entry, extra_secrets=[access_token])

        assert b64_token not in result
        assert "[REDACTED]" in result

    def test_base64_token_in_json(self) -> None:
        entry = _make_oauth2_entry()
        access_token = "my-secret-oauth2-token-value"
        b64_token = base64.b64encode(access_token.encode()).decode()
        response_text = f'{{"encoded_secret": "{b64_token}"}}'

        result = sanitize_response(response_text, entry, extra_secrets=[access_token])

        assert b64_token not in result
        assert "[REDACTED]" in result


class TestNonOAuth2CredentialsStillWork:
    """Normal (non-OAuth2) credentials still work as before."""

    def test_bearer_token_entry_secret_scrubbed(self) -> None:
        entry = _make_bearer_entry()
        response_text = f"The token is {entry.secret} in the response."

        result = sanitize_response(response_text, entry)

        assert entry.secret not in result
        assert "[REDACTED]" in result

    def test_bearer_token_no_extra_secrets(self) -> None:
        """Passing no extra_secrets should work the same as before."""
        entry = _make_bearer_entry()
        response_text = f"Bearer {entry.secret}"

        result = sanitize_response(response_text, entry, extra_secrets=None)

        assert entry.secret not in result
        assert "[REDACTED]" in result

    def test_basic_auth_entry_scrubbed(self) -> None:
        entry = CredentialEntry(
            alias="basic-api",
            auth_type="basic_auth",
            username="admin",
            secret="super-secret-password-123",
            allowed_urls=["https://api.example.com/*"],
            allowed_methods=["GET"],
        )
        b64_basic = base64.b64encode(f"{entry.username}:{entry.secret}".encode()).decode()
        response_text = f"Basic {b64_basic}"

        result = sanitize_response(response_text, entry)

        assert b64_basic not in result
        assert "[REDACTED]" in result

    def test_extra_secrets_combined_with_entry_secret(self) -> None:
        """Both the entry secret and extra secrets should be scrubbed."""
        entry = _make_oauth2_entry()
        access_token = "dynamic-oauth2-token-999"
        response_text = f"entry_secret={entry.secret} oauth_token={access_token}"

        result = sanitize_response(response_text, entry, extra_secrets=[access_token])

        assert access_token not in result
        # The entry secret for OAuth2 entries is the token_url|scope,
        # which is long enough to be scrubbed
        assert entry.secret not in result


class TestUrlEncodedOAuth2Token:
    """OAuth2 access token URL-encoded is scrubbed."""

    def test_url_encoded_token_scrubbed(self) -> None:
        from urllib.parse import quote

        entry = _make_oauth2_entry()
        access_token = "token/with+special=chars&more"
        url_encoded = quote(access_token, safe="")
        response_text = f"callback?token={url_encoded}"

        result = sanitize_response(response_text, entry, extra_secrets=[access_token])

        assert url_encoded not in result
        assert "[REDACTED]" in result
