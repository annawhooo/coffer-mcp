"""Tests for the second audit round P0 fixes."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from coffer_mcp.audit.logger import AuditLogger
from coffer_mcp.security import validate_header_name
from coffer_mcp.store.encrypted_store import CredentialEntry, EncryptedStore


@pytest.fixture()
def store(tmp_path):
    key = os.urandom(32)
    return EncryptedStore(key, tmp_path / "creds.json")


@pytest.fixture()
def audit(tmp_path):
    return AuditLogger(log_path=tmp_path / "audit.jsonl", hmac_key=os.urandom(32))


# ---------------------------------------------------------------------------
# A3: browser_web_login must validate login_url against allowlist
# ---------------------------------------------------------------------------


class TestBrowserLoginAllowlist:
    """browser_web_login must reject login_urls not in the allowlist."""

    async def test_login_url_blocked_if_not_in_allowlist(self, store, audit):
        store.add(
            CredentialEntry(
                alias="portal",
                auth_type="web_login",
                username="user@example.com",
                secret="password123",
                allowed_urls=["https://portal.example.com/*"],
            )
        )
        from coffer_mcp.browser.playwright_bridge import browser_web_login

        result = await browser_web_login(
            store=store,
            audit=audit,
            alias="portal",
            login_url="https://evil.com/phishing",
        )
        assert result["status"] == "error"
        assert "not in the allowlist" in result["message"].lower()


# ---------------------------------------------------------------------------
# A2: web_fetch must block when credential is deleted
# ---------------------------------------------------------------------------


class TestFetchBlocksOnDeletedCredential:
    """Fetching after credential deletion must not bypass allowlist."""

    async def test_httpx_web_fetch_blocks(self, store, audit):
        store.add(
            CredentialEntry(
                alias="portal",
                auth_type="web_login",
                username="user",
                secret="pass",
                allowed_urls=["https://portal.example.com/*"],
            )
        )
        import httpx

        from coffer_mcp.tools.vault_web_login import _sessions, _sessions_lock, vault_web_fetch

        # Simulate an active session
        async with _sessions_lock:
            _sessions["portal"] = httpx.AsyncClient()

        # Delete the credential
        store.remove("portal")

        # Fetch should be blocked (credential gone)
        result = await vault_web_fetch(
            store=store,
            audit=audit,
            alias="portal",
            url="https://evil.com/steal",
        )
        assert result["status"] == "error"
        assert "deleted" in result["message"].lower()

        # Session should be cleaned up
        async with _sessions_lock:
            assert "portal" not in _sessions


# ---------------------------------------------------------------------------
# B1: OAuth2 token_url must be validated against allowlist
# ---------------------------------------------------------------------------


class TestOAuth2TokenUrlAllowlist:
    """OAuth2 token_url must match the credential's allowed_urls."""

    async def test_token_url_outside_allowlist_blocked(self, store, audit):
        # Credential with token_url pointing to an evil server
        store.add(
            CredentialEntry(
                alias="oauth-cred",
                auth_type="oauth2_client_credentials",
                username="client_id|client_secret",
                secret="https://evil.com/token|read",
                allowed_urls=["https://api.legit.com/*"],
            )
        )
        from coffer_mcp.tools.vault_http_request import vault_http_request

        result = await vault_http_request(
            store=store,
            audit=audit,
            alias="oauth-cred",
            url="https://api.legit.com/data",
        )
        assert result["status"] == "error"
        assert "token url" in result["message"].lower() or "allowlist" in result["message"].lower()

    async def test_token_url_in_allowlist_proceeds(self, store, audit):
        # Token URL is in the allowlist — should proceed to token acquisition
        store.add(
            CredentialEntry(
                alias="oauth-ok",
                auth_type="oauth2_client_credentials",
                username="client_id|client_secret",
                secret="https://auth.legit.com/token|read",
                allowed_urls=[
                    "https://api.legit.com/*",
                    "https://auth.legit.com/*",
                ],
            )
        )
        from coffer_mcp.tools.vault_http_request import vault_http_request

        # Mock the token acquisition (we only need to verify it gets past the check)
        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = mock_cls.return_value.__aenter__.return_value

            # Mock token endpoint
            import httpx

            token_response = httpx.Response(
                200,
                json={"access_token": "tok_123", "expires_in": 3600},
                request=httpx.Request("POST", "https://auth.legit.com/token"),
            )
            api_response = httpx.Response(
                200,
                text='{"data": "ok"}',
                headers={"content-type": "application/json"},
                request=httpx.Request("GET", "https://api.legit.com/data"),
            )
            mock_client.post.return_value = token_response
            mock_client.request.return_value = api_response

            result = await vault_http_request(
                store=store,
                audit=audit,
                alias="oauth-ok",
                url="https://api.legit.com/data",
            )

        # Should succeed (or at least get past the token_url check)
        assert result["status"] != "error" or "token url" not in result.get("message", "").lower()


# ---------------------------------------------------------------------------
# B2: api_key_header must block dangerous headers
# ---------------------------------------------------------------------------


class TestBlockedHeaders:
    """api_key_header must reject security-sensitive header names."""

    @pytest.mark.parametrize(
        "header",
        [
            "Host",
            "Cookie",
            "Authorization",
            "Transfer-Encoding",
            "X-Forwarded-For",
            "X-Forwarded-Host",
            "Proxy-Authorization",
            "Connection",
        ],
    )
    def test_blocked_header_names(self, header):
        assert validate_header_name(header) is None

    @pytest.mark.parametrize(
        "header",
        [
            "X-API-Key",
            "X-Custom-Auth",
            "Api-Token",
            "X-Request-ID",
        ],
    )
    def test_allowed_header_names(self, header):
        assert validate_header_name(header) == header

    def test_empty_header_blocked(self):
        assert validate_header_name("") is None
        assert validate_header_name("   ") is None

    def test_case_insensitive_blocking(self):
        assert validate_header_name("HOST") is None
        assert validate_header_name("host") is None
        assert validate_header_name("Host") is None

    async def test_dangerous_header_in_request_blocked(self, store, audit):
        store.add(
            CredentialEntry(
                alias="evil-header",
                auth_type="api_key_header",
                secret="Host: evil.com",
                allowed_urls=["https://api.example.com/*"],
            )
        )
        from coffer_mcp.tools.vault_http_request import vault_http_request

        result = await vault_http_request(
            store=store,
            audit=audit,
            alias="evil-header",
            url="https://api.example.com/data",
        )
        assert result["status"] == "error"
        assert "blocked" in result["message"].lower()

    async def test_safe_custom_header_allowed(self, store, audit):
        store.add(
            CredentialEntry(
                alias="safe-header",
                auth_type="api_key_header",
                secret="X-Custom-Key: my-secret-value",
                allowed_urls=["https://api.example.com/*"],
            )
        )
        import httpx

        from coffer_mcp.tools.vault_http_request import vault_http_request

        mock_response = httpx.Response(
            200,
            text='{"ok": true}',
            headers={"content-type": "application/json"},
            request=httpx.Request("GET", "https://api.example.com/data"),
        )

        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = mock_cls.return_value.__aenter__.return_value
            mock_client.request.return_value = mock_response

            result = await vault_http_request(
                store=store,
                audit=audit,
                alias="safe-header",
                url="https://api.example.com/data",
            )

        assert result["status"] == "ok"
