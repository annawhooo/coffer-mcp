"""
Tests for the per-credential OAuth2 auth style (client_secret_post vs
client_secret_basic).

Some providers (OneTrust's /api/access/v1/oauth/token among them) require the
client_id and client_secret in the form body and ignore an HTTP Basic header.
Others require Basic. The auth style is selectable per credential via an
optional third segment of the secret: "token_url|scope|auth_style".
Default is "body".
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx

from coffer_mcp.security import validate_oauth2_secret
from coffer_mcp.tools.oauth2 import clear_token_cache, get_oauth2_token


class TestParseAuthStyle:
    """validate_oauth2_secret parses the optional auth_style segment."""

    def test_defaults_to_body_when_omitted(self) -> None:
        result = validate_oauth2_secret("cid|cs", "https://auth.example.com/token|read")
        assert result is not None
        client_id, client_secret, token_url, scope, auth_style = result
        assert client_id == "cid"
        assert client_secret == "cs"
        assert token_url == "https://auth.example.com/token"
        assert scope == "read"
        assert auth_style == "body"

    def test_explicit_body(self) -> None:
        result = validate_oauth2_secret("cid|cs", "https://auth.example.com/token|read|body")
        assert result is not None
        assert result[4] == "body"

    def test_explicit_basic(self) -> None:
        result = validate_oauth2_secret("cid|cs", "https://auth.example.com/token|read|basic")
        assert result is not None
        assert result[4] == "basic"

    def test_basic_with_empty_scope(self) -> None:
        result = validate_oauth2_secret("cid|cs", "https://auth.example.com/token||basic")
        assert result is not None
        assert result[3] == ""
        assert result[4] == "basic"

    def test_no_scope_no_style_defaults_body(self) -> None:
        result = validate_oauth2_secret("cid", "https://auth.example.com/token")
        assert result is not None
        assert result[3] == ""
        assert result[4] == "body"

    def test_unknown_auth_style_rejected(self) -> None:
        assert validate_oauth2_secret("cid|cs", "https://auth.example.com/token|read|weird") is None


def _token_ok(url: str) -> httpx.Response:
    return httpx.Response(
        200,
        json={"access_token": "tok_abc", "token_type": "Bearer", "expires_in": 3600},
        request=httpx.Request("POST", url),
    )


class TestTokenRequestShaping:
    """get_oauth2_token puts credentials where auth_style says."""

    async def test_body_style_sends_creds_in_form_body(self) -> None:
        await clear_token_cache()
        url = "https://auth.example.com/token"
        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = mock_cls.return_value.__aenter__.return_value
            mock_client.post = AsyncMock(return_value=_token_ok(url))

            await get_oauth2_token("my_id", "my_secret", url, scope="read", auth_style="body")

            kwargs = mock_client.post.call_args.kwargs
            data = kwargs["data"]
            assert data["grant_type"] == "client_credentials"
            assert data["client_id"] == "my_id"
            assert data["client_secret"] == "my_secret"
            assert data["scope"] == "read"
            # No HTTP Basic auth in body style.
            assert kwargs.get("auth") is None
            assert kwargs["headers"]["Content-Type"] == "application/x-www-form-urlencoded"

    async def test_basic_style_sends_creds_in_basic_header(self) -> None:
        await clear_token_cache()
        url = "https://auth.example.com/token"
        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = mock_cls.return_value.__aenter__.return_value
            mock_client.post = AsyncMock(return_value=_token_ok(url))

            await get_oauth2_token("my_id", "my_secret", url, scope="read", auth_style="basic")

            kwargs = mock_client.post.call_args.kwargs
            data = kwargs["data"]
            assert data["grant_type"] == "client_credentials"
            # Basic style: creds go in the Authorization header, not the body.
            assert "client_id" not in data
            assert "client_secret" not in data
            assert kwargs.get("auth") == ("my_id", "my_secret")

    async def test_default_style_is_body(self) -> None:
        await clear_token_cache()
        url = "https://auth.example.com/token"
        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = mock_cls.return_value.__aenter__.return_value
            mock_client.post = AsyncMock(return_value=_token_ok(url))

            await get_oauth2_token("my_id", "my_secret", url)

            kwargs = mock_client.post.call_args.kwargs
            assert kwargs["data"]["client_id"] == "my_id"
            assert kwargs.get("auth") is None
