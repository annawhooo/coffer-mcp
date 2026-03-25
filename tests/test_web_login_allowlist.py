"""Tests for URL allowlist enforcement in vault_web_login and vault_web_fetch."""

from __future__ import annotations

import asyncio
import os
from unittest.mock import AsyncMock, patch

import pytest

from coffer_mcp.audit.logger import AuditLogger
from coffer_mcp.store.encrypted_store import CredentialEntry, EncryptedStore
from coffer_mcp.tools.vault_web_login import vault_web_fetch, vault_web_login


@pytest.fixture
def master_key():
    return os.urandom(32)


@pytest.fixture
def store(master_key, tmp_path):
    return EncryptedStore(master_key, tmp_path / "creds.json")


@pytest.fixture
def audit(tmp_path):
    import hashlib

    return AuditLogger(tmp_path / "audit.jsonl", hmac_key=hashlib.sha256(b"k").digest())


@pytest.fixture
def web_entry(store):
    entry = CredentialEntry(
        alias="portal",
        auth_type="web_login",
        username="user@example.com",
        secret="s3cret-pass",
        allowed_urls=[
            "https://portal.example.com/*",
            "https://portal.example.com/login",
        ],
    )
    store.add(entry)
    return entry


class TestWebLoginAllowlist:
    """vault_web_login must validate login_url against allowed_urls."""

    def test_login_url_not_in_allowlist_rejected(self, store, audit, web_entry):
        """Login URL outside the allowlist should be rejected immediately."""
        result = asyncio.get_event_loop().run_until_complete(
            vault_web_login(
                store,
                audit,
                "portal",
                login_url="https://evil.com/phish",
            )
        )
        assert result["status"] == "error"
        assert "not in the allowed URLs" in result["message"]

    def test_login_url_in_allowlist_proceeds(self, store, audit, web_entry):
        """Login URL in the allowlist should proceed to make the request."""
        # Mock httpx to avoid real network calls
        mock_response = AsyncMock()
        mock_response.status_code = 200

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client_cls.return_value = mock_client

            result = asyncio.get_event_loop().run_until_complete(
                vault_web_login(
                    store,
                    audit,
                    "portal",
                    login_url="https://portal.example.com/login",
                )
            )
            assert result["status"] == "ok"
            mock_client.post.assert_called_once()

    def test_login_url_subdomain_blocked(self, store, audit, web_entry):
        """Subdomain of allowed domain should still be blocked."""
        result = asyncio.get_event_loop().run_until_complete(
            vault_web_login(
                store,
                audit,
                "portal",
                login_url="https://evil.portal.example.com/login",
            )
        )
        assert result["status"] == "error"
        assert "not in the allowed URLs" in result["message"]

    def test_login_url_scheme_mismatch_blocked(self, store, audit, web_entry):
        """HTTP when HTTPS required should be blocked."""
        result = asyncio.get_event_loop().run_until_complete(
            vault_web_login(
                store,
                audit,
                "portal",
                login_url="http://portal.example.com/login",
            )
        )
        assert result["status"] == "error"

    def test_audit_records_url_not_allowed(self, store, audit, web_entry):
        """Blocked login attempts should be audited."""
        asyncio.get_event_loop().run_until_complete(
            vault_web_login(
                store,
                audit,
                "portal",
                login_url="https://evil.com/phish",
            )
        )
        events = audit.get_events(alias="portal", limit=10)
        assert len(events) >= 1
        assert events[0]["event_type"] == "web_login.failed"
        assert events[0]["details"]["reason"] == "url_not_allowed"


class TestWebFetchAllowlist:
    """vault_web_fetch must validate the fetch URL against allowed_urls."""

    def test_fetch_url_not_in_allowlist_rejected(self, store, audit, web_entry):
        """Fetch URL outside the allowlist should be rejected."""
        # First, create a fake session

        mock_client = AsyncMock()
        loop = asyncio.get_event_loop()
        loop.run_until_complete(_set_session("portal", mock_client))

        try:
            result = loop.run_until_complete(
                vault_web_fetch(
                    store,
                    audit,
                    "portal",
                    url="https://evil.com/steal-data",
                )
            )
            assert result["status"] == "error"
            assert "not in the allowed URLs" in result["message"]
            # The HTTP client should NOT have been called
            mock_client.get.assert_not_called()
        finally:
            loop.run_until_complete(_clear_session("portal"))

    def test_fetch_url_in_allowlist_proceeds(self, store, audit, web_entry):
        """Fetch URL in the allowlist should proceed to fetch."""
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.text = "<html><body><p>Hello</p></body></html>"
        mock_response.content = mock_response.text.encode()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        loop = asyncio.get_event_loop()
        loop.run_until_complete(_set_session("portal", mock_client))

        try:
            result = loop.run_until_complete(
                vault_web_fetch(
                    store,
                    audit,
                    "portal",
                    url="https://portal.example.com/articles/latest",
                )
            )
            assert result["status"] == "ok"
            mock_client.get.assert_called_once()
        finally:
            loop.run_until_complete(_clear_session("portal"))


# Helpers to manipulate the session cache in tests
async def _set_session(alias, client):
    from coffer_mcp.tools.vault_web_login import _sessions, _sessions_lock

    async with _sessions_lock:
        _sessions[alias] = client


async def _clear_session(alias):
    from coffer_mcp.tools.vault_web_login import _sessions, _sessions_lock

    async with _sessions_lock:
        _sessions.pop(alias, None)
