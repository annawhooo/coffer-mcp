"""
End-to-end MCP integration tests.

These tests exercise the actual MCP server tool surface — the same code path
that Claude Desktop / Claude Code hits when it calls tools.  We bypass the
stdio transport and call `mcp.call_tool()` directly, which exercises:
  - JSON serialisation at the protocol boundary
  - The lazy init of store + audit
  - The full tool -> business logic -> store -> response chain
  - Error handling at the MCP layer
"""

from __future__ import annotations

import json
import os
from unittest.mock import patch

import pytest

from coffer_mcp.store.encrypted_store import CredentialEntry, EncryptedStore

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _text(result) -> str:
    """Extract the text string from a call_tool result.

    call_tool returns (list[ContentBlock], structured_output).
    The first ContentBlock is TextContent with a .text attribute.
    """
    content_blocks, _ = result
    return content_blocks[0].text


def _json(result) -> dict | list:
    """Extract and parse JSON from a call_tool result."""
    return json.loads(_text(result))


@pytest.fixture()
def vault_env(tmp_path, monkeypatch):
    """Set up an isolated vault with test credentials, then patch the server
    globals so the MCP tools use it."""
    master_key = os.urandom(32)
    store_path = tmp_path / "credentials.json"
    audit_path = tmp_path / "audit.jsonl"

    store = EncryptedStore(master_key, store_path)
    store.add(
        CredentialEntry(
            alias="test-api",
            auth_type="bearer_token",
            username="",
            secret="sk-test-secret-12345",
            allowed_urls=["https://api.example.com/*"],
            description="Test API key",
        )
    )
    store.add(
        CredentialEntry(
            alias="basic-cred",
            auth_type="basic_auth",
            username="admin",
            secret="hunter2",
            allowed_urls=["https://internal.example.com/*"],
            description="Basic auth credential",
        )
    )
    store.add(
        CredentialEntry(
            alias="expired-api",
            auth_type="bearer_token",
            username="",
            secret="sk-expired-key",
            allowed_urls=["https://api.example.com/*"],
            expires_at=1.0,  # expired in 1970
        )
    )

    from coffer_mcp.audit.logger import AuditLogger

    audit = AuditLogger(log_path=audit_path, hmac_key=master_key)

    import coffer_mcp.server as srv

    monkeypatch.setattr(srv, "_store", store)
    monkeypatch.setattr(srv, "_audit", audit)

    return {"store": store, "audit": audit, "master_key": master_key}


@pytest.fixture()
def mcp_server():
    """Return the FastMCP server instance."""
    from coffer_mcp.server import mcp

    return mcp


# ---------------------------------------------------------------------------
# Test: coffer_list
# ---------------------------------------------------------------------------


class TestCofferList:
    """E2E tests for coffer_list tool."""

    async def test_list_returns_all_credentials(self, vault_env, mcp_server):
        data = _json(await mcp_server.call_tool("coffer_list", {}))
        # coffer_list returns a JSON array of credential objects
        aliases = [c["alias"] for c in data]
        assert "test-api" in aliases
        assert "basic-cred" in aliases
        assert "expired-api" in aliases

    async def test_list_never_exposes_secrets(self, vault_env, mcp_server):
        text = _text(await mcp_server.call_tool("coffer_list", {}))
        assert "sk-test-secret-12345" not in text
        assert "hunter2" not in text
        assert "sk-expired-key" not in text

    async def test_list_shows_status(self, vault_env, mcp_server):
        data = _json(await mcp_server.call_tool("coffer_list", {}))
        statuses = {c["alias"]: c["status"].lower() for c in data}
        assert statuses["test-api"] == "active"
        assert statuses["expired-api"] == "expired"

    async def test_list_returns_valid_json(self, vault_env, mcp_server):
        text = _text(await mcp_server.call_tool("coffer_list", {}))
        parsed = json.loads(text)  # Should not raise
        assert isinstance(parsed, list)


# ---------------------------------------------------------------------------
# Test: coffer_http_request
# ---------------------------------------------------------------------------


class TestCofferHttpRequest:
    """E2E tests for coffer_http_request tool."""

    async def test_unknown_alias_returns_error(self, vault_env, mcp_server):
        data = _json(
            await mcp_server.call_tool(
                "coffer_http_request",
                {"alias": "nonexistent", "url": "https://api.example.com/data"},
            )
        )
        assert data["status"] == "error"
        assert "no credential found" in data["message"].lower()

    async def test_url_not_in_allowlist_blocked(self, vault_env, mcp_server):
        data = _json(
            await mcp_server.call_tool(
                "coffer_http_request",
                {"alias": "test-api", "url": "https://evil.com/steal"},
            )
        )
        assert data["status"] == "error"
        msg = data["message"].lower()
        assert "not allowed" in msg or "allowlist" in msg

    async def test_invalid_method_rejected(self, vault_env, mcp_server):
        data = _json(
            await mcp_server.call_tool(
                "coffer_http_request",
                {
                    "alias": "test-api",
                    "url": "https://api.example.com/data",
                    "method": "HACK",
                },
            )
        )
        assert data["status"] == "error"
        assert "method" in data["message"].lower()

    async def test_invalid_json_body_rejected(self, vault_env, mcp_server):
        data = _json(
            await mcp_server.call_tool(
                "coffer_http_request",
                {
                    "alias": "test-api",
                    "url": "https://api.example.com/data",
                    "body": "{invalid json",
                },
            )
        )
        assert data["status"] == "error"
        assert "json" in data["message"].lower()

    async def test_expired_credential_rejected(self, vault_env, mcp_server):
        data = _json(
            await mcp_server.call_tool(
                "coffer_http_request",
                {
                    "alias": "expired-api",
                    "url": "https://api.example.com/data",
                },
            )
        )
        assert data["status"] == "error"
        assert "expired" in data["message"].lower()

    async def test_successful_request(self, vault_env, mcp_server):
        """A valid request to an allowed URL should succeed (mocked HTTP)."""
        import httpx

        mock_response = httpx.Response(
            200,
            text='{"result": "success"}',
            headers={"content-type": "application/json"},
            request=httpx.Request("GET", "https://api.example.com/data"),
        )

        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = mock_cls.return_value.__aenter__.return_value
            mock_client.request.return_value = mock_response

            result = await mcp_server.call_tool(
                "coffer_http_request",
                {
                    "alias": "test-api",
                    "url": "https://api.example.com/data",
                    "method": "GET",
                },
            )

        data = _json(result)
        assert data["status"] == "ok"
        assert data["status_code"] == 200
        assert "sk-test-secret-12345" not in _text(result)

    async def test_secret_scrubbed_from_response(self, vault_env, mcp_server):
        """If the API response contains the secret, it must be scrubbed."""
        import httpx

        mock_response = httpx.Response(
            200,
            text='{"echo": "Bearer sk-test-secret-12345"}',
            headers={"content-type": "application/json"},
            request=httpx.Request("GET", "https://api.example.com/data"),
        )

        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = mock_cls.return_value.__aenter__.return_value
            mock_client.request.return_value = mock_response

            result = await mcp_server.call_tool(
                "coffer_http_request",
                {"alias": "test-api", "url": "https://api.example.com/data"},
            )

        assert "sk-test-secret-12345" not in _text(result)

    async def test_response_always_valid_json(self, vault_env, mcp_server):
        result = await mcp_server.call_tool(
            "coffer_http_request",
            {"alias": "nonexistent", "url": "https://api.example.com/data"},
        )
        json.loads(_text(result))  # Should not raise


# ---------------------------------------------------------------------------
# Test: coffer_test
# ---------------------------------------------------------------------------


class TestCofferTest:
    """E2E tests for coffer_test tool."""

    async def test_unknown_alias(self, vault_env, mcp_server):
        data = _json(await mcp_server.call_tool("coffer_test", {"alias": "nonexistent"}))
        assert data["status"] == "error"

    async def test_url_outside_allowlist(self, vault_env, mcp_server):
        data = _json(
            await mcp_server.call_tool(
                "coffer_test",
                {"alias": "test-api", "url": "https://evil.com/test"},
            )
        )
        assert data["status"] == "error"


# ---------------------------------------------------------------------------
# Test: coffer_audit
# ---------------------------------------------------------------------------


class TestCofferAudit:
    """E2E tests for coffer_audit tool."""

    async def test_audit_returns_chain_integrity(self, vault_env, mcp_server):
        # Generate some audit events first
        await mcp_server.call_tool("coffer_list", {})

        data = _json(await mcp_server.call_tool("coffer_audit", {}))
        assert "chain_valid" in data
        assert "chain_integrity" in data
        assert "events" in data
        assert isinstance(data["events"], list)

    async def test_audit_filter_by_alias(self, vault_env, mcp_server):
        # Generate events for different aliases
        await mcp_server.call_tool(
            "coffer_http_request",
            {"alias": "nonexistent", "url": "https://api.example.com/data"},
        )
        await mcp_server.call_tool("coffer_list", {})

        data = _json(await mcp_server.call_tool("coffer_audit", {"alias": "nonexistent"}))
        for event in data["events"]:
            if "alias" in event:
                assert event["alias"] == "nonexistent"

    async def test_audit_valid_json(self, vault_env, mcp_server):
        result = await mcp_server.call_tool("coffer_audit", {})
        json.loads(_text(result))  # Should not raise


# ---------------------------------------------------------------------------
# Test: Protocol-level concerns
# ---------------------------------------------------------------------------


class TestProtocolBoundary:
    """Tests for MCP protocol-level behaviour."""

    async def test_all_tools_registered(self, vault_env, mcp_server):
        tools = await mcp_server.list_tools()
        tool_names = {t.name for t in tools}
        expected = {
            "coffer_list",
            "coffer_http_request",
            "coffer_web_login",
            "coffer_web_fetch",
            "coffer_web_logout",
            "coffer_test",
            "coffer_audit",
        }
        assert expected.issubset(tool_names), f"Missing: {expected - tool_names}"

    async def test_tool_descriptions_present(self, vault_env, mcp_server):
        tools = await mcp_server.list_tools()
        for tool in tools:
            assert tool.description, f"Tool {tool.name} has no description"
            assert len(tool.description) > 20, f"Tool {tool.name} description too short"

    async def test_unknown_tool_raises(self, vault_env, mcp_server):
        with pytest.raises(Exception):
            await mcp_server.call_tool("nonexistent_tool", {})

    async def test_response_contains_text_content(self, vault_env, mcp_server):
        """Every tool should return TextContent blocks."""
        content_blocks, _ = await mcp_server.call_tool("coffer_list", {})
        assert len(content_blocks) > 0
        assert hasattr(content_blocks[0], "text")
