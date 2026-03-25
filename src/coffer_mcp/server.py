"""
Coffer MCP Server.

Exposes credential vault tools to Claude Desktop (and Claude Code) via
the Model Context Protocol. Credentials are encrypted at rest, resolved
server-side, and never returned to the LLM context.

Usage (Claude Desktop claude_desktop_config.json):
    {
        "mcpServers": {
            "Coffer": {
                "command": "python",
                "args": ["-m", "coffer_mcp.server"]
            }
        }
    }
"""

from __future__ import annotations

import json
import threading

from mcp.server.fastmcp import FastMCP

from coffer_mcp.audit import AuditLogger
from coffer_mcp.browser.playwright_bridge import (
    browser_web_fetch as _browser_web_fetch,
)
from coffer_mcp.browser.playwright_bridge import (
    browser_web_login as _browser_web_login,
)
from coffer_mcp.browser.playwright_bridge import (
    browser_web_logout as _browser_web_logout,
)
from coffer_mcp.store import EncryptedStore, get_master_key
from coffer_mcp.tools.vault_http_request import vault_http_request as _vault_http_request
from coffer_mcp.tools.vault_list import vault_list as _vault_list
from coffer_mcp.tools.vault_test import vault_test as _vault_test

# ---------------------------------------------------------------------------
# Initialize server, store, and audit logger
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "Coffer",
    instructions=(
        "Coffer — credential vault for LLM agents. "
        "Stores encrypted credentials and uses them on your behalf — "
        "passwords and API keys never appear in the conversation."
    ),
)

# These are initialized lazily on first tool call to avoid startup errors
# if the keyring isn't configured yet.  The lock prevents duplicate
# initialisation when concurrent async tool calls race on first use.
_init_lock = threading.Lock()
_store: EncryptedStore | None = None
_audit: AuditLogger | None = None


def _get_store() -> EncryptedStore:
    global _store
    if _store is None:
        with _init_lock:
            if _store is None:  # double-checked locking
                master_key = get_master_key()
                _store = EncryptedStore(master_key)
    return _store


def _get_audit() -> AuditLogger:
    global _audit
    if _audit is None:
        with _init_lock:
            if _audit is None:  # double-checked locking
                # Derive a separate HMAC key from the master key for audit
                # chain integrity. This prevents attackers with file access
                # (but not the master key) from recomputing valid hashes
                # after log tampering.
                import hashlib

                master_key = get_master_key()
                hmac_key = hashlib.sha256(b"coffer-audit-hmac:" + master_key).digest()
                _audit = AuditLogger(hmac_key=hmac_key)
    return _audit


# ---------------------------------------------------------------------------
# MCP Tools
# ---------------------------------------------------------------------------


@mcp.tool()
def coffer_list() -> str:
    """
    List all stored credentials. Returns aliases and metadata only — never
    passwords, API keys, or tokens.

    Use this to see what credentials are available before making requests.
    """
    result = _vault_list(_get_store(), _get_audit())
    return json.dumps(result, indent=2)


@mcp.tool()
async def coffer_http_request(
    alias: str,
    url: str,
    method: str = "GET",
    body: str = "",
    headers: str = "",
    params: str = "",
) -> str:
    """
    Make an authenticated HTTP request using a stored credential.

    The credential is resolved server-side and injected into the request.
    You never see the actual password or API key — only the response.

    Args:
        alias: The credential alias to use (see coffer_list).
        url: The target URL.
        method: HTTP method (GET, POST, PUT, DELETE, PATCH).
        body: Optional JSON body as a string (for POST/PUT/PATCH).
        headers: Optional additional headers as a JSON string.
        params: Optional query parameters as a JSON string.
    """
    try:
        body_dict = json.loads(body) if body else None
        headers_dict = json.loads(headers) if headers else None
        params_dict = json.loads(params) if params else None
    except json.JSONDecodeError as e:
        err = {"status": "error", "message": f"Invalid JSON: {e}"}
        return json.dumps(err, indent=2)

    result = await _vault_http_request(
        store=_get_store(),
        audit=_get_audit(),
        alias=alias,
        url=url,
        method=method,
        body=body_dict,
        headers=headers_dict,
        params=params_dict,
    )
    return json.dumps(result, indent=2)


@mcp.tool()
async def coffer_web_login(
    alias: str,
    login_url: str,
    username_selector: str = 'input[name="username"], input[type="email"], input#username',
    password_selector: str = 'input[name="password"], input[type="password"], input#password',
    submit_selector: str = 'button[type="submit"], input[type="submit"], button:has-text("Log In")',
    wait_after_login: int = 5000,
) -> str:
    """
    Log into a website using stored credentials via a real browser.

    Uses Playwright to automate a headless Chromium browser. The credential
    is resolved from the vault, filled into the login form, and submitted.
    Your password never appears in the conversation.

    After login, use coffer_web_fetch to read pages from the authenticated session.

    Args:
        alias: The credential alias to use (must be auth_type 'web_login').
        login_url: The login page URL (not the POST endpoint — the actual page with the form).
        username_selector: CSS selector for the username/email input field.
        password_selector: CSS selector for the password input field.
        submit_selector: CSS selector for the submit/login button.
        wait_after_login: Milliseconds to wait after clicking submit (default: 5000).
    """
    result = await _browser_web_login(
        store=_get_store(),
        audit=_get_audit(),
        alias=alias,
        login_url=login_url,
        username_selector=username_selector,
        password_selector=password_selector,
        submit_selector=submit_selector,
        wait_after_login=wait_after_login,
    )
    return json.dumps(result, indent=2)


@mcp.tool()
async def coffer_web_fetch(
    alias: str,
    url: str,
    extract_content: bool = True,
) -> str:
    """
    Fetch a page from an authenticated web session and return clean content.

    Must call coffer_web_login first to establish a session.
    Returns the page content as clean markdown (or raw HTML if requested).

    Args:
        alias: The credential alias with an active session.
        url: The page URL to fetch.
        extract_content: If True, extract main article content as markdown.
                        If False, return raw HTML.
    """
    result = await _browser_web_fetch(
        store=_get_store(),
        audit=_get_audit(),
        alias=alias,
        url=url,
        extract_content=extract_content,
    )
    return json.dumps(result, indent=2)


@mcp.tool()
async def coffer_web_logout(alias: str) -> str:
    """
    Close an authenticated web session.

    Args:
        alias: The credential alias whose session to close.
    """
    result = await _browser_web_logout(alias)
    return json.dumps(result, indent=2)


@mcp.tool()
async def coffer_test(alias: str, url: str = "") -> str:
    """
    Test a stored credential by making a lightweight authenticated request.

    Verifies the credential is valid, not expired, and the target server
    accepts it. Returns pass/fail, status code, and latency.

    If no URL is provided, tests against the first URL in the credential's
    allowlist.

    Args:
        alias: The credential alias to test.
        url: Optional URL to test against.
    """
    result = await _vault_test(
        store=_get_store(),
        audit=_get_audit(),
        alias=alias,
        url=url,
    )
    return json.dumps(result, indent=2)


@mcp.tool()
def coffer_audit(alias: str = "", limit: int = 20) -> str:
    """
    View recent audit log entries and verify chain integrity.

    Args:
        alias: Optional — filter events for a specific credential.
        limit: Maximum number of events to return (default: 20).
    """
    audit = _get_audit()
    is_valid, count, message = audit.verify_chain()
    events = audit.get_events(alias=alias if alias else None, limit=limit)

    result = {
        "chain_integrity": message,
        "chain_valid": is_valid,
        "total_events": count,
        "events": events,
    }
    return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main():
    """Run the MCP server via stdio transport."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
