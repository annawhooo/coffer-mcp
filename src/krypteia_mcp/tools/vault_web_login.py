"""
vault_web_login tool — performs form-based web login and content retrieval.

This is the tool that handles the OneTrust blog portal scenario:
1. Logs into a website using stored credentials via HTTP session
2. Navigates to content pages
3. Extracts clean markdown content
4. Returns content to the LLM (credentials never exposed)

For v1, this uses httpx with session cookies (no browser automation).
If a site requires JavaScript rendering, the `browser` optional dependency
with Playwright can be used in a future version.
"""

from __future__ import annotations

from typing import Any

import httpx
from readability import Document
import html2text

from krypteia_mcp.audit import AuditLogger
from krypteia_mcp.security import sanitize_response
from krypteia_mcp.store import EncryptedStore


# Module-level session cache (keyed by alias)
_sessions: dict[str, httpx.AsyncClient] = {}


async def vault_web_login(
    store: EncryptedStore,
    audit: AuditLogger,
    alias: str,
    login_url: str,
    username_field: str = "email",
    password_field: str = "password",
    extra_form_data: dict[str, str] | None = None,
) -> dict[str, Any]:
    """
    Log into a website using stored credentials and cache the session.

    Args:
        store: The encrypted credential store.
        audit: The audit logger.
        alias: Credential alias to use.
        login_url: The URL to POST login credentials to.
        username_field: Form field name for the username/email.
        password_field: Form field name for the password.
        extra_form_data: Any additional form fields needed for login.

    Returns:
        Dict with status and login result (no credentials exposed).
    """
    # 1. Resolve credential
    try:
        entry = store.get(alias)
    except KeyError:
        audit.log("web_login.failed", alias, "failure", {"reason": "not_found"})
        return {"status": "error", "message": f"No credential found with alias '{alias}'"}

    if entry.auth_type != "web_login":
        audit.log("web_login.failed", alias, "failure", {"reason": "wrong_auth_type"})
        return {
            "status": "error",
            "message": f"Credential '{alias}' is type '{entry.auth_type}', not 'web_login'",
        }

    # 2. Build login form data
    form_data = {
        username_field: entry.username,
        password_field: entry.secret,
    }
    if extra_form_data:
        form_data.update(extra_form_data)

    # 3. Create a persistent session and login
    try:
        client = httpx.AsyncClient(timeout=30.0, follow_redirects=True)
        response = await client.post(login_url, data=form_data)

        if response.status_code >= 400:
            await client.aclose()
            audit.log(
                "web_login.failed",
                alias,
                "failure",
                {"login_url": login_url, "status_code": response.status_code},
            )
            return {
                "status": "error",
                "message": f"Login failed with status {response.status_code}",
            }

        # Cache the authenticated session
        _sessions[alias] = client

        audit.log(
            "web_login.success",
            alias,
            "success",
            {"login_url": login_url, "status_code": response.status_code},
        )

        return {
            "status": "ok",
            "message": f"Successfully logged in as {entry.username}",
            "session_active": True,
        }

    except httpx.HTTPError as e:
        audit.log(
            "web_login.failed",
            alias,
            "failure",
            {"login_url": login_url, "error": str(e)},
        )
        return {"status": "error", "message": f"Login request failed: {str(e)}"}


async def vault_web_fetch(
    store: EncryptedStore,
    audit: AuditLogger,
    alias: str,
    url: str,
    extract_content: bool = True,
) -> dict[str, Any]:
    """
    Fetch a page using an authenticated session and return clean content.

    Args:
        store: The encrypted credential store.
        audit: The audit logger.
        alias: Credential alias (must have an active session from vault_web_login).
        url: The page URL to fetch.
        extract_content: If True, extract main content as markdown.
                        If False, return raw HTML.

    Returns:
        Dict with status and page content (as markdown or HTML).
    """
    # 1. Check for active session
    client = _sessions.get(alias)
    if client is None:
        audit.log("web_fetch.failed", alias, "failure", {"reason": "no_session"})
        return {
            "status": "error",
            "message": f"No active session for '{alias}'. Call vault_web_login first.",
        }

    # 2. Fetch the page
    try:
        response = await client.get(url)
    except httpx.HTTPError as e:
        audit.log(
            "web_fetch.failed",
            alias,
            "failure",
            {"url": url, "error": str(e)},
        )
        return {"status": "error", "message": f"Fetch failed: {str(e)}"}

    if response.status_code >= 400:
        audit.log(
            "web_fetch.failed",
            alias,
            "failure",
            {"url": url, "status_code": response.status_code},
        )
        return {
            "status": "error",
            "message": f"Page returned status {response.status_code}",
        }

    # 3. Extract content
    raw_html = response.text

    if extract_content:
        try:
            doc = Document(raw_html)
            title = doc.title()
            content_html = doc.summary()

            converter = html2text.HTML2Text()
            converter.ignore_links = False
            converter.ignore_images = True
            converter.body_width = 0  # No wrapping
            markdown_content = converter.handle(content_html)
        except Exception:
            # Fallback: return raw HTML if extraction fails
            title = "Unknown"
            markdown_content = raw_html
            extract_content = False
    else:
        title = "Raw HTML"
        markdown_content = raw_html

    # 4. Sanitize (in case any credentials leaked into the page somehow)
    try:
        entry = store.get(alias)
        markdown_content = sanitize_response(markdown_content, entry)
    except KeyError:
        pass

    # 5. Audit
    audit.log(
        "web_fetch.success",
        alias,
        "success",
        {"url": url, "title": title, "content_length": len(markdown_content)},
    )

    return {
        "status": "ok",
        "title": title,
        "url": url,
        "content": markdown_content,
        "format": "markdown" if extract_content else "html",
    }


async def vault_web_logout(alias: str) -> dict[str, Any]:
    """Close an authenticated web session."""
    client = _sessions.pop(alias, None)
    if client:
        await client.aclose()
        return {"status": "ok", "message": f"Session for '{alias}' closed"}
    return {"status": "ok", "message": f"No active session for '{alias}'"}
