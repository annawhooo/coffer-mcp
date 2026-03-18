"""
Playwright browser bridge for Alcove.

Handles form-based web login and content extraction using a real browser.
This is necessary for sites that use JavaScript-heavy login flows
(Salesforce Community Cloud, SPAs, etc.) where simple HTTP POST won't work.

The credential is resolved inside Alcove, injected into the browser form,
and the browser is controlled entirely server-side. Claude never sees the
password — only the resulting page content.
"""

from __future__ import annotations

import asyncio
from typing import Any

from alcove_mcp.audit import AuditLogger
from alcove_mcp.security import sanitize_response
from alcove_mcp.store import EncryptedStore


# Module-level browser context cache (keyed by alias)
_contexts: dict[str, dict[str, Any]] = {}


async def _ensure_browser():
    """Get or create a shared Playwright browser instance."""
    global _browser, _playwright
    if "_browser" not in globals() or _browser is None:
        from playwright.async_api import async_playwright
        _playwright = await async_playwright().start()
        _browser = await _playwright.chromium.launch(headless=True)
    return _browser


async def browser_web_login(
    store: EncryptedStore,
    audit: AuditLogger,
    alias: str,
    login_url: str,
    username_selector: str = 'input[name="username"], input[type="email"], input#username',
    password_selector: str = 'input[name="password"], input[type="password"], input#password',
    submit_selector: str = 'button[type="submit"], input[type="submit"], button:has-text("Log In")',
    wait_after_login: int = 5000,
) -> dict[str, Any]:
    """
    Log into a website using a real browser and stored credentials.

    Navigates to the login page, fills in credentials from the vault,
    submits the form, and caches the authenticated browser context.

    Args:
        store: The encrypted credential store.
        audit: The audit logger.
        alias: Credential alias (must be auth_type 'web_login').
        login_url: The login page URL.
        username_selector: CSS selector for the username/email field.
        password_selector: CSS selector for the password field.
        submit_selector: CSS selector for the submit button.
        wait_after_login: Milliseconds to wait after clicking submit.

    Returns:
        Dict with status and page title (no credentials exposed).
    """
    # 1. Resolve credential
    try:
        entry = store.get(alias)
    except KeyError:
        audit.log("browser_login.failed", alias, "failure", {"reason": "not_found"})
        return {"status": "error", "message": f"No credential found with alias '{alias}'"}

    if entry.auth_type != "web_login":
        audit.log("browser_login.failed", alias, "failure", {"reason": "wrong_auth_type"})
        return {
            "status": "error",
            "message": f"Credential '{alias}' is type '{entry.auth_type}', not 'web_login'",
        }

    # 2. Launch browser and navigate to login page
    try:
        browser = await _ensure_browser()
        context = await browser.new_context()
        page = await context.new_page()

        await page.goto(login_url, wait_until="networkidle", timeout=30000)

        # 3. Fill in credentials
        username_el = await page.wait_for_selector(username_selector, timeout=10000)
        await username_el.fill(entry.username)

        password_el = await page.wait_for_selector(password_selector, timeout=10000)
        await password_el.fill(entry.secret)

        # 4. Click submit
        submit_el = await page.wait_for_selector(submit_selector, timeout=10000)
        await submit_el.click()

        # 5. Wait for navigation / page load after login
        await page.wait_for_timeout(wait_after_login)
        try:
            await page.wait_for_load_state("networkidle", timeout=15000)
        except Exception:
            pass  # Some sites never fully settle; that's okay

        page_title = await page.title()

        # 6. Cache the authenticated context
        _contexts[alias] = {"context": context, "page": page}

        audit.log(
            "browser_login.success",
            alias,
            "success",
            {"login_url": login_url, "page_title": page_title},
        )

        return {
            "status": "ok",
            "message": f"Successfully logged in. Page title: {page_title}",
            "page_title": page_title,
            "session_active": True,
        }

    except Exception as e:
        audit.log(
            "browser_login.failed",
            alias,
            "failure",
            {"login_url": login_url, "error": str(e)},
        )
        return {"status": "error", "message": f"Browser login failed: {str(e)}"}


async def browser_web_fetch(
    store: EncryptedStore,
    audit: AuditLogger,
    alias: str,
    url: str,
    extract_content: bool = True,
) -> dict[str, Any]:
    """
    Fetch a page using an authenticated browser session and return clean content.

    Args:
        store: The encrypted credential store.
        audit: The audit logger.
        alias: Credential alias with an active browser session.
        url: The page URL to fetch.
        extract_content: If True, extract main content as markdown.

    Returns:
        Dict with status, title, and page content as markdown.
    """
    ctx = _contexts.get(alias)
    if ctx is None:
        audit.log("browser_fetch.failed", alias, "failure", {"reason": "no_session"})
        return {
            "status": "error",
            "message": f"No active browser session for '{alias}'. Call alcove_web_login first.",
        }

    page = ctx["page"]

    try:
        await page.goto(url, wait_until="networkidle", timeout=30000)
        page_title = await page.title()
        raw_html = await page.content()
    except Exception as e:
        audit.log("browser_fetch.failed", alias, "failure", {"url": url, "error": str(e)})
        return {"status": "error", "message": f"Failed to fetch page: {str(e)}"}

    # Extract content
    if extract_content:
        try:
            from readability import Document
            import html2text

            doc = Document(raw_html)
            title = doc.title() or page_title
            content_html = doc.summary()

            converter = html2text.HTML2Text()
            converter.ignore_links = False
            converter.ignore_images = True
            converter.body_width = 0
            markdown_content = converter.handle(content_html)
        except Exception:
            title = page_title
            markdown_content = raw_html
            extract_content = False
    else:
        title = page_title
        markdown_content = raw_html

    # Sanitize response
    try:
        entry = store.get(alias)
        markdown_content = sanitize_response(markdown_content, entry)
    except KeyError:
        pass

    audit.log(
        "browser_fetch.success",
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


async def browser_web_logout(alias: str) -> dict[str, Any]:
    """Close an authenticated browser session and free resources."""
    ctx = _contexts.pop(alias, None)
    if ctx:
        try:
            await ctx["page"].close()
            await ctx["context"].close()
        except Exception:
            pass
        return {"status": "ok", "message": f"Browser session for '{alias}' closed"}
    return {"status": "ok", "message": f"No active browser session for '{alias}'"}
