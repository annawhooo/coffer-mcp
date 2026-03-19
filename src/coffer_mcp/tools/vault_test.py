"""
vault_test tool -- verify a credential works by making a test request.

Makes a lightweight HEAD or GET request to the first allowed URL and
reports whether authentication succeeds. The LLM never sees the
credential -- only the test result.
"""

from __future__ import annotations

import time
from typing import Any

import httpx

from coffer_mcp.audit import AuditLogger
from coffer_mcp.security import check_url_allowed, sanitize_response
from coffer_mcp.store import EncryptedStore


async def vault_test(
    store: EncryptedStore,
    audit: AuditLogger,
    alias: str,
    url: str = "",
    method: str = "HEAD",
) -> dict[str, Any]:
    """
    Test a stored credential by making a lightweight authenticated request.

    If no URL is provided, uses the first URL in the credential's allowlist.

    Returns:
        Dict with test result: status_code, latency, and pass/fail.
    """
    try:
        entry = store.get(alias)
    except KeyError:
        return {"status": "error", "message": f"No credential found with alias '{alias}'"}

    # Check expiry
    if entry.expires_at and time.time() > entry.expires_at:
        return {"status": "error", "test": "FAIL", "reason": "credential_expired"}

    # Determine test URL
    test_url = url
    if not test_url:
        if not entry.allowed_urls:
            return {"status": "error", "message": "No allowed URLs configured; pass a URL to test against."}
        test_url = entry.allowed_urls[0].replace("/*", "/").rstrip("*")

    if not check_url_allowed(entry, test_url):
        return {"status": "error", "message": f"URL '{test_url}' is not in the allowlist."}


    # Build auth headers
    request_headers: dict[str, str] = {}
    if entry.auth_type == "bearer_token":
        request_headers["Authorization"] = f"Bearer {entry.secret}"
    elif entry.auth_type == "basic_auth":
        import base64
        encoded = base64.b64encode(f"{entry.username}:{entry.secret}".encode()).decode()
        request_headers["Authorization"] = f"Basic {encoded}"
    elif entry.auth_type == "api_key_header":
        if ":" in entry.secret:
            header_name, header_value = entry.secret.split(":", 1)
            request_headers[header_name.strip()] = header_value.strip()
        else:
            request_headers["X-API-Key"] = entry.secret
    elif entry.auth_type == "oauth2_client_credentials":
        from coffer_mcp.tools.oauth2 import get_cached_token
        parts = entry.secret.split("|", 1)
        token_url = parts[0]
        scope = parts[1] if len(parts) > 1 else ""
        id_parts = entry.username.split("|", 1)
        client_id = id_parts[0]
        client_secret = id_parts[1] if len(id_parts) > 1 else ""
        try:
            access_token = await get_cached_token(
                alias, client_id, client_secret, token_url, scope
            )
            request_headers["Authorization"] = f"Bearer {access_token}"
        except Exception as e:
            audit.log("credential.test", alias, "failure", {
                "reason": f"oauth2_token_error: {e}",
            })
            return {
                "status": "error",
                "test": "FAIL",
                "reason": f"OAuth2 token fetch failed: {e}",
            }
    elif entry.auth_type == "web_login":
        return {
            "status": "error",
            "message": (
                f"Credential '{alias}' is type 'web_login'. "
                f"Use coffer_web_login to test browser-based credentials."
            ),
        }

    # Make the test request
    start = time.time()
    try:
        async with httpx.AsyncClient(
            timeout=15.0, follow_redirects=False,
        ) as client:
            response = await client.request(
                method=method.upper(),
                url=test_url,
                headers=request_headers,
            )
        latency_ms = int((time.time() - start) * 1000)
        passed = response.status_code < 400
        result = {
            "status": "ok",
            "test": "PASS" if passed else "FAIL",
            "status_code": response.status_code,
            "latency_ms": latency_ms,
            "url": test_url,
            "method": method.upper(),
        }
        audit.log(
            "credential.test", alias,
            "success" if passed else "failure", result,
        )
        return result

    except httpx.HTTPError as e:
        latency_ms = int((time.time() - start) * 1000)
        error_msg = sanitize_response(str(e), entry)
        audit.log("credential.test", alias, "failure", {
            "error": error_msg, "latency_ms": latency_ms,
        })
        return {
            "status": "error",
            "test": "FAIL",
            "reason": error_msg,
            "latency_ms": latency_ms,
        }
