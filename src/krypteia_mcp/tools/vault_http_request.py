"""
vault_http_request tool — makes authenticated HTTP calls with injected credentials.

The MCP server resolves the credential, injects auth headers, makes the request,
sanitizes the response, and returns only the clean result. The LLM never sees
the actual credential.
"""

from __future__ import annotations

from typing import Any

import httpx

from krypteia_mcp.audit import AuditLogger
from krypteia_mcp.security import check_method_allowed, check_url_allowed, sanitize_response
from krypteia_mcp.store import EncryptedStore


async def vault_http_request(
    store: EncryptedStore,
    audit: AuditLogger,
    alias: str,
    url: str,
    method: str = "GET",
    body: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    params: dict[str, str] | None = None,
) -> dict[str, Any]:
    """
    Make an authenticated HTTP request using a stored credential.

    The credential is resolved server-side, injected into the request,
    and the response is sanitized before being returned.

    Args:
        store: The encrypted credential store.
        audit: The audit logger.
        alias: Credential alias to use.
        url: Target URL.
        method: HTTP method (GET, POST, PUT, DELETE, PATCH).
        body: Optional JSON body for POST/PUT/PATCH.
        headers: Optional additional headers.
        params: Optional query parameters.

    Returns:
        Dict with status_code, headers (safe subset), and body.
    """
    # 1. Resolve the credential
    try:
        entry = store.get(alias)
    except KeyError:
        audit.log("credential.access_failed", alias, "failure", {"reason": "not_found"})
        return {"status": "error", "message": f"No credential found with alias '{alias}'"}

    # 2. Enforce URL allowlist
    if not check_url_allowed(entry, url):
        audit.log(
            "credential.access_denied",
            alias,
            "failure",
            {"reason": "url_not_allowed", "url": url},
        )
        return {
            "status": "error",
            "message": f"URL '{url}' is not in the allowlist for credential '{alias}'",
        }

    # 3. Enforce method allowlist
    if not check_method_allowed(entry, method):
        audit.log(
            "credential.access_denied",
            alias,
            "failure",
            {"reason": "method_not_allowed", "method": method},
        )
        return {
            "status": "error",
            "message": f"Method '{method}' is not allowed for credential '{alias}'",
        }

    # 4. Build the request with injected auth
    request_headers = dict(headers or {})

    if entry.auth_type == "bearer_token":
        request_headers["Authorization"] = f"Bearer {entry.secret}"
    elif entry.auth_type == "basic_auth":
        import base64
        encoded = base64.b64encode(f"{entry.username}:{entry.secret}".encode()).decode()
        request_headers["Authorization"] = f"Basic {encoded}"
    elif entry.auth_type == "api_key_header":
        # Convention: secret is in format "HeaderName: value"
        if ":" in entry.secret:
            header_name, header_value = entry.secret.split(":", 1)
            request_headers[header_name.strip()] = header_value.strip()
        else:
            request_headers["X-API-Key"] = entry.secret

    # 5. Make the request
    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            response = await client.request(
                method=method.upper(),
                url=url,
                headers=request_headers,
                json=body if body and method.upper() in ("POST", "PUT", "PATCH") else None,
                params=params,
            )

        # 6. Sanitize the response
        response_text = response.text
        clean_text = sanitize_response(response_text, entry)

        # 7. Audit success
        audit.log(
            "credential.used",
            alias,
            "success",
            {
                "url": url,
                "method": method.upper(),
                "status_code": response.status_code,
            },
        )

        return {
            "status": "ok",
            "status_code": response.status_code,
            "body": clean_text,
            "content_type": response.headers.get("content-type", ""),
        }

    except httpx.HTTPError as e:
        audit.log(
            "credential.used",
            alias,
            "failure",
            {"url": url, "method": method.upper(), "error": str(e)},
        )
        return {
            "status": "error",
            "message": f"HTTP request failed: {str(e)}",
        }
