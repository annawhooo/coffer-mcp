"""
vault_http_request tool — makes authenticated HTTP calls with injected credentials.

The MCP server resolves the credential, injects auth headers, makes the request,
sanitizes the response, and returns only the clean result. The LLM never sees
the actual credential.
"""

from __future__ import annotations

import time
from typing import Any

import httpx

from coffer_mcp.audit import AuditLogger
from coffer_mcp.secmem import wipe_entry
from coffer_mcp.security import (
    MAX_RESPONSE_BYTES,
    check_method_allowed,
    check_url_allowed,
    sanitize_content,
    sanitize_response,
    validate_header_name,
    validate_http_method,
    validate_oauth2_secret,
)
from coffer_mcp.store import EncryptedStore


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
    # 0. Validate HTTP method
    validated_method = validate_http_method(method)
    if validated_method is None:
        return {
            "status": "error",
            "message": (
                f"Invalid HTTP method '{method}'."
                " Must be one of: GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS."
            ),
        }
    method = validated_method

    # 1. Resolve the credential
    try:
        entry = store.get(alias)
    except KeyError:
        audit.log("credential.access_failed", alias, "failure", {"reason": "not_found"})
        return {"status": "error", "message": f"No credential found with alias '{alias}'"}

    # 2. Check credential expiry
    if entry.expires_at and time.time() > entry.expires_at:
        from datetime import datetime, timezone

        exp_str = datetime.fromtimestamp(
            entry.expires_at,
            tz=timezone.utc,
        ).strftime("%Y-%m-%d %H:%M UTC")
        audit.log("credential.expired", alias, "failure", {"expired_at": exp_str})
        return {
            "status": "error",
            "message": (
                f"Credential '{alias}' expired on {exp_str}. "
                f"Ask the user to rotate it with: coffer rotate {alias}"
            ),
        }

    # 3. Enforce URL allowlist
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

    # 4. Enforce method allowlist
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

    # 5. Build the request with injected auth
    request_headers = dict(headers or {})
    extra_secrets: list[str] = []  # Runtime secrets to scrub (e.g., OAuth2 tokens)

    if entry.auth_type == "bearer_token":
        request_headers["Authorization"] = f"Bearer {entry.secret}"
    elif entry.auth_type == "basic_auth":
        import base64

        encoded = base64.b64encode(f"{entry.username}:{entry.secret}".encode()).decode()
        request_headers["Authorization"] = f"Basic {encoded}"
    elif entry.auth_type == "oauth2_client_credentials":
        from coffer_mcp.tools.oauth2 import get_cached_token

        oauth2_parts = validate_oauth2_secret(entry.username, entry.secret)
        if oauth2_parts is None:
            return {
                "status": "error",
                "message": (
                    f"Credential '{alias}' has invalid OAuth2 format. "
                    f"Expected username='client_id|client_secret', secret='token_url|scope'."
                ),
            }
        client_id, client_secret, token_url, scope = oauth2_parts

        # Validate token_url against allowlist to prevent exfiltration
        # of client credentials to an attacker-controlled token endpoint
        if not check_url_allowed(entry, token_url):
            audit.log(
                "credential.access_denied",
                alias,
                "failure",
                {"reason": "token_url_not_allowed", "token_url": token_url},
            )
            return {
                "status": "error",
                "message": (
                    f"OAuth2 token URL '{token_url}' is not in the "
                    f"allowlist for credential '{alias}'."
                ),
            }

        access_token = await get_cached_token(alias, client_id, client_secret, token_url, scope)
        request_headers["Authorization"] = f"Bearer {access_token}"
        extra_secrets.append(access_token)
    elif entry.auth_type == "api_key_header":
        # Convention: secret is in format "HeaderName: value"
        if ":" in entry.secret:
            header_name, header_value = entry.secret.split(":", 1)
            safe_name = validate_header_name(header_name)
            if safe_name is None:
                return {
                    "status": "error",
                    "message": (f"Header '{header_name.strip()}' is blocked for security reasons."),
                }
            request_headers[safe_name] = header_value.strip()
        else:
            request_headers["X-API-Key"] = entry.secret

    # 5b. Capture secret for response sanitization, then wipe the entry.
    # The secret is still in the header dict (needed for the request) and
    # in extra_secrets (needed for scrubbing), but no longer on the entry.
    if entry.secret and entry.secret not in extra_secrets:
        extra_secrets.append(entry.secret)
    wipe_entry(entry)

    # 6. Make the request (redirects checked per-hop against allowlist)
    max_redirects = 10
    current_url = url
    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=False) as client:
            for redirect_hop in range(max_redirects + 1):
                response = await client.request(
                    method=method.upper(),
                    url=current_url,
                    headers=request_headers,
                    json=body if body and method.upper() in ("POST", "PUT", "PATCH") else None,
                    params=params if redirect_hop == 0 else None,
                )

                # If not a redirect, we're done
                if response.status_code not in (301, 302, 303, 307, 308):
                    break

                # It's a redirect — check the new location against the allowlist
                location = response.headers.get("location")
                if not location:
                    break

                # Resolve relative redirects
                from urllib.parse import urljoin

                next_url = urljoin(current_url, location)

                if not check_url_allowed(entry, next_url):
                    audit.log(
                        "credential.access_denied",
                        alias,
                        "failure",
                        {
                            "reason": "redirect_url_not_allowed",
                            "original_url": url,
                            "redirect_url": next_url,
                            "hop": redirect_hop + 1,
                        },
                    )
                    return {
                        "status": "error",
                        "message": (
                            f"Redirect from '{current_url}' to '{next_url}' "
                            f"is outside the allowlist for credential '{alias}'. "
                            f"Blocked at hop {redirect_hop + 1}."
                        ),
                    }

                current_url = next_url
                # On 303, method changes to GET per HTTP spec
                if response.status_code == 303:
                    method = "GET"
                    body = None
            else:
                # Exceeded max redirects
                return {
                    "status": "error",
                    "message": f"Too many redirects ({max_redirects}) for '{url}'",
                }

        # 7. Enforce response size limit and sanitize
        if len(response.content) > MAX_RESPONSE_BYTES:
            response_text = response.content[:MAX_RESPONSE_BYTES].decode("utf-8", errors="replace")
            mb = MAX_RESPONSE_BYTES // (1024 * 1024)
            response_text += f"\n\n[TRUNCATED -- response exceeded {mb} MB]"
        else:
            response_text = response.text
        clean_text = sanitize_response(response_text, entry, extra_secrets=extra_secrets)
        clean_text = sanitize_content(clean_text)

        # 8. Audit success
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
        # Sanitize the error message to prevent credential leakage
        # via exception strings (some httpx errors include full URLs
        # with query params, headers, or auth tokens in repr).
        error_msg = str(e)
        error_msg = sanitize_response(error_msg, entry, extra_secrets=extra_secrets)
        # Further strip anything that looks like a token or key
        import re as _re

        error_msg = _re.sub(
            r"(Bearer |Basic |Token |Authorization: )\S+",
            r"\1[REDACTED]",
            error_msg,
        )
        audit.log(
            "credential.used",
            alias,
            "failure",
            {"url": url, "method": method.upper(), "error": error_msg},
        )
        return {
            "status": "error",
            "message": f"HTTP request failed: {error_msg}",
        }
