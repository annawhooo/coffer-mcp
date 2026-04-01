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
from coffer_mcp.errors import (
    CREDENTIAL_EXPIRED,
    CREDENTIAL_NOT_FOUND,
    CREDENTIAL_WRONG_TYPE,
    HTTP_REQUEST_FAILED,
    INVALID_HTTP_METHOD,
    INVALID_OAUTH2_FORMAT,
    URL_NOT_ALLOWED,
    error_response,
)
from coffer_mcp.security import (
    check_url_allowed,
    sanitize_response,
    validate_http_method,
    validate_oauth2_secret,
)
from coffer_mcp.store import EncryptedStore


async def vault_test(
    store: EncryptedStore,
    audit: AuditLogger,
    alias: str,
    url: str = "",
    method: str = "HEAD",
    expected_status: int | None = None,
    reason: str = "",
) -> dict[str, Any]:
    """
    Test a stored credential by making a lightweight authenticated request.

    If no URL is provided, uses the first URL in the credential's allowlist.

    Args:
        expected_status: If set, the test PASSes only when the response
            status code matches this value exactly (e.g. 200).  This
            catches the case where a HEAD to the API root returns 200
            regardless of auth — set expected_status=200 and test
            against an endpoint that actually enforces authentication.
            When None (default), the legacy behaviour applies: any
            status < 400 is a PASS.

    Returns:
        Dict with test result: status_code, latency, and pass/fail.
    """
    # Validate HTTP method
    validated_method = validate_http_method(method)
    if validated_method is None:
        audit.log(
            "credential.test",
            alias,
            "failure",
            {"reason": "invalid_http_method", "method": method},
        )
        return error_response(
            INVALID_HTTP_METHOD,
            f"Invalid HTTP method '{method}'."
            " Must be one of: GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS.",
        )
    method = validated_method

    try:
        entry = store.get(alias)
    except KeyError:
        audit.log(
            "credential.test",
            alias,
            "failure",
            {"reason": "credential_not_found"},
        )
        return error_response(CREDENTIAL_NOT_FOUND, f"No credential found with alias '{alias}'")

    # Check expiry
    if entry.expires_at and time.time() > entry.expires_at:
        audit.log(
            "credential.test",
            alias,
            "failure",
            {"reason": "credential_expired"},
        )
        return {**error_response(CREDENTIAL_EXPIRED, "credential_expired"), "test": "FAIL"}

    # Determine test URL
    test_url = url
    if not test_url:
        if not entry.allowed_urls:
            audit.log(
                "credential.test",
                alias,
                "failure",
                {"reason": "no_allowed_urls"},
            )
            return error_response(
                URL_NOT_ALLOWED,
                "No allowed URLs configured; pass a URL to test.",
            )
        test_url = entry.allowed_urls[0].replace("/*", "/").rstrip("*")

    if not check_url_allowed(entry, test_url):
        audit.log(
            "credential.test",
            alias,
            "failure",
            {"reason": "url_not_allowed", "url": test_url},
        )
        return error_response(URL_NOT_ALLOWED, f"URL '{test_url}' is not in the allowlist.")

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

        oauth2_parts = validate_oauth2_secret(entry.username, entry.secret)
        if oauth2_parts is None:
            audit.log(
                "credential.test",
                alias,
                "failure",
                {"reason": "invalid_oauth2_format"},
            )
            return {
                **error_response(
                    INVALID_OAUTH2_FORMAT,
                    f"Credential '{alias}' has invalid OAuth2 format. "
                    f"Expected username='client_id|client_secret', secret='token_url|scope'.",
                ),
                "test": "FAIL",
            }
        client_id, client_secret, token_url, scope = oauth2_parts
        try:
            access_token = await get_cached_token(alias, client_id, client_secret, token_url, scope)
            request_headers["Authorization"] = f"Bearer {access_token}"
        except Exception as e:
            audit.log(
                "credential.test",
                alias,
                "failure",
                {
                    "reason": f"oauth2_token_error: {e}",
                },
            )
            return {
                **error_response(HTTP_REQUEST_FAILED, f"OAuth2 token fetch failed: {e}"),
                "test": "FAIL",
            }
    elif entry.auth_type == "web_login":
        audit.log(
            "credential.test",
            alias,
            "failure",
            {"reason": "wrong_type", "auth_type": entry.auth_type},
        )
        return error_response(
            CREDENTIAL_WRONG_TYPE,
            f"Credential '{alias}' is type 'web_login'. "
            "Use coffer_web_login to test browser-based credentials.",
        )

    # Make the test request
    start = time.time()
    try:
        async with httpx.AsyncClient(
            timeout=15.0,
            follow_redirects=False,
        ) as client:
            response = await client.request(
                method=method.upper(),
                url=test_url,
                headers=request_headers,
            )
        latency_ms = int((time.time() - start) * 1000)

        # Determine pass/fail
        if expected_status is not None:
            passed = response.status_code == expected_status
        else:
            passed = response.status_code < 400

        # Distinguish auth rejection from generic failure in audit
        if response.status_code in (401, 403):
            audit_status = "auth_rejected"
        elif passed:
            audit_status = "success"
        else:
            audit_status = "failure"

        result = {
            "status": "ok",
            "test": "PASS" if passed else "FAIL",
            "status_code": response.status_code,
            "latency_ms": latency_ms,
            "url": test_url,
            "method": method.upper(),
        }
        if expected_status is not None:
            result["expected_status"] = expected_status
        audit_details = dict(result)
        if reason:
            audit_details["reason"] = reason
        audit.log(
            "credential.test",
            alias,
            audit_status,
            audit_details,
        )
        return result

    except httpx.HTTPError as e:
        latency_ms = int((time.time() - start) * 1000)
        error_msg = sanitize_response(str(e), entry)
        audit.log(
            "credential.test",
            alias,
            "failure",
            {
                "error": error_msg,
                "latency_ms": latency_ms,
            },
        )
        return {
            **error_response(HTTP_REQUEST_FAILED, error_msg),
            "test": "FAIL",
            "latency_ms": latency_ms,
        }
