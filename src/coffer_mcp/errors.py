"""
Structured error codes for Coffer MCP tools.

Every error response includes a machine-readable `code` field that
the LLM (or any programmatic consumer) can use for structured
decision-making without parsing English error messages.
"""

from __future__ import annotations

# Credential resolution
CREDENTIAL_NOT_FOUND = "CREDENTIAL_NOT_FOUND"
CREDENTIAL_EXPIRED = "CREDENTIAL_EXPIRED"
CREDENTIAL_WRONG_TYPE = "CREDENTIAL_WRONG_TYPE"
CREDENTIAL_DELETED = "CREDENTIAL_DELETED"

# Access control
URL_NOT_ALLOWED = "URL_NOT_ALLOWED"
METHOD_NOT_ALLOWED = "METHOD_NOT_ALLOWED"
HEADER_BLOCKED = "HEADER_BLOCKED"
TOKEN_URL_NOT_ALLOWED = "TOKEN_URL_NOT_ALLOWED"
REDIRECT_URL_NOT_ALLOWED = "REDIRECT_URL_NOT_ALLOWED"

# Input validation
INVALID_HTTP_METHOD = "INVALID_HTTP_METHOD"
INVALID_JSON = "INVALID_JSON"
INVALID_CSS_SELECTOR = "INVALID_CSS_SELECTOR"
INVALID_OAUTH2_FORMAT = "INVALID_OAUTH2_FORMAT"

# Access control (rate limiting)
RATE_LIMITED = "RATE_LIMITED"

# Runtime errors
HTTP_REQUEST_FAILED = "HTTP_REQUEST_FAILED"
TOO_MANY_REDIRECTS = "TOO_MANY_REDIRECTS"
LOGIN_FAILED = "LOGIN_FAILED"
NO_ACTIVE_SESSION = "NO_ACTIVE_SESSION"
SESSION_EXPIRED = "SESSION_EXPIRED"
FETCH_FAILED = "FETCH_FAILED"
STORE_CORRUPTED = "STORE_CORRUPTED"


def error_response(code: str, message: str) -> dict:
    """Build a standardized error response dict."""
    return {"status": "error", "code": code, "message": message}
