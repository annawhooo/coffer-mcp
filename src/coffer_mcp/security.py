"""
Security utilities for URL allowlist enforcement, response sanitization,
input validation, and response content safety.
"""

from __future__ import annotations

import fnmatch
import re
from urllib.parse import urlparse

from coffer_mcp.store.encrypted_store import CredentialEntry

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Maximum response size returned to the LLM (characters). Larger responses
# are truncated with a warning. Prevents prompt-stuffing attacks where a
# malicious server returns a massive payload designed to push instructions
# into the LLM context.
MAX_RESPONSE_LENGTH = 200_000

# Maximum response body size in bytes to read from the network.
# Prevents memory exhaustion from a malicious server sending huge payloads.
MAX_RESPONSE_BYTES = 10 * 1024 * 1024  # 10 MB

# Valid HTTP methods
VALID_HTTP_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})

# Max wait time for wait_after_login (60 seconds)
MAX_WAIT_AFTER_LOGIN_MS = 60_000

# Patterns that indicate embedded prompt-injection attempts in response
# bodies. These are stripped before the response reaches the LLM.
_INJECTION_PATTERNS = [
    # HTML comments (commonly used to hide instructions)
    re.compile(r"<!--.*?-->", re.DOTALL),
    # Hidden HTML elements
    re.compile(
        r"<[^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0)"
        r"[^>]*>.*?</[^>]+>",
        re.DOTALL | re.IGNORECASE,
    ),
    # Zero-width / invisible unicode characters used to smuggle text
    re.compile(r"[\u200b\u200c\u200d\u2060\ufeff\u00ad]+"),
]


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def validate_http_method(method: str) -> str | None:
    """
    Validate and normalize an HTTP method string.

    Returns the uppercased method if valid, or None if invalid.
    """
    normalized = method.strip().upper()
    if normalized in VALID_HTTP_METHODS:
        return normalized
    return None


def validate_wait_after_login(wait_ms: int) -> int:
    """Clamp wait_after_login to a safe range [0, MAX_WAIT_AFTER_LOGIN_MS]."""
    return max(0, min(wait_ms, MAX_WAIT_AFTER_LOGIN_MS))


def validate_css_selector(selector: str) -> str | None:
    """
    Basic validation of a CSS selector string.

    Rejects selectors containing characters that could indicate injection
    (JavaScript URIs, script tags, unbalanced quotes). Returns the
    cleaned selector or None if suspicious.
    """
    if not selector or not selector.strip():
        return None
    s = selector.strip()
    # Reject anything that looks like script injection
    suspicious = [
        "<script",
        "javascript:",
        "onerror=",
        "onload=",
        "expression(",
        "url(",
        "eval(",
        "import(",
    ]
    lower = s.lower()
    for pattern in suspicious:
        if pattern in lower:
            return None
    # Reject unbalanced quotes
    if s.count('"') % 2 != 0 or s.count("'") % 2 != 0:
        return None
    return s


def validate_oauth2_secret(username: str, secret: str) -> tuple[str, str, str, str] | None:
    """
    Parse and validate OAuth2 client_credentials format.

    Expected formats:
        username: "client_id|client_secret"  (or just client_id)
        secret: "token_url|scope"  (or just token_url)

    Returns (client_id, client_secret, token_url, scope) or None if invalid.
    """
    if not secret:
        return None

    parts = secret.split("|", 1)
    token_url = parts[0].strip()
    scope = parts[1].strip() if len(parts) > 1 else ""

    if not token_url or not token_url.startswith(("https://", "http://")):
        return None

    id_parts = username.split("|", 1)
    client_id = id_parts[0].strip()
    client_secret = id_parts[1].strip() if len(id_parts) > 1 else ""

    if not client_id:
        return None

    return client_id, client_secret, token_url, scope


# ---------------------------------------------------------------------------
# URL / method allowlist
# ---------------------------------------------------------------------------


def check_url_allowed(entry: CredentialEntry, url: str) -> bool:
    """
    Check if a URL is allowed for a given credential entry.

    Uses strict scheme + netloc matching with fnmatch only on the path
    component. The netloc (host:port) must match exactly -- no wildcards
    allowed on the domain to prevent subdomain bypass attacks.

    If allowed_urls is empty, ALL URLs are blocked (fail-closed).

    Args:
        entry: The credential entry with its allowlist.
        url: The target URL to check.

    Returns:
        True if the URL matches at least one allowed pattern.
    """
    if not entry.allowed_urls:
        return False  # Fail closed: no allowlist = no access

    parsed = urlparse(url)
    # Normalize: resolve path traversal attempts
    from posixpath import normpath

    normalized_path = normpath(parsed.path) if parsed.path else "/"

    for pattern in entry.allowed_urls:
        pat_parsed = urlparse(pattern)

        # Scheme must match exactly
        if parsed.scheme != pat_parsed.scheme:
            continue

        # Netloc (host:port) must match exactly -- NO wildcards on domain
        if parsed.netloc != pat_parsed.netloc:
            continue

        # Path: use fnmatch for wildcard matching (e.g., /v1/*)
        pat_path = pat_parsed.path if pat_parsed.path else "/"
        if fnmatch.fnmatch(normalized_path, pat_path):
            return True

    return False


def check_method_allowed(entry: CredentialEntry, method: str) -> bool:
    """
    Check if an HTTP method is allowed for a given credential entry.

    Args:
        entry: The credential entry with its allowed methods.
        method: The HTTP method (GET, POST, etc.).

    Returns:
        True if the method is in the allowed list.
    """
    if not entry.allowed_methods:
        return False
    return method.upper() in [m.upper() for m in entry.allowed_methods]


def sanitize_response(
    response_text: str,
    entry: CredentialEntry,
    extra_secrets: list[str] | None = None,
) -> str:
    """
    Scrub any leaked credentials from a response before returning to the LLM.

    Checks for the secret in multiple representations:
    - Literal plaintext
    - URL-encoded
    - Base64-encoded (standalone and as Basic auth)
    - Bearer/token patterns (headers, query params, JSON values)

    Args:
        response_text: The raw response body.
        entry: The credential entry whose secrets to scrub.
        extra_secrets: Additional secrets to scrub (e.g., OAuth2 access
            tokens that are not stored in the entry but were used at runtime).

    Returns:
        Sanitized response text with secrets replaced by [REDACTED].
    """
    sanitized = response_text

    # Scrub any extra runtime secrets first (e.g., OAuth2 access tokens)
    for secret in extra_secrets or []:
        if secret and len(secret) > 3:
            sanitized = _scrub_secret(sanitized, secret)

    if not entry.secret or len(entry.secret) <= 3:
        return sanitized

    sanitized = _scrub_secret(sanitized, entry.secret)

    # Also scrub base64-encoded Basic auth (username:password)
    if entry.username:
        import base64

        basic_auth = base64.b64encode(f"{entry.username}:{entry.secret}".encode()).decode()
        sanitized = sanitized.replace(basic_auth, "[REDACTED]")

    return sanitized


def _scrub_secret(text: str, secret: str) -> str:
    """
    Scrub a single secret from text in multiple representations.

    Checks: literal, URL-encoded, base64-encoded, and Bearer/token patterns.
    """
    import base64
    from urllib.parse import quote

    # 1. Literal
    text = text.replace(secret, "[REDACTED]")

    # 2. URL-encoded
    encoded = quote(secret, safe="")
    if encoded != secret:
        text = text.replace(encoded, "[REDACTED]")

    # 3. Base64-encoded
    b64 = base64.b64encode(secret.encode()).decode()
    text = text.replace(b64, "[REDACTED]")

    # 4. Bearer/token patterns
    escaped = re.escape(secret)
    for pattern in [
        r"Bearer\s+" + escaped,
        r"token[\"']?\s*[:=]\s*[\"']?" + escaped,
        r"access_token[\"']?\s*[:=]\s*[\"']?" + escaped,
        r"api[_-]?key[\"']?\s*[:=]\s*[\"']?" + escaped,
    ]:
        text = re.sub(pattern, "[REDACTED]", text, flags=re.IGNORECASE)

    return text


def sanitize_content(text: str) -> str:
    """
    Strip potentially dangerous content from response bodies before they
    reach the LLM context. This defends against prompt injection via
    server-controlled response content.

    Protections:
        - Strips HTML comments (<!-- ... -->)
        - Strips hidden HTML elements (display:none, visibility:hidden)
        - Strips zero-width / invisible Unicode characters
        - Truncates oversized responses

    Args:
        text: Raw response body (HTML or plain text).

    Returns:
        Cleaned text safe for LLM consumption.
    """
    cleaned = text

    # Strip injection-suspect patterns
    for pattern in _INJECTION_PATTERNS:
        cleaned = pattern.sub("", cleaned)

    # Truncate oversized responses
    if len(cleaned) > MAX_RESPONSE_LENGTH:
        cleaned = (
            cleaned[:MAX_RESPONSE_LENGTH]
            + f"\n\n[TRUNCATED — response exceeded {MAX_RESPONSE_LENGTH:,} characters]"
        )

    return cleaned
