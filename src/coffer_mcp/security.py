"""
Security utilities for URL allowlist enforcement, response sanitization,
and response content safety.
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

# Patterns that indicate embedded prompt-injection attempts in response
# bodies. These are stripped before the response reaches the LLM.
_INJECTION_PATTERNS = [
    # HTML comments (commonly used to hide instructions)
    re.compile(r"<!--.*?-->", re.DOTALL),
    # Hidden HTML elements
    re.compile(r"<[^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0)[^>]*>.*?</[^>]+>", re.DOTALL | re.IGNORECASE),
    # Zero-width / invisible unicode characters used to smuggle text
    re.compile(r"[\u200b\u200c\u200d\u2060\ufeff\u00ad]+"),
]


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


def sanitize_response(response_text: str, entry: CredentialEntry) -> str:
    """
    Scrub any leaked credentials from a response before returning to the LLM.

    Checks for the secret, username, and any partial matches.

    Args:
        response_text: The raw response body.
        entry: The credential entry whose secrets to scrub.

    Returns:
        Sanitized response text with secrets replaced by [REDACTED].
    """
    sanitized = response_text

    # Scrub the secret itself
    if entry.secret and len(entry.secret) > 3:
        sanitized = sanitized.replace(entry.secret, "[REDACTED]")

    # Scrub URL-encoded version of the secret
    if entry.secret:
        from urllib.parse import quote
        encoded_secret = quote(entry.secret, safe="")
        if encoded_secret != entry.secret:
            sanitized = sanitized.replace(encoded_secret, "[REDACTED]")

    # Scrub base64-encoded version of common auth patterns
    if entry.username and entry.secret:
        import base64
        basic_auth = base64.b64encode(
            f"{entry.username}:{entry.secret}".encode()
        ).decode()
        sanitized = sanitized.replace(basic_auth, "[REDACTED]")

    return sanitized


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
