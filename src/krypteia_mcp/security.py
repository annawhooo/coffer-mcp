"""
Security utilities for URL allowlist enforcement and response sanitization.
"""

from __future__ import annotations

import fnmatch
import re
from urllib.parse import urlparse

from krypteia_mcp.store.encrypted_store import CredentialEntry


def check_url_allowed(entry: CredentialEntry, url: str) -> bool:
    """
    Check if a URL is allowed for a given credential entry.

    Uses fnmatch-style pattern matching against the entry's allowed_urls list.
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
    url_to_check = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    for pattern in entry.allowed_urls:
        if fnmatch.fnmatch(url_to_check, pattern):
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
