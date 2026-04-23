"""
OAuth2 client_credentials token management.

Handles automatic token acquisition and refresh for OAuth2 APIs.
The client_id and client_secret are stored in the vault; tokens are
cached in memory and refreshed automatically when they expire.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx

# In-memory token cache: alias -> {"access_token": str, "expires_at": float}
# Protected by an asyncio lock so two concurrent expired-token checks
# don't both fire token requests to the OAuth2 server.
_token_cache: dict[str, dict[str, Any]] = {}
_token_lock = asyncio.Lock()


async def get_oauth2_token(
    client_id: str,
    client_secret: str,
    token_url: str,
    scope: str = "",
) -> dict[str, Any]:
    """
    Acquire an OAuth2 access token using the client_credentials grant.

    Uses HTTP Basic authentication for the client credentials, which is
    the method RECOMMENDED by RFC 6749 §2.3.1 and required by many
    providers (ServiceNow, Okta, Auth0, etc.). Form-body credentials
    are rejected by some providers with a 400 response.

    Args:
        client_id: The OAuth2 client ID.
        client_secret: The OAuth2 client secret.
        token_url: The token endpoint URL.
        scope: Optional space-separated scopes.

    Returns:
        Dict with access_token and expires_at.
    """
    form_data = {"grant_type": "client_credentials"}
    if scope:
        form_data["scope"] = scope

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            token_url,
            data=form_data,
            headers=headers,
            auth=(client_id, client_secret),
        )
        if response.status_code >= 400:
            body_snippet = response.text[:500] if response.text else "<empty>"
            raise httpx.HTTPStatusError(
                f"OAuth2 token endpoint returned {response.status_code}: {body_snippet}",
                request=response.request,
                response=response,
            )

    token_data = response.json()
    expires_in = token_data.get("expires_in", 3600)

    return {
        "access_token": token_data["access_token"],
        "token_type": token_data.get("token_type", "Bearer"),
        "expires_at": time.time() + expires_in - 60,  # 60s safety buffer
    }


async def get_cached_token(
    alias: str,
    client_id: str,
    client_secret: str,
    token_url: str,
    scope: str = "",
) -> str:
    """
    Get a valid OAuth2 token, using cache if available.
    Automatically refreshes expired tokens.

    Uses an asyncio lock so that concurrent callers waiting on an
    expired token don't all fire separate token requests.
    """
    async with _token_lock:
        cached = _token_cache.get(alias)
        if cached and time.time() < cached["expires_at"]:
            return cached["access_token"]

        token_data = await get_oauth2_token(client_id, client_secret, token_url, scope)
        _token_cache[alias] = token_data
        return token_data["access_token"]


async def clear_token_cache(alias: str | None = None) -> None:
    """Clear cached OAuth2 tokens."""
    async with _token_lock:
        if alias:
            _token_cache.pop(alias, None)
        else:
            _token_cache.clear()
