"""
vault_list tool — returns credential aliases and metadata only.

The LLM sees: alias, auth_type, description, timestamps.
The LLM never sees: passwords, tokens, API keys, usernames.
"""

from __future__ import annotations

from typing import Any

from coffer_mcp.audit import AuditLogger
import time
from coffer_mcp.store import EncryptedStore


def vault_list(store: EncryptedStore, audit: AuditLogger) -> list[dict[str, Any]]:
    """
    List all stored credentials (metadata only, no secrets).

    Returns:
        List of dicts with alias, auth_type, description, and timestamps.
    """
    aliases = store.list_aliases()

    audit.log(
        event_type="credential.listed",
        alias="*",
        status="success",
        details={"count": len(aliases)},
    )

    for a in aliases:
        exp = a.get("expires_at")
        if exp is not None:
            if time.time() > exp:
                a["status"] = "EXPIRED"
            elif time.time() > exp - 7 * 86400:
                a["status"] = "EXPIRING_SOON"
            else:
                a["status"] = "active"
        else:
            a["status"] = "active"

    return aliases
