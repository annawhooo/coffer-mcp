"""
vault_list tool — returns credential aliases and metadata only.

The LLM sees: alias, auth_type, description, timestamps.
The LLM never sees: passwords, tokens, API keys, usernames.
"""

from __future__ import annotations

from typing import Any

from alcove_mcp.audit import AuditLogger
from alcove_mcp.store import EncryptedStore


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

    return aliases
