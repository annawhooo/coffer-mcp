"""
Append-only audit logger with SHA-256 hash chain.

Each event is a JSON line with a hash that includes the previous event's hash,
creating a tamper-evident chain. If any entry is modified, the chain breaks.
"""

from __future__ import annotations

import hashlib
import json
import time
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from coffer_mcp.filelock import FileLock
from coffer_mcp.permissions import secure_directory, secure_file


@dataclass
class AuditEvent:
    """A single audit log entry."""

    event_id: str
    event_type: str  # credential.created, credential.used, credential.removed, etc.
    alias: str
    status: str  # success, failure
    details: dict[str, Any]
    timestamp: float
    prev_hash: str
    hash: str


class AuditLogger:
    """
    Append-only JSONL audit logger with hash chain integrity.

    File layout:
        ~/.coffer/audit.jsonl
    """

    def __init__(self, log_path: Path | None = None, hmac_key: bytes | None = None):
        self._path = log_path or Path.home() / ".coffer" / "audit.jsonl"
        self._hmac_key = hmac_key
        self._warned_no_hmac = False
        self._lock = FileLock(self._path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        secure_directory(self._path.parent)
        if not self._path.exists():
            self._path.touch()
        secure_file(self._path)
        self._event_counter = self._count_events()

    def log(
        self,
        event_type: str,
        alias: str,
        status: str = "success",
        details: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """
        Append an audit event to the log.

        Args:
            event_type: Type of event (e.g., "credential.created").
            alias: The credential alias involved.
            status: "success" or "failure".
            details: Additional context (never include secrets).

        Returns:
            The created AuditEvent.
        """
        with self._lock.acquire():
            self._event_counter += 1
            prev_hash = self._get_last_hash()
            timestamp = time.time()

            event_data = {
                "event_id": f"evt_{self._event_counter:06d}",
                "event_type": event_type,
                "alias": alias,
                "status": status,
                "details": details or {},
                "timestamp": timestamp,
                "prev_hash": prev_hash,
            }

            # Compute hash over all fields except "hash" itself
            event_hash = self._compute_hash(event_data)
            event_data["hash"] = event_hash

            # Append to log
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event_data) + "\n")

            return AuditEvent(**event_data)

    def verify_chain(self) -> tuple[bool, int, str]:
        """
        Verify the integrity of the entire audit log.

        Returns:
            Tuple of (is_valid, entry_count, message).
        """
        entries = self._read_all()
        if not entries:
            return True, 0, "Audit log is empty"

        prev_hash = "genesis"
        for i, entry in enumerate(entries):
            # Check prev_hash linkage
            if entry.get("prev_hash") != prev_hash:
                return False, i + 1, f"Chain broken at entry {i + 1}: prev_hash mismatch"

            # Recompute and verify hash
            entry_without_hash = {k: v for k, v in entry.items() if k != "hash"}
            expected_hash = self._compute_hash(entry_without_hash)
            if entry.get("hash") != expected_hash:
                return False, i + 1, f"Chain broken at entry {i + 1}: hash mismatch (tampered)"

            prev_hash = entry["hash"]

        return True, len(entries), f"Chain integrity: VALID ({len(entries)} entries)"

    def get_events(self, alias: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        """
        Retrieve recent audit events, optionally filtered by alias.

        Args:
            alias: Filter to events for this credential alias.
            limit: Maximum number of events to return.

        Returns:
            List of event dicts (most recent first).
        """
        entries = self._read_all()
        if alias:
            entries = [e for e in entries if e.get("alias") == alias]
        return list(reversed(entries[-limit:]))

    # -- internal helpers ----------------------------------------------------

    def _get_last_hash(self) -> str:
        """Get the hash of the most recent log entry, or 'genesis' if empty."""
        entries = self._read_all()
        if not entries:
            return "genesis"
        return entries[-1].get("hash", "genesis")

    def _compute_hash(self, data: dict) -> str:
        """
        Compute HMAC-SHA-256 of a dict's canonical JSON representation.

        Uses the master key as the HMAC key so that an attacker who gains
        file access but not the master key cannot recompute valid hashes
        after tampering with log entries.

        Emits a warning if falling back to bare SHA-256 (no HMAC key),
        since this weakens tamper detection.
        """
        import hmac

        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
        if self._hmac_key:
            return hmac.new(
                self._hmac_key,
                canonical.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
        # Fallback: bare SHA-256 if no key provided (backward compat)
        if not self._warned_no_hmac:
            warnings.warn(
                "AuditLogger has no HMAC key -- using bare SHA-256. "
                "Audit entries can be forged by anyone with file access. "
                "Pass hmac_key= to enable tamper-proof logging.",
                UserWarning,
                stacklevel=3,
            )
            self._warned_no_hmac = True
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def _read_all(self) -> list[dict]:
        """Read all entries from the JSONL file."""
        entries = []
        try:
            with open(self._path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        entries.append(json.loads(line))
        except FileNotFoundError:
            pass
        return entries

    def _count_events(self) -> int:
        """Count the number of existing events."""
        return len(self._read_all())
