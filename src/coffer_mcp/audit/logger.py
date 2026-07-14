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
    source: str  # "cli", "mcp", or "" for unspecified
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

    def __init__(
        self, log_path: Path | None = None, hmac_key: bytes | None = None, source: str = ""
    ):
        self._path = log_path or Path.home() / ".coffer" / "audit.jsonl"
        # Checkpoint sidecar for truncation detection (RR-H5). Records the
        # last entry's id+hash under an HMAC so an attacker with file write
        # access cannot silently delete entries from the end of the log.
        self._state_path = Path(str(self._path) + ".state")
        self._hmac_key = hmac_key
        self._source = source
        self._warned_no_hmac = False
        self._lock = FileLock(self._path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        secure_directory(self._path.parent)
        if not self._path.exists():
            self._path.touch()
        secure_file(self._path)
        self._event_counter = self._count_events()
        # Cache the last hash to avoid re-reading the entire log on each write.
        # Initialized from disk on startup, then updated in memory after each append.
        self._last_hash = self._read_last_hash_from_disk()

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
            # Re-read counter and last_hash from disk under lock.
            # This prevents duplicate event IDs when multiple processes
            # (CLI + MCP server) write to the same audit log file.
            self._event_counter = self._count_events()
            self._last_hash = self._read_last_hash_from_disk()

            self._event_counter += 1
            prev_hash = self._last_hash
            timestamp = time.time()

            event_data = {
                "event_id": f"evt_{self._event_counter:06d}",
                "event_type": event_type,
                "alias": alias,
                "status": status,
                "source": self._source,
                "details": details or {},
                "timestamp": timestamp,
                "prev_hash": prev_hash,
            }

            # Compute hash over all fields except "hash" itself
            event_hash = self._compute_hash(event_data)
            event_data["hash"] = event_hash

            # Append to log and update cached hash
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event_data) + "\n")
            self._last_hash = event_hash

            # Advance the truncation-detection checkpoint. Done after the
            # append so a crash between the two writes leaves the checkpoint
            # exactly one entry behind (tolerated by verify_chain).
            self._write_state(event_data["event_id"], event_hash)

            return AuditEvent(**event_data)

    def verify_chain(self) -> tuple[bool, int, str]:
        """
        Verify the integrity of the entire audit log.

        Returns:
            Tuple of (is_valid, entry_count, message).
        """
        entries = self._read_all()
        state_status, state = self._read_state()

        if not entries:
            if state_status == "ok":
                return (
                    False,
                    0,
                    (
                        "Truncation detected: audit log is empty but the checkpoint "
                        f"expects the chain to end at {state['event_id']}"
                    ),
                )
            if state_status == "invalid":
                return False, 0, "Audit checkpoint file is invalid or tampered"
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

        # Chain is internally consistent — now prove the tail hasn't been
        # truncated by comparing against the checkpoint (RR-H5).
        if state_status == "invalid":
            return False, len(entries), "Audit checkpoint file is invalid or tampered"
        if state_status == "missing":
            return (
                True,
                len(entries),
                (
                    f"Chain integrity: VALID ({len(entries)} entries) — "
                    "no checkpoint file; truncation detection unavailable until the next append"
                ),
            )

        last = entries[-1]
        exact_match = (
            last.get("event_id") == state["event_id"] and last.get("hash") == state["hash"]
        )
        # Crash window: the process appended an entry but died before
        # advancing the checkpoint. The log is then exactly one entry ahead,
        # and that entry's prev_hash is the checkpointed hash.
        one_ahead = last.get("prev_hash") == state["hash"]
        if not (exact_match or one_ahead):
            return (
                False,
                len(entries),
                (
                    "Truncation detected: checkpoint expects the chain to end at "
                    f"{state['event_id']}, but the log ends at {last.get('event_id')} "
                    "with a non-matching hash"
                ),
            )

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

    def _state_mac(self, event_id: str, entry_hash: str) -> str:
        """MAC over the checkpoint contents, keyed like the chain hashes."""
        return self._compute_hash({"event_id": event_id, "hash": entry_hash})

    def _write_state(self, event_id: str, entry_hash: str) -> None:
        """Atomically write the truncation-detection checkpoint."""
        state = {
            "event_id": event_id,
            "hash": entry_hash,
            "mac": self._state_mac(event_id, entry_hash),
        }
        tmp_path = self._state_path.with_suffix(".state.tmp")
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(state, f)
        secure_file(tmp_path)
        tmp_path.replace(self._state_path)
        secure_file(self._state_path)

    def _read_state(self) -> tuple[str, dict | None]:
        """Read and authenticate the checkpoint.

        Returns (status, state) where status is:
            "ok"      — checkpoint present and MAC valid
            "missing" — no checkpoint file (legacy log or first run)
            "invalid" — checkpoint unreadable or MAC mismatch
        """
        try:
            with open(self._state_path, "r", encoding="utf-8") as f:
                state = json.load(f)
        except FileNotFoundError:
            return "missing", None
        except (json.JSONDecodeError, OSError):
            return "invalid", None

        if not isinstance(state, dict):
            return "invalid", None
        event_id = state.get("event_id")
        entry_hash = state.get("hash")
        mac = state.get("mac")
        if not (isinstance(event_id, str) and isinstance(entry_hash, str)):
            return "invalid", None
        import hmac as hmac_mod

        expected = self._state_mac(event_id, entry_hash)
        if not (isinstance(mac, str) and hmac_mod.compare_digest(mac, expected)):
            return "invalid", None
        return "ok", {"event_id": event_id, "hash": entry_hash}

    def _read_last_hash_from_disk(self) -> str:
        """Read the hash of the last entry from disk. Used at init only."""
        try:
            with open(self._path, "rb") as f:
                # Seek to end, then scan backwards for the last newline
                f.seek(0, 2)
                size = f.tell()
                if size == 0:
                    return "genesis"
                # Read last 4KB — enough to contain the last JSON line
                read_size = min(4096, size)
                f.seek(size - read_size)
                chunk = f.read().decode("utf-8", errors="replace")
                lines = chunk.strip().split("\n")
                if lines:
                    last = json.loads(lines[-1])
                    return last.get("hash", "genesis")
        except (FileNotFoundError, json.JSONDecodeError, KeyError):
            pass
        return "genesis"

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
        """Read the highest event counter from the last log entry.

        Parsing the last entry's event_id (rather than counting lines)
        ensures monotonicity even if earlier entries are lost to
        truncation, rotation, or corruption.
        """
        try:
            with open(self._path, "rb") as f:
                f.seek(0, 2)
                size = f.tell()
                if size == 0:
                    return 0
                read_size = min(4096, size)
                f.seek(size - read_size)
                chunk = f.read().decode("utf-8", errors="replace")
                lines = chunk.strip().split("\n")
                if lines:
                    last = json.loads(lines[-1])
                    event_id = last.get("event_id", "")
                    # event_id format: "evt_000042"
                    if event_id.startswith("evt_"):
                        return int(event_id[4:])
        except (FileNotFoundError, json.JSONDecodeError, KeyError, ValueError):
            pass
        return 0
