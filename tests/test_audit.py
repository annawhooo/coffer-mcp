"""Tests for the audit logger and hash chain integrity."""

import json

import pytest

from alcove_mcp.audit.logger import AuditLogger


@pytest.fixture
def audit(tmp_path):
    """Create a temporary audit logger."""
    return AuditLogger(tmp_path / "audit.jsonl")


class TestAuditLogger:
    def test_log_creates_event(self, audit):
        """Logging an event should create an entry."""
        event = audit.log("credential.created", "test-api", "success")

        assert event.event_type == "credential.created"
        assert event.alias == "test-api"
        assert event.status == "success"
        assert event.event_id == "evt_000001"

    def test_chain_integrity_valid(self, audit):
        """A clean audit log should pass integrity verification."""
        audit.log("credential.created", "api-1")
        audit.log("credential.used", "api-1")
        audit.log("credential.removed", "api-1")

        is_valid, count, message = audit.verify_chain()
        assert is_valid is True
        assert count == 3
        assert "VALID" in message

    def test_chain_detects_tamper(self, audit):
        """Modifying an entry should break the hash chain."""
        audit.log("credential.created", "api-1")
        audit.log("credential.used", "api-1")

        # Tamper with the log file
        with open(audit._path, "r") as f:
            lines = f.readlines()

        # Modify the first entry
        entry = json.loads(lines[0])
        entry["alias"] = "tampered-alias"
        lines[0] = json.dumps(entry) + "\n"

        with open(audit._path, "w") as f:
            f.writelines(lines)

        is_valid, count, message = audit.verify_chain()
        assert is_valid is False
        assert "hash mismatch" in message.lower() or "broken" in message.lower()

    def test_empty_log_is_valid(self, audit):
        """An empty audit log should pass verification."""
        is_valid, count, message = audit.verify_chain()
        assert is_valid is True
        assert count == 0

    def test_genesis_hash(self, audit):
        """The first event should reference 'genesis' as prev_hash."""
        event = audit.log("credential.created", "first")
        assert event.prev_hash == "genesis"

    def test_hash_chain_linkage(self, audit):
        """Each event's prev_hash should match the previous event's hash."""
        evt1 = audit.log("credential.created", "api-1")
        evt2 = audit.log("credential.used", "api-1")
        evt3 = audit.log("credential.removed", "api-1")

        assert evt2.prev_hash == evt1.hash
        assert evt3.prev_hash == evt2.hash

    def test_get_events_filtered(self, audit):
        """get_events should filter by alias when specified."""
        audit.log("credential.created", "api-1")
        audit.log("credential.created", "api-2")
        audit.log("credential.used", "api-1")

        events = audit.get_events(alias="api-1")
        assert len(events) == 2
        assert all(e["alias"] == "api-1" for e in events)

    def test_get_events_limit(self, audit):
        """get_events should respect the limit parameter."""
        for i in range(10):
            audit.log("credential.used", f"api-{i}")

        events = audit.get_events(limit=3)
        assert len(events) == 3

    def test_details_recorded(self, audit):
        """Extra details should be stored in the event."""
        event = audit.log(
            "credential.used",
            "api-1",
            details={"url": "https://api.example.com/data", "status_code": 200},
        )
        assert event.details["url"] == "https://api.example.com/data"
        assert event.details["status_code"] == 200
