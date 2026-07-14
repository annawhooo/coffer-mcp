"""Tests for RR-H5: audit log truncation detection via HMAC-protected checkpoint."""

import json
import os

import pytest

from coffer_mcp.audit.logger import AuditLogger


@pytest.fixture
def hmac_key():
    return os.urandom(32)


@pytest.fixture
def audit(tmp_path, hmac_key):
    return AuditLogger(tmp_path / "audit.jsonl", hmac_key=hmac_key)


def _truncate_last_line(path):
    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    with open(path, "w", encoding="utf-8") as f:
        f.writelines(lines[:-1])


class TestTruncationDetection:
    def test_intact_log_with_checkpoint_verifies(self, audit):
        audit.log("credential.created", "api-1")
        audit.log("credential.used", "api-1")
        audit.log("credential.removed", "api-1")

        is_valid, count, message = audit.verify_chain()
        assert is_valid is True
        assert count == 3

    def test_checkpoint_file_created_on_log(self, audit):
        audit.log("credential.created", "api-1")
        assert audit._state_path.exists()
        state = json.loads(audit._state_path.read_text(encoding="utf-8"))
        assert state["event_id"] == "evt_000001"
        assert "hash" in state
        assert "mac" in state

    def test_tail_truncation_detected(self, audit):
        """Deleting the last entry must break verification even though the
        remaining chain is internally consistent."""
        audit.log("credential.created", "api-1")
        audit.log("credential.used", "api-1")
        audit.log("credential.removed", "api-1")

        _truncate_last_line(audit._path)

        is_valid, _, message = audit.verify_chain()
        assert is_valid is False
        assert "truncat" in message.lower()

    def test_multi_entry_truncation_detected(self, audit):
        for _ in range(5):
            audit.log("credential.used", "api-1")
        _truncate_last_line(audit._path)
        _truncate_last_line(audit._path)
        _truncate_last_line(audit._path)

        is_valid, _, message = audit.verify_chain()
        assert is_valid is False

    def test_full_wipe_detected(self, audit):
        """Emptying the log entirely while a checkpoint exists is truncation,
        not a legitimately empty log."""
        audit.log("credential.created", "api-1")
        audit._path.write_text("", encoding="utf-8")

        is_valid, _, message = audit.verify_chain()
        assert is_valid is False

    def test_tampered_checkpoint_detected(self, audit):
        audit.log("credential.created", "api-1")
        audit.log("credential.used", "api-1")

        state = json.loads(audit._state_path.read_text(encoding="utf-8"))
        state["event_id"] = "evt_000001"  # roll checkpoint back without valid mac
        audit._state_path.write_text(json.dumps(state), encoding="utf-8")

        is_valid, _, message = audit.verify_chain()
        assert is_valid is False
        assert "checkpoint" in message.lower()

    def test_missing_checkpoint_warns_but_verifies(self, audit):
        """Legacy logs (or a deleted state file) can't prove absence of
        truncation. Chain still verifies, but the message must say detection
        is unavailable."""
        audit.log("credential.created", "api-1")
        audit._state_path.unlink()

        is_valid, count, message = audit.verify_chain()
        assert is_valid is True
        assert count == 1
        assert "checkpoint" in message.lower()

    def test_checkpoint_heals_on_next_append(self, audit):
        audit.log("credential.created", "api-1")
        audit._state_path.unlink()
        audit.log("credential.used", "api-1")

        is_valid, count, message = audit.verify_chain()
        assert is_valid is True
        assert count == 2
        assert audit._state_path.exists()

    def test_crash_window_tolerated(self, audit):
        """If the process crashed after appending an entry but before updating
        the checkpoint, the log is one entry ahead of the checkpoint. That
        exact successor case must verify."""
        audit.log("credential.created", "api-1")
        stale_state = audit._state_path.read_text(encoding="utf-8")
        audit.log("credential.used", "api-1")
        audit._state_path.write_text(stale_state, encoding="utf-8")

        is_valid, count, message = audit.verify_chain()
        assert is_valid is True
        assert count == 2

    def test_stale_checkpoint_beyond_crash_window_detected(self, audit):
        """A checkpoint more than one entry behind the log tail is not a
        legitimate crash window — the state file must advance with the log.

        (Note the converse — an attacker who both truncates the log AND
        replays a captured old checkpoint that matches the truncated tail —
        is undetectable by design and documented as a residual risk. Defeating
        replay requires an anchor outside the attacker's write access.)
        """
        audit.log("credential.created", "api-1")
        stale_state = audit._state_path.read_text(encoding="utf-8")
        audit.log("credential.used", "api-1")
        audit.log("credential.removed", "api-1")
        audit._state_path.write_text(stale_state, encoding="utf-8")

        is_valid, _, message = audit.verify_chain()
        assert is_valid is False

    def test_empty_log_no_checkpoint_is_valid(self, tmp_path, hmac_key):
        logger = AuditLogger(tmp_path / "fresh.jsonl", hmac_key=hmac_key)
        is_valid, count, _ = logger.verify_chain()
        assert is_valid is True
        assert count == 0

    def test_no_hmac_key_checkpoint_still_functions(self, tmp_path):
        """Without an HMAC key the checkpoint uses bare SHA-256 (same
        weakened-but-working behavior as the chain itself)."""
        logger = AuditLogger(tmp_path / "nokey.jsonl")
        logger.log("credential.created", "api-1")
        logger.log("credential.used", "api-1")
        _truncate_last_line(logger._path)

        is_valid, _, message = logger.verify_chain()
        assert is_valid is False
