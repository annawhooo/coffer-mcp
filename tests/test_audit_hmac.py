"""Tests for HMAC-keyed audit chain integrity."""

import json
import os

import pytest

from coffer_mcp.audit.logger import AuditLogger


@pytest.fixture
def hmac_key():
    return os.urandom(32)


@pytest.fixture
def audit_hmac(tmp_path, hmac_key):
    """Audit logger with HMAC key."""
    return AuditLogger(tmp_path / "audit.jsonl", hmac_key=hmac_key)


@pytest.fixture
def audit_no_key(tmp_path):
    """Audit logger without HMAC key (backward compat)."""
    return AuditLogger(tmp_path / "audit_nokey.jsonl")


class TestHmacAuditChain:
    def test_hmac_chain_valid(self, audit_hmac):
        """HMAC-keyed chain should pass verification."""
        audit_hmac.log("credential.created", "api-1")
        audit_hmac.log("credential.used", "api-1")
        audit_hmac.log("credential.removed", "api-1")

        is_valid, count, message = audit_hmac.verify_chain()
        assert is_valid is True
        assert count == 3

    def test_tamper_detected_with_hmac(self, audit_hmac):
        """Tampering should be detected even if attacker recomputes SHA-256."""
        audit_hmac.log("credential.created", "api-1")
        audit_hmac.log("credential.used", "api-1")

        # Tamper: change the alias and recompute bare SHA-256 (no HMAC key)
        import hashlib
        with open(audit_hmac._path, "r") as f:
            lines = f.readlines()

        entry = json.loads(lines[0])
        entry["alias"] = "tampered"
        # Recompute hash WITHOUT the HMAC key (attacker doesn't have it)
        entry_no_hash = {k: v for k, v in entry.items() if k != "hash"}
        canonical = json.dumps(entry_no_hash, sort_keys=True, separators=(",", ":"))
        entry["hash"] = hashlib.sha256(canonical.encode()).hexdigest()
        lines[0] = json.dumps(entry) + "\n"

        with open(audit_hmac._path, "w") as f:
            f.writelines(lines)

        is_valid, _, message = audit_hmac.verify_chain()
        assert is_valid is False

    def test_backward_compat_no_key(self, audit_no_key):
        """Logger without HMAC key should still work (bare SHA-256)."""
        audit_no_key.log("credential.created", "api-1")
        audit_no_key.log("credential.used", "api-1")

        is_valid, count, message = audit_no_key.verify_chain()
        assert is_valid is True
        assert count == 2

    def test_different_keys_produce_different_hashes(self, tmp_path):
        """Two loggers with different HMAC keys should produce different hashes."""
        key_a = os.urandom(32)
        key_b = os.urandom(32)

        logger_a = AuditLogger(tmp_path / "a.jsonl", hmac_key=key_a)
        logger_b = AuditLogger(tmp_path / "b.jsonl", hmac_key=key_b)

        evt_a = logger_a.log("credential.created", "test")
        evt_b = logger_b.log("credential.created", "test")

        # Same event content, different keys = different hashes
        assert evt_a.hash != evt_b.hash

    def test_wrong_key_fails_verification(self, tmp_path):
        """Verifying a chain with the wrong HMAC key should fail."""
        key_original = os.urandom(32)
        key_wrong = os.urandom(32)

        logger = AuditLogger(tmp_path / "chain.jsonl", hmac_key=key_original)
        logger.log("credential.created", "api-1")
        logger.log("credential.used", "api-1")

        # Try to verify with a different key
        verifier = AuditLogger(tmp_path / "chain.jsonl", hmac_key=key_wrong)
        is_valid, _, message = verifier.verify_chain()
        assert is_valid is False
