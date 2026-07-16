"""Tests for revoking coffer_exec permissions (deny-command / list-commands)."""

import os
import sys

import pytest
from click.testing import CliRunner

from coffer_mcp import cli
from coffer_mcp.audit.logger import AuditLogger
from coffer_mcp.security import check_command_allowed
from coffer_mcp.store.encrypted_store import CredentialEntry, EncryptedStore

PYTHON = sys.executable


@pytest.fixture
def store(tmp_path):
    return EncryptedStore(os.urandom(32), store_path=tmp_path / "credentials.json")


@pytest.fixture
def audit(tmp_path):
    return AuditLogger(tmp_path / "audit.jsonl", hmac_key=os.urandom(32), source="cli")


@pytest.fixture
def runner(monkeypatch, store, audit):
    monkeypatch.setattr(cli, "_get_store", lambda: store)
    monkeypatch.setattr(cli, "_get_audit", lambda: audit)
    return CliRunner()


@pytest.fixture
def cred(store):
    store.add(
        CredentialEntry(alias="c1", auth_type="web_login", username="u", secret="s3cret-value")
    )
    store.add_allowed_command("c1", [PYTHON, "a.py"], cwd="/tmp")
    store.add_allowed_command("c1", [PYTHON, "b.py", "--flag"])
    return "c1"


class TestRemoveAllowedCommand:
    def test_remove_one(self, store, cred):
        removed = store.remove_allowed_command("c1", argv=[PYTHON, "a.py"])
        assert removed == 1
        remaining = store.list_allowed_commands("c1")
        assert remaining == [{"argv": [PYTHON, "b.py", "--flag"], "cwd": None}]

    def test_removed_command_is_actually_denied(self, store, cred):
        """The revoked command must stop passing the allowlist check."""
        entry = store.get("c1")
        assert check_command_allowed(entry, [PYTHON, "a.py"]) is not None

        store.remove_allowed_command("c1", argv=[PYTHON, "a.py"])
        entry = store.get("c1")
        assert check_command_allowed(entry, [PYTHON, "a.py"]) is None
        assert check_command_allowed(entry, [PYTHON, "b.py", "--flag"]) is not None

    def test_remove_all(self, store, cred):
        removed = store.remove_allowed_command("c1", all=True)
        assert removed == 2
        assert store.list_allowed_commands("c1") == []
        entry = store.get("c1")
        assert check_command_allowed(entry, [PYTHON, "a.py"]) is None

    def test_remove_matches_argv_regardless_of_cwd(self, store, cred):
        """a.py was added with cwd=/tmp; revoking by argv alone must work."""
        assert store.remove_allowed_command("c1", argv=[PYTHON, "a.py"]) == 1

    def test_remove_nonmatching_is_noop(self, store, cred):
        assert store.remove_allowed_command("c1", argv=[PYTHON, "nope.py"]) == 0
        assert len(store.list_allowed_commands("c1")) == 2

    def test_secret_survives_revocation(self, store, cred):
        """Revoking must not disturb the credential itself."""
        store.remove_allowed_command("c1", all=True)
        assert store.get("c1").secret == "s3cret-value"

    def test_unknown_alias(self, store):
        with pytest.raises(KeyError):
            store.remove_allowed_command("nope", argv=[PYTHON, "a.py"])

    def test_requires_argv_or_all(self, store, cred):
        with pytest.raises(ValueError):
            store.remove_allowed_command("c1")


class TestDenyCommandCli:
    def test_deny_one(self, runner, store, cred, audit):
        import json

        result = runner.invoke(
            cli.main,
            ["deny-command", "c1", "--argv-json", json.dumps([PYTHON, "a.py"])],
        )
        assert result.exit_code == 0
        assert "Revoked 1 command" in result.output
        assert len(store.list_allowed_commands("c1")) == 1

        events = audit.get_events(limit=5)
        assert any(e["event_type"] == "credential.command_denied" for e in events)

    def test_deny_all(self, runner, store, cred):
        result = runner.invoke(cli.main, ["deny-command", "c1", "--all"])
        assert result.exit_code == 0
        assert "Revoked 2 command" in result.output
        assert store.list_allowed_commands("c1") == []

    def test_deny_requires_target(self, runner, cred):
        result = runner.invoke(cli.main, ["deny-command", "c1"])
        assert result.exit_code == 1
        assert "--argv-json" in result.output

    def test_deny_nonmatching_reports_noop(self, runner, cred):
        import json

        result = runner.invoke(
            cli.main, ["deny-command", "c1", "--argv-json", json.dumps([PYTHON, "zz.py"])]
        )
        assert result.exit_code == 0
        assert "nothing changed" in result.output

    def test_deny_bad_json(self, runner, cred):
        result = runner.invoke(cli.main, ["deny-command", "c1", "--argv-json", "{oops"])
        assert result.exit_code == 1
        assert "not valid JSON" in result.output

    def test_deny_unknown_alias(self, runner):
        import json

        result = runner.invoke(
            cli.main, ["deny-command", "nope", "--argv-json", json.dumps([PYTHON, "a.py"])]
        )
        assert result.exit_code == 1


class TestListCommandsCli:
    def test_list(self, runner, cred):
        result = runner.invoke(cli.main, ["list-commands", "c1"])
        assert result.exit_code == 0
        assert "2 command(s)" in result.output
        assert "a.py" in result.output
        assert "b.py" in result.output

    def test_list_empty_warns_fail_closed(self, runner, store):
        store.add(CredentialEntry(alias="bare", auth_type="bearer_token", secret="x"))
        result = runner.invoke(cli.main, ["list-commands", "bare"])
        assert result.exit_code == 0
        assert "no allowed commands" in result.output

    def test_list_unknown_alias(self, runner):
        result = runner.invoke(cli.main, ["list-commands", "nope"])
        assert result.exit_code == 1
