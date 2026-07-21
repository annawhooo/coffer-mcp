"""Tests for the `coffer exec` CLI command (unattended coffer_exec)."""

import json
import os
import sys

import pytest
from click.testing import CliRunner

from coffer_mcp import cli
from coffer_mcp.audit.logger import AuditLogger
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
        CredentialEntry(
            alias="c1",
            auth_type="web_login",
            username="user@example.com",
            secret="s3cret-value-123",
        )
    )
    return "c1"


def _script(tmp_path, name, body):
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return str(p)


class TestExecCli:
    def test_runs_allowlisted_command_with_env(self, runner, store, cred, tmp_path):
        s = _script(
            tmp_path,
            "env.py",
            "import os\nprint('U=' + os.environ.get('COFFER_USERNAME',''))\n"
            "print('L=' + str(len(os.environ.get('COFFER_SECRET',''))))\n",
        )
        store.add_allowed_command("c1", [PYTHON, s])

        result = runner.invoke(cli.main, ["exec", "c1", "--argv-json", json.dumps([PYTHON, s])])
        assert result.exit_code == 0
        assert "U=user@example.com" in result.output
        assert "L=16" in result.output

    def test_not_allowlisted_exits_2(self, runner, cred, tmp_path):
        s = _script(tmp_path, "x.py", "print('hi')\n")
        result = runner.invoke(cli.main, ["exec", "c1", "--argv-json", json.dumps([PYTHON, s])])
        assert result.exit_code == 2
        assert "COMMAND_NOT_ALLOWED" in result.output

    def test_child_exit_code_propagates(self, runner, store, cred, tmp_path):
        """Scheduled jobs branch on the exit code, so it must pass through."""
        s = _script(tmp_path, "fail.py", "import sys\nsys.exit(7)\n")
        store.add_allowed_command("c1", [PYTHON, s])

        result = runner.invoke(cli.main, ["exec", "c1", "--argv-json", json.dumps([PYTHON, s])])
        assert result.exit_code == 7

    def test_secret_scrubbed_from_output(self, runner, store, cred, tmp_path):
        s = _script(
            tmp_path, "leak.py", "import os\nprint('leaked ' + os.environ['COFFER_SECRET'])\n"
        )
        store.add_allowed_command("c1", [PYTHON, s])

        result = runner.invoke(cli.main, ["exec", "c1", "--argv-json", json.dumps([PYTHON, s])])
        assert "s3cret-value-123" not in result.output
        assert "[REDACTED]" in result.output

    def test_quiet_suppresses_output_but_keeps_exit_code(self, runner, store, cred, tmp_path):
        s = _script(tmp_path, "noisy.py", "import sys\nprint('chatter')\nsys.exit(3)\n")
        store.add_allowed_command("c1", [PYTHON, s])

        result = runner.invoke(
            cli.main, ["exec", "c1", "--argv-json", json.dumps([PYTHON, s]), "--quiet"]
        )
        assert result.exit_code == 3
        assert "chatter" not in result.output

    def test_invocation_is_audited(self, runner, store, audit, cred, tmp_path):
        s = _script(tmp_path, "ok.py", "print('ok')\n")
        store.add_allowed_command("c1", [PYTHON, s])

        runner.invoke(
            cli.main,
            ["exec", "c1", "--argv-json", json.dumps([PYTHON, s]), "--reason", "scheduled check"],
        )
        events = audit.get_events(limit=5)
        execs = [e for e in events if e["event_type"] == "credential.exec"]
        assert len(execs) == 1
        assert execs[0]["details"]["agent_reason"] == "scheduled check"
        assert execs[0]["details"]["exit_code"] == 0

    def test_bad_json_exits_2(self, runner, cred):
        result = runner.invoke(cli.main, ["exec", "c1", "--argv-json", "{nope"])
        assert result.exit_code == 2
        assert "not valid JSON" in result.output

    def test_unknown_alias_exits_2(self, runner, tmp_path):
        s = _script(tmp_path, "x.py", "print('hi')\n")
        result = runner.invoke(cli.main, ["exec", "nope", "--argv-json", json.dumps([PYTHON, s])])
        assert result.exit_code == 2
        assert "CREDENTIAL_NOT_FOUND" in result.output

    def test_timeout_exits_2(self, runner, store, cred, tmp_path):
        s = _script(tmp_path, "slow.py", "import time\ntime.sleep(30)\n")
        store.add_allowed_command("c1", [PYTHON, s])

        result = runner.invoke(
            cli.main, ["exec", "c1", "--argv-json", json.dumps([PYTHON, s]), "--timeout", "1"]
        )
        assert result.exit_code == 2
        assert "EXEC_TIMEOUT" in result.output
