"""Tests for coffer_exec (TB-7): allowlisted subprocess credential injection."""

import json
import os
import sys
import time

import pytest

from coffer_mcp.audit.logger import AuditLogger
from coffer_mcp.security import check_command_allowed
from coffer_mcp.store.encrypted_store import CredentialEntry, EncryptedStore
from coffer_mcp.tools.vault_exec import vault_exec

PYTHON = sys.executable  # absolute path to the running interpreter


@pytest.fixture
def store(tmp_path):
    return EncryptedStore(os.urandom(32), store_path=tmp_path / "credentials.json")


@pytest.fixture
def audit(tmp_path):
    return AuditLogger(tmp_path / "audit.jsonl", hmac_key=os.urandom(32), source="mcp")


@pytest.fixture
def env_script(tmp_path):
    """Child script that reports whether the credential env vars arrived."""
    script = tmp_path / "child_env.py"
    script.write_text(
        "import os\n"
        "print('USER=' + os.environ.get('COFFER_USERNAME', 'MISSING'))\n"
        "print('SECRET_LEN=' + str(len(os.environ.get('COFFER_SECRET', ''))))\n",
        encoding="utf-8",
    )
    return str(script)


@pytest.fixture
def echo_secret_script(tmp_path):
    """Child script that (badly) prints the secret to stdout."""
    script = tmp_path / "child_echo.py"
    script.write_text(
        "import os\nprint('leaked: ' + os.environ.get('COFFER_SECRET', ''))\n",
        encoding="utf-8",
    )
    return str(script)


def _add_cred(store, alias="exec-cred", secret="s3cret-value-123", expires_at=None):
    store.add(
        CredentialEntry(
            alias=alias,
            auth_type="web_login",
            username="user@example.com",
            secret=secret,
            allowed_urls=["https://example.com/*"],
            expires_at=expires_at,
        )
    )


class TestCheckCommandAllowed:
    def _entry(self, commands):
        return CredentialEntry(
            alias="x", auth_type="web_login", secret="s", allowed_commands=commands
        )

    def test_empty_allowlist_fails_closed(self):
        entry = self._entry([])
        assert check_command_allowed(entry, [PYTHON, "x.py"]) is None

    def test_exact_match_allowed(self):
        cmd = {"argv": [PYTHON, "x.py", "--flag"], "cwd": None}
        entry = self._entry([cmd])
        assert check_command_allowed(entry, [PYTHON, "x.py", "--flag"]) == cmd

    def test_extra_argument_rejected(self):
        entry = self._entry([{"argv": [PYTHON, "x.py"], "cwd": None}])
        assert check_command_allowed(entry, [PYTHON, "x.py", "--extra"]) is None

    def test_missing_argument_rejected(self):
        entry = self._entry([{"argv": [PYTHON, "x.py", "--flag"], "cwd": None}])
        assert check_command_allowed(entry, [PYTHON, "x.py"]) is None

    def test_relative_argv0_rejected(self):
        entry = self._entry([{"argv": ["python", "x.py"], "cwd": None}])
        assert check_command_allowed(entry, ["python", "x.py"]) is None

    def test_non_string_argv_rejected(self):
        entry = self._entry([{"argv": [PYTHON, "x.py"], "cwd": None}])
        assert check_command_allowed(entry, [PYTHON, 42]) is None
        assert check_command_allowed(entry, "not-a-list") is None
        assert check_command_allowed(entry, []) is None


class TestAllowedCommandsStorage:
    def test_add_and_round_trip(self, store):
        _add_cred(store)
        count = store.add_allowed_command("exec-cred", [PYTHON, "x.py"], cwd=None)
        assert count == 1
        entry = store.get("exec-cred")
        assert entry.allowed_commands == [{"argv": [PYTHON, "x.py"], "cwd": None}]

    def test_duplicate_not_added_twice(self, store):
        _add_cred(store)
        store.add_allowed_command("exec-cred", [PYTHON, "x.py"])
        count = store.add_allowed_command("exec-cred", [PYTHON, "x.py"])
        assert count == 1

    def test_allowlist_is_encrypted_on_disk(self, store, tmp_path):
        """The allowlist must live in the ciphertext, not plaintext metadata."""
        _add_cred(store)
        store.add_allowed_command("exec-cred", [PYTHON, "sekrit_script.py"])
        raw = store._path.read_text(encoding="utf-8")
        assert "sekrit_script" not in raw

    def test_validation(self, store):
        _add_cred(store)
        with pytest.raises(ValueError, match="absolute"):
            store.add_allowed_command("exec-cred", ["python", "x.py"])
        with pytest.raises(ValueError, match="absolute"):
            store.add_allowed_command("exec-cred", [PYTHON, "x.py"], cwd="relative/dir")
        with pytest.raises(ValueError):
            store.add_allowed_command("exec-cred", [])
        with pytest.raises(KeyError):
            store.add_allowed_command("nope", [PYTHON, "x.py"])


class TestVaultExec:
    async def test_not_allowlisted_denied_and_audited(self, store, audit, env_script):
        _add_cred(store)
        result = await vault_exec(store, audit, "exec-cred", [PYTHON, env_script])
        assert result["code"] == "COMMAND_NOT_ALLOWED"

        events = audit.get_events(limit=5)
        denied = [e for e in events if e["event_type"] == "credential.access_denied"]
        assert len(denied) == 1
        assert denied[0]["details"]["reason"] == "command_not_allowed"

    async def test_allowlisted_runs_with_env_credential(self, store, audit, env_script):
        _add_cred(store, secret="s3cret-value-123")
        store.add_allowed_command("exec-cred", [PYTHON, env_script])

        result = await vault_exec(
            store, audit, "exec-cred", [PYTHON, env_script], reason="test run"
        )
        assert result["status"] == "ok"
        assert result["exit_code"] == 0
        assert "USER=user@example.com" in result["stdout"]
        assert f"SECRET_LEN={len('s3cret-value-123')}" in result["stdout"]

        events = audit.get_events(limit=5)
        execs = [e for e in events if e["event_type"] == "credential.exec"]
        assert len(execs) == 1
        assert execs[0]["status"] == "success"
        assert execs[0]["details"]["exit_code"] == 0
        assert execs[0]["details"]["agent_reason"] == "test run"

    async def test_secret_scrubbed_from_output(self, store, audit, echo_secret_script):
        secret = "super-unique-secret-98765"
        _add_cred(store, secret=secret)
        store.add_allowed_command("exec-cred", [PYTHON, echo_secret_script])

        result = await vault_exec(store, audit, "exec-cred", [PYTHON, echo_secret_script])
        assert result["exit_code"] == 0
        assert secret not in result["stdout"]
        assert "[REDACTED]" in result["stdout"]

    async def test_nonzero_exit_code_propagates(self, store, audit, tmp_path):
        script = tmp_path / "fail.py"
        script.write_text("import sys\nsys.exit(3)\n", encoding="utf-8")
        _add_cred(store)
        store.add_allowed_command("exec-cred", [PYTHON, str(script)])

        result = await vault_exec(store, audit, "exec-cred", [PYTHON, str(script)])
        assert result["status"] == "ok"
        assert result["exit_code"] == 3
        events = audit.get_events(limit=5)
        execs = [e for e in events if e["event_type"] == "credential.exec"]
        assert execs[0]["status"] == "failure"

    async def test_timeout_kills_process(self, store, audit, tmp_path):
        script = tmp_path / "slow.py"
        script.write_text("import time\ntime.sleep(60)\n", encoding="utf-8")
        _add_cred(store)
        store.add_allowed_command("exec-cred", [PYTHON, str(script)])

        started = time.monotonic()
        result = await vault_exec(
            store, audit, "exec-cred", [PYTHON, str(script)], timeout_s=1
        )
        elapsed = time.monotonic() - started
        assert result["code"] == "EXEC_TIMEOUT"
        assert elapsed < 30  # killed, not waited out

        events = audit.get_events(limit=5)
        execs = [e for e in events if e["event_type"] == "credential.exec"]
        assert execs[0]["details"]["reason"] == "timeout"

    async def test_spawn_failure_reported(self, store, audit, tmp_path):
        missing = str(tmp_path / "does_not_exist.exe")
        _add_cred(store)
        store.add_allowed_command("exec-cred", [missing])

        result = await vault_exec(store, audit, "exec-cred", [missing])
        assert result["code"] == "EXEC_FAILED"

    async def test_cwd_from_allowlist_honored(self, store, audit, tmp_path):
        workdir = tmp_path / "workdir"
        workdir.mkdir()
        script = tmp_path / "cwd.py"
        script.write_text("import os\nprint(os.getcwd())\n", encoding="utf-8")
        _add_cred(store)
        store.add_allowed_command("exec-cred", [PYTHON, str(script)], cwd=str(workdir))

        result = await vault_exec(store, audit, "exec-cred", [PYTHON, str(script)])
        assert result["exit_code"] == 0
        assert os.path.normcase(result["stdout"].strip()) == os.path.normcase(str(workdir))

    async def test_expired_credential_rejected(self, store, audit, env_script):
        _add_cred(store, expires_at=1000.0)
        store.add_allowed_command("exec-cred", [PYTHON, env_script])

        result = await vault_exec(store, audit, "exec-cred", [PYTHON, env_script])
        assert result["code"] == "CREDENTIAL_EXPIRED"

    async def test_unknown_alias(self, store, audit):
        result = await vault_exec(store, audit, "nope", [PYTHON, "x.py"])
        assert result["code"] == "CREDENTIAL_NOT_FOUND"


class TestServerTool:
    @pytest.fixture
    def server(self, monkeypatch, tmp_path):
        from coffer_mcp import server as server_mod
        from coffer_mcp.ratelimit import RateLimiter

        store = EncryptedStore(os.urandom(32), store_path=tmp_path / "creds.json")
        audit = AuditLogger(tmp_path / "audit.jsonl", hmac_key=os.urandom(32), source="mcp")
        monkeypatch.setattr(server_mod, "_store", store)
        monkeypatch.setattr(server_mod, "_audit", audit)
        monkeypatch.setattr(
            server_mod, "_rate_limiter", RateLimiter(max_requests=3, window_seconds=60)
        )
        return server_mod

    async def test_invalid_json_argv(self, server):
        result = json.loads(await server.coffer_exec("x", "not json"))
        assert result["code"] == "INVALID_JSON"

    async def test_rate_limited(self, server):
        for _ in range(3):
            await server.coffer_exec("x", json.dumps([PYTHON, "y.py"]))
        result = json.loads(await server.coffer_exec("x", json.dumps([PYTHON, "y.py"])))
        assert result["code"] == "RATE_LIMITED"

    async def test_end_to_end_through_server(self, server, tmp_path):
        script = tmp_path / "ok.py"
        script.write_text("print('hello from child')\n", encoding="utf-8")
        server._store.add(
            CredentialEntry(
                alias="e2e", auth_type="web_login", username="u", secret="s3cret-value",
            )
        )
        server._store.add_allowed_command("e2e", [PYTHON, str(script)])

        result = json.loads(
            await server.coffer_exec("e2e", json.dumps([PYTHON, str(script)]))
        )
        assert result["status"] == "ok"
        assert "hello from child" in result["stdout"]
