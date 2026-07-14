"""
coffer_exec — run a pre-allowlisted local command with the credential
injected into the child process environment (TB-7).

The credential leaves the server process by design: the user decides,
at allowlist-add time, exactly which command may receive which
credential. The LLM can only trigger an exact allowlisted invocation —
it cannot choose the binary, arguments, working directory, or the
environment variable names.

Security properties (see THREAT_MODEL.md §3.7):
- Exact argv match against the encrypted, integrity-protected
  allowlist; argv[0] absolute; fail-closed when the allowlist is empty.
- Credential passed via child env only (COFFER_USERNAME /
  COFFER_SECRET) — never argv, never temp files.
- Fixed per-command cwd from the allowlist, not LLM-settable.
- Wall-clock timeout with kill; output truncated and scrubbed with
  sanitize_response() before returning to the LLM.
- Every invocation (allowed or rejected) is audited.
"""

from __future__ import annotations

import asyncio
import os
import time
from typing import Any

from coffer_mcp.audit import AuditLogger
from coffer_mcp.errors import (
    COMMAND_NOT_ALLOWED,
    CREDENTIAL_EXPIRED,
    CREDENTIAL_NOT_FOUND,
    EXEC_FAILED,
    EXEC_TIMEOUT,
    error_response,
)
from coffer_mcp.secmem import wipe_entry
from coffer_mcp.security import check_command_allowed, sanitize_response
from coffer_mcp.store import EncryptedStore

# Environment variable names the child receives. Fixed — not LLM-settable.
ENV_USERNAME = "COFFER_USERNAME"
ENV_SECRET = "COFFER_SECRET"

DEFAULT_TIMEOUT_S = 300
MAX_TIMEOUT_S = 3600
MAX_OUTPUT_CHARS = 20_000


def _clamp_timeout(timeout_s: Any) -> int:
    try:
        return max(1, min(int(timeout_s), MAX_TIMEOUT_S))
    except (TypeError, ValueError):
        return DEFAULT_TIMEOUT_S


async def vault_exec(
    store: EncryptedStore,
    audit: AuditLogger,
    alias: str,
    argv: list,
    timeout_s: int = DEFAULT_TIMEOUT_S,
    reason: str = "",
) -> dict:
    """Run an allowlisted command with the credential in its environment.

    Returns a result dict with exit_code and sanitized stdout/stderr,
    or a structured error response.
    """
    timeout_s = _clamp_timeout(timeout_s)

    # 1. Resolve credential
    try:
        entry = store.get(alias)
    except KeyError:
        audit.log(
            "credential.access_failed",
            alias,
            "failure",
            {"tool": "coffer_exec", "reason": "not_found", "agent_reason": reason},
        )
        return error_response(
            CREDENTIAL_NOT_FOUND, f"No credential found with alias '{alias}'"
        )

    # 2. Expiry check
    if entry.expires_at and time.time() > entry.expires_at:
        wipe_entry(entry)
        audit.log(
            "credential.expired",
            alias,
            "failure",
            {"tool": "coffer_exec", "agent_reason": reason},
        )
        return error_response(
            CREDENTIAL_EXPIRED,
            f"Credential '{alias}' has expired. "
            f"Ask the user to rotate it with: coffer rotate {alias}",
        )

    # 3. Command allowlist (exact argv match, fail-closed)
    match = check_command_allowed(entry, argv)
    if match is None:
        wipe_entry(entry)
        audit.log(
            "credential.access_denied",
            alias,
            "failure",
            {
                "tool": "coffer_exec",
                "reason": "command_not_allowed",
                "argv": argv if isinstance(argv, list) else str(argv),
                "agent_reason": reason,
            },
        )
        return error_response(
            COMMAND_NOT_ALLOWED,
            f"Command is not on the allowlist for credential '{alias}'. "
            "The exact argv must match an entry added with: coffer allow-command "
            f"{alias} (argv[0] must be an absolute path).",
        )

    # 4. Build child environment. The secret exists only in the child's
    # env and in `secret` (kept for output scrubbing, deleted after).
    env = os.environ.copy()
    env[ENV_USERNAME] = entry.username
    env[ENV_SECRET] = entry.secret
    cwd = match.get("cwd") or None

    started = time.monotonic()
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            env=env,
            cwd=cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.DEVNULL,
        )
    except (OSError, ValueError) as e:
        wipe_entry(entry)
        env[ENV_SECRET] = ""
        audit.log(
            "credential.exec",
            alias,
            "failure",
            {
                "tool": "coffer_exec",
                "reason": "spawn_failed",
                "argv": argv,
                "agent_reason": reason,
            },
        )
        return error_response(EXEC_FAILED, f"Failed to start process: {e}")

    timed_out = False
    try:
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
    except asyncio.TimeoutError:
        timed_out = True
        proc.kill()
        # Reap the killed process and collect whatever output exists.
        stdout_b, stderr_b = await proc.communicate()

    duration_ms = int((time.monotonic() - started) * 1000)

    # 5. Truncate, then scrub secrets from output before it reaches the LLM.
    # Scrub AFTER truncation could split a secret across the boundary and
    # miss it, so scrub first on a bounded slice (2x cap covers the split
    # risk at the final cut).
    stdout = stdout_b.decode("utf-8", errors="replace")[: MAX_OUTPUT_CHARS * 2]
    stderr = stderr_b.decode("utf-8", errors="replace")[: MAX_OUTPUT_CHARS * 2]
    stdout = sanitize_response(stdout, entry)[:MAX_OUTPUT_CHARS]
    stderr = sanitize_response(stderr, entry)[:MAX_OUTPUT_CHARS]
    wipe_entry(entry)
    env[ENV_SECRET] = ""

    if timed_out:
        audit.log(
            "credential.exec",
            alias,
            "failure",
            {
                "tool": "coffer_exec",
                "reason": "timeout",
                "argv": argv,
                "timeout_s": timeout_s,
                "duration_ms": duration_ms,
                "agent_reason": reason,
            },
        )
        return {
            **error_response(
                EXEC_TIMEOUT,
                f"Process killed after exceeding {timeout_s}s timeout.",
            ),
            "stdout": stdout,
            "stderr": stderr,
            "duration_ms": duration_ms,
        }

    audit.log(
        "credential.exec",
        alias,
        "success" if proc.returncode == 0 else "failure",
        {
            "tool": "coffer_exec",
            "argv": argv,
            "exit_code": proc.returncode,
            "duration_ms": duration_ms,
            "agent_reason": reason,
        },
    )

    return {
        "status": "ok",
        "exit_code": proc.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "duration_ms": duration_ms,
        "cwd": cwd,
    }
