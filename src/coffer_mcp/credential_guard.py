#!/usr/bin/env python3
"""
credential_guard.py: Prevents credential values from entering the chat context.

Validates MCP tool parameters for common secret patterns and rejects
calls that contain credential values. Designed for use in coffer-mcp's
tool handlers.

Usage in coffer-mcp tool handler:

    from credential_guard import check_for_secrets

    def handle_coffer_store(params):
        violation = check_for_secrets(params)
        if violation:
            return {
                "error": violation["error"],
                "details": violation["details"],
            }
        # proceed with alias-only operation...

The guard checks ALL string values in the params dict, including
nested dicts and lists. If any value matches a known secret pattern,
the call is rejected before the value reaches storage.
"""

import re
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Secret Patterns
# ---------------------------------------------------------------------------
# Each tuple: (name, compiled regex, description)
# These detect common credential formats. Not exhaustive, but catches
# the most common accidental exposure paths.

SECRET_PATTERNS = [
    (
        "GitHub PAT (classic)",
        re.compile(r"ghp_[A-Za-z0-9_]{36,}"),
        "GitHub personal access token (classic format)",
    ),
    (
        "GitHub PAT (fine-grained)",
        re.compile(r"github_pat_[A-Za-z0-9_]{22,}"),
        "GitHub personal access token (fine-grained format)",
    ),
    ("OpenAI API Key", re.compile(r"sk-[A-Za-z0-9]{20,}"), "OpenAI or Stripe secret key"),
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key ID"),
    # AWS secret access keys are 40 chars of base64 data. Real keys are 30
    # random bytes encoded to 40 chars with no padding -- so `=` never appears.
    # We require:
    #   - boundaries on both sides (run of base64-charset chars is exactly 40,
    #     not a longer substring of a URL path, a UUID segment, etc.)
    #   - at least one uppercase, one lowercase, and one digit inside the
    #     match -- random 30-byte base64 has all three with probability ~1;
    #     URL paths and hex UUIDs usually don't.
    (
        "AWS Secret Key",
        re.compile(
            r"(?<![A-Za-z0-9/+])"
            r"(?=[A-Za-z0-9/+]{0,39}[A-Z])"
            r"(?=[A-Za-z0-9/+]{0,39}[a-z])"
            r"(?=[A-Za-z0-9/+]{0,39}[0-9])"
            r"[A-Za-z0-9/+]{40}"
            r"(?![A-Za-z0-9/+])",
            re.ASCII,
        ),
        "Possible AWS secret access key (40-char base64)",
    ),
    (
        "Bearer Token",
        re.compile(r"Bearer\s+[A-Za-z0-9._\-]{20,}", re.IGNORECASE),
        "Bearer authentication token",
    ),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}"), "JSON Web Token"),
    ("Slack Token", re.compile(r"xox[bpsar]-[A-Za-z0-9-]{10,}"), "Slack API token"),
    ("Google API Key", re.compile(r"AIza[A-Za-z0-9_-]{35}"), "Google API key"),
    ("Azure Key", re.compile(r"[A-Za-z0-9/+=]{86}=="), "Possible Azure storage/service key"),
    (
        "Generic Long Secret",
        re.compile(
            r'(?:key|token|secret|password|credential|api_key|apikey)\s*[=:]\s*["\']?([A-Za-z0-9_\-./+=]{20,})',
            re.IGNORECASE,
        ),
        "Generic key=value secret pattern",
    ),
    (
        "Private Key Header",
        re.compile(r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----"),
        "PEM private key",
    ),
    (
        "Connection String",
        re.compile(r"(?:mongodb|postgres|mysql|redis|amqp)://\S+:\S+@", re.IGNORECASE),
        "Database/service connection string with embedded credentials",
    ),
]

# ---------------------------------------------------------------------------
# Guard Functions
# ---------------------------------------------------------------------------


def check_for_secrets(params: dict, param_name: str = None) -> dict | None:
    """
    Check a params dict for credential values.

    Recursively inspects all string values in the dict, including
    nested dicts and lists.

    Returns None if clean.
    Returns a violation dict if a secret is detected:
    {
        "error": "CREDENTIAL_VALUE_DETECTED",
        "details": "...",
        "pattern": "...",
        "param_path": "...",
    }
    """
    if params is None:
        return None

    if isinstance(params, str):
        return _check_string(params, param_name or "value")

    if isinstance(params, dict):
        for key, value in params.items():
            path = f"{param_name}.{key}" if param_name else key
            result = check_for_secrets(value, path)
            if result:
                return result

    if isinstance(params, list):
        for i, item in enumerate(params):
            path = f"{param_name}[{i}]" if param_name else f"[{i}]"
            result = check_for_secrets(item, path)
            if result:
                return result

    return None


def _check_string(value: str, path: str) -> dict | None:
    """Check a single string value against all secret patterns."""
    for name, pattern, description in SECRET_PATTERNS:
        if pattern.search(value):
            return {
                "error": "CREDENTIAL_VALUE_DETECTED",
                "details": (
                    f"A value matching '{name}' was detected in parameter '{path}'. "
                    f"Credential values must not be passed through the chat context. "
                    f"Use coffer_cli.py to load credentials out-of-band: "
                    f"python coffer_cli.py store --alias <name> --from-env <ENV_VAR>"
                ),
                "pattern": name,
                "param_path": path,
            }
    return None


def create_rejection_response(violation: dict) -> dict:
    """
    Create an MCP tool response that rejects the call and tells the
    agent how to do it correctly.
    """
    return {
        "content": [
            {
                "type": "text",
                "text": (
                    f"ERROR: {violation['error']}\n\n"
                    f"{violation['details']}\n\n"
                    f"This tool does not accept credential values as parameters. "
                    f"Credentials must be loaded out-of-band using one of:\n"
                    f"  1. python coffer_cli.py store --alias <name> --from-env <ENV_VAR>\n"
                    f"  2. python coffer_cli.py store --alias <name>  (interactive masked prompt)\n"
                    f"  3. python coffer_cli.py load --config credentials.yaml\n\n"
                    f"After loading, use the credential by alias only."
                ),
            }
        ],
        "isError": True,
    }


def log_violation(violation: dict, logger=None) -> dict:
    """
    Create an audit event for a credential exposure attempt.

    This records that a secret-shaped value was submitted through
    an MCP tool. The credential may now be in the conversation
    history regardless of whether coffer rejected it.
    """
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "credential_exposure_attempt",
        "severity": "HIGH",
        "pattern": violation["pattern"],
        "param_path": violation["param_path"],
        "note": (
            "A credential value was submitted through an MCP tool parameter. "
            "The value was REJECTED by credential_guard and was NOT stored. "
            "However, the value may exist in the conversation history and "
            "platform logs. The credential should be rotated."
        ),
    }

    if logger:
        logger.log(
            event_type="credential.exposure_attempt",
            alias="",
            status="failure",
            details=event,
        )

    return event


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("credential_guard self-test")
    print("=" * 50)

    # Should trigger
    test_cases_bad = [
        {"alias": "test", "value": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm"},
        {"alias": "test", "value": "sk-abc123def456ghi789jkl012mno345pqr"},
        {"alias": "test", "token": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"},
        {"alias": "test", "value": "AKIAIOSFODNN7EXAMPLE"},
        {"alias": "test", "config": {"nested": {"deep": "xoxb-123456789-abcdefghij"}}},
        {"alias": "test", "value": "-----BEGIN PRIVATE KEY-----"},
        {"alias": "test", "url": "postgres://admin:secretpass@db.example.com:5432/mydb"},
        {"alias": "test", "value": "github_pat_11AABBBCC22DDDEEEFFF33GGG"},
        {"alias": "test", "data": "api_key=EXAMPLE_00abc11def22ghi33jkl44mno55pqr"},
    ]

    # Should NOT trigger
    test_cases_good = [
        {"alias": "github-pat"},
        {"alias": "my-key", "allowlist": ["https://api.github.com/*"]},
        {"alias": "test", "action": "revoke"},
        {"alias": "rename-me", "new_alias": "renamed"},
        {"path": "/data/normal/report.txt"},
        {"name": "read_file", "arguments": {"path": "/data/file.txt"}},
    ]

    print("\nShould REJECT (credential detected):")
    for i, params in enumerate(test_cases_bad):
        result = check_for_secrets(params)
        status = "REJECTED" if result else "MISSED"
        pattern = result["pattern"] if result else "none"
        print(f"  {i + 1}. [{status}] {pattern}")
        if not result:
            print(f"     WARNING: False negative! Params: {params}")

    print("\nShould ACCEPT (no credential):")
    for i, params in enumerate(test_cases_good):
        result = check_for_secrets(params)
        status = "REJECTED" if result else "ACCEPTED"
        print(f"  {i + 1}. [{status}]", end="")
        if result:
            print(f" WARNING: False positive! Pattern: {result['pattern']}")
        else:
            print()

    print()
    print("Done.")
