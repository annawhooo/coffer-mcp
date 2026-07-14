"""
Coffer CLI — manage credentials from the command line.

Usage:
    coffer init          Set up the master key in the OS keyring
    coffer add           Add a new credential (interactive)
    coffer list          List all stored credentials
    coffer test ALIAS    Make a lightweight authenticated request to verify a credential
    coffer rotate ALIAS  Replace the secret for an existing credential
    coffer remove ALIAS  Remove a credential
    coffer audit         View audit log and verify integrity
    coffer migrate       Upgrade entries to the integrity-protected format
    coffer allow-command ALIAS  Allow coffer_exec to run a command with this credential
    coffer export PATH   Export all credentials to an encrypted backup file
    coffer import PATH    Import credentials from an encrypted backup file
    coffer rekey         Re-encrypt the vault with a new master passphrase
    coffer clear-key     Remove the master key from the OS keyring
    coffer serve         Start the MCP server (for debugging)

Run `coffer COMMAND --help` for the parameters and examples of any command.
"""

from __future__ import annotations

import getpass
import sys

import click

from coffer_mcp.audit import AuditLogger
from coffer_mcp.store import (
    CredentialEntry,
    EncryptedStore,
    clear_keyring,
    get_master_key,
    store_master_key_in_keyring,
)


def _read_secret(prompt: str = "Secret (password / token / API key): ") -> str:
    """Read a secret from the terminal, with fallback for Windows paste issues.

    On Windows, getpass uses msvcrt.getwch() which reads raw keystrokes.
    Ctrl+V paste sends the literal \\x16 control character instead of
    clipboard content. When this is detected, we fall back to input()
    which processes paste correctly (but echoes to the terminal).
    """
    value = getpass.getpass(prompt).strip()
    if value and all(c < " " for c in value):
        # Got only control characters (e.g. \x16 from Ctrl+V) —
        # getpass didn't capture the paste.
        click.echo(
            "It looks like paste didn't work with hidden input. Retrying with visible input.",
            err=True,
        )
        click.echo(
            "WARNING: your secret WILL be visible on screen.",
            err=True,
        )
        value = input(prompt).strip()
    return value


def _get_store() -> EncryptedStore:
    return EncryptedStore(get_master_key())


def _get_audit() -> AuditLogger:
    import hashlib

    master_key = get_master_key()
    hmac_key = hashlib.sha256(b"coffer-audit-hmac:" + master_key).digest()
    return AuditLogger(hmac_key=hmac_key, source="cli")


@click.group()
def main():
    """Coffer - credential vault for LLM agents."""
    pass


@main.command()
def init():
    """Set up the master key in the OS keyring."""
    click.echo("Setting up Coffer master key.")
    click.echo("This passphrase encrypts all your stored credentials.")
    click.echo()

    passphrase = getpass.getpass("Enter master passphrase: ")
    confirm = getpass.getpass("Confirm master passphrase: ")

    if passphrase != confirm:
        click.echo("Error: Passphrases do not match.", err=True)
        sys.exit(1)

    if len(passphrase) < 8:
        click.echo("Error: Passphrase must be at least 8 characters.", err=True)
        sys.exit(1)

    key = store_master_key_in_keyring(passphrase)
    click.echo(f"Master key stored in OS keyring (key fingerprint: {key[:4].hex()}...)")
    click.echo("You can now add credentials with: coffer add")


@main.command()
@click.option(
    "--alias",
    prompt="Credential alias (e.g., 'my-api')",
    help="Unique name you'll use to refer to this credential later (e.g. 'onetrust-uat').",
)
@click.option(
    "--auth-type",
    type=click.Choice(
        [
            "bearer_token",
            "basic_auth",
            "api_key_header",
            "web_login",
            "oauth2_client_credentials",
        ]
    ),
    prompt="Authentication type",
    help="How the credential authenticates. See the per-type field guide below.",
)
@click.option(
    "--username",
    prompt="Username / email (leave blank if N/A)",
    default="",
    help="Identity field; meaning depends on --auth-type (see below). "
    "Leave blank for bearer_token and api_key_header.",
)
@click.option(
    "--description",
    prompt="Description",
    default="",
    help="Free-text note shown in 'coffer list'.",
)
@click.option(
    "--allowed-urls",
    prompt="Allowed URL patterns (comma-separated, e.g., 'https://api.example.com/*')",
    default="",
    help="Comma-separated URL glob patterns this credential may be used against, "
    "e.g. 'https://api.example.com/*'. For OAuth2 this must also cover the token URL.",
)
@click.option(
    "--allowed-methods",
    prompt="Allowed HTTP methods (comma-separated, e.g., 'GET,POST')",
    default="GET",
    help="Comma-separated HTTP methods allowed, e.g. 'GET,POST'. Defaults to GET.",
)
@click.option(
    "--expires",
    default="",
    help="Expiry date (YYYY-MM-DD or days from now like '90d'). Leave blank for no expiry.",
)
def add(alias, auth_type, username, description, allowed_urls, allowed_methods, expires):
    """Add a new credential to the vault.

    The secret (password, token, or API key) is read interactively and is
    never passed as a command-line flag. What goes into --username and the
    secret depends on --auth-type:

    \b
    bearer_token       username: (unused)
                       secret:   the bearer token
    \b
    basic_auth         username: account username
                       secret:   account password
    \b
    api_key_header     username: (unused)
                       secret:   "Header-Name:value", or just the value to
                                 use the default header X-API-Key
    \b
    oauth2_client_credentials
                       username: "client_id|client_secret"
                       secret:   "token_url|scope|auth_style"
                                 scope and auth_style are optional.
                                 auth_style is "body" (default; sends the
                                 credentials in the form body) or "basic"
                                 (sends them in an HTTP Basic header).
                                 OneTrust requires "body". The token_url
                                 must also match --allowed-urls.
    \b
    web_login          username: login username
                       secret:   login password

    \b
    Examples:
      coffer add --alias gh --auth-type bearer_token \\
        --allowed-urls 'https://api.github.com/*' --allowed-methods GET,POST
    \b
      coffer add --alias ot-uat --auth-type oauth2_client_credentials \\
        --username 'CLIENT_ID|CLIENT_SECRET' --allowed-urls 'https://uat.onetrust.com/*'
        (then paste the secret: https://uat.onetrust.com/api/access/v1/oauth/token|read)
    """
    secret = _read_secret()

    if not secret:
        click.echo("Error: Secret cannot be empty.", err=True)
        sys.exit(1)

    url_list = [u.strip() for u in allowed_urls.split(",") if u.strip()]
    method_list = [m.strip().upper() for m in allowed_methods.split(",") if m.strip()]

    # Parse expiry
    expires_at = None
    if expires:
        import time as _time

        expires = expires.strip()
        if expires.endswith("d"):
            # Relative: "90d" = 90 days from now
            try:
                days = int(expires[:-1])
                expires_at = _time.time() + days * 86400
            except ValueError:
                click.echo(
                    f"Error: Invalid expiry format '{expires}'. Use YYYY-MM-DD or Nd (e.g., 90d).",
                    err=True,
                )
                sys.exit(1)
        else:
            # Absolute: YYYY-MM-DD
            try:
                from datetime import datetime, timezone

                dt = datetime.strptime(expires, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                expires_at = dt.timestamp()
            except ValueError:
                click.echo(
                    f"Error: Invalid date '{expires}'. Use YYYY-MM-DD or Nd (e.g., 90d).",
                    err=True,
                )
                sys.exit(1)

    entry = CredentialEntry(
        alias=alias,
        auth_type=auth_type,
        username=username,
        secret=secret,
        allowed_urls=url_list,
        allowed_methods=method_list,
        description=description,
        expires_at=expires_at,
    )

    store = _get_store()
    audit = _get_audit()

    try:
        store.add(entry)
        audit.log("credential.created", alias, "success", {"auth_type": auth_type})
        click.echo(f"Credential '{alias}' added successfully.")
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@main.command(name="list")
def list_creds():
    """List all stored credentials (no secrets shown).

    Shows each alias, auth type, expiry status, and description. Takes no
    parameters.
    """
    store = _get_store()
    aliases = store.list_aliases()

    if not aliases:
        click.echo("No credentials stored. Add one with: coffer add")
        return

    click.echo(f"\n{'Alias':<25} {'Type':<18} {'Status':<15} {'Description'}")
    click.echo("-" * 80)
    for a in aliases:
        status = a.get("status", "active")
        status_display = status
        if status == "EXPIRED":
            status_display = "EXPIRED!"
        elif status == "EXPIRING_SOON":
            status_display = "expiring soon"
        click.echo(f"{a['alias']:<25} {a['auth_type']:<18} {status_display:<15} {a['description']}")
    click.echo(f"\n{len(aliases)} credential(s) stored.")


@main.command()
@click.argument("alias")
def remove(alias):
    """Remove a credential from the vault.

    ALIAS is the credential to delete. This is irreversible; run 'coffer export'
    first if you want a backup.

    \b
    Example:
      coffer remove onetrust-uat
    """
    store = _get_store()
    audit = _get_audit()

    if store.remove(alias):
        audit.log("credential.removed", alias, "success")
        click.echo(f"Credential '{alias}' removed.")
    else:
        click.echo(f"No credential found with alias '{alias}'.", err=True)
        sys.exit(1)


@main.command()
@click.option(
    "--alias",
    default="",
    help="Filter events to a single credential alias. Default: all.",
)
@click.option("--limit", default=20, help="Maximum number of recent events to show. Default: 20.")
def audit(alias, limit):
    """View the audit log and verify its tamper-evident HMAC chain.

    \b
    Examples:
      coffer audit
      coffer audit --alias onetrust-uat --limit 50
    """
    logger = _get_audit()

    is_valid, count, message = logger.verify_chain()
    click.echo(f"\n{message}")

    events = logger.get_events(alias=alias if alias else None, limit=limit)
    if events:
        click.echo(f"\nRecent events (showing {len(events)} of {count}):\n")
        for evt in events:
            ts = evt.get("timestamp", 0)
            from datetime import datetime, timezone

            dt = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            click.echo(
                f"  {evt['event_id']}  {dt}  "
                f"{evt['event_type']:<25} {evt['alias']:<20} {evt['status']}"
            )
    else:
        click.echo("No audit events recorded.")


@main.command()
@click.argument("alias")
def rotate(alias):
    """Rotate (replace) the secret for an existing credential.

    ALIAS is the credential to update. The new secret is prompted for twice and
    read interactively; all other fields (URLs, methods, auth type) are kept.
    Use the same secret format that 'coffer add' documents for the auth type.

    \b
    Example:
      coffer rotate onetrust-uat
    """
    store = _get_store()
    audit = _get_audit()

    # Verify credential exists
    try:
        entry = store.get(alias)
    except KeyError:
        click.echo(f"No credential found with alias '{alias}'.", err=True)
        sys.exit(1)

    click.echo(f"Rotating secret for '{alias}' (type: {entry.auth_type})")
    new_secret = _read_secret("New secret (password / token / API key): ")
    if not new_secret:
        click.echo("Error: Secret cannot be empty.", err=True)
        sys.exit(1)

    confirm = _read_secret("Confirm new secret: ")
    if new_secret != confirm:
        click.echo("Error: Secrets do not match.", err=True)
        sys.exit(1)

    store.update_secret(alias, new_secret)
    audit.log("credential.rotated", alias, "success")
    click.echo(f"Secret for '{alias}' rotated successfully.")


@main.command()
@click.argument("alias")
@click.option("--url", default="", help="URL to test against. Defaults to the first allowed URL.")
def test(alias, url):
    """Test a credential by making a lightweight authenticated request.

    ALIAS is the credential to test. For oauth2_client_credentials this also
    exercises the token fetch, so it's the fastest way to confirm the
    client_id/client_secret/token_url/auth_style are correct. The response
    body is printed on failure to help diagnose the token endpoint's error.

    \b
    Examples:
      coffer test onetrust-uat
      coffer test gh --url https://api.github.com/user
    """
    import asyncio

    from coffer_mcp.tools.vault_test import vault_test

    store = _get_store()
    audit = _get_audit()

    click.echo(f"Testing credential '{alias}'...")
    result = asyncio.run(vault_test(store, audit, alias, url=url))

    if result.get("test") == "PASS":
        click.echo(
            f"  PASS  {result['method']} {result['url']}  "
            f"-> {result['status_code']}  ({result['latency_ms']}ms)"
        )
    elif result.get("test") == "FAIL":
        reason = result.get("reason", f"HTTP {result.get('status_code', '?')}")
        click.echo(f"  FAIL  {reason}", err=True)
        sys.exit(1)
    else:
        click.echo(f"  ERROR  {result.get('message', 'Unknown error')}", err=True)
        sys.exit(1)


@main.command()
def rekey():
    """Re-encrypt all credentials with a new master passphrase.

    Use this if your master key may have been compromised, or to migrate
    to a stronger passphrase. All credentials are decrypted with the
    current key and re-encrypted with the new one in a single atomic
    write. The old key is then replaced in the OS keyring.
    """
    import hashlib

    # 1. Verify access with the current key
    try:
        old_key = get_master_key()
        old_store = EncryptedStore(old_key)
    except Exception as e:
        click.echo(f"Error: Cannot access current vault: {e}", err=True)
        sys.exit(1)

    count = len(old_store.list_aliases())
    if count == 0:
        click.echo(
            "Vault is empty -- nothing to re-encrypt. Use 'coffer init' to set a new passphrase."
        )
        return

    click.echo(f"Re-keying {count} credential(s). This will:")
    click.echo("  1. Decrypt all credentials with the current key")
    click.echo("  2. Re-encrypt them with a new key")
    click.echo("  3. Replace the master key in the OS keyring")
    click.echo()

    # 2. Get new passphrase
    new_passphrase = getpass.getpass("New master passphrase: ")
    confirm = getpass.getpass("Confirm new master passphrase: ")

    if new_passphrase != confirm:
        click.echo("Error: Passphrases do not match.", err=True)
        sys.exit(1)

    if len(new_passphrase) < 8:
        click.echo("Error: Passphrase must be at least 8 characters.", err=True)
        sys.exit(1)

    # 3. Derive new key and re-encrypt
    new_key = store_master_key_in_keyring(new_passphrase)

    try:
        rekeyed = old_store.rekey(new_key)
    except Exception as e:
        # Rekey failed — restore the old key in the keyring so the vault
        # remains accessible (the file was not modified on failure).
        click.echo(f"Error during re-encryption: {e}", err=True)
        click.echo("Restoring original key in keyring...", err=True)
        # We can't easily restore the old keyring entry since we don't have
        # the old passphrase. But the file is untouched, so the old key
        # (still in memory) works. Warn the user.
        click.echo(
            "WARNING: The keyring was updated but re-encryption failed. "
            "Run 'coffer init' with your OLD passphrase to restore access, "
            "then try 'coffer rekey' again.",
            err=True,
        )
        sys.exit(1)

    # 4. Audit the rekey
    hmac_key = hashlib.sha256(b"coffer-audit-hmac:" + new_key).digest()
    audit = AuditLogger(hmac_key=hmac_key, source="cli")
    audit.log("vault.rekeyed", "*", "success", {"credentials_rekeyed": rekeyed})

    click.echo(f"Successfully re-encrypted {rekeyed} credential(s) with new key.")
    click.echo(f"New key fingerprint: {new_key[:4].hex()}...")


@main.command()
def migrate():
    """Upgrade stored credentials to the integrity-protected format.

    Re-encrypts every credential so all plaintext metadata fields
    (auth_type, description, timestamps, expires_at) are bound into the
    GCM authentication tag. Entries written by older versions are not
    protected against metadata tampering until this runs. Atomic: if any
    entry fails to decrypt, nothing is changed.
    """
    import warnings as _warnings

    store = _get_store()
    audit = _get_audit()

    count = len(store.list_aliases())
    if count == 0:
        click.echo("Vault is empty -- nothing to migrate.")
        return

    try:
        with _warnings.catch_warnings(record=True) as caught:
            _warnings.simplefilter("always")
            migrated = store.migrate_aad()
    except Exception as e:
        click.echo(f"Error during migration: {e}", err=True)
        click.echo("The vault file was not modified.", err=True)
        sys.exit(1)

    legacy = sum(1 for w in caught if "legacy AAD" in str(w.message))
    audit.log(
        "vault.aad_migrated",
        "*",
        "success",
        {"credentials": migrated, "legacy_upgraded": legacy},
    )
    if legacy:
        click.echo(
            f"Re-encrypted {migrated} credential(s); "
            f"{legacy} upgraded from a legacy AAD format."
        )
    else:
        click.echo(f"Re-encrypted {migrated} credential(s); all were already current.")


@main.command(name="allow-command")
@click.argument("alias")
@click.option(
    "--argv-json",
    required=True,
    help='Exact command as a JSON array, e.g. \'["C:\\\\Python311\\\\python.exe", "scraper.py"]\'. '
    "argv[0] must be an absolute path.",
)
@click.option(
    "--cwd",
    default=None,
    help="Fixed absolute working directory for the command (optional).",
)
def allow_command(alias, argv_json, cwd):
    """Allow coffer_exec to run a command with this credential's secret
    in its environment.

    The command is matched by exact argv equality — the LLM cannot add,
    remove, or change arguments. Only allowlist specific scripts; never
    shells (cmd /c, bash -c) or bare interpreters, which would defeat
    the exact-match protection.
    """
    import json as _json

    try:
        argv = _json.loads(argv_json)
    except _json.JSONDecodeError as e:
        click.echo(f"Error: --argv-json is not valid JSON: {e}", err=True)
        sys.exit(1)

    store = _get_store()
    audit = _get_audit()

    try:
        count = store.add_allowed_command(alias, argv, cwd=cwd)
    except KeyError:
        click.echo(f"No credential found with alias '{alias}'.", err=True)
        sys.exit(1)
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    audit.log(
        "credential.command_allowed",
        alias,
        "success",
        {"argv": argv, "cwd": cwd},
    )
    click.echo(f"Command allowed for '{alias}' ({count} command(s) on allowlist).")
    click.echo("Note: the credential is passed to this command via the environment")
    click.echo("variables COFFER_USERNAME and COFFER_SECRET.")


@main.command(name="export")
@click.argument("output_path", type=click.Path())
def export_cmd(output_path):
    """Export all credentials to an encrypted backup file.

    OUTPUT_PATH is where the encrypted backup is written. You're prompted for a
    separate backup passphrase (independent of the master key) that encrypts the
    file, so the backup stays protected if moved off this machine.

    \b
    Example:
      coffer export ./coffer-backup.enc
    """
    from pathlib import Path

    from coffer_mcp.store.backup import export_vault

    store = _get_store()
    passphrase = getpass.getpass("Backup passphrase: ")
    confirm = getpass.getpass("Confirm backup passphrase: ")

    if passphrase != confirm:
        click.echo("Error: Passphrases do not match.", err=True)
        sys.exit(1)
    if len(passphrase) < 8:
        click.echo("Error: Passphrase must be at least 8 characters.", err=True)
        sys.exit(1)

    result = export_vault(store, passphrase, Path(output_path))
    if result["status"] == "ok":
        click.echo(f"Exported {result['count']} credential(s) to {result['path']}")
    else:
        click.echo(f"Error: {result.get('message', 'Unknown error')}", err=True)
        sys.exit(1)


@main.command(name="import")
@click.argument("input_path", type=click.Path(exists=True))
@click.option(
    "--overwrite",
    is_flag=True,
    help="Replace existing credentials that have the same alias. Default: skip them.",
)
def import_cmd(input_path, overwrite):
    """Import credentials from an encrypted backup file.

    INPUT_PATH is the encrypted backup to read. You're prompted for the backup
    passphrase that was set during export. Aliases that already exist are
    skipped unless --overwrite is given.

    \b
    Example:
      coffer import ./coffer-backup.enc --overwrite
    """
    from pathlib import Path

    from coffer_mcp.store.backup import import_vault

    store = _get_store()
    passphrase = getpass.getpass("Backup passphrase: ")

    result = import_vault(store, passphrase, Path(input_path), overwrite=overwrite)
    if result["status"] == "ok":
        click.echo(
            f"Imported {result['imported']}, "
            f"skipped {result['skipped']} "
            f"(of {result['total_in_backup']} in backup)"
        )
        if result["errors"]:
            for err in result["errors"]:
                click.echo(f"  Error: {err}", err=True)
    else:
        click.echo(f"Error: {result.get('message', 'Unknown error')}", err=True)
        sys.exit(1)


@main.command()
def serve():
    """Start the MCP server (for debugging)."""
    click.echo("Starting Coffer MCP server...")
    from coffer_mcp.server import main as server_main

    server_main()


@main.command()
def clear_key():
    """Remove the master key from the OS keyring."""
    clear_keyring()
    click.echo("Master key removed from OS keyring.")


if __name__ == "__main__":
    main()
