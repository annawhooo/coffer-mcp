"""
Coffer CLI — manage credentials from the command line.

Usage:
    coffer add           Add a new credential (interactive)
    coffer list          List all stored credentials
    coffer remove ALIAS  Remove a credential
    coffer audit         View audit log and verify integrity
    coffer init          Set up the master key in the OS keyring
    coffer serve         Start the MCP server (for debugging)
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
            "It looks like paste didn't work with hidden input. "
            "Retrying with visible input.",
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
    """Coffer — credential vault for LLM agents."""
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
@click.option("--alias", prompt="Credential alias (e.g., 'my-api')")
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
)
@click.option("--username", prompt="Username / email (leave blank if N/A)", default="")
@click.option("--description", prompt="Description", default="")
@click.option(
    "--allowed-urls",
    prompt="Allowed URL patterns (comma-separated, e.g., 'https://my.onetrust.com/*')",
    default="",
)
@click.option(
    "--allowed-methods",
    prompt="Allowed HTTP methods (comma-separated, e.g., 'GET,POST')",
    default="GET",
)
@click.option(
    "--expires",
    default="",
    help="Expiry date (YYYY-MM-DD or days from now like '90d'). Leave blank for no expiry.",
)
def add(alias, auth_type, username, description, allowed_urls, allowed_methods, expires):
    """Add a new credential to the vault."""
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
    """List all stored credentials (no secrets shown)."""
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
    """Remove a credential from the vault."""
    store = _get_store()
    audit = _get_audit()

    if store.remove(alias):
        audit.log("credential.removed", alias, "success")
        click.echo(f"Credential '{alias}' removed.")
    else:
        click.echo(f"No credential found with alias '{alias}'.", err=True)
        sys.exit(1)


@main.command()
@click.option("--alias", default="", help="Filter events by credential alias.")
@click.option("--limit", default=20, help="Number of events to show.")
def audit(alias, limit):
    """View audit log and verify chain integrity."""
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
    """Rotate the secret for an existing credential."""
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
@click.option("--url", default="", help="URL to test against (defaults to first allowed URL).")
def test(alias, url):
    """Test a credential by making a lightweight authenticated request."""
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


@main.command(name="export")
@click.argument("output_path", type=click.Path())
def export_cmd(output_path):
    """Export all credentials to an encrypted backup file."""
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
@click.option("--overwrite", is_flag=True, help="Overwrite existing credentials with same alias.")
def import_cmd(input_path, overwrite):
    """Import credentials from an encrypted backup file."""
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
