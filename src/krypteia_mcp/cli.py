"""
Krypteia CLI — manage credentials from the command line.

Usage:
    krypteia add           Add a new credential (interactive)
    krypteia list          List all stored credentials
    krypteia remove ALIAS  Remove a credential
    krypteia audit         View audit log and verify integrity
    krypteia init          Set up the master key in the OS keyring
    krypteia serve         Start the MCP server (for debugging)
"""

from __future__ import annotations

import getpass
import json
import sys

import click

from krypteia_mcp.audit import AuditLogger
from krypteia_mcp.store import (
    CredentialEntry,
    EncryptedStore,
    clear_keyring,
    get_master_key,
    store_master_key_in_keyring,
)


def _get_store() -> EncryptedStore:
    return EncryptedStore(get_master_key())


def _get_audit() -> AuditLogger:
    return AuditLogger()


@click.group()
def main():
    """Krypteia — credential vault for LLM agents."""
    pass


@main.command()
def init():
    """Set up the master key in the OS keyring."""
    click.echo("Setting up Krypteia master key.")
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
    click.echo("You can now add credentials with: krypteia add")


@main.command()
@click.option("--alias", prompt="Credential alias (e.g., 'onetrust-blog')")
@click.option(
    "--auth-type",
    type=click.Choice(["bearer_token", "basic_auth", "api_key_header", "web_login"]),
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
def add(alias, auth_type, username, description, allowed_urls, allowed_methods):
    """Add a new credential to the vault."""
    secret = getpass.getpass("Secret (password / token / API key): ")

    if not secret:
        click.echo("Error: Secret cannot be empty.", err=True)
        sys.exit(1)

    url_list = [u.strip() for u in allowed_urls.split(",") if u.strip()]
    method_list = [m.strip().upper() for m in allowed_methods.split(",") if m.strip()]

    entry = CredentialEntry(
        alias=alias,
        auth_type=auth_type,
        username=username,
        secret=secret,
        allowed_urls=url_list,
        allowed_methods=method_list,
        description=description,
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
        click.echo("No credentials stored. Add one with: krypteia add")
        return

    click.echo(f"\n{'Alias':<25} {'Type':<18} {'Description'}")
    click.echo("-" * 70)
    for a in aliases:
        click.echo(f"{a['alias']:<25} {a['auth_type']:<18} {a['description']}")
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
def serve():
    """Start the MCP server (for debugging)."""
    click.echo("Starting Krypteia MCP server...")
    from krypteia_mcp.server import main as server_main
    server_main()


@main.command()
def clear_key():
    """Remove the master key from the OS keyring."""
    clear_keyring()
    click.echo("Master key removed from OS keyring.")


if __name__ == "__main__":
    main()
