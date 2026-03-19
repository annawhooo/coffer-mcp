# Coffer MCP

**Credential vault for LLM agents.** Your AI assistant uses passwords and API keys — but never sees them.

---

## The Problem

When you give Claude a password or API key, it lives in the conversation context — stored in history, visible in logs, potentially exposed. Even if you delete the chat, the credential was still processed in plaintext.

## The Solution

Coffer stores your credentials **encrypted on your machine** and exposes MCP tools that let Claude make authenticated requests **without ever seeing the actual credential**. The password goes from your vault to the target server. Claude only sees the result.

```
You (one-time setup)
  │
  ▼
Coffer MCP Server (runs locally)
  ├── Encrypted vault (AES-256-GCM)
  ├── coffer_list         → returns aliases only
  ├── coffer_http_request → injects auth, returns clean response
  ├── coffer_test         → verifies credential works (pass/fail)
  ├── coffer_web_login    → logs into websites, caches session
  ├── coffer_web_fetch    → fetches pages as markdown
  └── coffer_audit        → tamper-proof activity log

Claude sees: { "status": "ok", "body": "..." }
Claude never sees: your password
```

## Quickstart

### 1. Install

```bash
pip install coffer-mcp
```

### 2. Set up your master key

```bash
coffer init
# Enter a master passphrase — this encrypts all your credentials
```

### 3. Add a credential

```bash
coffer add
# Follow the prompts: alias, auth type, username, password, allowed URLs

# With expiry (optional):
coffer add --expires 90d           # expires in 90 days
coffer add --expires 2026-12-31    # expires on a specific date
```

### 4. Configure Claude Desktop

Add to your `claude_desktop_config.json`:

**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
    "mcpServers": {
        "Coffer": {
            "command": "python",
            "args": ["-m", "coffer_mcp.server"]
        }
    }
}
```

### 5. Use in Claude

> "What credentials do I have stored?"
> → Claude calls `coffer_list` → sees aliases only, plus expiry status

> "Test my API credential"
> → Claude calls `coffer_test` → `{ test: "PASS", status_code: 200, latency_ms: 142 }`

> "Fetch the latest article from my blog"
> → Claude calls `coffer_web_login` then `coffer_web_fetch`
> → You get the article content, Claude never sees your password

## MCP Tools

| Tool | What it does | What Claude sees |
|---|---|---|
| `coffer_list` | List stored credentials | Aliases, types, expiry status |
| `coffer_http_request` | Authenticated API call | Response body (sanitized) |
| `coffer_test` | Verify credential works | Pass/fail, status code, latency |
| `coffer_web_login` | Log into a website | `{ status: "ok" }` |
| `coffer_web_fetch` | Fetch page content | Clean markdown |
| `coffer_web_logout` | Close web session | `{ status: "ok" }` |
| `coffer_audit` | View activity log | Events + chain integrity |

**What Claude never sees:** passwords, API keys, tokens, session cookies.

## CLI Commands

```bash
coffer init              # Set up master key in OS keyring
coffer add               # Add a credential (interactive)
coffer add --expires 90d # Add with 90-day expiry
coffer list              # List credentials (no secrets, shows expiry)
coffer test <alias>      # Test a credential works (HEAD request)
coffer rotate <alias>    # Rotate the secret for a credential
coffer export <file>     # Encrypted backup to file
coffer import <file>     # Restore from encrypted backup
coffer remove <alias>    # Remove a credential
coffer audit             # View audit log + verify integrity
coffer clear-key         # Remove master key from OS keyring
coffer serve             # Start MCP server (for debugging)
```

## Security

See [SECURITY.md](SECURITY.md) for the full threat model.

**Key protections:**
- AES-256-GCM encryption at rest (per-entry unique nonces)
- Master key stored in OS keyring (Windows Credential Manager / macOS Keychain)
- Random PBKDF2 salt per user (stored with key in keyring)
- URL allowlisting with strict domain matching
- Per-hop redirect checking against allowlist
- Response sanitization scrubs credentials from bodies and error messages
- Prompt injection defense (strips HTML comments, hidden elements, invisible unicode)
- Browser session auto-expiry (30 minutes)
- HMAC-SHA-256 audit chain (keyed to master key)
- Credential expiry with automatic enforcement

## Supported Auth Types

| Type | Use case | How it works |
|---|---|---|
| `bearer_token` | REST APIs with Bearer tokens | Injects `Authorization: Bearer <token>` |
| `basic_auth` | APIs with Basic authentication | Injects `Authorization: Basic <base64>` |
| `api_key_header` | APIs with custom API key headers | Injects custom header with key |
| `web_login` | Websites with form-based login | Browser automation via Playwright |
| `oauth2_client_credentials` | OAuth2 APIs (ServiceNow, etc.) | Auto-fetches and caches tokens |

## Credential Expiry

Credentials can have an optional expiry date. When set:
- `coffer list` shows `EXPIRED` or `EXPIRING_SOON` (within 7 days) status
- Expired credentials are **blocked** from use — Claude gets a clear error
- `coffer test` checks expiry before making requests

## Backup & Restore

```bash
# Export all credentials to an encrypted backup file
coffer export ~/coffer-backup-2026.enc
# Enter a backup passphrase (separate from your master key)

# Restore from backup on a new machine
coffer import ~/coffer-backup-2026.enc
# --overwrite flag replaces existing credentials with same alias
coffer import ~/coffer-backup-2026.enc --overwrite
```

Backups are AES-256-GCM encrypted with a separate passphrase. Safe to store in cloud storage.

## File Layout

```
~/.coffer/
├── credentials.json    # Encrypted credentials (AES-256-GCM)
├── audit.jsonl         # Append-only audit log with HMAC chain
└── .master-key         # Auto-generated master key (fallback only)
```

## Requirements

- Python 3.10+
- Claude Desktop (for MCP integration)
- Windows / macOS / Linux

## License

MIT
