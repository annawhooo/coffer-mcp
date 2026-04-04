# Coffer MCP

[![CI](https://github.com/annawhooo/coffer-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/annawhooo/coffer-mcp/actions/workflows/ci.yml)

*The strongbox between your secrets and your AI.*

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
  ├── Encrypted vault (AES-256-GCM with AAD)
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

> **Default deny:** If you omit `--allowed-urls` (or leave it blank), the credential
> is blocked from **all** URLs. This is intentional — fail-closed security.
> You must explicitly list which URLs the credential is allowed to reach.

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

> "Test my API credential against an auth-enforcing endpoint"
> → Claude calls `coffer_test` with `expected_status: 200`
> → `{ test: "FAIL", status_code: 401, expected_status: 200 }` — catches false positives

> "Fetch the latest article from my blog"
> → Claude calls `coffer_web_login` then `coffer_web_fetch`
> → You get the article content, Claude never sees your password

## MCP Tools

| Tool | What it does | What Claude sees |
|---|---|---|
| `coffer_list` | List stored credentials | Aliases, types, expiry status |
| `coffer_http_request` | Authenticated API call | Response body (sanitized) |
| `coffer_test` | Verify credential works | Pass/fail, status code, latency. Optional `expected_status` for strict validation. |
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
coffer test <alias> --url https://api.example.com/me --expected-status 200  # Strict test
coffer rotate <alias>    # Rotate the secret for a credential
coffer rekey             # Re-encrypt all credentials with a new passphrase
coffer export <file>     # Encrypted backup to file
coffer import <file>     # Restore from encrypted backup
coffer remove <alias>    # Remove a credential
coffer audit             # View audit log + verify integrity
coffer clear-key         # Remove master key from OS keyring
coffer serve             # Start MCP server (for debugging)
```

## Security

See [SECURITY.md](SECURITY.md) for the full threat model.

**Encryption & storage:**
- AES-256-GCM encryption at rest with per-entry unique nonces
- Associated Authenticated Data (AAD) binds each ciphertext to its alias, preventing copy-paste attacks between entries
- Master key stored in OS keyring (Windows Credential Manager / macOS Keychain / Linux Secret Service)
- Random PBKDF2 salt per user (stored with key in keyring)
- Key rotation via `coffer rekey` — re-encrypts all credentials atomically with a new passphrase

**Access control:**
- URL allowlisting with strict domain matching
- Per-hop redirect checking against allowlist
- HTTP method validation (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS)
- CSS selector validation to prevent injection in web scraping
- OAuth2 pipe-delimited format validation
- Response body size cap (10 MB) to prevent memory exhaustion

**Data protection:**
- Response sanitization scrubs credentials from bodies and error messages
- Expanded scrubbing catches base64-encoded secrets, Bearer tokens, and URL-embedded credentials
- Prompt injection defense (strips HTML comments, hidden elements, invisible unicode)
- Browser session auto-expiry (30 minutes)
- Credential expiry with automatic enforcement

**Integrity & auditability:**
- HMAC-SHA-256 audit chain (keyed to master key) — detects tampering
- Warning emitted when audit logger runs without HMAC key
- Atomic backup writes (write-to-temp + rename) prevent corruption on crash
- Audit status reflects target server response: `auth_rejected` when credentials are injected but the server returns 401/403, distinguishing between vault-level success and target-level failure

**Concurrency:**
- Cross-platform file locking (fcntl on Unix, Win32 LockFileEx on Windows) for credential store and audit log
- Thread-safe global state for sessions, token cache, and store/audit initialization

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

## Key Rotation

If your master passphrase is compromised, rotate it without losing any credentials:

```bash
coffer rekey
# Enter current passphrase → enter new passphrase → confirm
# All credentials are re-encrypted atomically
# Old vault is untouched until migration completes
```

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

Backups are AES-256-GCM encrypted with a separate passphrase. Writes are atomic (temp file + rename) so a crash mid-export won't corrupt your backup. Safe to store in cloud storage.

## File Layout

```
~/.coffer/
├── credentials.json    # Encrypted credentials (AES-256-GCM + AAD)
├── audit.jsonl         # Append-only audit log with HMAC chain
└── .master-key         # Auto-generated master key (fallback only)
```

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests (142 tests)
pytest

# Lint
ruff check src/ tests/
ruff format --check src/ tests/
```

CI runs automatically on every push and PR — lint + test matrix across Python 3.10-3.13 on Ubuntu, Windows, and macOS.

## Requirements

- Python 3.10+
- Claude Desktop (for MCP integration)
- Windows / macOS / Linux

## License

MIT
