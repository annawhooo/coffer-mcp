# Krypteia MCP

**Credential vault for LLM agents.** Your AI assistant uses passwords and API keys — but never sees them.

Named for Sparta's secret operatives (Κρυπτεία) — the Greek root of *cryptography*.

---

## The Problem

When you give Claude a password or API key, it lives in the conversation context — stored in history, visible in logs, potentially exposed. Even if you delete the chat, the credential was still processed in plaintext.

## The Solution

Krypteia stores your credentials **encrypted on your machine** and exposes MCP tools that let Claude make authenticated requests **without ever seeing the actual credential**. The password goes from your vault to the target server. Claude only sees the result.

```
You (one-time setup)
  │
  ▼
Krypteia MCP Server (runs locally)
  ├── Encrypted vault (AES-256-GCM)
  ├── krypteia_list        → returns aliases only
  ├── krypteia_http_request → injects auth, returns clean response
  ├── krypteia_web_login    → logs into websites, caches session
  ├── krypteia_web_fetch    → fetches pages as markdown
  └── krypteia_audit        → tamper-proof activity log

Claude sees: { "status": "ok", "body": "..." }
Claude never sees: your password
```

## Quickstart

### 1. Install

```bash
pip install krypteia-mcp
```

### 2. Set up your master key

```bash
krypteia init
# Enter a master passphrase — this encrypts all your credentials
```

### 3. Add a credential

```bash
krypteia add
# Follow the prompts: alias, auth type, username, password, allowed URLs
```

### 4. Configure Claude Desktop

Add to your `claude_desktop_config.json`:

**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
    "mcpServers": {
        "krypteia": {
            "command": "python",
            "args": ["-m", "krypteia_mcp.server"]
        }
    }
}
```

### 5. Use in Claude

> "What credentials do I have stored?"
> → Claude calls `krypteia_list` → sees aliases only

> "Fetch the latest article from my OneTrust blog"
> → Claude calls `krypteia_web_login` then `krypteia_web_fetch`
> → You get the article content, Claude never sees your password

## MCP Tools

| Tool | What it does | What Claude sees |
|---|---|---|
| `krypteia_list` | List stored credentials | Aliases, types, descriptions |
| `krypteia_http_request` | Authenticated API call | Response body (sanitized) |
| `krypteia_web_login` | Log into a website | `{ status: "ok" }` |
| `krypteia_web_fetch` | Fetch page content | Clean markdown |
| `krypteia_web_logout` | Close web session | `{ status: "ok" }` |
| `krypteia_audit` | View activity log | Events + chain integrity |

**What Claude never sees:** passwords, API keys, tokens, session cookies.

## CLI Commands

```bash
krypteia init              # Set up master key in OS keyring
krypteia add               # Add a credential (interactive)
krypteia list              # List credentials (no secrets)
krypteia remove <alias>    # Remove a credential
krypteia audit             # View audit log + verify integrity
krypteia clear-key         # Remove master key from OS keyring
krypteia serve             # Start MCP server (for debugging)
```

## Security

See [SECURITY.md](SECURITY.md) for the full threat model.

**Key protections:**
- AES-256-GCM encryption at rest (per-entry unique nonces)
- Master key stored in OS keyring (Windows Credential Manager / macOS Keychain)
- URL allowlisting prevents prompt injection credential theft
- Response sanitization scrubs leaked credentials
- Tamper-proof audit log with SHA-256 hash chain

## Supported Auth Types

| Type | Use case | How it works |
|---|---|---|
| `bearer_token` | REST APIs with Bearer tokens | Injects `Authorization: Bearer <token>` |
| `basic_auth` | APIs with Basic authentication | Injects `Authorization: Basic <base64>` |
| `api_key_header` | APIs with custom API key headers | Injects custom header with key |
| `web_login` | Websites with form-based login | POSTs credentials, caches session cookies |

## File Layout

```
~/.krypteia/
├── credentials.json    # Encrypted credentials (AES-256-GCM)
├── audit.jsonl         # Append-only audit log with hash chain
└── .master-key         # Auto-generated master key (fallback only)
```

## Requirements

- Python 3.10+
- Claude Desktop (for MCP integration)
- Windows / macOS / Linux

## License

MIT
