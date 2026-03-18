# Security Model

## Threat Model

Alcove is designed to prevent **credential exposure in LLM conversation context**.
It is NOT a general-purpose secrets manager.

### What Alcove Protects Against

| Threat | Protection |
|---|---|
| LLM context leakage | Credentials are resolved server-side; only results are returned |
| Plaintext credential storage | AES-256-GCM encryption with per-entry nonces |
| Prompt injection credential theft | URL allowlisting prevents credentials from being sent to attacker-controlled endpoints |
| Accidental exposure in logs | Response sanitization scrubs leaked credentials |
| Audit log tampering | SHA-256 hash chain detects modifications |
| Credential enumeration | `alcove_list` returns aliases only, never secrets |

### What Alcove Does NOT Protect Against

| Threat | Why |
|---|---|
| Compromised host (root/admin access) | If the machine is compromised, the attacker can read memory |
| User typing password into chat | Alcove can't prevent what you type directly |
| Malicious MCP client | A client that ignores tool output boundaries could theoretically access raw IPC |
| Browser-level memory attacks | If using Playwright, credentials exist briefly in browser process memory |
| Master key compromise | If the OS keyring or master key file is compromised, all credentials are exposed |

## Encryption Details

- **Algorithm**: AES-256-GCM (authenticated encryption with associated data)
- **Key size**: 256 bits (32 bytes)
- **Nonce**: 96 bits (12 bytes), unique per credential entry, generated via `os.urandom()`
- **Key derivation**: PBKDF2-HMAC-SHA256 with 600,000 iterations (OWASP 2023 recommendation)
- **Key storage**: OS keyring (preferred), environment variable, or auto-generated file

## URL Allowlisting

Each credential defines which URLs it can be used against. The allowlist uses
`fnmatch`-style patterns:

```
https://my.onetrust.com/*       — matches any path on my.onetrust.com
https://api.example.com/v1/*    — matches any v1 API endpoint
```

If `allowed_urls` is empty, the credential **cannot be used for any request**
(fail-closed design).

## Audit Chain

Every credential operation is logged in `~/.alcove/audit.jsonl` with:
- Timestamp
- Event type
- Credential alias (never the secret)
- Status (success/failure)
- Context details

Each entry includes a SHA-256 hash incorporating the previous entry's hash,
creating a tamper-evident chain. Use `alcove audit` to verify integrity.

## Reporting Vulnerabilities

If you discover a security vulnerability, please report it responsibly
by opening a GitHub issue tagged `security` or contacting the maintainer directly.
