# Security Model

## Threat Model

Coffer is designed to prevent **credential exposure in LLM conversation context**.
It is NOT a general-purpose secrets manager.

### What Coffer Protects Against

| Threat | Protection |
|---|---|
| LLM context leakage | Credentials are resolved server-side; only results are returned |
| Plaintext credential storage | AES-256-GCM encryption with per-entry nonces |
| Prompt injection via response body | HTML comments, hidden elements, invisible unicode, and oversized responses are stripped before reaching the LLM |
| Prompt injection credential theft | URL allowlisting with strict domain matching prevents credentials from being sent to attacker-controlled endpoints |
| Open redirect credential leak | HTTP redirects are checked per-hop against the URL allowlist; credentials are never followed to off-allowlist domains |
| Accidental exposure in logs | Response sanitization scrubs leaked credentials from response bodies AND error messages |
| Audit log tampering | HMAC-SHA-256 hash chain keyed to the master key; attackers with file access but not the key cannot recompute valid hashes |
| Credential enumeration | `coffer_list` returns aliases only, never secrets |
| Browser session hijack | Authenticated browser sessions expire after 30 minutes; `coffer_web_fetch` enforces URL allowlist on every navigation |
| Race condition credential loss | `update_secret` is atomic (single file write); no window where the credential is missing from disk |

### What Coffer Does NOT Protect Against

| Threat | Why | Mitigation |
|---|---|---|
| Compromised host (root/admin access) | If the machine is compromised, the attacker can read memory | Use full-disk encryption; keep OS patched |
| User typing password into chat | Coffer can't prevent what you type directly | Use `coffer add` CLI instead |
| Malicious MCP client | A client that ignores tool output boundaries could access raw IPC | Only use trusted MCP clients (Claude Desktop) |
| Browser-level memory attacks | Playwright credentials exist briefly in browser process memory | Sessions auto-expire after 30 minutes |
| Master key compromise | If the OS keyring or master key file is compromised, all credentials are exposed | Use a strong passphrase via `coffer init`; avoid the file-based fallback |
| Supply-chain attack on Coffer itself | A modified package could change tool descriptions or behavior to trick the LLM | Pin package versions; verify checksums; install from trusted sources only |
| MCP stdio man-in-the-middle | An attacker with local user access could proxy the stdio IPC channel | MCP protocol does not support mutual authentication; physical/user-level host security is required |
| Prompt injection via response content | A malicious server could embed LLM instructions in response bodies | Coffer strips HTML comments, hidden elements, and invisible unicode — but novel injection techniques may bypass this |
| COFFER_MASTER_KEY env var with fixed salt | The env var derivation path uses a deterministic salt (no place to store a random salt) | Prefer `coffer init` (random salt stored in keyring); use env var only for CI/automation |


## Encryption Details

- **Algorithm**: AES-256-GCM (authenticated encryption with associated data)
- **Key size**: 256 bits (32 bytes)
- **Nonce**: 96 bits (12 bytes), unique per credential entry, generated via `os.urandom()`
- **Key derivation**: PBKDF2-HMAC-SHA256 with 600,000 iterations (OWASP 2023 recommendation)
- **Key storage**: OS keyring (preferred), environment variable, or auto-generated file
- **PBKDF2 salt**: Random 16-byte salt generated per-user, stored alongside the derived key in the OS keyring. The env var path uses a deterministic salt (documented limitation).

## URL Allowlisting

Each credential defines which URLs it can be used against. The allowlist uses
strict matching on scheme and domain with fnmatch wildcards on the path only:

```
https://my.onetrust.com/*       — matches any path on my.onetrust.com
https://api.example.com/v1/*    — matches any v1 API endpoint
```

**Security properties:**
- Domain (netloc) must match exactly — no wildcard subdomains
- Path traversal attempts (`/../`) are normalized before matching
- HTTP redirects are checked per-hop against the allowlist
- Empty `allowed_urls` blocks ALL requests (fail-closed design)

If `allowed_urls` is empty, the credential **cannot be used for any request**
(fail-closed design).


## Response Content Safety

Response bodies from target servers pass through two sanitization layers
before reaching the LLM:

1. **Credential scrubbing** (`sanitize_response`): Replaces the credential
   secret, its URL-encoded form, and its base64-encoded form with `[REDACTED]`.
   Also scrubs error messages from httpx exceptions.

2. **Content safety** (`sanitize_content`): Strips content that could be used
   for prompt injection attacks:
   - HTML comments (`<!-- ... -->`)
   - Hidden HTML elements (`display:none`, `visibility:hidden`, `opacity:0`)
   - Zero-width and invisible Unicode characters
   - Oversized responses (truncated at 200,000 characters)

These defenses reduce the attack surface but cannot guarantee protection
against all novel prompt injection techniques. The URL allowlist remains the
primary defense: credentials can only be sent to pre-approved domains.

## Browser Session Security

Authenticated browser sessions (Playwright):
- Auto-expire after 30 minutes of creation
- URL allowlist is enforced on every `coffer_web_fetch` navigation
- Sessions are in-memory only (not persisted to disk)
- `coffer_web_logout` immediately destroys the browser context


## Audit Chain

Every credential operation is logged in `~/.coffer/audit.jsonl` with:
- Timestamp
- Event type
- Credential alias (never the secret)
- Status (success/failure)
- Context details

Each entry includes an HMAC-SHA-256 hash (keyed to the master key) incorporating
the previous entry's hash, creating a tamper-evident chain. An attacker who gains
file access but not the master key cannot recompute valid hashes after modifying
entries. Use `coffer audit` to verify integrity.

**Known limitation:** An attacker with the master key can recompute the entire
chain. The audit log is a detection mechanism, not a prevention mechanism.

## Supply-Chain Considerations

Coffer is a locally-installed Python package. If an attacker modifies the
installed package (via dependency confusion, pip package replacement, or local
file access), they could:

- Change tool descriptions to manipulate LLM behavior
- Modify URL allowlist checks to allow exfiltration
- Add a backdoor that logs decrypted credentials

**Mitigations:**
- Pin Coffer to a specific version in your requirements
- Install from a trusted source (GitHub release or private PyPI)
- Verify file checksums after installation
- Monitor `src/coffer_mcp/server.py` for unexpected changes to tool descriptions

## MCP Protocol Limitations

The MCP protocol uses stdio (stdin/stdout JSON-RPC) for communication between
Claude Desktop and Coffer. This channel has no mutual authentication:

- Claude Desktop does not verify the identity of the MCP server
- An attacker with local user access could proxy the stdio channel
- There is no TLS, code signing, or attestation on the IPC path

This is a fundamental limitation of the MCP protocol, not specific to Coffer.
Physical and user-level host security is the required mitigation.

## Audit Event Reference

### Event Types

| Event Type | Emitted By | Description |
|---|---|---|
| `credential.created` | CLI `coffer add` | New credential added to vault |
| `credential.removed` | CLI `coffer remove` | Credential deleted from vault |
| `credential.rotated` | CLI `coffer rotate` | Credential secret was rotated |
| `credential.used` | `coffer_http_request` | Credential was used for an HTTP request |
| `credential.test` | `coffer_test` | Credential was tested (lightweight auth check) |
| `credential.expired` | `coffer_http_request` | Attempted use of an expired credential |
| `credential.access_failed` | `coffer_http_request` | Credential alias not found |
| `credential.access_denied` | `coffer_http_request` | Request blocked by URL/method allowlist |
| `credential.listed` | `coffer_list` | Credential metadata was listed |
| `vault.rekeyed` | CLI `coffer rekey` | All credentials re-encrypted with new key |
| `browser_login.success` | `coffer_web_login` | Browser login completed |
| `browser_login.failed` | `coffer_web_login` | Browser login failed |
| `browser_fetch.success` | `coffer_web_fetch` | Page fetched from authenticated session |
| `browser_fetch.failed` | `coffer_web_fetch` | Page fetch failed |

### Status Values

| Status | Meaning | When Used |
|---|---|---|
| `success` | Operation completed as expected | Successful requests (HTTP 2xx/3xx), successful logins, credential creation |
| `failure` | Operation failed | Credential not found, URL blocked, HTTP 4xx (non-auth), HTTP 5xx, network errors, expired credentials |
| `auth_rejected` | Credential was injected but the target server returned 401 or 403 | Distinguishes vault-level success (credential resolved and sent) from target-level auth failure |

**Note on 400 responses:** HTTP 400 (Bad Request) is classified as `failure`, not `auth_rejected`. Only 401 and 403 trigger `auth_rejected` status.

### Audit Event Fields

Every audit event contains:

| Field | Type | Description |
|---|---|---|
| `event_id` | string | Unique monotonic identifier (`evt_000001`, `evt_000002`, ...) |
| `event_type` | string | One of the event types above |
| `alias` | string | The credential alias involved |
| `status` | string | One of: `success`, `failure`, `auth_rejected` |
| `source` | string | Where the event originated: `cli` or `mcp` |
| `details` | object | Context-specific data (URL, method, status code, etc.) |
| `timestamp` | float | Unix timestamp |
| `prev_hash` | string | Hash of the previous event (chain linkage) |
| `hash` | string | HMAC-SHA-256 hash of this event |

The `details` object may contain:

| Field | Context | Description |
|---|---|---|
| `reason` | Failure events | System reason (e.g., `url_not_allowed`, `credential_expired`, `not_found`) |
| `agent_reason` | Any event with a stated reason | The LLM agent's stated justification for the request |
| `url` | HTTP requests | Target URL |
| `method` | HTTP requests | HTTP method used |
| `status_code` | HTTP requests | Response status code from the target server |
| `expired_at` | Expired credentials | When the credential expired |


## Reporting Vulnerabilities

If you discover a security vulnerability, please report it responsibly
by opening a GitHub issue tagged `security` or contacting the maintainer directly.
