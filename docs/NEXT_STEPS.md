# Coffer MCP — Next Steps (Security & Architecture)

*Generated 2026-03-25 from principal security architect review*

---

## Tier 1 — Critical risks

| # | Item | Status | Effort |
|---|------|--------|--------|
| 1 | **Formal threat model (STRIDE on MCP boundary)** — structured analysis of trust boundaries, attack surfaces, and the novel LLM↔credential-store interface | ✅ DONE | 1-2 days |
| 2 | **Dependency supply chain** — pin versions with hashes, add pip-audit to CI, evaluate whether readability-lxml/html2text C extensions are worth the attack surface | ✅ DONE | Half day |
| 3 | **Memory handling of secrets** — SecureBuffer zeroing, wipe_entry after use, core dump disabled, mlock. Residual: Python str immutability (see THREAT_MODEL.md Appendix A) | ✅ DONE | Half day |
| 4 | **MCP trust boundary hardening** — prompt injection in fetched pages could instruct Claude to exfiltrate credentials via coffer_http_request; URL allowlist is the only defense | ✅ DONE | Evaluate |

## Tier 2 — Architectural maturity

| # | Item | Status | Effort |
|---|------|--------|--------|
| 5 | **End-to-end MCP integration tests** — start server, send tools/call requests, verify responses at the protocol boundary | ✅ DONE | 1-2 days |
| 6 | **Property-based testing / fuzzing** — Hypothesis for encrypt/decrypt round-trip, URL allowlist invariants, backup import crash resistance, CSS selector fuzzing | ✅ DONE | 1-2 days |
| 7 | **Mutation testing** — cosmic-ray to verify tests actually catch bugs (100% mutation kill rate) | ✅ DONE | Half day |
| 8 | **File permissions hardening** — set 0600 on credentials.json and audit.jsonl on creation; Windows ACLs for current user only | ✅ DONE | 1 hour |

## Tier 2.5 — Open High residual risks (from THREAT_MODEL.md §6)

*Added 2026-07-14: these were recommended in the threat model (P2-2/P2-3/P2-4) but never carried into this task list. Verified still open against the code on 2026-07-14. Priority: ahead of all Tier 3 items, including #14 (coffer_exec), which should not land on top of an audit chain that can't detect truncation.*

| # | Item | Status | Effort |
|---|------|--------|--------|
| 15 | **RR-H5: Audit log truncation detection** — HMAC-protected checkpoint sidecar (`audit.jsonl.state`) advanced on every append; `verify_chain()` fails on tail truncation, full wipe, tampered checkpoint, or a checkpoint more than one entry behind (crash window tolerated). Residual: attacker who captures and replays an old checkpoint matching a truncated tail is undetectable without an external anchor. (Threat model P2-4) | ✅ DONE 2026-07-14 | Medium |
| 16 | **RR-H6: Integrity-protect plaintext metadata** — AAD now covers all plaintext metadata (`alias`, `auth_type`, `description`, `created_at`, `rotated_at`, `expires_at`). Ordered legacy fallback (alias-only, then no-AAD) succeeds only for genuinely-legacy blobs and warns; `migrate_aad()` upgrades in place, exposed as `coffer migrate` in the CLI (audited as `vault.aad_migrated`). Retiring the fallbacks entirely (RR-L6) still open. (Threat model P2-2) | ✅ DONE 2026-07-14 | Medium |
| 17 | **RR-H4: Rate limiting on MCP tool calls** — per-alias sliding window (default 60 req/alias/min, env-overridable via `COFFER_RATE_LIMIT_MAX`/`_WINDOW`) enforced in the server layer on all four credential-using tools, before credential resolution. Rejections return structured `RATE_LIMITED` errors with retry-after and are audited as `rate.limited`; rejected attempts don't consume window slots. (Threat model P2-3) | ✅ DONE 2026-07-14 | Medium |

## Tier 3 — Enterprise readiness

| # | Item | Status | Effort |
|---|------|--------|--------|
| 9 | **Secret rotation automation** — webhook/plugin architecture for automated key rotation with provider APIs | TODO | 1-2 weeks |
| 10 | **Compliance alignment** — mapping to NIST 800-53 SC-28, SOC 2 CC6.1; document which controls are satisfied | TODO | 1-2 days |
| 11 | **Observability** — alerting (N failed auths = lockout), metrics (usage frequency, latency), SIEM/syslog/OpenTelemetry export | TODO | 1 week |
| 12 | **Multi-user / team support** — RBAC, key escrow, shared vaults; or explicitly document single-user boundary | TODO | Evaluate |
| 13 | **Fix C: Generic API key pattern scanning** — response body scan for common key patterns (`sk_test_*`, `ghp_*`, `AKIA*`, etc.) regardless of whether they match the stored secret. Catches keys the sanitizer doesn't know about. | TODO | Half day |
| 14 | **coffer_exec: scoped subprocess credential injection** — new tool + new trust boundary (TB-7: Server ↔ Local Subprocess). Motivating case: interactive Playwright scrapers that must own the browser session, which coffer_web_login/web_fetch cannot serve. Design constraints: (a) per-alias `allowed_commands` allowlist, same shape and fail-closed semantics as `allowed_urls`; (b) credential resolved server-side and passed via child process environment only — never argv (process-listing exposure), never temp files; (c) server spawns only the allowlisted command, waits for exit, then wipes; (d) audited like every other credential use, with `agent_reason`; (e) STRIDE pass on TB-7 added to THREAT_MODEL.md **before** implementation (env inheritance by grandchild processes, Windows process-listing exposure, command tampering between allowlist check and spawn, stdout/stderr sanitization before return to LLM). Aligns with the subprocess-isolation direction already named in THREAT_MODEL.md Appendix A residual risks. | TODO | 1-2 days |

## Completed work

| Item | Date |
|------|------|
| P0: File locking, AAD encryption, thread-safe globals | 2026-03-25 |
| P1: Atomic backups, expanded scrubbing, HMAC audit warning | 2026-03-25 |
| P2: Input validation, response size limits | 2026-03-25 |
| P3: Key rotation (coffer rekey) | 2026-03-25 |
| CI/CD: GitHub Actions lint + 12-job test matrix | 2026-03-25 |
| README update | 2026-03-25 |
| Expanded test suite (51 tests — Unicode/IDN, concurrency, corrupted backup, edge cases) | 2026-03-25 |
| File permissions hardening (0600/0700 on store, audit, backups) | 2026-03-25 |
| Dependency supply chain: pip-audit in CI + pinned lockfile | 2026-03-25 |
| STRIDE threat model (docs/THREAT_MODEL.md) | 2026-03-25 |
| Fix #1: login_url allowlist enforcement in web_login/web_fetch | 2026-03-25 |
| Fix #2: OAuth2 access token sanitization from responses | 2026-03-25 |
| MCP trust boundary: URL allowlist on all credential-using tools | 2026-03-25 |
| Secure memory: SecureBuffer, wipe_entry, harden_process + residual risk docs | 2026-03-25 |
| E2E MCP integration tests (TestCofferHttpRequest, TestCofferWebFetch, etc.) | 2026-03-26 |
| Property-based testing with Hypothesis (encrypt/decrypt round-trip, allowlist invariants) | 2026-03-26 |
| Mutation testing with cosmic-ray (100% kill rate) | 2026-03-26 |
| Structured error codes, MCP ToolAnnotations, store format versioning | 2026-03-26 |
| Fix: httpx.AsyncClient patch target in E2E tests | 2026-03-27 |
| Fix A: Masked echo scrubbing (prefix/suffix leakage from API error responses) | 2026-04-04 |
| Fix: Duplicate event IDs between CLI and MCP (re-read counter under lock) | 2026-04-04 |
| Fix: Reason field schema — standardized to `agent_reason` across all event types | 2026-04-04 |
| Enhancement: Source tagging (`cli`/`mcp`) in all audit events | 2026-04-04 |
| Enhancement: Capture `agent_reason` in expired credential events | 2026-04-04 |
| Docs: Audit event reference (event types, status values, field schema) | 2026-04-04 |
| Docs: Default-deny behavior for empty `--allowed-urls` | 2026-04-04 |
| RR-H5: Audit truncation detection (HMAC checkpoint sidecar + verify_chain tail check) | 2026-07-14 |
| RR-H6: Full-metadata AAD + migrate_aad() (tamper-evident expires_at/auth_type/description) | 2026-07-14 |
| Fix: stale comment in browser/__init__.py (claimed httpx-only, is Playwright bridge) | 2026-07-14 |
| CLI: `coffer migrate` command wiring migrate_aad() (reports legacy-upgraded count, audited) | 2026-07-14 |
| RR-H4: Per-alias sliding-window rate limiting on credential-using MCP tools | 2026-07-14 |
