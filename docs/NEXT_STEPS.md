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

## Tier 3 — Enterprise readiness

| # | Item | Status | Effort |
|---|------|--------|--------|
| 9 | **Secret rotation automation** — webhook/plugin architecture for automated key rotation with provider APIs | TODO | 1-2 weeks |
| 10 | **Compliance alignment** — mapping to NIST 800-53 SC-28, SOC 2 CC6.1; document which controls are satisfied | TODO | 1-2 days |
| 11 | **Observability** — alerting (N failed auths = lockout), metrics (usage frequency, latency), SIEM/syslog/OpenTelemetry export | TODO | 1 week |
| 12 | **Multi-user / team support** — RBAC, key escrow, shared vaults; or explicitly document single-user boundary | TODO | Evaluate |

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
