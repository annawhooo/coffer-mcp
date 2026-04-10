# Example Audit Data

Synthetic audit log for testing coffer-detect detection rules. Contains 25 events across two phases:

## Phase 1: Normal Baseline (events 1-12)

Standard credential lifecycle: create 3 credentials, list, test, use for legitimate API calls. All events include `agent_reason` (Layer 2 context binding). Content lengths are typical (150-4500 bytes). Timing is unhurried.

## Phase 2: Anomalous Activity (events 13-25)

Six deliberate anomalies embedded in the log:

| Events | Anomaly | Expected Rule | Severity |
|--------|---------|---------------|----------|
| 13-15 | 3 credentials tested in 16 seconds | Rule 004: Credential Enumeration | MEDIUM |
| 16 | 1.3MB response (300x baseline median) | Rule 011: Content Volume Spike | MEDIUM |
| 17 | github-api used against stripe URL | Rule 013: Auth Status Mismatch | MEDIUM-HIGH |
| 18-19 | Requests with no agent_reason | Rule 017: Missing Reason | MEDIUM |
| 20-23 | 4 credentials created in 3 minutes | Rule 006: Burst Credential Creation | MEDIUM |
| 24-25 | stripe-test removed and re-created 28s later | Rule 012: Credential Lifecycle Anomaly | MEDIUM |

## Usage

```bash
# Run detection against this log
python detect/coffer_detect_v03.py --input examples/example-audit.jsonl
```

## Notes

- All data is synthetic. No real credentials, URLs, or API responses.
- HMAC chain is intact (no Rule 001 violations by design).
- Aliases are generic (github-api, stripe-test, internal-api, temp-api-N).
