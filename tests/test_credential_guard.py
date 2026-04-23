"""Tests for credential_guard, including regression coverage for the
log_violation -> AuditLogger integration that used to crash with
`'AuditLogger' object has no attribute 'log_lifecycle'`.
"""

from coffer_mcp.audit.logger import AuditLogger
from coffer_mcp.credential_guard import (
    check_for_secrets,
    create_rejection_response,
    log_violation,
)


def test_log_violation_writes_audit_event(tmp_path):
    audit = AuditLogger(log_path=tmp_path / "audit.jsonl")
    violation = {
        "error": "CREDENTIAL_VALUE_DETECTED",
        "details": "...",
        "pattern": "AWS Secret Key",
        "param_path": "url",
    }
    event = log_violation(violation, logger=audit)
    assert event["pattern"] == "AWS Secret Key"
    entries = audit.get_events()
    assert len(entries) == 1
    assert entries[0]["event_type"] == "credential.exposure_attempt"
    assert entries[0]["status"] == "failure"


def test_log_violation_without_logger_does_not_raise():
    violation = {"pattern": "JWT", "param_path": "headers.Authorization"}
    event = log_violation(violation, logger=None)
    assert event["pattern"] == "JWT"


def test_uuid_in_url_path_does_not_trip_aws_secret_key_pattern():
    url = (
        "https://api.example.com/assessment/v2/assessments/"
        "60521f35-4135-4d39-8d58-043ca767d5bc/export"
    )
    assert check_for_secrets({"url": url}) is None


def test_aws_secret_key_pattern_rejects_common_url_shapes():
    benign = [
        {"url": "https://example.com/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/v/w/x/y/z"},
        {"url": "https://example.com/60521f35-4135-4d39-8d58-043ca767d5bc"},
        {"value": "abcdefghijklmnopqrstuvwxyzabcdefghijklmn"},
        {"value": "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMN"},
        {"value": "0123456789012345678901234567890123456789"},
    ]
    for params in benign:
        assert check_for_secrets(params) is None, params


def test_aws_secret_key_pattern_still_matches_real_key_shapes():
    aws = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    for template in [
        f'"secret_access_key": "{aws}"',
        f"aws_secret: {aws}",
        f"?token={aws}",
        f"Cookie: session={aws}; path=/",
        aws,
    ]:
        v = check_for_secrets({"value": template})
        assert v is not None, f"expected match in: {template}"
        assert v["pattern"] == "AWS Secret Key"


def test_log_violation_and_guard_end_to_end_does_not_crash(tmp_path):
    audit = AuditLogger(log_path=tmp_path / "audit.jsonl")
    aws = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    violation = check_for_secrets({"body": f'{{"secret": "{aws}"}}'})
    assert violation is not None
    log_violation(violation, logger=audit)
    rejection = create_rejection_response(violation)
    assert rejection["isError"] is True
