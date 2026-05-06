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


# Test fixtures are built by concatenation rather than literal strings so
# GitHub secret scanning doesn't pattern-match them as real Stripe keys.
# The runtime value is identical; only the source representation differs.
_STRIPE_BODY = "EXAMPLE" + "abcdefghijklmnopqrstuvwx"


def test_stripe_secret_key_live_detected():
    """Bare Stripe secret key (sk_live_...) must trip the Stripe pattern.

    Regression: previously the OpenAI pattern (sk-...) was claimed to cover
    Stripe in its description, but Stripe uses an underscore between prefix
    and body. Bare Stripe keys passed through unless wrapped in key=value
    form.
    """
    stripe_key = "sk" + "_live_" + _STRIPE_BODY
    v = check_for_secrets({"value": stripe_key})
    assert v is not None
    assert v["pattern"] == "Stripe API Key"


def test_stripe_secret_key_test_detected():
    """sk_test_ keys are also secret and must be detected."""
    stripe_key = "sk" + "_test_" + _STRIPE_BODY
    v = check_for_secrets({"value": stripe_key})
    assert v is not None
    assert v["pattern"] == "Stripe API Key"


def test_stripe_restricted_key_detected():
    """Restricted keys (rk_live_, rk_test_) are also secret and must be
    detected."""
    for prefix_letters, environment in (("rk", "live"), ("rk", "test")):
        stripe_key = f"{prefix_letters}_{environment}_{_STRIPE_BODY}"
        v = check_for_secrets({"value": stripe_key})
        assert v is not None, f"expected match for {prefix_letters}_{environment}_"
        assert v["pattern"] == "Stripe API Key"


def test_stripe_publishable_key_not_flagged():
    """Publishable keys (pk_live_, pk_test_) are intentionally public and
    must NOT be flagged. Flagging them would produce false positives on
    every legitimate Stripe integration that includes them in client-side
    code, configuration, or fixtures."""
    for prefix_letters, environment in (("pk", "live"), ("pk", "test")):
        publishable = f"{prefix_letters}_{environment}_{_STRIPE_BODY}"
        v = check_for_secrets({"value": publishable})
        assert v is None, f"{prefix_letters}_{environment}_ should not be flagged but was: {v}"


def test_stripe_key_in_nested_dict():
    """Stripe key buried in nested config still detected (recursive scan)."""
    stripe_key = "sk" + "_live_" + _STRIPE_BODY
    params = {"alias": "stripe", "config": {"keys": {"secret": stripe_key}}}
    v = check_for_secrets(params)
    assert v is not None
    assert v["pattern"] == "Stripe API Key"


def test_openai_key_still_detected_separately():
    """The OpenAI/Stripe split must not regress OpenAI detection."""
    openai_key = "sk-" + "EXAMPLEabc123def456ghi789jkl012mno"
    v = check_for_secrets({"value": openai_key})
    assert v is not None
    assert v["pattern"] == "OpenAI API Key"
