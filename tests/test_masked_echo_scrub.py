"""Tests for masked echo / prefix-suffix leakage scrubbing (Fix A).

Covers _scrub_masked_echoes directly and end-to-end through sanitize_response.
"""

import pytest

from coffer_mcp.security import _scrub_masked_echoes, sanitize_response
from coffer_mcp.store.encrypted_store import CredentialEntry

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def stripe_entry():
    """Stripe-style test API key credential."""
    return CredentialEntry(
        alias="stripe-test",
        auth_type="bearer_token",
        secret="sl_test_abc123def456ghi7890",
        allowed_urls=["https://api.stripe.com/*"],
        allowed_methods=["GET"],
    )


@pytest.fixture
def github_entry():
    """GitHub PAT-style credential."""
    return CredentialEntry(
        alias="gh-pat",
        auth_type="bearer_token",
        secret="ghp_a1b2c3d4e5f6g7h8i9j0klmnopqrst",
        allowed_urls=["https://api.github.com/*"],
        allowed_methods=["GET"],
    )


@pytest.fixture
def aws_entry():
    """AWS access key style credential."""
    return CredentialEntry(
        alias="aws-key",
        auth_type="api_key_header",
        secret="AKIAIOSFODNN7EXAMPLE",
        allowed_urls=["https://sts.amazonaws.com/*"],
        allowed_methods=["GET"],
    )


@pytest.fixture
def short_entry():
    """Short secret — should NOT trigger masked echo scrubbing."""
    return CredentialEntry(
        alias="short",
        auth_type="bearer_token",
        secret="abc1234",  # 7 chars, below _MIN_SECRET_LEN_FOR_FRAGMENT_SCRUB
    )


# ---------------------------------------------------------------------------
# Direct tests on _scrub_masked_echoes
# ---------------------------------------------------------------------------


class TestMaskedEchoDirect:
    """Test _scrub_masked_echoes in isolation."""

    def test_stripe_full_mask(self):
        """Stripe pattern: prefix + asterisks + last 4 digits."""
        secret = "sl_test_abc123def456ghi7890"
        text = (
            '{"error": {"message": "Invalid API Key provided: sl_test_**********************7890"}}'
        )
        result = _scrub_masked_echoes(text, secret)
        assert "sl_test_" not in result
        assert "7890" not in result
        assert "[REDACTED]" in result

    def test_prefix_only_mask(self):
        """Server masks everything after the prefix."""
        secret = "sk-live-abc123xyz789foobar"
        text = "Key sk-live-**************** is invalid"
        result = _scrub_masked_echoes(text, secret)
        assert "sk-live-" not in result
        assert "[REDACTED]" in result

    def test_suffix_only_mask(self):
        """Server shows only the last chars with long mask prefix."""
        secret = "ghp_a1b2c3d4e5f6g7h8i9j0klmnopqrst"
        # suffix is "qrst" (last 4), mask is 8+ chars
        text = "Token **************qrst was revoked"
        result = _scrub_masked_echoes(text, secret)
        assert "qrst" not in result
        assert "[REDACTED]" in result

    def test_dot_mask_chars(self):
        """Some APIs use dots instead of asterisks."""
        secret = "sl_test_abc123def456ghi7890"
        text = "Invalid key: sl_test_......................7890"
        result = _scrub_masked_echoes(text, secret)
        assert "sl_test_" not in result
        assert "[REDACTED]" in result

    def test_bullet_mask_chars(self):
        """Unicode bullet (•) used as mask fill."""
        secret = "sl_test_abc123def456ghi7890"
        bullets = "\u2022" * 22
        text = f"Invalid key: sl_test_{bullets}7890"
        result = _scrub_masked_echoes(text, secret)
        assert "sl_test_" not in result
        assert "[REDACTED]" in result

    def test_short_secret_skipped(self):
        """Secrets < 8 chars should not trigger masked echo scrubbing."""
        secret = "abc1234"  # 7 chars
        text = "abc1****234 something"
        result = _scrub_masked_echoes(text, secret)
        assert result == text  # unchanged

    def test_clean_response_unchanged(self):
        """Response with no credential fragments passes through."""
        secret = "sl_test_abc123def456ghi7890"
        text = '{"status": "ok", "data": [1, 2, 3]}'
        result = _scrub_masked_echoes(text, secret)
        assert result == text

    def test_suffix_only_short_mask_no_match(self):
        """Suffix with < 8 mask chars should NOT match (false positive guard)."""
        secret = "ghp_a1b2c3d4e5f6g7h8i9j0klmnopqrst"
        # Only 3 asterisks before suffix — too short for pattern 3
        text = "Code ***qrst found in log"
        result = _scrub_masked_echoes(text, secret)
        assert result == text  # unchanged — not enough mask chars

    def test_multiple_masked_echoes(self):
        """Multiple masked echoes in one response body."""
        secret = "sl_test_abc123def456ghi7890"
        text = (
            'First: "sl_test_**********************7890", second: "sl_test_**********************"'
        )
        result = _scrub_masked_echoes(text, secret)
        assert "sl_test_" not in result
        assert result.count("[REDACTED]") == 2

    def test_mask_x_chars(self):
        """Literal 'x' characters used as mask fill."""
        secret = "sl_test_abc123def456ghi7890"
        text = "Key: sl_test_xxxxxxxxxxxxxxxxxxxxxx7890"
        result = _scrub_masked_echoes(text, secret)
        assert "sl_test_" not in result
        assert "[REDACTED]" in result


# ---------------------------------------------------------------------------
# End-to-end through sanitize_response
# ---------------------------------------------------------------------------


class TestMaskedEchoEndToEnd:
    """Verify masked echo scrubbing fires through the public sanitize_response API."""

    def test_stripe_401_response(self, stripe_entry):
        """Reproduce the exact Stripe 401 scenario that prompted Fix A."""
        response = (
            '{"error": {"message": '
            '"Invalid API Key provided: sl_test_**********************7890", '
            '"type": "invalid_request_error"}}'
        )
        sanitized = sanitize_response(response, stripe_entry)
        assert "sl_test_" not in sanitized
        assert "7890" not in sanitized
        assert "[REDACTED]" in sanitized
        # The rest of the JSON structure should survive
        assert "invalid_request_error" in sanitized

    def test_github_masked_echo(self, github_entry):
        """GitHub-style masked token in error response."""
        response = (
            '{"message": "Bad credentials", "token": "ghp_a1b2****************************qrst"}'
        )
        sanitized = sanitize_response(response, github_entry)
        assert "ghp_a1b2" not in sanitized
        assert "qrst" not in sanitized
        assert "[REDACTED]" in sanitized

    def test_aws_masked_echo(self, aws_entry):
        """AWS-style masked access key."""
        response = "The security token included in the request is invalid: AKIA********MPLE"
        # Secret is AKIAIOSFODNN7EXAMPLE — derived prefix is "AKIAIO" (6 chars),
        # suffix is "MPLE" (4 chars). The server only echoed 4 prefix chars ("AKIA"),
        # so Pattern 1 (prefix+mask+suffix) won't match. Pattern 3 (mask+suffix)
        # WILL match and scrub "********MPLE", leaving a 4-char residual "AKIA".
        # This is a known limitation — Fix C (generic key patterns) would catch it.
        sanitized = sanitize_response(response, aws_entry, extra_secrets=["AKIAIOSFODNN7EXAMPLE"])
        assert "MPLE" not in sanitized
        assert "[REDACTED]" in sanitized

    def test_extra_secrets_masked_echo(self, stripe_entry):
        """Masked echoes of extra_secrets (e.g., OAuth2 tokens) are also caught."""
        oauth_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.long_payload_here"
        response = 'Token "eyJhbGc************************here" is expired'
        # Derived prefix is "eyJhbGci" (8 chars) but server echoed 7.
        # Pattern 3 (mask+suffix) catches "************************here",
        # leaving a 7-char prefix residual "eyJhbGc".
        sanitized = sanitize_response(response, stripe_entry, extra_secrets=[oauth_token])
        assert "here" not in sanitized
        assert "[REDACTED]" in sanitized

    def test_clean_response_unchanged(self, stripe_entry):
        """Responses with no credential fragments should pass through unchanged."""
        response = '{"users": [{"name": "Alice"}, {"name": "Bob"}]}'
        sanitized = sanitize_response(response, stripe_entry)
        assert sanitized == response

    def test_short_secret_no_masked_scrub(self, short_entry):
        """Short secrets should not trigger masked echo scrubbing."""
        response = "abc1****234 something"
        sanitized = sanitize_response(response, short_entry)
        # The exact secret "abc1234" isn't in this response, so nothing changes
        assert sanitized == response

    def test_exact_and_masked_both_scrubbed(self, stripe_entry):
        """Response contains both the exact secret AND a masked echo."""
        response = (
            'Key "sl_test_abc123def456ghi7890" failed. Masked: sl_test_**********************7890'
        )
        sanitized = sanitize_response(response, stripe_entry)
        assert "sl_test_" not in sanitized
        assert "abc123" not in sanitized
        assert "7890" not in sanitized
        assert sanitized.count("[REDACTED]") >= 2
