"""Tests for P2 fixes: input validation and response size limits."""

from coffer_mcp.security import (
    MAX_RESPONSE_BYTES,
    MAX_WAIT_AFTER_LOGIN_MS,
    VALID_HTTP_METHODS,
    validate_css_selector,
    validate_http_method,
    validate_oauth2_secret,
    validate_wait_after_login,
)

# ===========================================================================
# HTTP method validation
# ===========================================================================


class TestValidateHttpMethod:
    def test_valid_methods_accepted(self):
        for m in ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]:
            assert validate_http_method(m) == m

    def test_lowercase_normalized(self):
        assert validate_http_method("get") == "GET"
        assert validate_http_method("post") == "POST"

    def test_whitespace_stripped(self):
        assert validate_http_method("  GET  ") == "GET"

    def test_invalid_method_rejected(self):
        assert validate_http_method("CONNECT") is None
        assert validate_http_method("TRACE") is None
        assert validate_http_method("FOOBAR") is None
        assert validate_http_method("") is None

    def test_injection_attempt_rejected(self):
        assert validate_http_method("GET\r\nX-Injected: yes") is None


# ===========================================================================
# CSS selector validation
# ===========================================================================


class TestValidateCssSelector:
    def test_valid_selectors(self):
        assert validate_css_selector('input[name="username"]') is not None
        assert validate_css_selector("button.submit") is not None
        assert validate_css_selector("#login-btn") is not None
        assert validate_css_selector('button:has-text("Log In")') is not None

    def test_empty_rejected(self):
        assert validate_css_selector("") is None
        assert validate_css_selector("   ") is None

    def test_script_injection_rejected(self):
        assert validate_css_selector("<script>alert(1)</script>") is None
        assert validate_css_selector("input[onerror=alert(1)]") is None
        assert validate_css_selector('div[style="expression(alert(1))"]') is None

    def test_javascript_uri_rejected(self):
        assert validate_css_selector('a[href="javascript:alert(1)"]') is None

    def test_unbalanced_quotes_rejected(self):
        assert validate_css_selector('input[name="foo]') is None
        assert validate_css_selector("input[name='foo]") is None

    def test_balanced_quotes_accepted(self):
        assert validate_css_selector('input[name="foo"]') is not None
        assert validate_css_selector("input[name='foo']") is not None


# ===========================================================================
# wait_after_login bounds
# ===========================================================================


class TestValidateWaitAfterLogin:
    def test_normal_value_unchanged(self):
        assert validate_wait_after_login(5000) == 5000

    def test_negative_clamped_to_zero(self):
        assert validate_wait_after_login(-100) == 0

    def test_excessive_clamped_to_max(self):
        assert validate_wait_after_login(999_999) == MAX_WAIT_AFTER_LOGIN_MS

    def test_zero_accepted(self):
        assert validate_wait_after_login(0) == 0

    def test_max_accepted(self):
        assert validate_wait_after_login(MAX_WAIT_AFTER_LOGIN_MS) == MAX_WAIT_AFTER_LOGIN_MS


# ===========================================================================
# OAuth2 secret format validation
# ===========================================================================


class TestValidateOauth2Secret:
    def test_valid_full_format(self):
        result = validate_oauth2_secret(
            "myid|mysecret",
            "https://auth.example.com/token|read write",
        )
        assert result is not None
        client_id, client_secret, token_url, scope = result
        assert client_id == "myid"
        assert client_secret == "mysecret"
        assert token_url == "https://auth.example.com/token"
        assert scope == "read write"

    def test_valid_minimal_format(self):
        result = validate_oauth2_secret("myid", "https://auth.example.com/token")
        assert result is not None
        client_id, client_secret, token_url, scope = result
        assert client_id == "myid"
        assert client_secret == ""
        assert token_url == "https://auth.example.com/token"
        assert scope == ""

    def test_empty_secret_rejected(self):
        assert validate_oauth2_secret("myid", "") is None

    def test_non_url_secret_rejected(self):
        assert validate_oauth2_secret("myid", "not-a-url") is None
        assert validate_oauth2_secret("myid", "ftp://wrong.com/token") is None

    def test_empty_client_id_rejected(self):
        assert validate_oauth2_secret("", "https://auth.example.com/token") is None
        assert validate_oauth2_secret("|secret", "https://auth.example.com/token") is None

    def test_http_url_accepted(self):
        """http:// should be accepted (for local dev/testing)."""
        result = validate_oauth2_secret("myid", "http://localhost:8080/token")
        assert result is not None


# ===========================================================================
# Response size constant
# ===========================================================================


class TestResponseSizeLimit:
    def test_max_response_bytes_is_10mb(self):
        assert MAX_RESPONSE_BYTES == 10 * 1024 * 1024

    def test_valid_methods_set(self):
        assert "GET" in VALID_HTTP_METHODS
        assert "POST" in VALID_HTTP_METHODS
        assert "TRACE" not in VALID_HTTP_METHODS
        assert "CONNECT" not in VALID_HTTP_METHODS
