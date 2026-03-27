"""
Property-based tests using Hypothesis.

These tests verify invariants that must hold for ALL inputs, not just
hand-picked examples. They are especially valuable for:
  - Encryption round-trip (any bytes in -> same bytes out)
  - URL allowlist (never allows what it shouldn't)
  - Backup import/export (never crashes, always round-trips)
  - CSS selector validation (never passes injection)
  - Input validation (never crashes on arbitrary input)
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from coffer_mcp.security import (
    MAX_WAIT_AFTER_LOGIN_MS,
    VALID_HTTP_METHODS,
    check_url_allowed,
    sanitize_content,
    validate_css_selector,
    validate_http_method,
    validate_wait_after_login,
)
from coffer_mcp.store.encrypted_store import CredentialEntry, EncryptedStore

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Printable strings for secrets (avoid null bytes which break JSON)
secret_text = st.text(
    alphabet=st.characters(
        blacklist_categories=("Cs",),  # no surrogates
        blacklist_characters=("\x00",),
    ),
    min_size=1,
    max_size=500,
)

# Valid aliases (alphanumeric + dash/underscore)
alias_st = st.from_regex(r"[a-zA-Z][a-zA-Z0-9_-]{0,30}", fullmatch=True)

# URLs for allowlist testing
url_st = st.from_regex(
    r"https?://[a-z0-9.-]{1,50}(:[0-9]{1,5})?(/[a-zA-Z0-9._/-]{0,100})?",
    fullmatch=True,
)


# ---------------------------------------------------------------------------
# Encrypt/Decrypt round-trip
# ---------------------------------------------------------------------------


class TestEncryptDecryptRoundTrip:
    """The core invariant: encrypt(decrypt(x)) == x for all valid inputs."""

    @given(
        secret=secret_text,
        username=secret_text,
        alias=alias_st,
    )
    @settings(
        max_examples=200,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow],
    )
    def test_roundtrip_preserves_data(self, secret, username, alias):
        """Any valid secret+username must survive encrypt -> decrypt."""
        with tempfile.TemporaryDirectory() as td:
            key = os.urandom(32)
            store = EncryptedStore(key, Path(td) / "creds.json")
            entry = CredentialEntry(
                alias=alias,
                auth_type="bearer_token",
                username=username,
                secret=secret,
                allowed_urls=["https://example.com/*"],
            )
            store.add(entry)

            recovered = store.get(alias)
            assert recovered is not None
            assert recovered.secret == secret
            assert recovered.username == username
            assert recovered.alias == alias

    @given(data=st.binary(min_size=0, max_size=1000))
    @settings(
        max_examples=100,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow],
    )
    def test_arbitrary_bytes_in_secret(self, data):
        """Even raw bytes (base64-encoded) must round-trip."""
        import base64

        with tempfile.TemporaryDirectory() as td:
            secret = base64.b64encode(data).decode("ascii")
            key = os.urandom(32)
            store = EncryptedStore(key, Path(td) / "creds.json")
            store.add(
                CredentialEntry(
                    alias="bintest",
                    auth_type="bearer_token",
                    secret=secret,
                    allowed_urls=["https://x.com/*"],
                )
            )
            assert store.get("bintest").secret == secret

    @given(secret=secret_text)
    @settings(
        max_examples=50,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow],
    )
    def test_wrong_key_always_fails(self, secret):
        """Decrypting with the wrong key must always fail.

        Note: Uses deadline=None because file I/O + crypto can be slow.
        """
        with tempfile.TemporaryDirectory() as td:
            key1 = os.urandom(32)
            key2 = os.urandom(32)
            path = Path(td) / "creds.json"

            store1 = EncryptedStore(key1, path)
            store1.add(
                CredentialEntry(
                    alias="wrongkey",
                    auth_type="bearer_token",
                    secret=secret,
                    allowed_urls=["https://x.com/*"],
                )
            )

            store2 = EncryptedStore(key2, path)
            with pytest.raises(Exception):
                store2.get("wrongkey")


# ---------------------------------------------------------------------------
# URL allowlist invariants
# ---------------------------------------------------------------------------


class TestUrlAllowlistInvariants:
    """Properties that must always hold for the URL allowlist."""

    @given(url=url_st)
    @settings(max_examples=200)
    def test_empty_allowlist_blocks_everything(self, url):
        """An empty allowlist must block ALL URLs (fail-closed)."""
        entry = CredentialEntry(
            alias="test",
            auth_type="bearer_token",
            secret="s",
            allowed_urls=[],
        )
        assert check_url_allowed(entry, url) is False

    @given(
        scheme=st.sampled_from(["http", "https"]),
        host=st.from_regex(r"[a-z]{3,10}\.[a-z]{2,5}", fullmatch=True),
        path=st.from_regex(r"/[a-z]{1,20}", fullmatch=True),
    )
    @settings(max_examples=200)
    def test_exact_match_always_allowed(self, scheme, host, path):
        """A URL that exactly matches an allowlist entry must be allowed."""
        url = f"{scheme}://{host}{path}"
        entry = CredentialEntry(
            alias="test",
            auth_type="bearer_token",
            secret="s",
            allowed_urls=[url],
        )
        assert check_url_allowed(entry, url) is True

    @given(
        host=st.from_regex(r"[a-z]{3,10}\.[a-z]{2,5}", fullmatch=True),
        path=st.from_regex(r"/[a-z]{1,20}", fullmatch=True),
    )
    @settings(max_examples=200)
    def test_scheme_mismatch_always_blocked(self, host, path):
        """https URL must NOT match http allowlist entry and vice versa."""
        entry = CredentialEntry(
            alias="test",
            auth_type="bearer_token",
            secret="s",
            allowed_urls=[f"https://{host}{path}"],
        )
        assert check_url_allowed(entry, f"http://{host}{path}") is False

    @given(
        allowed_host=st.from_regex(r"[a-z]{3,10}\.[a-z]{2,5}", fullmatch=True),
        attack_prefix=st.from_regex(r"[a-z]{1,5}", fullmatch=True),
    )
    @settings(max_examples=200)
    def test_subdomain_never_matches(self, allowed_host, attack_prefix):
        """evil.example.com must never match an allowlist for example.com."""
        assume(attack_prefix != allowed_host.split(".")[0])
        entry = CredentialEntry(
            alias="test",
            auth_type="bearer_token",
            secret="s",
            allowed_urls=[f"https://{allowed_host}/*"],
        )
        attack_url = f"https://{attack_prefix}.{allowed_host}/anything"
        assert check_url_allowed(entry, attack_url) is False

    @given(
        host=st.from_regex(r"[a-z]{3,10}\.[a-z]{2,5}", fullmatch=True),
    )
    @settings(max_examples=100)
    def test_path_traversal_blocked(self, host):
        """Path traversal (/../) must not escape the allowed path."""
        entry = CredentialEntry(
            alias="test",
            auth_type="bearer_token",
            secret="s",
            allowed_urls=[f"https://{host}/api/*"],
        )
        # Try to escape /api/ via path traversal
        attack = f"https://{host}/api/../secrets/steal"
        # If allowed, the normalized path should still be under /api/
        # (our implementation normalizes paths)
        if check_url_allowed(entry, attack):
            from posixpath import normpath
            from urllib.parse import urlparse

            normalized = normpath(urlparse(attack).path)
            assert normalized.startswith("/api") or normalized == "/api"


# ---------------------------------------------------------------------------
# Backup round-trip
# ---------------------------------------------------------------------------


class TestBackupRoundTrip:
    """Backup export/import must preserve all data."""

    @given(
        secrets=st.lists(secret_text, min_size=1, max_size=5),
    )
    @settings(
        max_examples=30,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow],
    )
    def test_export_import_preserves_all_entries(self, secrets):
        """All credentials must survive export -> import."""
        from coffer_mcp.store.backup import export_vault, import_vault

        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            key = os.urandom(32)
            passphrase = "test-pass-123"
            store = EncryptedStore(key, td_path / "creds.json")

            for i, secret in enumerate(secrets):
                store.add(
                    CredentialEntry(
                        alias=f"entry{i}",
                        auth_type="bearer_token",
                        secret=secret,
                        allowed_urls=["https://x.com/*"],
                    )
                )

            backup_path = td_path / "backup.enc"
            export_vault(store, passphrase, backup_path)

            new_key = os.urandom(32)
            new_store = EncryptedStore(new_key, td_path / "new_creds.json")
            result = import_vault(new_store, passphrase, backup_path)
            assert result["status"] == "ok"

            for i, secret in enumerate(secrets):
                entry = new_store.get(f"entry{i}")
                assert entry is not None
                assert entry.secret == secret


# ---------------------------------------------------------------------------
# CSS selector validation
# ---------------------------------------------------------------------------


class TestCssSelectorFuzzing:
    """validate_css_selector must never pass injection payloads."""

    @given(text=st.text(min_size=0, max_size=500))
    @settings(max_examples=500)
    def test_never_crashes(self, text):
        """validate_css_selector must not crash on any input."""
        result = validate_css_selector(text)
        assert result is None or isinstance(result, str)

    @given(
        payload=st.sampled_from(
            [
                "<script>alert(1)</script>",
                "javascript:alert(1)",
                "img onerror=alert(1)",
                "div onload=alert(1)",
                "expression(alert(1))",
                "url(javascript:alert(1))",
                "eval(document.cookie)",
                "import('evil.js')",
            ]
        ),
        prefix=st.text(max_size=20),
        suffix=st.text(max_size=20),
    )
    def test_injection_always_blocked(self, payload, prefix, suffix):
        """Known injection patterns must always be rejected."""
        result = validate_css_selector(f"{prefix}{payload}{suffix}")
        assert result is None


# ---------------------------------------------------------------------------
# HTTP method validation
# ---------------------------------------------------------------------------


class TestHttpMethodFuzzing:
    """validate_http_method invariants."""

    @given(text=st.text(min_size=0, max_size=100))
    @settings(max_examples=500)
    def test_never_crashes(self, text):
        result = validate_http_method(text)
        assert result is None or result in VALID_HTTP_METHODS

    @given(method=st.sampled_from(list(VALID_HTTP_METHODS)))
    def test_valid_methods_always_accepted(self, method):
        assert validate_http_method(method) == method
        assert validate_http_method(method.lower()) == method
        assert validate_http_method(f"  {method}  ") == method


# ---------------------------------------------------------------------------
# Wait validation
# ---------------------------------------------------------------------------


class TestWaitValidationFuzzing:
    """validate_wait_after_login must always return a safe value."""

    @given(value=st.integers(min_value=-(10**9), max_value=10**9))
    @settings(max_examples=500)
    def test_always_in_safe_range(self, value):
        result = validate_wait_after_login(value)
        assert 0 <= result <= MAX_WAIT_AFTER_LOGIN_MS


# ---------------------------------------------------------------------------
# Content sanitization
# ---------------------------------------------------------------------------


class TestSanitizationInvariants:
    """sanitize_content must handle any input without crashing."""

    @given(text=st.text(min_size=0, max_size=5000))
    @settings(max_examples=200)
    def test_never_crashes(self, text):
        result = sanitize_content(text)
        assert isinstance(result, str)

    @given(text=st.text(min_size=0, max_size=5000))
    @settings(max_examples=200)
    def test_output_no_longer_than_input(self, text):
        """Sanitization removes content; it should never grow the string."""
        result = sanitize_content(text)
        assert len(result) <= len(text)
