"""Tests for strict URL allowlist matching."""

import pytest

from coffer_mcp.security import check_url_allowed
from coffer_mcp.store.encrypted_store import CredentialEntry


@pytest.fixture
def api_entry():
    return CredentialEntry(
        alias="api",
        auth_type="bearer_token",
        secret="token",
        allowed_urls=["https://api.example.com/*"],
    )


class TestStrictUrlMatching:
    def test_exact_domain_match(self, api_entry):
        """URL with exact domain should be allowed."""
        assert check_url_allowed(api_entry, "https://api.example.com/data") is True

    def test_subdomain_blocked(self, api_entry):
        """Subdomains should NOT match (strict domain matching)."""
        assert check_url_allowed(api_entry, "https://evil.api.example.com/data") is False

    def test_similar_domain_blocked(self, api_entry):
        """Similar but different domains should be blocked."""
        assert check_url_allowed(api_entry, "https://api.example.com.evil.com/data") is False

    def test_scheme_mismatch_blocked(self, api_entry):
        """HTTP when HTTPS is required should be blocked."""
        assert check_url_allowed(api_entry, "http://api.example.com/data") is False

    def test_path_traversal_normalized(self, api_entry):
        """Path traversal attempts should be normalized."""
        # /../ should be collapsed before matching
        assert check_url_allowed(api_entry, "https://api.example.com/a/../data") is True

    def test_path_wildcard_matches(self, api_entry):
        """Wildcard in path pattern should match subpaths."""
        assert check_url_allowed(api_entry, "https://api.example.com/v1/users") is True
        assert check_url_allowed(api_entry, "https://api.example.com/deeply/nested/path") is True

    def test_root_path_matches_wildcard(self, api_entry):
        """Root path should match /* pattern."""
        assert check_url_allowed(api_entry, "https://api.example.com/") is True

    def test_query_params_ignored(self, api_entry):
        """Query parameters should not affect matching."""
        assert check_url_allowed(api_entry, "https://api.example.com/data?key=val") is True

    def test_port_must_match(self):
        """Port in URL must match port in pattern."""
        entry = CredentialEntry(
            alias="ported",
            auth_type="bearer_token",
            secret="t",
            allowed_urls=["https://api.example.com:8443/*"],
        )
        assert check_url_allowed(entry, "https://api.example.com:8443/data") is True
        assert check_url_allowed(entry, "https://api.example.com/data") is False
        assert check_url_allowed(entry, "https://api.example.com:9999/data") is False

    def test_multiple_patterns(self):
        """Multiple allowlist patterns should each be checked."""
        entry = CredentialEntry(
            alias="multi",
            auth_type="bearer_token",
            secret="t",
            allowed_urls=[
                "https://api.example.com/v1/*",
                "https://api.example.com/v2/*",
            ],
        )
        assert check_url_allowed(entry, "https://api.example.com/v1/users") is True
        assert check_url_allowed(entry, "https://api.example.com/v2/data") is True
        assert check_url_allowed(entry, "https://api.example.com/v3/nope") is False

    def test_empty_allowlist_blocks_all(self):
        """Empty allowlist should block everything (fail-closed)."""
        entry = CredentialEntry(
            alias="locked",
            auth_type="bearer_token",
            secret="t",
            allowed_urls=[],
        )
        assert check_url_allowed(entry, "https://api.example.com/data") is False
        assert check_url_allowed(entry, "https://localhost/anything") is False
