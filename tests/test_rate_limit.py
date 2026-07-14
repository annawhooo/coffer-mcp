"""Tests for RR-H4: per-alias sliding-window rate limiting."""

import json
import os
import threading

import pytest

from coffer_mcp.ratelimit import RateLimiter


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


@pytest.fixture
def clock():
    return FakeClock()


class TestRateLimiter:
    def test_allows_up_to_max(self, clock):
        rl = RateLimiter(max_requests=5, window_seconds=60, clock=clock)
        for _ in range(5):
            allowed, retry = rl.check("api-1")
            assert allowed is True
            assert retry == 0.0

    def test_blocks_over_max(self, clock):
        rl = RateLimiter(max_requests=5, window_seconds=60, clock=clock)
        for _ in range(5):
            rl.check("api-1")
        allowed, retry = rl.check("api-1")
        assert allowed is False
        assert retry > 0

    def test_window_slides(self, clock):
        rl = RateLimiter(max_requests=2, window_seconds=60, clock=clock)
        assert rl.check("api-1")[0] is True
        clock.advance(30)
        assert rl.check("api-1")[0] is True
        assert rl.check("api-1")[0] is False
        # First event (t=1000) expires at t=1060
        clock.advance(31)
        assert rl.check("api-1")[0] is True

    def test_retry_after_matches_oldest_event(self, clock):
        rl = RateLimiter(max_requests=1, window_seconds=60, clock=clock)
        rl.check("api-1")
        clock.advance(10)
        allowed, retry = rl.check("api-1")
        assert allowed is False
        assert retry == pytest.approx(50.0)

    def test_aliases_are_independent(self, clock):
        rl = RateLimiter(max_requests=1, window_seconds=60, clock=clock)
        assert rl.check("api-1")[0] is True
        assert rl.check("api-2")[0] is True
        assert rl.check("api-1")[0] is False
        assert rl.check("api-2")[0] is False

    def test_rejections_do_not_consume_slots(self, clock):
        """A flood of rejected calls must not push recovery further out."""
        rl = RateLimiter(max_requests=1, window_seconds=60, clock=clock)
        rl.check("api-1")
        for _ in range(100):
            assert rl.check("api-1")[0] is False
        clock.advance(61)
        assert rl.check("api-1")[0] is True

    def test_invalid_config_rejected(self):
        with pytest.raises(ValueError):
            RateLimiter(max_requests=0)
        with pytest.raises(ValueError):
            RateLimiter(window_seconds=0)

    def test_thread_safety_no_overadmission(self, clock):
        """Concurrent checks must never admit more than max_requests."""
        rl = RateLimiter(max_requests=50, window_seconds=60, clock=clock)
        admitted = []

        def worker():
            for _ in range(20):
                allowed, _ = rl.check("api-1")
                if allowed:
                    admitted.append(1)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(admitted) == 50


class TestServerIntegration:
    @pytest.fixture
    def server(self, monkeypatch, tmp_path):
        """Server module with tiny rate limit and isolated store/audit."""
        from coffer_mcp import server as server_mod
        from coffer_mcp.audit.logger import AuditLogger
        from coffer_mcp.store.encrypted_store import EncryptedStore

        store = EncryptedStore(os.urandom(32), store_path=tmp_path / "creds.json")
        audit = AuditLogger(tmp_path / "audit.jsonl", hmac_key=os.urandom(32), source="mcp")
        monkeypatch.setattr(server_mod, "_store", store)
        monkeypatch.setattr(server_mod, "_audit", audit)
        monkeypatch.setattr(
            server_mod, "_rate_limiter", RateLimiter(max_requests=2, window_seconds=60)
        )
        return server_mod

    @pytest.mark.asyncio
    async def test_third_call_rate_limited(self, server):
        # Unknown alias — the first two calls fail credential resolution
        # but still consume rate-limit slots; the third is rejected at
        # the rate-limit layer before touching the store.
        for _ in range(2):
            result = json.loads(await server.coffer_test("nope"))
            assert result.get("code") != "RATE_LIMITED"

        result = json.loads(await server.coffer_test("nope"))
        assert result["status"] == "error"
        assert result["code"] == "RATE_LIMITED"
        assert "retry" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_rejection_is_audited(self, server):
        for _ in range(3):
            await server.coffer_test("nope")
        events = server._audit.get_events(limit=10)
        limited = [e for e in events if e["event_type"] == "rate.limited"]
        assert len(limited) == 1
        assert limited[0]["alias"] == "nope"
        assert limited[0]["details"]["tool"] == "coffer_test"

    @pytest.mark.asyncio
    async def test_limit_is_per_alias(self, server):
        for _ in range(2):
            await server.coffer_test("alias-a")
        result = json.loads(await server.coffer_test("alias-b"))
        assert result.get("code") != "RATE_LIMITED"

    def test_env_override(self, monkeypatch):
        from coffer_mcp import server as server_mod

        monkeypatch.setenv("COFFER_RATE_LIMIT_MAX", "5")
        monkeypatch.setenv("COFFER_RATE_LIMIT_WINDOW", "10")
        rl = server_mod._make_rate_limiter()
        assert rl._max == 5
        assert rl._window == 10.0

    def test_env_override_invalid_falls_back_to_defaults(self, monkeypatch):
        from coffer_mcp import server as server_mod
        from coffer_mcp.ratelimit import DEFAULT_MAX_REQUESTS

        monkeypatch.setenv("COFFER_RATE_LIMIT_MAX", "not-a-number")
        rl = server_mod._make_rate_limiter()
        assert rl._max == DEFAULT_MAX_REQUESTS
