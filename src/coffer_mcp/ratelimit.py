"""
Per-alias sliding-window rate limiter (RR-H4).

A prompt-injected LLM session can otherwise invoke credential-using
tools in a tight loop, flooding target APIs with authenticated
requests until the *target* locks the account. This limiter bounds
the rate per credential alias at the server layer.

The check runs before the tool body, so attempts count against the
window whether or not the credential resolves or the request succeeds
— probing invalid aliases is rate-limited the same as legitimate use.
Rejected attempts do not consume a slot (they are already over the
limit), so the window drains predictably.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from typing import Callable

DEFAULT_MAX_REQUESTS = 60
DEFAULT_WINDOW_SECONDS = 60.0


class RateLimiter:
    """Thread-safe sliding-window rate limiter keyed by credential alias."""

    def __init__(
        self,
        max_requests: int = DEFAULT_MAX_REQUESTS,
        window_seconds: float = DEFAULT_WINDOW_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ):
        if max_requests < 1:
            raise ValueError("max_requests must be >= 1")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")
        self._max = max_requests
        self._window = window_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._events: dict[str, deque[float]] = defaultdict(deque)

    def check(self, alias: str) -> tuple[bool, float]:
        """Record an attempt for `alias` and report whether it is allowed.

        Returns:
            (allowed, retry_after_seconds). retry_after is 0.0 when allowed,
            otherwise the seconds until the oldest in-window event expires.
        """
        now = self._clock()
        cutoff = now - self._window
        with self._lock:
            q = self._events[alias]
            while q and q[0] <= cutoff:
                q.popleft()
            if len(q) >= self._max:
                retry_after = q[0] + self._window - now
                return False, max(retry_after, 0.0)
            q.append(now)
            return True, 0.0
