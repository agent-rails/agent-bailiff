from __future__ import annotations

import threading
from collections import deque

MAX_TRACKED_TASKS = 65536


class TaskRateLimiter:
    def __init__(self, limit: int, window_seconds: int) -> None:
        for name, value in (("limit", limit), ("window_seconds", window_seconds)):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        self._limit = limit
        self._window = window_seconds
        self._releases: dict[tuple[str, str], deque[int]] = {}
        self._lock = threading.Lock()

    def allow(self, tenant: str, task: str, now: int) -> bool:
        with self._lock:
            if len(self._releases) >= MAX_TRACKED_TASKS:
                self._sweep(now)
            releases = self._releases.setdefault((tenant, task), deque())
            while releases and releases[0] <= now - self._window:
                releases.popleft()
            if len(releases) >= self._limit:
                return False
            releases.append(now)
            return True

    def _sweep(self, now: int) -> None:
        stale = [key for key, releases in self._releases.items() if not releases or releases[-1] <= now - self._window]
        for key in stale:
            del self._releases[key]
