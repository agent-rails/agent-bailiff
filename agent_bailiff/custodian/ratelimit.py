from __future__ import annotations

import threading
from collections import deque

MAX_TRACKED_TASKS = 65536


class TaskRateLimiter:
    def __init__(self, limit: int, window_seconds: int, max_tasks: int = MAX_TRACKED_TASKS) -> None:
        for name, value in (("limit", limit), ("window_seconds", window_seconds), ("max_tasks", max_tasks)):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        self._limit = limit
        self._window = window_seconds
        self._max_tasks = max_tasks
        self._releases: dict[tuple[str, str], deque[int]] = {}
        self._lock = threading.Lock()

    def exhausted(self, tenant: str, task: str, now: int) -> bool:
        with self._lock:
            releases = self._releases.get((tenant, task))
            if releases is None:
                if len(self._releases) >= self._max_tasks:
                    self._sweep(now)
                return len(self._releases) >= self._max_tasks
            while releases and releases[0] <= now - self._window:
                releases.popleft()
            return len(releases) >= self._limit

    def record(self, tenant: str, task: str, now: int) -> None:
        with self._lock:
            key = (tenant, task)
            if key not in self._releases and len(self._releases) >= self._max_tasks:
                self._sweep(now)
                if len(self._releases) >= self._max_tasks:
                    raise OverflowError("rate limiter is tracking its maximum number of tasks")
            self._releases.setdefault(key, deque()).append(now)

    def _sweep(self, now: int) -> None:
        stale = [key for key, releases in self._releases.items() if not releases or releases[-1] <= now - self._window]
        for key in stale:
            del self._releases[key]
