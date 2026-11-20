from __future__ import annotations

import threading

MAX_RECORDED_PER_TASK = 16
WINDOW_SECONDS = 60
MAX_TRACKED_TASKS = 65536


class RefusalBudget:
    def __init__(
        self,
        limit: int = MAX_RECORDED_PER_TASK,
        window_seconds: int = WINDOW_SECONDS,
        max_tasks: int = MAX_TRACKED_TASKS,
    ) -> None:
        for name, value in (("limit", limit), ("window_seconds", window_seconds), ("max_tasks", max_tasks)):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        self._limit = limit
        self._window = window_seconds
        self._max_tasks = max_tasks
        self._windows: dict[tuple[str, str], tuple[int, int]] = {}
        self._lock = threading.Lock()

    def admit(self, tenant: str, task: str, now: int) -> bool:
        key = (tenant, task)
        with self._lock:
            start, count = self._windows.pop(key, (now, 0))
            if now - start >= self._window or now < start:
                start, count = now, 0
            if count >= self._limit:
                self._windows[key] = (start, count)
                return False
            if len(self._windows) >= self._max_tasks:
                self._evict(now)
            self._windows[key] = (start, count + 1)
            return True

    def _evict(self, now: int) -> None:
        stale = [key for key, (start, _) in self._windows.items() if now - start >= self._window]
        for key in stale:
            del self._windows[key]
        while len(self._windows) >= self._max_tasks:
            del self._windows[next(iter(self._windows))]
