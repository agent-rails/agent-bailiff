from __future__ import annotations

import threading
import time
from collections.abc import Callable

MAX_RECORDED_PER_TASK = 16
WINDOW_SECONDS = 60
MAX_TRACKED_TASKS = 65536


class RefusalBudget:
    def __init__(
        self,
        limit: int = MAX_RECORDED_PER_TASK,
        window_seconds: int = WINDOW_SECONDS,
        max_tasks: int = MAX_TRACKED_TASKS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        for name, value in (("limit", limit), ("window_seconds", window_seconds), ("max_tasks", max_tasks)):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        self._limit = limit
        self._window = window_seconds
        self._max_tasks = max_tasks
        self._clock = clock
        self._windows: dict[tuple[str, str], tuple[float, int]] = {}
        self._lock = threading.Lock()

    def admit(self, tenant: str, task: str) -> bool:
        key = (tenant, task)
        with self._lock:
            now = self._clock()
            window = self._windows.get(key)
            if window is None or now - window[0] >= self._window:
                if window is None and len(self._windows) >= self._max_tasks:
                    self._sweep(now)
                    if len(self._windows) >= self._max_tasks:
                        return False
                window = (now, 0)
            start, count = window
            if count >= self._limit:
                return False
            self._windows[key] = (start, count + 1)
            return True

    def refund(self, tenant: str, task: str) -> None:
        key = (tenant, task)
        with self._lock:
            window = self._windows.get(key)
            if window is not None and window[1] > 0:
                self._windows[key] = (window[0], window[1] - 1)

    def _sweep(self, now: float) -> None:
        stale = [key for key, (start, _) in self._windows.items() if now - start >= self._window]
        for key in stale:
            del self._windows[key]
