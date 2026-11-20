from __future__ import annotations

import threading
import time
from collections import OrderedDict
from collections.abc import Callable

MAX_RECORDED_PER_KIND = 16
WINDOW_SECONDS = 60
MAX_TRACKED_KINDS = 65536
MAX_TRACKED_KINDS_PER_TENANT = 4096

RefusalKind = tuple[str, str, str, str]


class RefusalBudget:
    def __init__(
        self,
        limit: int = MAX_RECORDED_PER_KIND,
        window_seconds: int = WINDOW_SECONDS,
        max_kinds: int = MAX_TRACKED_KINDS,
        max_kinds_per_tenant: int = MAX_TRACKED_KINDS_PER_TENANT,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        for name, value in (
            ("limit", limit),
            ("window_seconds", window_seconds),
            ("max_kinds", max_kinds),
            ("max_kinds_per_tenant", max_kinds_per_tenant),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        self._limit = limit
        self._window = window_seconds
        self._max_kinds = max_kinds
        self._max_kinds_per_tenant = max_kinds_per_tenant
        self._clock = clock
        self._windows: OrderedDict[RefusalKind, tuple[float, int]] = OrderedDict()
        self._per_tenant: dict[str, int] = {}
        self._lock = threading.Lock()

    def admit(self, tenant: str, task: str, reason: str, tool: str) -> float | None:
        kind = (tenant, task, reason, tool)
        with self._lock:
            now = self._clock()
            self._expire(now)
            window = self._windows.get(kind)
            if window is None:
                if len(self._windows) >= self._max_kinds:
                    return None
                if self._per_tenant.get(tenant, 0) >= self._max_kinds_per_tenant:
                    return None
                self._windows[kind] = (now, 1)
                self._per_tenant[tenant] = self._per_tenant.get(tenant, 0) + 1
                return now
            start, count = window
            if count >= self._limit:
                return None
            self._windows[kind] = (start, count + 1)
            return start

    def refund(self, tenant: str, task: str, reason: str, tool: str, window_start: float) -> None:
        kind = (tenant, task, reason, tool)
        with self._lock:
            window = self._windows.get(kind)
            if window is not None and window[0] == window_start and window[1] > 0:
                self._windows[kind] = (window[0], window[1] - 1)

    def _expire(self, now: float) -> None:
        while self._windows:
            kind, (start, _) = next(iter(self._windows.items()))
            if now - start < self._window:
                return
            del self._windows[kind]
            remaining = self._per_tenant[kind[0]] - 1
            if remaining:
                self._per_tenant[kind[0]] = remaining
            else:
                del self._per_tenant[kind[0]]
