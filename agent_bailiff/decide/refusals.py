from __future__ import annotations

import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

MAX_RECORDED_PER_TASK = 16
WINDOW_SECONDS = 60
MAX_TRACKED_TASKS = 65536
MAX_TRACKED_TASKS_PER_TENANT = 4096
CAPPED_REASON = "refusals_capped"
TENANT_CAPPED_REASON = "tenant_refusals_capped"

Verdict = Literal["record", "capped", "drop"]


@dataclass(frozen=True)
class Admission:
    verdict: Verdict
    window_start: float
    tenant_overflow: bool = False


@dataclass
class _Window:
    start: float
    count: int
    capped: bool = False


class RefusalBudget:
    def __init__(
        self,
        limit: int = MAX_RECORDED_PER_TASK,
        window_seconds: int = WINDOW_SECONDS,
        max_tasks: int = MAX_TRACKED_TASKS,
        max_tasks_per_tenant: int = MAX_TRACKED_TASKS_PER_TENANT,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        for name, value in (
            ("limit", limit),
            ("window_seconds", window_seconds),
            ("max_tasks", max_tasks),
            ("max_tasks_per_tenant", max_tasks_per_tenant),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        self._limit = limit
        self._window = window_seconds
        self._max_tasks = max_tasks
        self._max_tasks_per_tenant = max_tasks_per_tenant
        self._clock = clock
        self._tasks: OrderedDict[tuple[str, str], _Window] = OrderedDict()
        self._per_tenant: dict[str, int] = {}
        self._overflow: OrderedDict[str, float] = OrderedDict()
        self._lock = threading.Lock()

    def admit(self, tenant: str, task: str) -> Admission:
        key = (tenant, task)
        with self._lock:
            now = self._clock()
            self._expire(now)
            window = self._tasks.get(key)
            if window is not None and now - window.start >= self._window:
                self._forget(key)
                window = None
            if window is None:
                if len(self._tasks) >= self._max_tasks or self._per_tenant.get(tenant, 0) >= self._max_tasks_per_tenant:
                    return self._admit_overflow(tenant, now)
                self._tasks[key] = _Window(now, 1)
                self._per_tenant[tenant] = self._per_tenant.get(tenant, 0) + 1
                return Admission("record", now)
            if window.count < self._limit:
                window.count += 1
                return Admission("record", window.start)
            if not window.capped:
                window.capped = True
                return Admission("capped", window.start)
            return Admission("drop", window.start)

    def refund(self, tenant: str, task: str, admission: Admission) -> None:
        with self._lock:
            if admission.tenant_overflow:
                if self._overflow.get(tenant) == admission.window_start:
                    del self._overflow[tenant]
                return
            window = self._tasks.get((tenant, task))
            if window is None or window.start != admission.window_start:
                return
            if admission.verdict == "capped":
                window.capped = False
            elif admission.verdict == "record" and window.count > 0:
                window.count -= 1

    def _admit_overflow(self, tenant: str, now: float) -> Admission:
        marked = self._overflow.get(tenant)
        if marked is not None and now - marked < self._window:
            return Admission("drop", marked, tenant_overflow=True)
        if marked is None and len(self._overflow) >= self._max_tasks:
            return Admission("drop", now, tenant_overflow=True)
        self._overflow.pop(tenant, None)
        self._overflow[tenant] = now
        return Admission("capped", now, tenant_overflow=True)

    def _expire(self, now: float) -> None:
        while self._tasks:
            key, window = next(iter(self._tasks.items()))
            if now - window.start < self._window:
                break
            self._forget(key)
        while self._overflow:
            tenant, marked = next(iter(self._overflow.items()))
            if now - marked < self._window:
                break
            del self._overflow[tenant]

    def _forget(self, key: tuple[str, str]) -> None:
        del self._tasks[key]
        remaining = self._per_tenant[key[0]] - 1
        if remaining:
            self._per_tenant[key[0]] = remaining
        else:
            del self._per_tenant[key[0]]
