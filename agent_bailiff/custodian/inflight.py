from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from agent_bailiff.docket.entry import Entry

logger = logging.getLogger(__name__)


class InflightFull(Exception):
    pass


@dataclass(frozen=True)
class InflightRelease:
    header_value: str = field(repr=False)
    tenant: str
    release_entry_id: str
    entry: Entry
    expires_at: int


@dataclass(frozen=True, eq=False)
class Reservation:
    key: str
    tenant: str
    header_value: str = field(repr=False)
    size: int


@dataclass
class _Slot:
    reservation: Reservation
    release: InflightRelease | None = None


class InflightReleases:
    def __init__(
        self,
        *,
        max_entries: int,
        max_bytes: int,
        per_tenant: int,
        ttl_ns: int,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
    ) -> None:
        bounds = (
            ("max_entries", max_entries),
            ("max_bytes", max_bytes),
            ("per_tenant", per_tenant),
            ("ttl_ns", ttl_ns),
        )
        for name, value in bounds:
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        self._max_entries = max_entries
        self._max_bytes = max_bytes
        self._per_tenant = per_tenant
        self._ttl_ns = ttl_ns
        self._monotonic_ns = monotonic_ns
        self._slots: dict[str, _Slot] = {}
        self._expiry: dict[str, int] = {}
        self._tenants: dict[str, int] = {}
        self._bytes = 0
        self._lock = threading.Lock()

    def reserve(self, key: str, tenant: str, header_value: str) -> Reservation:
        size = len(header_value.encode("utf-8"))
        with self._lock:
            expired = self._sweep()
            if key in self._slots:
                raise ValueError("release key is already in flight")
            if len(self._slots) >= self._max_entries or self._bytes + size > self._max_bytes:
                raise InflightFull("in-flight release map is full")
            if self._tenants.get(tenant, 0) >= self._per_tenant:
                raise InflightFull("in-flight release quota for the tenant is full")
            reservation = Reservation(key, tenant, header_value, size)
            self._slots[key] = _Slot(reservation)
            self._tenants[tenant] = self._tenants.get(tenant, 0) + 1
            self._bytes += size
        _warn_expired(expired)
        return reservation

    def commit(self, reservation: Reservation, release_entry_id: str, entry: Entry) -> None:
        with self._lock:
            slot = self._pending(reservation)
            expires_at = self._monotonic_ns() + self._ttl_ns
            slot.release = InflightRelease(
                reservation.header_value, reservation.tenant, release_entry_id, entry, expires_at
            )
            self._expiry[reservation.key] = expires_at

    def discard(self, reservation: Reservation) -> None:
        with self._lock:
            self._pending(reservation)
            self._remove(reservation.key)

    def take(self, key: str) -> InflightRelease | None:
        with self._lock:
            expired = self._sweep()
            release = self._take(key)
        _warn_expired(expired)
        return release

    def sweep(self) -> int:
        with self._lock:
            expired = self._sweep()
        _warn_expired(expired)
        return expired

    def _take(self, key: str) -> InflightRelease | None:
        slot = self._slots.get(key)
        if slot is None or slot.release is None:
            return None
        self._remove(key)
        if slot.release.expires_at <= self._monotonic_ns():
            return None
        return slot.release

    def _pending(self, reservation: Reservation) -> _Slot:
        slot = self._slots.get(reservation.key)
        if slot is None or slot.reservation is not reservation or slot.release is not None:
            raise ValueError("reservation is not pending")
        return slot

    def _sweep(self) -> int:
        if not self._expiry:
            return 0
        now = self._monotonic_ns()
        expired = []
        for key, expires_at in self._expiry.items():
            if expires_at > now:
                break
            expired.append(key)
        for key in expired:
            self._remove(key)
        return len(expired)

    def _remove(self, key: str) -> None:
        reservation = self._slots.pop(key).reservation
        self._expiry.pop(key, None)
        self._bytes -= reservation.size
        remaining = self._tenants[reservation.tenant] - 1
        if remaining:
            self._tenants[reservation.tenant] = remaining
        else:
            del self._tenants[reservation.tenant]


def _warn_expired(expired: int) -> None:
    if expired:
        logger.warning("%d in-flight releases expired unmatched", expired)
