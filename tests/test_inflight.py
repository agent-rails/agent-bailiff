import logging

import pytest

from agent_bailiff.custodian.inflight import InflightFull, InflightRelease, InflightReleases

TTL = 60_000_000_000
ENTRY = object()


class Clock:
    def __init__(self):
        self.now = 1_000

    def __call__(self):
        return self.now


@pytest.fixture
def clock():
    return Clock()


def make(clock, max_entries=4, max_bytes=1024, per_tenant=4, ttl_ns=TTL):
    return InflightReleases(
        max_entries=max_entries, max_bytes=max_bytes, per_tenant=per_tenant, ttl_ns=ttl_ns, monotonic_ns=clock
    )


def committed(inflight, key, tenant="tenant-a", value="Bearer secret-value-1", entry_id="release-1"):
    reservation = inflight.reserve(key, tenant, value)
    inflight.commit(reservation, entry_id, ENTRY)
    return reservation


@pytest.mark.parametrize("name", ["max_entries", "max_bytes", "per_tenant", "ttl_ns"])
@pytest.mark.parametrize("value", [0, -1, True, 1.5])
def test_bounds_must_be_positive_integers(clock, name, value):
    with pytest.raises(ValueError):
        make(clock, **{name: value})


def test_a_committed_release_is_taken_once(clock):
    inflight = make(clock)
    committed(inflight, "k1")
    release = inflight.take("k1")
    assert release == InflightRelease("Bearer secret-value-1", "tenant-a", "release-1", ENTRY, 1_000 + TTL)
    assert inflight.take("k1") is None


def test_the_header_value_is_not_in_the_repr(clock):
    inflight = make(clock)
    reservation = inflight.reserve("k1", "tenant-a", "Bearer secret-value-1")
    assert "secret-value" not in repr(reservation)
    inflight.commit(reservation, "release-1", ENTRY)
    assert "secret-value" not in repr(inflight.take("k1"))


def test_a_wrong_key_leaves_the_entry(clock):
    inflight = make(clock)
    committed(inflight, "k1")
    assert inflight.take("k2") is None
    assert inflight.take("k1") is not None


def test_a_pending_reservation_is_not_takeable(clock):
    inflight = make(clock)
    reservation = inflight.reserve("k1", "tenant-a", "Bearer secret-value-1")
    assert inflight.take("k1") is None
    inflight.commit(reservation, "release-1", ENTRY)
    assert inflight.take("k1") is not None


def test_a_duplicate_key_is_refused(clock):
    inflight = make(clock)
    inflight.reserve("k1", "tenant-a", "Bearer secret-value-1")
    with pytest.raises(ValueError):
        inflight.reserve("k1", "tenant-a", "Bearer secret-value-1")
    committed(inflight, "k2")
    with pytest.raises(ValueError):
        inflight.reserve("k2", "tenant-a", "Bearer secret-value-1")


def test_the_entry_count_is_bounded(clock):
    inflight = make(clock, max_entries=2)
    committed(inflight, "k1")
    inflight.reserve("k2", "tenant-b", "Bearer secret-value-1")
    with pytest.raises(InflightFull):
        inflight.reserve("k3", "tenant-c", "Bearer secret-value-1")
    inflight.take("k1")
    inflight.reserve("k3", "tenant-c", "Bearer secret-value-1")


def test_the_byte_total_is_bounded(clock):
    inflight = make(clock, max_bytes=40)
    first = inflight.reserve("k1", "tenant-a", "x" * 30)
    with pytest.raises(InflightFull):
        inflight.reserve("k2", "tenant-b", "y" * 11)
    inflight.reserve("k2", "tenant-b", "y" * 10)
    inflight.discard(first)
    inflight.reserve("k3", "tenant-c", "z" * 30)


def test_a_full_tenant_does_not_block_another_tenant(clock):
    inflight = make(clock, per_tenant=2)
    committed(inflight, "k1", tenant="tenant-a")
    inflight.reserve("k2", "tenant-a", "Bearer secret-value-1")
    with pytest.raises(InflightFull):
        inflight.reserve("k3", "tenant-a", "Bearer secret-value-1")
    inflight.reserve("k3", "tenant-b", "Bearer secret-value-1")
    inflight.take("k1")
    inflight.reserve("k4", "tenant-a", "Bearer secret-value-1")


def test_discard_frees_a_pending_reservation(clock):
    inflight = make(clock, max_entries=1)
    reservation = inflight.reserve("k1", "tenant-a", "Bearer secret-value-1")
    inflight.discard(reservation)
    assert inflight.take("k1") is None
    inflight.reserve("k1", "tenant-a", "Bearer secret-value-1")


def test_a_reservation_is_committed_or_discarded_once(clock):
    inflight = make(clock)
    reservation = committed(inflight, "k1")
    with pytest.raises(ValueError):
        inflight.commit(reservation, "release-2", ENTRY)
    with pytest.raises(ValueError):
        inflight.discard(reservation)
    assert inflight.take("k1").release_entry_id == "release-1"


def test_a_stale_reservation_never_touches_a_newer_one(clock):
    inflight = make(clock)
    stale = inflight.reserve("k1", "tenant-a", "Bearer secret-value-1")
    inflight.discard(stale)
    committed(inflight, "k1", entry_id="release-2")
    with pytest.raises(ValueError):
        inflight.discard(stale)
    assert inflight.take("k1").release_entry_id == "release-2"


def test_an_expired_release_is_not_taken(clock):
    inflight = make(clock)
    committed(inflight, "k1")
    clock.now += TTL
    assert inflight.take("k1") is None


def test_the_sweep_removes_expired_releases_and_returns_the_count(clock):
    inflight = make(clock, max_entries=3)
    committed(inflight, "k1")
    committed(inflight, "k2")
    clock.now += 5
    committed(inflight, "k3")
    clock.now += TTL - 4
    assert inflight.sweep() == 2
    assert inflight.sweep() == 0
    assert inflight.take("k3") is not None


def test_pending_reservations_are_never_swept(clock):
    inflight = make(clock)
    reservation = inflight.reserve("k1", "tenant-a", "Bearer secret-value-1")
    clock.now += 10 * TTL
    assert inflight.sweep() == 0
    inflight.commit(reservation, "release-1", ENTRY)
    assert inflight.take("k1").expires_at == clock.now + TTL


def test_a_reserve_sweeps_and_warns_with_the_count(clock, caplog):
    inflight = make(clock, max_entries=2)
    committed(inflight, "k1")
    committed(inflight, "k2")
    clock.now += TTL
    with caplog.at_level(logging.WARNING, logger="agent_bailiff.custodian.inflight"):
        inflight.reserve("k3", "tenant-a", "Bearer secret-value-1")
    assert "2 in-flight releases expired unmatched" in caplog.text
    assert "secret-value" not in caplog.text
