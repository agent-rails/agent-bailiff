import dataclasses
import logging

import pytest

from agent_bailiff.docket import retention as retention_module
from agent_bailiff.docket.entry import Head
from agent_bailiff.docket.manifest import Base, Manifest, SegmentEntry
from agent_bailiff.docket.receipt import Receipt
from agent_bailiff.docket.retention import MAX_CLOCK_AHEAD, removable

DOCKET_ID = "0123456789abcdef0123456789abcdef"
HASH_A = "A" * 43
HASH_B = "B" * 43
HASH_C = "C" * 43
BASE = Base(3, 5, {"decide": Head(5, HASH_A)})
OLDEST = SegmentEntry(4, "0" * 64, 1000, 6, 2, {"decide": Head(7, HASH_B)}, frozenset({"decide-1"}))
NEXT = SegmentEntry(5, "f" * 64, 900, 8, 1, {"decide": Head(8, HASH_C)}, frozenset({"decide-1"}))
MANIFEST = Manifest(DOCKET_ID, 9, BASE, (OLDEST, NEXT))
NOW = 1795262400
MAX_AGE = 3600
CAP = 1500
OVER = CAP + 1
RECEIPT = Receipt(DOCKET_ID, 4, OLDEST.sha256, OLDEST.size, OLDEST.end_heads, NOW - 10)


def decide(manifest=MANIFEST, receipt=RECEIPT, retained_bytes=OVER, now=NOW):
    return removable(manifest, receipt, retained_bytes=retained_bytes, cap=CAP, now=now, max_age=MAX_AGE)


def logs(caplog):
    return [(record.levelno, record.message) for record in caplog.records if record.name == retention_module.__name__]


def test_the_oldest_sealed_segment_is_removable_over_the_cap_with_a_fresh_matching_receipt():
    assert decide() == OLDEST


@pytest.mark.parametrize("retained_bytes", [CAP - 1, CAP])
def test_nothing_is_removable_at_or_under_the_cap(retained_bytes):
    assert decide(retained_bytes=retained_bytes) is None


def test_nothing_is_removable_without_a_sealed_segment():
    assert decide(manifest=Manifest(DOCKET_ID, 3, BASE)) is None


def test_nothing_is_removable_without_a_receipt(caplog):
    assert decide(receipt=None) is None
    assert logs(caplog) == []


def test_only_the_oldest_segment_is_considered():
    receipt = Receipt(DOCKET_ID, 5, NEXT.sha256, NEXT.size, NEXT.end_heads, NOW)
    assert decide(receipt=receipt) is None


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("docket_id", "f" * 32),
        ("segment", 5),
        ("sha256", "1" * 64),
        ("size", OLDEST.size + 1),
        ("end_heads", {"decide": Head(7, HASH_C)}),
        ("end_heads", {"decide": Head(6, HASH_B)}),
        ("end_heads", {"decide": Head(7, HASH_B), "custodian": Head(1, HASH_A)}),
    ],
)
def test_a_receipt_differing_in_any_field_is_kept_and_logged_as_an_error(field, value, caplog):
    assert decide(receipt=dataclasses.replace(RECEIPT, **{field: value})) is None
    [(level, message)] = logs(caplog)
    assert level == logging.ERROR
    assert message == f"receipt for docket segment 4 does not match its manifest entry ({field}); it is kept"


def test_a_receipt_exactly_max_age_old_is_fresh():
    assert decide(receipt=dataclasses.replace(RECEIPT, verified_at=NOW - MAX_AGE)) == OLDEST


def test_a_receipt_one_second_past_max_age_is_kept_with_a_warning(caplog):
    assert decide(receipt=dataclasses.replace(RECEIPT, verified_at=NOW - MAX_AGE - 1)) is None
    assert logs(caplog) == [
        (logging.WARNING, "receipt for docket segment 4 is 3601 s old, over the 3600 s limit; it is kept")
    ]


def test_a_receipt_up_to_the_clock_allowance_ahead_is_fresh():
    assert decide(receipt=dataclasses.replace(RECEIPT, verified_at=NOW + MAX_CLOCK_AHEAD)) == OLDEST


def test_a_receipt_further_in_the_future_is_kept_and_logged_as_an_error(caplog):
    assert decide(receipt=dataclasses.replace(RECEIPT, verified_at=NOW + MAX_CLOCK_AHEAD + 1)) is None
    assert logs(caplog) == [(logging.ERROR, "receipt for docket segment 4 was verified 61 s in the future; it is kept")]
