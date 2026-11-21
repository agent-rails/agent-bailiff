import json
import os
import stat

import pytest

from agent_bailiff.docket.entry import Head
from agent_bailiff.docket.receipt import (
    MAX_RECEIPT_BYTES,
    Receipt,
    ReceiptDir,
    ReceiptInvalid,
    receipt_name,
)

DOCKET_ID = "0123456789abcdef0123456789abcdef"
HASH_A = "A" * 43
HASH_B = "b-_9" * 10 + "xyz"
VERIFIED_AT = 1795262400
RECEIPT = Receipt(DOCKET_ID, 4, "0" * 64, 1000, {"decide": Head(4, HASH_A), "custodian": Head(3, HASH_B)}, VERIFIED_AT)
UID = os.geteuid()
GID = os.getegid()


def document(**changes):
    base = json.loads(RECEIPT.encode())
    base.update(changes)
    return base


@pytest.fixture
def directory(tmp_path):
    path = tmp_path / "receipts"
    path.mkdir()
    os.chmod(path, 0o750)
    os.chown(path, -1, GID)
    return path


@pytest.fixture
def receipts(directory):
    with ReceiptDir.open(directory, archiver_uid=UID, reader_gid=GID) as opened:
        yield opened


def place(directory, segment, content, mode=0o640):
    path = directory / receipt_name(segment)
    path.write_bytes(content)
    os.chmod(path, mode)
    return path


def test_receipt_round_trips():
    assert Receipt.from_document(json.loads(RECEIPT.encode())) == RECEIPT


def test_verified_at_is_rfc_3339_utc():
    assert json.loads(RECEIPT.encode())["verified_at"] == "2026-11-21T12:00:00Z"


@pytest.mark.parametrize(
    "bad",
    [
        [],
        document(version=2),
        document(version=True),
        document(extra=1),
        {key: value for key, value in document().items() if key != "size"},
        document(docket_id="0123456789ABCDEF0123456789ABCDEF"),
        document(segment=0),
        document(segment=10**12),
        document(sha256="0" * 63),
        document(sha256="A" * 64),
        document(size=0),
        document(size=2**53),
        document(end_heads={}),
        document(end_heads={"decide": {"seq": 0, "hash": HASH_A}}),
        document(verified_at="2026-11-21T12:00:00+00:00"),
        document(verified_at="2026-11-21T12:00:00.5Z"),
        document(verified_at="2026-13-21T12:00:00Z"),
        document(verified_at=VERIFIED_AT),
    ],
)
def test_receipt_refuses_an_invalid_document(bad):
    with pytest.raises(ReceiptInvalid):
        Receipt.from_document(bad)


@pytest.mark.parametrize("segment", [0, 10**12])
def test_receipt_name_refuses_numbers_outside_twelve_digits(segment):
    with pytest.raises(ValueError):
        receipt_name(segment)


def test_read_of_a_missing_receipt_is_none(receipts):
    assert receipts.read(4) is None


def test_write_then_read_gives_0640_and_the_reader_group(receipts, directory):
    receipts.write(RECEIPT)
    info = os.lstat(directory / "seg-000000000004.receipt")
    assert (stat.S_IMODE(info.st_mode), info.st_gid) == (0o640, GID)
    assert receipts.read(4) == RECEIPT
    assert sorted(os.listdir(directory)) == ["seg-000000000004.receipt"]


def test_write_replaces_the_previous_receipt(receipts):
    receipts.write(RECEIPT)
    refreshed = Receipt(**{**RECEIPT.__dict__, "verified_at": VERIFIED_AT + 60})
    receipts.write(refreshed)
    assert receipts.read(4) == refreshed


def test_remove_deletes_the_receipt_and_ignores_a_missing_one(receipts, directory):
    receipts.write(RECEIPT)
    receipts.remove(4)
    receipts.remove(4)
    assert os.listdir(directory) == []


def test_read_refuses_a_receipt_naming_another_segment(receipts, directory):
    place(directory, 5, RECEIPT.encode())
    with pytest.raises(ReceiptInvalid, match="names segment 4"):
        receipts.read(5)


@pytest.mark.parametrize("content", [b"", b"garbage", b"\xff", b'{"version":1,"version":1}'])
def test_read_refuses_invalid_content(receipts, directory, content):
    place(directory, 4, content)
    with pytest.raises(ReceiptInvalid, match="not a valid receipt"):
        receipts.read(4)


def test_read_refuses_a_receipt_over_the_cap(receipts, directory):
    place(directory, 4, b" " * (MAX_RECEIPT_BYTES + 1))
    with pytest.raises(ReceiptInvalid, match="larger"):
        receipts.read(4)


def test_read_refuses_another_mode(receipts, directory):
    place(directory, 4, RECEIPT.encode(), 0o644)
    with pytest.raises(ReceiptInvalid, match="0640"):
        receipts.read(4)


def test_read_refuses_a_receipt_not_owned_by_the_archiver(directory):
    place(directory, 4, RECEIPT.encode())
    with ReceiptDir(directory, os.open(directory, os.O_RDONLY), archiver_uid=UID + 1, reader_gid=GID) as receipts:
        with pytest.raises(ReceiptInvalid, match=f"uid {UID + 1}"):
            receipts.read(4)


def test_read_refuses_a_receipt_in_another_group(directory):
    place(directory, 4, RECEIPT.encode())
    with ReceiptDir(directory, os.open(directory, os.O_RDONLY), archiver_uid=UID, reader_gid=GID + 1000) as receipts:
        with pytest.raises(ReceiptInvalid, match=f"group {GID + 1000}"):
            receipts.read(4)


def test_read_refuses_a_symlinked_receipt(receipts, directory, tmp_path):
    target = tmp_path / "elsewhere"
    target.write_bytes(RECEIPT.encode())
    os.chmod(target, 0o640)
    (directory / receipt_name(4)).symlink_to(target)
    with pytest.raises(ReceiptInvalid, match="cannot be opened"):
        receipts.read(4)


def test_open_refuses_a_symlinked_directory(directory, tmp_path):
    link = tmp_path / "link"
    link.symlink_to(directory)
    with pytest.raises(ReceiptInvalid, match="cannot be opened"):
        ReceiptDir.open(link, archiver_uid=UID, reader_gid=GID)


def test_open_refuses_a_missing_directory(tmp_path):
    with pytest.raises(ReceiptInvalid, match="cannot be opened"):
        ReceiptDir.open(tmp_path / "absent", archiver_uid=UID, reader_gid=GID)


@pytest.mark.parametrize("mode", [0o700, 0o755, 0o770])
def test_open_refuses_a_directory_mode_other_than_0750(directory, mode):
    os.chmod(directory, mode)
    with pytest.raises(ReceiptInvalid, match="0750"):
        ReceiptDir.open(directory, archiver_uid=UID, reader_gid=GID)


@pytest.mark.parametrize(("uid", "gid"), [(UID + 1, GID), (UID, GID + 1000)])
def test_open_refuses_another_owner_or_group(directory, uid, gid):
    with pytest.raises(ReceiptInvalid, match=f"uid {uid}, group {gid}"):
        ReceiptDir.open(directory, archiver_uid=uid, reader_gid=gid)


def test_the_directory_stays_pinned_after_it_is_swapped(receipts, directory, tmp_path):
    receipts.write(RECEIPT)
    directory.rename(tmp_path / "moved")
    directory.mkdir()
    assert receipts.read(4) == RECEIPT
    assert os.listdir(directory) == []
