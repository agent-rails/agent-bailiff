import functools
import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
import threading
from dataclasses import replace
from pathlib import Path

import pytest
from test_docket import make_entry
from test_docket_report import OTHER_USER, PINS, WRITERS, Docket, filled, linux_cross_uid, run_as
from test_docket_report import cut as cut_docket

from agent_bailiff import cli
from agent_bailiff.docket.archiver import (
    REFRESH_BATCH,
    ArchiveMismatch,
    ArchiverCheckpoint,
    ArchiverLocked,
    DocketArchiver,
    encode_sidecar,
)
from agent_bailiff.docket.entry import Head
from agent_bailiff.docket.follower import DocketFollower
from agent_bailiff.docket.manifest import Base, Manifest, manifest_path, segment_path, write_manifest
from agent_bailiff.docket.receipt import Receipt, ReceiptDir
from agent_bailiff.docket.segments import SegmentRemoved
from agent_bailiff.docket.sink import build_kid_index
from agent_bailiff.docket.socket_dir import open_lock_file, try_lock

NOW = 1795262400
UID = os.geteuid()
GID = os.getegid()
INDEX = build_kid_index(WRITERS)


def cut(docket, manifest=None):
    sealed = cut_docket(docket, manifest)
    os.chmod(docket.path, 0o640)
    return sealed


def other_device(path):
    return -1


def make_layout(root):
    state = root / "state"
    archive = root / "archive"
    receipts = root / "receipts"
    for path, mode in ((state, 0o700), (archive, 0o750), (receipts, 0o750)):
        path.mkdir()
        os.chown(path, -1, GID)
        os.chmod(path, mode)
    docket_path = root / "docket" / "docket.log"
    docket_path.parent.mkdir()
    docket_path.touch(mode=0o640)
    os.chown(docket_path, -1, GID)
    os.chmod(docket_path, 0o640)
    return root, Docket(docket_path)


@pytest.fixture
def layout(tmp_path):
    return make_layout(tmp_path)


@pytest.fixture
def pin_files(tmp_path):
    paths = {}
    for name, pin in PINS.items():
        paths[name] = tmp_path / f"{name}.pub.json"
        paths[name].write_text(json.dumps(pin.to_document()))
        os.chmod(paths[name], 0o644)
    return paths


def archiver(layout, **options):
    root, docket = layout
    options.setdefault("device_of", other_device)
    options.setdefault("clock", lambda: NOW)
    return DocketArchiver(
        docket.path,
        INDEX,
        root / "archive",
        root / "receipts",
        root / "state" / "archiver.json",
        **options,
    )


def run(layout, **options):
    return archiver(layout, **options).run(threading.Event(), follow=False)


def copies(layout, manifest):
    return layout[0] / "archive" / manifest.docket_id


def receipt(layout, segment):
    with ReceiptDir.open(layout[0] / "receipts", archiver_uid=UID, reader_gid=GID) as receipts:
        return receipts.read(segment)


def checkpoint(layout):
    return ArchiverCheckpoint.from_document(json.loads((layout[0] / "state" / "archiver.json").read_bytes()))


def two_segments(docket):
    first = cut(filled(docket))
    docket.append("decide", make_entry(5))
    second = cut(docket, first)
    docket.append("decide", make_entry(6))
    return second


def test_archives_every_sealed_segment_with_a_sidecar_receipt_and_checkpoint(layout):
    _, docket = layout
    manifest = two_segments(docket)
    assert run(layout) == 2
    directory = copies(layout, manifest)
    assert sorted(os.listdir(directory)) == [
        "seg-000000000001",
        "seg-000000000001.json",
        "seg-000000000002",
        "seg-000000000002.json",
    ]
    for entry in manifest.segments:
        copy = directory / f"seg-{entry.segment:012d}"
        assert copy.read_bytes() == segment_path(docket.path, entry.segment).read_bytes()
        info = os.lstat(copy)
        assert (stat.S_IMODE(info.st_mode), info.st_gid) == (0o640, GID)
        sidecar = directory / f"seg-{entry.segment:012d}.json"
        assert sidecar.read_bytes() == encode_sidecar(manifest.docket_id, entry)
        made = receipt(layout, entry.segment)
        assert (made.sha256, made.size, made.end_heads, made.verified_at) == (
            entry.sha256,
            entry.size,
            entry.end_heads,
            NOW,
        )
    assert stat.S_IMODE(os.lstat(directory).st_mode) == 0o750
    last = manifest.segments[-1]
    assert checkpoint(layout) == ArchiverCheckpoint(manifest.docket_id, 3, 5, dict(last.end_heads))


def test_is_idle_without_a_manifest(layout):
    filled(layout[1])
    assert run(layout) == 0
    assert not (layout[0] / "state" / "archiver.json").exists()


def test_is_idle_until_the_next_segment_is_sealed(layout):
    _, docket = layout
    manifest = cut(filled(docket))
    assert run(layout) == 1
    docket.append("decide", make_entry(5))
    assert run(layout) == 0
    cut(docket, manifest)
    assert run(layout) == 1
    assert checkpoint(layout).segment == 3


def test_refuses_an_archive_on_the_docket_device(layout):
    cut(filled(layout[1]))
    with pytest.raises(PermissionError, match="docket's device"):
        run(layout, device_of=lambda path: os.stat(layout[0] / "archive").st_dev)


def test_refuses_a_symlinked_archive_dir(layout, tmp_path):
    cut(filled(layout[1]))
    (tmp_path / "archive").rename(tmp_path / "real")
    (tmp_path / "archive").symlink_to(tmp_path / "real")
    with pytest.raises(OSError):
        run(layout)


def test_refuses_a_docket_without_a_reader_group(layout):
    cut(filled(layout[1]))
    os.chmod(layout[1].path, 0o600)
    with pytest.raises(PermissionError, match="reader_group"):
        run(layout)


def test_refuses_to_run_beside_another_archiver(layout):
    cut(filled(layout[1]))
    lock_fd = open_lock_file(layout[0] / "state" / "archiver.json.lock")
    try:
        assert try_lock(lock_fd)
        with pytest.raises(ArchiverLocked):
            run(layout)
    finally:
        os.close(lock_fd)


def test_a_segment_differing_from_its_manifest_entry_gets_no_copy_or_receipt(layout):
    _, docket = layout
    manifest = cut(filled(docket))
    entry = replace(manifest.segments[0], kids=frozenset({"other"}))
    tampered = Manifest(manifest.docket_id, manifest.generation + 1, None, (entry,))
    write_manifest(manifest_path(docket.path), tampered)
    with pytest.raises(ArchiveMismatch, match="kids"):
        run(layout)
    assert os.listdir(copies(layout, manifest)) == []
    assert receipt(layout, 1) is None
    assert not (layout[0] / "state" / "archiver.json").exists()


def test_a_segment_failing_verification_gets_no_copy_or_receipt(layout):
    _, docket = layout
    cut(filled(docket))
    sealed = segment_path(docket.path, 1)
    content = bytearray(sealed.read_bytes())
    content[10] ^= 1
    sealed.write_bytes(bytes(content))
    with pytest.raises(ArchiveMismatch, match="fails verification"):
        run(layout)
    assert receipt(layout, 1) is None


def test_a_matching_existing_copy_is_reused(layout, caplog):
    _, docket = layout
    manifest = cut(filled(docket))
    directory = copies(layout, manifest)
    directory.mkdir(mode=0o750)
    (directory / "seg-000000000001").write_bytes(segment_path(docket.path, 1).read_bytes())
    assert run(layout) == 1
    assert "reusing the archived copy of segment 1" in caplog.text
    assert receipt(layout, 1) is not None


def test_a_differing_existing_copy_is_refused(layout):
    _, docket = layout
    manifest = cut(filled(docket))
    directory = copies(layout, manifest)
    directory.mkdir(mode=0o750)
    (directory / "seg-000000000001").write_bytes(b"other\n")
    with pytest.raises(ArchiveMismatch, match="other content"):
        run(layout)
    assert (directory / "seg-000000000001").read_bytes() == b"other\n"
    assert receipt(layout, 1) is None


def test_a_differing_existing_sidecar_is_refused(layout):
    _, docket = layout
    manifest = cut(filled(docket))
    directory = copies(layout, manifest)
    directory.mkdir(mode=0o750)
    (directory / "seg-000000000001.json").write_bytes(b"{}")
    with pytest.raises(ArchiveMismatch, match="sidecar"):
        run(layout)
    assert receipt(layout, 1) is None


def test_unfinished_copies_are_removed_at_start(layout, caplog):
    _, docket = layout
    manifest = cut(filled(docket))
    directory = copies(layout, manifest)
    directory.mkdir(mode=0o750)
    (directory / "seg-000000000001.tmp").write_bytes(b"partial")
    (directory / "seg-000000000007.json.tmp").write_bytes(b"partial")
    assert run(layout) == 1
    assert sorted(os.listdir(directory)) == ["seg-000000000001", "seg-000000000001.json"]
    assert "removed the unfinished archive copy" in caplog.text


def test_a_failed_directory_sync_writes_no_receipt_or_checkpoint(layout):
    _, docket = layout
    manifest = cut(filled(docket))

    def fsync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode) and os.fstat(fd).st_ino == os.stat(copies(layout, manifest)).st_ino:
            raise OSError(5, "Input/output error")
        os.fsync(fd)

    with pytest.raises(OSError, match="Input/output"):
        run(layout, fsync=fsync)
    assert receipt(layout, 1) is None
    assert not (layout[0] / "state" / "archiver.json").exists()
    assert run(layout) == 1
    assert receipt(layout, 1) is not None


def test_refuses_a_checkpoint_for_another_docket(layout):
    _, docket = layout
    cut(filled(docket))
    assert run(layout) == 1
    write_manifest(manifest_path(docket.path), Manifest("f" * 32, 1))
    with pytest.raises(ArchiveMismatch, match="checkpoint is for docket"):
        run(layout)


def test_rebuilds_heads_from_the_archive_for_a_removed_segment(layout):
    _, docket = layout
    manifest = two_segments(docket)
    assert run(layout) == 2
    first, second = manifest.segments
    write_manifest(
        manifest_path(docket.path),
        Manifest(manifest.docket_id, manifest.generation + 1, Base(1, first.entries, first.end_heads), (second,)),
    )
    segment_path(docket.path, 1).unlink()
    (layout[0] / "state" / "archiver.json").unlink()
    assert run(layout) == 2
    assert checkpoint(layout) == ArchiverCheckpoint(manifest.docket_id, 3, 5, dict(second.end_heads))


def test_a_removed_segment_without_an_archived_copy_is_refused(layout):
    _, docket = layout
    manifest = two_segments(docket)
    first, second = manifest.segments
    write_manifest(
        manifest_path(docket.path),
        Manifest(manifest.docket_id, manifest.generation + 1, Base(1, first.entries, first.end_heads), (second,)),
    )
    with pytest.raises(ArchiveMismatch, match="no archived copy"):
        run(layout)


def test_a_rebuild_refuses_a_copy_differing_from_its_sidecar(layout):
    _, docket = layout
    manifest = two_segments(docket)
    assert run(layout) == 2
    first, second = manifest.segments
    write_manifest(
        manifest_path(docket.path),
        Manifest(manifest.docket_id, manifest.generation + 1, Base(1, first.entries, first.end_heads), (second,)),
    )
    sidecar = copies(layout, manifest) / "seg-000000000001.json"
    os.chmod(sidecar, 0o600)
    sidecar.write_bytes(b"{}")
    (layout[0] / "state" / "archiver.json").unlink()
    with pytest.raises(ArchiveMismatch, match="sidecar"):
        run(layout)


def test_follow_stops_when_asked(layout):
    _, docket = layout
    cut(filled(docket))
    stop = threading.Event()
    instance = archiver(layout, poll_interval=0.01)
    thread = threading.Thread(target=lambda: instance.run(stop, follow=True))
    thread.start()
    stop.set()
    thread.join(timeout=5)
    assert not thread.is_alive()


@pytest.mark.parametrize(
    "document",
    [
        [],
        {"version": 2, "docket_id": "0" * 32, "segment": 1, "entries": 0, "heads": {}},
        {"version": 1, "docket_id": "0" * 32, "segment": 0, "entries": 0, "heads": {}},
        {"version": 1, "docket_id": "0" * 32, "segment": 1, "entries": 2, "heads": {}},
        {"version": 1, "docket_id": "X" * 32, "segment": 1, "entries": 0, "heads": {}},
        {"version": 1, "docket_id": "0" * 32, "segment": 1, "entries": 0, "heads": {}, "extra": 1},
    ],
)
def test_checkpoint_refuses_an_invalid_document(document):
    with pytest.raises(ValueError):
        ArchiverCheckpoint.from_document(document)


def test_checkpoint_round_trips():
    original = ArchiverCheckpoint("0" * 32, 3, 4, {"decide": Head(4, "A" * 43)})
    assert ArchiverCheckpoint.from_document(json.loads(original.encode())) == original


def test_copy_digest_matches_the_receipt(layout):
    _, docket = layout
    manifest = cut(filled(docket))
    run(layout)
    copy = (copies(layout, manifest) / "seg-000000000001").read_bytes()
    assert hashlib.sha256(copy).hexdigest() == receipt(layout, 1).sha256


def archive_command(layout, pin_files, capsys):
    root, docket = layout
    pins = [item for path in pin_files.values() for item in ("--pin", str(path))]
    code = cli.main(
        [
            "docket",
            "archive",
            "--docket",
            str(docket.path),
            *pins,
            "--archive",
            str(root / "archive"),
            "--receipts",
            str(root / "receipts"),
            "--checkpoint",
            str(root / "state" / "archiver.json"),
            "--once",
        ]
    )
    return code, capsys.readouterr().err


def test_cli_archives_every_sealed_segment(layout, pin_files, capsys, monkeypatch):
    two_segments(layout[1])
    monkeypatch.setattr(cli, "DocketArchiver", functools.partial(DocketArchiver, device_of=other_device))
    code, err = archive_command(layout, pin_files, capsys)
    assert code == 0, err
    assert "2 segments archived" in err


def test_cli_refuses_an_archive_on_the_docket_device(layout, pin_files, capsys):
    cut(filled(layout[1]))
    code, err = archive_command(layout, pin_files, capsys)
    assert code == 1
    assert "docket archive refused" in err
    assert "docket's device" in err


def verify_command(layout, pin_files, capsys, *arguments):
    root, docket = layout
    pins = [item for path in pin_files.values() for item in ("--pin", str(path))]
    code = cli.main(["docket", "verify", "--docket", str(docket.path), *pins, "--json", *map(str, arguments)])
    captured = capsys.readouterr()
    return code, [json.loads(line)["line"] for line in captured.out.splitlines()], captured.err


def archived_and_removed(layout):
    manifest = two_segments(layout[1])
    assert run(layout) == 2
    return manifest, remove_oldest(layout[1], manifest)


def test_verify_with_the_archive_reads_from_the_first_record(layout, pin_files, capsys):
    archived_and_removed(layout)
    code, lines, err = verify_command(layout, pin_files, capsys, "--archive", layout[0] / "archive")
    assert code == 0, err
    assert lines == [1, 2, 3, 4, 5, 6]
    assert "6 records verified, 6 printed" in err


def test_verify_without_the_archive_starts_at_the_base(layout, pin_files, capsys):
    archived_and_removed(layout)
    code, lines, err = verify_command(layout, pin_files, capsys)
    assert code == 0, err
    assert lines == [5, 6]


def tasks_command(layout, pin_files, capsys, *arguments):
    _, docket = layout
    pins = ["--pin", pin_files["decide"], "--pin", pin_files["custodian"], "--control-pin", pin_files["control"]]
    code = cli.main(["docket", "tasks", "--docket", str(docket.path), *map(str, pins), "--json", *map(str, arguments)])
    captured = capsys.readouterr()
    return code, [json.loads(line) for line in captured.out.splitlines()], captured.err


def test_tasks_with_the_archive_counts_records_in_removed_segments(layout, pin_files, capsys):
    archived_and_removed(layout)
    code, rows, err = tasks_command(layout, pin_files, capsys, "--archive", layout[0] / "archive")
    assert code == 0, err
    assert [(row["task"], row["allows"], row["releases"], row["refusals"]) for row in rows] == [("root-1", 3, 1, 1)]
    code, rows, err = tasks_command(layout, pin_files, capsys)
    assert code == 0, err
    assert [(row["task"], row["allows"], row["releases"], row["refusals"]) for row in rows] == [("root-1", 2, 0, 0)]


def test_verify_refuses_an_archived_copy_differing_from_its_sidecar(layout, pin_files, capsys):
    manifest, _ = archived_and_removed(layout)
    copy = copies(layout, manifest) / "seg-000000000001"
    content = bytearray(copy.read_bytes())
    content[-3] ^= 1
    copy.write_bytes(bytes(content))
    code, _, err = verify_command(layout, pin_files, capsys, "--archive", layout[0] / "archive")
    assert code == cli.EXIT_REFUSED
    assert "fails verification" in err


def test_verify_refuses_a_sidecar_differing_from_its_copy(layout, pin_files, capsys):
    manifest, _ = archived_and_removed(layout)
    sidecar = copies(layout, manifest) / "seg-000000000001.json"
    sidecar.write_bytes(sidecar.read_bytes().replace(b'"entries":4', b'"entries":3'))
    code, _, err = verify_command(layout, pin_files, capsys, "--archive", layout[0] / "archive")
    assert code == cli.EXIT_REFUSED
    assert "archived segment 1 does not match its sidecar" in err


def test_verify_refuses_an_archive_missing_a_removed_segment(layout, pin_files, capsys):
    manifest, _ = archived_and_removed(layout)
    (copies(layout, manifest) / "seg-000000000001").unlink()
    code, _, err = verify_command(layout, pin_files, capsys, "--archive", layout[0] / "archive")
    assert code == cli.EXIT_REFUSED
    assert "segment 1 has no archived copy" in err


def test_verify_refuses_an_archived_copy_another_uid_could_write(layout, pin_files, capsys):
    manifest, _ = archived_and_removed(layout)
    os.chmod(copies(layout, manifest) / "seg-000000000001", 0o664)
    code, _, err = verify_command(layout, pin_files, capsys, "--archive", layout[0] / "archive")
    assert code == cli.EXIT_REFUSED
    assert "with mode 0640" in err


def test_verify_refuses_an_archive_that_ends_away_from_the_base(layout, pin_files, capsys):
    _, removed = archived_and_removed(layout)
    base = removed.base
    forged = {**base.end_heads, "decide": Head(base.end_heads["decide"].seq, "A" * 43)}
    write_manifest(
        manifest_path(layout[1].path),
        Manifest(removed.docket_id, removed.generation + 1, Base(base.segment, base.entries, forged), removed.segments),
    )
    code, _, err = verify_command(layout, pin_files, capsys, "--archive", layout[0] / "archive")
    assert code == cli.EXIT_REFUSED
    assert "the archive ends at 4 records with other heads than the manifest base" in err


def receipts_flag(layout):
    return ("--receipts", layout[0] / "receipts")


def test_verify_with_receipts_matches_the_seeds(layout, pin_files, capsys):
    archived_and_removed(layout)
    code, _, err = verify_command(layout, pin_files, capsys, *receipts_flag(layout))
    assert code == 0, err
    assert "1 retained segments match their receipts and the base matches removed segment 1" in err


def test_verify_with_receipts_before_any_removal(layout, pin_files, capsys):
    two_segments(layout[1])
    run(layout)
    code, _, err = verify_command(layout, pin_files, capsys, *receipts_flag(layout))
    assert code == 0, err
    assert "2 retained segments match their receipts\n" in err


def test_verify_with_receipts_refuses_a_base_the_tombstone_disagrees_with(layout, pin_files, capsys):
    _, removed = archived_and_removed(layout)
    base, (kept,) = removed.base, removed.segments
    quiet = Head(base.end_heads["custodian"].seq, "A" * 43)
    forged_base = Base(base.segment, base.entries, {**base.end_heads, "custodian": quiet})
    forged_kept = replace(kept, end_heads={**kept.end_heads, "custodian": quiet})
    write_manifest(
        manifest_path(layout[1].path),
        Manifest(removed.docket_id, removed.generation + 1, forged_base, (forged_kept,)),
    )
    code, _, err = verify_command(layout, pin_files, capsys, *receipts_flag(layout))
    assert code == cli.EXIT_REFUSED
    assert "6 records verified" in err
    assert "segment 2 differs from its receipt; the base differs from the receipt of removed segment 1" in err


def test_verify_with_receipts_refuses_a_missing_tombstone(layout, pin_files, capsys):
    archived_and_removed(layout)
    (layout[0] / "receipts" / "seg-000000000001.receipt").unlink()
    code, _, err = verify_command(layout, pin_files, capsys, *receipts_flag(layout))
    assert code == cli.EXIT_REFUSED
    assert "removed segment 1 has no receipt" in err


def test_verify_with_receipts_refuses_a_retained_segment_its_receipt_disagrees_with(layout, pin_files, capsys):
    archived_and_removed(layout)
    with ReceiptDir.open(layout[0] / "receipts", archiver_uid=UID, reader_gid=GID) as receipts:
        receipts.write(replace(receipts.read(2), sha256="0" * 64))
    code, _, err = verify_command(layout, pin_files, capsys, *receipts_flag(layout))
    assert code == cli.EXIT_REFUSED
    assert "segment 2 differs from its receipt" in err


def test_verify_with_receipts_refuses_a_receipt_dir_others_can_write(layout, pin_files, capsys):
    archived_and_removed(layout)
    os.chmod(layout[0] / "receipts", 0o770)
    code, _, err = verify_command(layout, pin_files, capsys, *receipts_flag(layout))
    assert code == cli.EXIT_REFUSED
    assert "with mode 0750" in err


class HandlerStopped(Exception):
    pass


def follow_archive(layout, **options):
    root, docket = layout
    checkpoint = root / "follower" / "checkpoint.json"
    checkpoint.parent.mkdir(mode=0o700, exist_ok=True)
    seen = []
    follower = DocketFollower(
        docket.path,
        INDEX,
        checkpoint,
        lambda batch, stop: seen.extend(line.line for line in batch),
        archive=root / "archive",
        **options,
    )
    follower.run(threading.Event(), follow=False)
    return seen


def test_a_new_follower_with_the_archive_starts_at_the_first_record(layout):
    archived_and_removed(layout)
    assert follow_archive(layout) == [1, 2, 3, 4, 5, 6]


def test_a_follower_behind_a_removed_segment_resumes_from_its_archived_copy(layout):
    _, docket = layout
    manifest = two_segments(docket)
    run(layout)

    checkpoint_path = layout[0] / "follower" / "checkpoint.json"
    checkpoint_path.parent.mkdir(mode=0o700)
    seen = []

    def first_batch_only(batch, stop):
        if seen:
            raise HandlerStopped
        seen.extend(line.line for line in batch)

    with pytest.raises(HandlerStopped):
        DocketFollower(docket.path, INDEX, checkpoint_path, first_batch_only, batch_size=2).run(
            threading.Event(), follow=False
        )
    remove_oldest(docket, manifest)
    with pytest.raises(SegmentRemoved):
        DocketFollower(docket.path, INDEX, checkpoint_path, lambda batch, stop: None).run(
            threading.Event(), follow=False
        )
    assert follow_archive(layout) == [3, 4, 5, 6]


def test_a_follower_refuses_a_sidecar_that_is_not_canonical(layout):
    manifest, _ = archived_and_removed(layout)
    sidecar = copies(layout, manifest) / "seg-000000000001.json"
    sidecar.write_bytes(sidecar.read_bytes() + b" ")
    with pytest.raises(ArchiveMismatch, match="canonical sidecar"):
        follow_archive(layout)


def test_a_follower_refuses_an_archived_copy_cut_short(layout):
    manifest, _ = archived_and_removed(layout)
    copy = copies(layout, manifest) / "seg-000000000001"
    copy.write_bytes(copy.read_bytes()[:-1])
    with pytest.raises(ArchiveMismatch, match="not the .* of its sidecar"):
        follow_archive(layout)


class Clock:
    def __init__(self, now=NOW):
        self.now = now

    def __call__(self):
        return self.now


def remove_oldest(docket, manifest):
    oldest, *rest = manifest.segments
    removed = Manifest(
        manifest.docket_id,
        manifest.generation + 1,
        Base(oldest.segment, oldest.first_entry + oldest.entries - 1, oldest.end_heads),
        tuple(rest),
    )
    write_manifest(manifest_path(docket.path), removed)
    segment_path(docket.path, oldest.segment).unlink()
    return removed


def test_each_run_rechecks_receipts_at_start(layout):
    two_segments(layout[1])
    clock = Clock()
    assert run(layout, clock=clock) == 2
    clock.now = NOW + 99
    assert run(layout, clock=clock) == 0
    assert receipt(layout, 1).verified_at == NOW + 99


def test_refresh_waits_for_the_interval_within_one_run(layout):
    two_segments(layout[1])
    clock = Clock()
    instance = archiver(layout, clock=clock, refresh_interval=100, jitter=lambda: 0.5)
    instance._open()
    try:
        assert instance._archive_next() and instance._archive_next()
        assert instance._refresh_next()
        clock.now = NOW + 99
        assert not instance._refresh_next()
        assert receipt(layout, 2).verified_at == NOW
        clock.now = NOW + 100
        assert instance._refresh_next()
        assert receipt(layout, 2).verified_at == NOW + 100
    finally:
        instance._close()


@pytest.mark.parametrize(("draw", "delay"), [(0.0, 90), (0.5, 100), (0.999999, 110)])
def test_refresh_jitter_stays_within_ten_percent(layout, draw, delay):
    cut(filled(layout[1]))
    clock = Clock()
    instance = archiver(layout, clock=clock, refresh_interval=100, jitter=lambda: draw)
    instance._open()
    try:
        instance._archive_next()
        instance._refresh_next()
        assert round(instance._next_refresh - NOW) == delay
    finally:
        instance._close()


def test_refresh_handles_a_bounded_batch_per_step(layout):
    _, docket = layout
    manifest = cut(filled(docket))
    for number in range(5, 5 + REFRESH_BATCH + 2):
        docket.append("decide", make_entry(number))
        manifest = cut(docket, manifest)
    clock = Clock()
    instance = archiver(layout, clock=clock)
    instance._open()
    try:
        while instance._archive_next():
            pass
        clock.now = NOW + 1
        assert instance._refresh_next()
        refreshed = [receipt(layout, entry.segment).verified_at for entry in manifest.segments]
        assert refreshed == [NOW + 1] * REFRESH_BATCH + [NOW] * 3
        assert instance._refresh_next()
        assert not instance._refresh_next()
    finally:
        instance._close()


def test_refresh_removes_the_receipt_of_a_missing_copy(layout, caplog):
    manifest = two_segments(layout[1])
    assert run(layout) == 2
    (copies(layout, manifest) / "seg-000000000001").unlink()
    run(layout)
    assert receipt(layout, 1) is None
    assert receipt(layout, 2) is not None
    assert "missing or differs from its manifest entry" in caplog.text


def test_refresh_removes_the_receipt_of_a_changed_copy(layout):
    manifest = two_segments(layout[1])
    assert run(layout) == 2
    copy = copies(layout, manifest) / "seg-000000000002"
    os.chmod(copy, 0o600)
    copy.write_bytes(copy.read_bytes()[:-1] + b" ")
    run(layout)
    assert receipt(layout, 2) is None
    assert receipt(layout, 1) is not None


def test_refresh_removes_a_receipt_differing_from_its_manifest_entry(layout):
    two_segments(layout[1])
    assert run(layout) == 2
    with ReceiptDir.open(layout[0] / "receipts", archiver_uid=UID, reader_gid=GID) as receipts:
        receipts.write(replace(receipts.read(1), end_heads={"decide": Head(1, "A" * 43)}))
    run(layout)
    assert receipt(layout, 1) is None


def test_refresh_keeps_the_tombstone_and_removes_older_receipts(layout):
    _, docket = layout
    manifest = two_segments(docket)
    docket.append("decide", make_entry(7))
    manifest = cut(docket, manifest)
    assert run(layout) == 3
    manifest = remove_oldest(docket, manifest)
    run(layout)
    assert [receipt(layout, segment) is not None for segment in (1, 2, 3)] == [True, True, True]
    manifest = remove_oldest(docket, manifest)
    run(layout)
    assert [receipt(layout, segment) is not None for segment in (1, 2, 3)] == [False, True, True]
    tombstone = receipt(layout, 2)
    assert tombstone.verified_at == NOW


def replace_copies_dir(layout, manifest):
    live = copies(layout, manifest)
    os.rename(live, layout[0] / "archive" / "detached")
    live.mkdir(mode=0o750)
    os.chown(live, -1, GID)
    os.chmod(live, 0o750)


def test_writes_no_receipt_once_the_archive_dir_is_replaced_at_its_path(layout):
    _, docket = layout
    manifest = cut(filled(docket))
    instance = archiver(layout)
    instance._open()
    try:
        assert instance._archive_next()
        replace_copies_dir(layout, manifest)
        docket.append("decide", make_entry(5))
        cut(docket, manifest)
        with pytest.raises(ArchiveMismatch, match="no longer the directory the archiver opened"):
            instance._archive_next()
    finally:
        instance._close()
    assert receipt(layout, 2) is None


def test_writes_no_receipt_once_the_archive_root_is_replaced_by_a_symlink_to_it(layout):
    root, docket = layout
    manifest = cut(filled(docket))
    instance = archiver(layout)
    instance._open()
    try:
        assert instance._archive_next()
        os.rename(root / "archive", root / "detached")
        (root / "archive").symlink_to(root / "detached")
        docket.append("decide", make_entry(5))
        cut(docket, manifest)
        with pytest.raises(ArchiveMismatch, match=f"{root / 'archive'} is no longer the directory"):
            instance._archive_next()
    finally:
        instance._close()
    assert receipt(layout, 2) is None


@pytest.mark.parametrize("remove", [lambda path: os.rename(path, path.with_name("detached")), shutil.rmtree])
def test_writes_no_receipt_once_the_archive_dir_is_removed_from_its_path(layout, remove):
    _, docket = layout
    manifest = cut(filled(docket))
    instance = archiver(layout)
    instance._open()
    try:
        assert instance._archive_next()
        remove(copies(layout, manifest))
        docket.append("decide", make_entry(5))
        cut(docket, manifest)
        with pytest.raises(ArchiveMismatch, match="no longer the directory the archiver opened"):
            instance._archive_next()
    finally:
        instance._close()
    assert receipt(layout, 2) is None


def test_refreshes_no_receipt_once_the_archive_dir_is_replaced_at_its_path(layout):
    manifest = two_segments(layout[1])
    clock = Clock()
    instance = archiver(layout, clock=clock)
    instance._open()
    try:
        assert instance._archive_next() and instance._archive_next()
        replace_copies_dir(layout, manifest)
        clock.now = NOW + 1
        with pytest.raises(ArchiveMismatch, match="no longer the directory the archiver opened"):
            instance._refresh_next()
    finally:
        instance._close()
    assert receipt(layout, 1).verified_at == NOW


def test_the_first_prune_removes_every_receipt_below_the_tombstone(layout):
    tombstone = 100
    instance = archiver(layout)
    instance._open()
    try:
        heads = {"decide": Head(1, "A" * 43)}
        for segment in range(1, tombstone + 1):
            instance._receipts.write(Receipt("0" * 32, segment, "0" * 64, 1, heads, NOW))
        (layout[0] / "receipts" / "notes").write_bytes(b"")
        instance._prune(Manifest("0" * 32, 2, Base(tombstone, 1, heads), ()))
    finally:
        instance._close()
    assert sorted(os.listdir(layout[0] / "receipts")) == ["notes", "seg-000000000100.receipt"]


PROBE = """import os, sys
directory, name = sys.argv[1], sys.argv[2]
path = os.path.join(directory, name)


def attempt(label, operation):
    try:
        operation()
    except PermissionError:
        print(label, "denied")
    else:
        print(label, "allowed")


def rename():
    os.rename(path, path + ".moved")
    os.rename(path + ".moved", path)


attempt("write", lambda: open(path, "ab").close())
attempt("create", lambda: open(os.path.join(directory, "planted"), "xb").close())
attempt("rename", rename)
attempt("unlink", lambda: os.unlink(path))
"""

OPERATIONS = ("write", "create", "rename", "unlink")


def probe_as(user, directory, name):
    result = run_as(user, sys.executable, "-I", "-c", PROBE, str(directory), name)
    assert result.returncode == 0, result
    return dict(line.split() for line in result.stdout.splitlines())


@pytest.fixture
def shared_layout():
    root = Path(tempfile.mkdtemp(prefix="ba-", dir="/tmp"))
    os.chmod(root, 0o755)
    yield make_layout(root)
    shutil.rmtree(root)


@linux_cross_uid[0]
@linux_cross_uid[1]
def test_the_sink_uid_cannot_write_the_receipt_dir(shared_layout):
    two_segments(shared_layout[1])
    assert run(shared_layout) == 2
    receipts = shared_layout[0] / "receipts"
    for name in sorted(os.listdir(receipts)):
        assert probe_as(OTHER_USER, receipts, name) == dict.fromkeys(OPERATIONS, "denied")
    assert len(os.listdir(receipts)) == 2


@linux_cross_uid[0]
@linux_cross_uid[1]
def test_the_sink_uid_cannot_change_the_archive(shared_layout):
    manifest = two_segments(shared_layout[1])
    assert run(shared_layout) == 2
    directory = copies(shared_layout, manifest)
    before = {name: (directory / name).read_bytes() for name in os.listdir(directory)}
    for name in sorted(before):
        assert probe_as(OTHER_USER, directory, name) == dict.fromkeys(OPERATIONS, "denied")
    assert {name: (directory / name).read_bytes() for name in os.listdir(directory)} == before


@linux_cross_uid[0]
@linux_cross_uid[1]
def test_the_probe_reports_a_group_writable_dir(shared_layout):
    directory = shared_layout[0] / "open"
    directory.mkdir()
    os.chown(directory, -1, GID)
    os.chmod(directory, 0o770)
    target = directory / "target"
    target.touch()
    os.chown(target, -1, GID)
    os.chmod(target, 0o660)
    assert probe_as(OTHER_USER, directory, "target") == dict.fromkeys(OPERATIONS, "allowed")
