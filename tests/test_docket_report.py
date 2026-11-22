import asyncio
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_docket import RunningSink, make_entry

from agent_bailiff import cli
from agent_bailiff.docket import DocketClient, DocketSink, decode_record, encode_record
from agent_bailiff.docket import segments as segments_module
from agent_bailiff.docket.entry import ENTRY_TYP, Head, _entry_body
from agent_bailiff.docket.manifest import Base, Manifest, SegmentEntry, manifest_path, segment_path, write_manifest
from agent_bailiff.docket.report import RELEASED, verify_docket
from agent_bailiff.docket.sink import ChainState, Verification, build_kid_index
from agent_bailiff.docket.snapshot import Anchor, Snapshot, read_snapshot, snapshot_path, write_snapshot
from agent_bailiff.keys import PublicKeyRecord, key_id
from agent_bailiff.signing import sign

DECIDE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
CUSTODIAN_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
CONTROL_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(2, 34)))
PINS = {
    name: PublicKeyRecord(name, key_id(name, key.public_key()), key.public_key())
    for name, key in (("decide", DECIDE_KEY), ("custodian", CUSTODIAN_KEY), ("control", CONTROL_KEY))
}
KEYS = {"decide": DECIDE_KEY, "custodian": CUSTODIAN_KEY, "control": CONTROL_KEY}
WRITERS = {name: {pin.kid: pin.public_key} for name, pin in PINS.items()}
OTHER_USER = os.environ.get("AGENT_BAILIFF_TEST_OTHER_USER")


@pytest.fixture
def workdir():
    path = Path(tempfile.mkdtemp(prefix="br-", dir="/tmp"))
    yield path
    shutil.rmtree(path)


@pytest.fixture
def pin_files(workdir):
    paths = {}
    for name, pin in PINS.items():
        paths[name] = workdir / f"{name}.pub.json"
        paths[name].write_text(json.dumps(pin.to_document()))
        os.chmod(paths[name], 0o644)
    return paths


class Docket:
    def __init__(self, path):
        self.path = path
        self.heads = {}
        self.records = []

    def append(self, writer, entry):
        seq, prev = self.heads.get(writer, (0, None))
        record = encode_record(KEYS[writer], PINS[writer].kid, writer, seq + 1, prev, entry)
        with open(self.path, "a") as docket:
            docket.write(f"{record.token}\n")
        self.heads[writer] = (record.seq, record.hash)
        self.records.append(record)
        return record


@pytest.fixture
def docket(workdir):
    path = workdir / "docket.log"
    path.touch(mode=0o600)
    return Docket(path)


def sealed_entry(docket, manifest):
    content = docket.path.read_bytes()
    before = manifest.entries
    records = docket.records[before:]
    return SegmentEntry(
        manifest.active_segment,
        hashlib.sha256(content).hexdigest(),
        len(content),
        before + 1,
        len(records),
        {writer: Head(*head) for writer, head in docket.heads.items()},
        frozenset(record.kid for record in records),
    )


def cut(docket, manifest=None, *, rename=True):
    previous = manifest or Manifest.new()
    sealed = previous.sealed(sealed_entry(docket, previous))
    write_manifest(manifest_path(docket.path), sealed)
    if rename:
        finish_cut(docket, sealed)
    return sealed


def finish_cut(docket, manifest):
    docket.path.rename(segment_path(docket.path, manifest.segments[-1].segment))
    docket.path.touch(mode=0o600)


def filled(docket):
    docket.append("decide", make_entry(1, trace_id="trace-a", task_root="task-a"))
    docket.append(
        "custodian",
        make_entry(2, trace_id="trace-a", task_root="task-a", hop="custodian", component="custodian", performed=True),
    )
    docket.append("decide", make_entry(3, trace_id="trace-b", task_root="task-b", decision="refuse"))
    docket.append(
        "decide",
        make_entry(4, trace_id="trace-a", task_root=None, decision="revoke", handles={"task": "task-a"}),
    )
    return docket


def verify(docket, pin_files, *arguments, capsys, writers=("decide", "custodian")):
    pins = [item for name in writers for item in ("--pin", pin_files[name])]
    code = cli.main(["docket", "verify", "--docket", str(docket.path), *map(str, pins), *arguments])
    captured = capsys.readouterr()
    return code, captured.out.splitlines(), captured.err


def json_rows(lines):
    return [json.loads(line) for line in lines]


def test_verify_prints_every_record_and_succeeds(docket, pin_files, capsys):
    filled(docket)
    code, out, err = verify(docket, pin_files, capsys=capsys)
    assert code == 0, err
    assert out[0].split("\t") == ["LINE", "AT", "WRITER", "SEQ", "DECISION", "TOOL", "RESOURCE", "REASON", "NOTE"]
    assert [row.split("\t")[:5] for row in out[1:]] == [
        ["1", "2023-11-14T22:13:21Z", "decide", "1", "allow"],
        ["2", "2023-11-14T22:13:22Z", "custodian", "1", "allow"],
        ["3", "2023-11-14T22:13:23Z", "decide", "2", "refuse"],
        ["4", "2023-11-14T22:13:24Z", "decide", "3", "revoke"],
    ]
    assert "4 records verified, 4 printed" in err


def test_a_released_record_is_labelled_outcome_unknown(docket, pin_files, capsys):
    filled(docket)
    _, out, _ = verify(docket, pin_files, capsys=capsys)
    assert [row.split("\t")[-1] for row in out[1:]] == ["-", RELEASED, "-", "-"]


def test_json_rows_carry_the_signed_record(docket, pin_files, capsys):
    filled(docket)
    code, out, err = verify(docket, pin_files, "--json", capsys=capsys)
    assert code == 0, err
    rows = json_rows(out)
    assert [row["token"] for row in rows] == [record.token for record in docket.records]
    assert [row["hash"] for row in rows] == [record.hash for record in docket.records]
    assert rows[1]["note"] == RELEASED and rows[1]["entry"]["performed"] is True
    assert rows[3]["entry"]["handles"] == {"task": "task-a"}
    decoded = decode_record(rows[2]["token"], build_kid_index(WRITERS))
    assert decoded.entry.decision == rows[2]["entry"]["decision"] == "refuse"


@pytest.mark.parametrize(
    ("arguments", "lines"),
    [
        (["--trace", "trace-a"], [1, 2, 4]),
        (["--task", "task-a"], [1, 2, 4]),
        (["--task", "task-b"], [3]),
        (["--since", "1700000003"], [3, 4]),
        (["--trace", "trace-a", "--since", "1700000002"], [2, 4]),
        (["--trace", "trace-none"], []),
    ],
)
def test_filters_select_records_but_every_record_is_verified(docket, pin_files, capsys, arguments, lines):
    filled(docket)
    code, out, err = verify(docket, pin_files, "--json", *arguments, capsys=capsys)
    assert code == 0, err
    assert [row["line"] for row in json_rows(out)] == lines
    assert f"4 records verified, {len(lines)} printed" in err


def test_filters_do_not_hide_a_corrupt_record(docket, pin_files, capsys):
    filled(docket)
    with open(docket.path, "a") as stream:
        stream.write("garbage\n")
    code, out, err = verify(docket, pin_files, "--json", "--trace", "trace-none", capsys=capsys)
    assert code == cli.EXIT_REFUSED
    assert out == []
    assert "line 5 fails verification: malformed" in err


def test_a_corrupt_record_fails_after_printing_the_records_before_it(docket, pin_files, capsys):
    filled(docket)
    content = docket.path.read_text().splitlines()
    docket.path.write_text("\n".join([content[0], content[1], content[3], content[2]]) + "\n")
    code, out, err = verify(docket, pin_files, "--json", capsys=capsys)
    assert code == cli.EXIT_REFUSED
    assert [row["line"] for row in json_rows(out)] == [1, 2]
    assert "line 3 fails verification: wrong_seq" in err and "2 records before it verified" in err


def test_a_torn_tail_fails_and_points_to_repair(docket, pin_files, capsys):
    filled(docket)
    with open(docket.path, "a") as stream:
        stream.write("partial")
    code, out, err = verify(docket, pin_files, "--json", capsys=capsys)
    assert code == cli.EXIT_REFUSED
    assert len(out) == 4
    assert "line 5 fails verification: torn_tail" in err and "Torn tail repair" in err


def test_torn_tail_after_a_cut_is_reported_as_torn_tail(docket):
    docket.append("decide", make_entry(1))
    docket.append("decide", make_entry(2))
    cut(docket)
    docket.append("decide", make_entry(3))
    with open(docket.path, "a") as stream:
        stream.write("partial")
    report = verify_docket(docket.path, WRITERS)
    assert (report.ok, report.reason, report.entries) == (False, "torn_tail", 3)


def test_a_missing_docket_that_was_never_cut_raises_file_not_found(tmp_path):
    with pytest.raises(FileNotFoundError):
        verify_docket(tmp_path / "docket.log", WRITERS)


def test_a_record_of_an_unpinned_writer_fails(docket, pin_files, capsys):
    filled(docket)
    code, _, err = verify(docket, pin_files, "--json", capsys=capsys, writers=("decide",))
    assert code == cli.EXIT_REFUSED
    assert "line 2 fails verification: unknown_kid" in err


def test_a_record_signed_by_another_key_fails(docket, pin_files, capsys):
    record = encode_record(
        Ed25519PrivateKey.generate(), PINS["decide"].kid, "decide", 1, None, make_entry(1, decision="allow")
    )
    docket.path.write_text(f"{record.token}\n")
    code, out, err = verify(docket, pin_files, "--json", capsys=capsys)
    assert code == cli.EXIT_REFUSED and out == []
    assert "line 1 fails verification: bad_signature" in err


def test_an_empty_docket_verifies(docket, pin_files, capsys):
    code, out, err = verify(docket, pin_files, capsys=capsys)
    assert code == 0, err
    assert len(out) == 1 and "0 records verified, 0 printed" in err


def test_an_invalid_pin_file_is_refused(docket, pin_files, capsys):
    pin_files["decide"].write_text("{}")
    code, _, err = verify(docket, pin_files, capsys=capsys)
    assert code == cli.EXIT_REFUSED and "not a public key record" in err


def test_a_missing_docket_is_refused(docket, pin_files, capsys):
    docket.path.unlink()
    code, _, err = verify(docket, pin_files, "--json", capsys=capsys)
    assert code == cli.EXIT_REFUSED and "docket verify refused" in err


def test_table_cells_escape_control_characters(docket, pin_files, capsys):
    docket.append("decide", make_entry(1, tool="evil\x1b[2J\ttool", resource="r‮", reason="line\nbreak"))
    _, out, _ = verify(docket, pin_files, capsys=capsys)
    cells = out[1].split("\t")
    assert len(cells) == 9
    assert cells[5:8] == ["evil\\x1b[2J\\ttool", "r\\u202e", "line\\nbreak"]


def test_a_literal_backslash_is_escaped_so_it_cannot_imitate_an_escape(docket, pin_files, capsys):
    docket.append("decide", make_entry(1, tool="evil\\x1b"))
    _, out, _ = verify(docket, pin_files, capsys=capsys)
    assert out[1].split("\t")[5] == "evil\\\\x1b"


def test_a_failure_detail_escapes_control_characters(docket, pin_files, capsys):
    body = {**_entry_body(make_entry(1)), "handles": {"\x1b[2J": "x"}, "writer": "decide", "seq": 1, "prev": None}
    docket.path.write_text(sign(DECIDE_KEY, PINS["decide"].kid, ENTRY_TYP, body) + "\n")
    code, _, err = verify(docket, pin_files, capsys=capsys)
    assert code == cli.EXIT_REFUSED
    assert "invalid_field" in err and "\\x1b[2J" in err and "\x1b" not in err


def test_a_time_beyond_the_calendar_is_printed_as_a_number(docket, pin_files, capsys):
    docket.append("decide", replace(make_entry(1), at=2**53 - 1))
    code, out, err = verify(docket, pin_files, capsys=capsys)
    assert code == 0, err
    assert out[1].split("\t")[1] == str(2**53 - 1)


def run_as(user, *command):
    return subprocess.run(["sudo", "-n", "-u", user, *command], capture_output=True, text=True, timeout=60)


def shared_docket(workdir, reader_gid):
    os.chmod(workdir, 0o755)
    directory = workdir / "d"
    directory.mkdir(mode=0o700)
    os.chown(directory, -1, os.getegid())
    os.chmod(directory, 0o750 if reader_gid is not None else 0o700)
    path = directory / "docket.log"
    sink = DocketSink(path, workdir / "s" / "docket.sock", WRITERS, {os.getuid()}, reader_gid=reader_gid)

    async def start_and_stop():
        await sink.start()
        await sink.close()

    asyncio.run(start_and_stop())
    return filled(Docket(path))


def verify_as(user, docket, pin_files, *arguments):
    pins = [str(item) for name in PINS for item in ("--pin", pin_files[name])]
    command = [sys.executable, "-I", "-m", "agent_bailiff.cli", "docket", "verify", "--docket", str(docket.path)]
    return run_as(user, *command, *pins, "--json", *arguments)


linux_cross_uid = [
    pytest.mark.skipif(sys.platform != "linux", reason="cross-uid reads run in Linux CI only"),
    pytest.mark.skipif(not OTHER_USER, reason="set AGENT_BAILIFF_TEST_OTHER_USER to a user in this user's group"),
]


@linux_cross_uid[0]
@linux_cross_uid[1]
def test_a_reader_group_member_verifies_the_docket_as_its_own_uid(workdir, pin_files):
    docket = shared_docket(workdir, os.getegid())
    result = verify_as(OTHER_USER, docket, pin_files)
    assert result.returncode == 0, result
    assert [json.loads(line)["token"] for line in result.stdout.splitlines()] == [r.token for r in docket.records]


@linux_cross_uid[0]
@linux_cross_uid[1]
def test_a_reader_group_member_cross_checks_the_snapshot_as_its_own_uid(workdir, pin_files):
    docket = shared_docket(workdir, os.getegid())
    result = verify_as(OTHER_USER, docket, pin_files, "--snapshot", str(snapshot_path(docket.path)))
    assert result.returncode == 0, result
    assert "matches the docket" in result.stderr


@linux_cross_uid[0]
@linux_cross_uid[1]
def test_a_user_outside_the_reader_group_cannot_open_the_docket(workdir):
    docket = shared_docket(workdir, os.getegid())
    probe = "import sys\ntry:\n    open(sys.argv[1], 'rb')\nexcept PermissionError:\n    print('denied')\n"
    result = run_as("nobody", "/usr/bin/python3", "-I", "-c", probe, str(docket.path))
    assert result.stdout.strip() == "denied", result


@linux_cross_uid[0]
@linux_cross_uid[1]
def test_a_group_member_cannot_read_a_docket_without_a_reader_group(workdir, pin_files):
    docket = shared_docket(workdir, None)
    result = verify_as(OTHER_USER, docket, pin_files)
    assert result.returncode == cli.EXIT_REFUSED and "Permission denied" in result.stderr, result


def snapshot_at(docket, lines=None):
    chain = ChainState()
    with open(docket.path, "rb") as stream:
        for verified in Verification(stream, build_kid_index(WRITERS)):
            if lines is not None and verified.line > lines:
                break
            chain.add(verified.start, verified.record)
    return chain.snapshot()


def sealed(docket, snapshot):
    path = snapshot_path(docket.path)
    write_snapshot(path, snapshot)
    return path


def test_verify_with_a_matching_snapshot_succeeds(docket, pin_files, capsys):
    filled(docket)
    plain = verify(docket, pin_files, capsys=capsys)
    snapshot = snapshot_at(docket, lines=3)
    path = sealed(docket, snapshot)
    code, out, err = verify(docket, pin_files, "--snapshot", str(path), capsys=capsys)
    assert code == 0, err
    assert out == plain[1]
    assert f"snapshot at offset {snapshot.offset} matches the docket, 1 records after it" in err


def test_verify_without_the_flag_prints_no_snapshot_line(docket, pin_files, capsys):
    filled(docket)
    sealed(docket, snapshot_at(docket))
    code, _, err = verify(docket, pin_files, capsys=capsys)
    assert code == 0 and "snapshot" not in err


def test_an_empty_snapshot_matches_any_docket(docket, pin_files, capsys):
    path = sealed(docket, snapshot_at(docket))
    filled(docket)
    code, _, err = verify(docket, pin_files, "--snapshot", str(path), capsys=capsys)
    assert code == 0, err
    assert "snapshot at offset 0 matches the docket, 4 records after it" in err


def other_anchor(snapshot):
    anchor = snapshot.anchors["decide"]
    return {**snapshot.anchors, "decide": Anchor(anchor.offset, anchor.seq, "A" * 43)}


@pytest.mark.parametrize(
    ("change", "difference"),
    [
        (lambda snapshot: replace(snapshot, segment=2), "segment"),
        (lambda snapshot: replace(snapshot, prefix_sha256="0" * 64), "prefix_sha256"),
        (lambda snapshot: replace(snapshot, entries=snapshot.entries + 1), "entries"),
        (lambda snapshot: replace(snapshot, anchors=other_anchor(snapshot)), "anchors"),
        (lambda snapshot: replace(snapshot, kids=snapshot.kids | {"rogue-1"}), "kids"),
        (lambda snapshot: replace(snapshot, offset=snapshot.offset - 1), "is not the end of a verified line"),
        (lambda snapshot: replace(snapshot, offset=snapshot.offset + 10_000), "is not the end of a verified line"),
    ],
)
def test_verify_with_a_mismatched_snapshot_fails(docket, pin_files, capsys, change, difference):
    filled(docket)
    path = sealed(docket, change(snapshot_at(docket, lines=3)))
    code, out, err = verify(docket, pin_files, "--snapshot", str(path), capsys=capsys)
    assert code == cli.EXIT_REFUSED
    assert len(out) == 5
    assert "does not match the docket" in err and difference in err


def test_verify_with_a_snapshot_still_fails_on_a_corrupt_docket(docket, pin_files, capsys):
    filled(docket)
    path = sealed(docket, snapshot_at(docket))
    with open(docket.path, "a") as stream:
        stream.write("garbage\n")
    code, _, err = verify(docket, pin_files, "--snapshot", str(path), capsys=capsys)
    assert code == cli.EXIT_REFUSED
    assert "line 5 fails verification: malformed" in err


def test_verify_refuses_a_missing_snapshot(docket, pin_files, capsys):
    filled(docket)
    code, out, err = verify(docket, pin_files, "--snapshot", str(snapshot_path(docket.path)), capsys=capsys)
    assert code == cli.EXIT_REFUSED and out == []
    assert "does not exist" in err


@pytest.mark.parametrize("mode", [0o644, 0o640])
def test_verify_refuses_a_snapshot_with_another_mode_than_the_docket(docket, pin_files, capsys, mode):
    filled(docket)
    path = sealed(docket, snapshot_at(docket))
    os.chmod(path, mode)
    code, _, err = verify(docket, pin_files, "--snapshot", str(path), capsys=capsys)
    assert code == cli.EXIT_REFUSED and "0600" in err


def test_verify_takes_the_snapshot_group_from_a_shared_docket(docket, pin_files, capsys):
    filled(docket)
    path = snapshot_path(docket.path)
    write_snapshot(path, snapshot_at(docket), reader_gid=os.getegid())
    os.chown(docket.path, -1, os.getegid())
    os.chmod(docket.path, 0o640)
    code, _, err = verify(docket, pin_files, "--snapshot", str(path), capsys=capsys)
    assert code == 0, err
    os.chmod(path, 0o600)
    code, _, err = verify(docket, pin_files, "--snapshot", str(path), capsys=capsys)
    assert code == cli.EXIT_REFUSED and "0640" in err


def test_verify_cross_checks_a_snapshot_the_sink_wrote(docket, pin_files, capsys):
    socket_dir = docket.path.parent / "s"
    sink = DocketSink(docket.path, socket_dir / "docket.sock", WRITERS, {os.getuid()})

    async def run():
        await sink.start()
        await sink.close()

    filled(docket)
    asyncio.run(run())
    code, _, err = verify(docket, pin_files, "--snapshot", str(snapshot_path(docket.path)), capsys=capsys)
    assert code == 0, err
    assert "matches the docket" in err


def sink_paths(docket):
    return docket.path, docket.path.parent / "s" / "docket.sock"


def start_sink(docket, **options):
    docket_path, socket_path = sink_paths(docket)
    return RunningSink(DocketSink(docket_path, socket_path, WRITERS, {os.getuid()}, **options))


def client(docket, writer, state="state"):
    directory = docket.path.parent / state
    directory.mkdir(mode=0o700, exist_ok=True)
    socket_path = sink_paths(docket)[1]
    return DocketClient(socket_path, writer, PINS[writer].kid, KEYS[writer], sink_uid=os.getuid(), state_dir=directory)


def check_snapshot(docket, pin_files, capsys):
    return verify(docket, pin_files, "--snapshot", str(snapshot_path(docket.path)), capsys=capsys)


def test_two_writers_across_restarts_keep_a_snapshot_verify_accepts(docket, pin_files, capsys):
    number = 0
    for _ in range(3):
        handle = start_sink(docket, snapshot_every=2)
        writers = {name: client(docket, name) for name in ("decide", "custodian")}
        for _ in range(3):
            for name, writer in writers.items():
                number += 1
                writer.append(make_entry(number, hop=name, component=name))
        for writer in writers.values():
            writer.close()
        handle.stop()
        code, _, err = check_snapshot(docket, pin_files, capsys)
        assert code == 0, err
        assert read_snapshot(snapshot_path(docket.path), uid=os.getuid()).entries == number
    handle = start_sink(docket)
    heads = handle.sink.heads
    handle.stop()
    snapshot_path(docket.path).unlink()
    handle = start_sink(docket)
    assert handle.sink.heads == heads
    handle.stop()
    assert {name: head.seq for name, head in heads.items()} == {"decide": 9, "custodian": 9}


def forged_snapshot(docket, anchors):
    content = docket.path.read_bytes()
    lines = content.splitlines(keepends=True)
    return Snapshot(
        segment=1,
        offset=len(content),
        entries=len(lines),
        prefix_sha256=hashlib.sha256(content).hexdigest(),
        anchors=anchors,
        kids=frozenset(pin.kid for pin in PINS.values()),
    )


def line_starts(docket):
    starts, position = [], 0
    for line in docket.path.read_bytes().splitlines(keepends=True):
        starts.append(position)
        position += len(line)
    return starts


def test_residual_sink_uid_deleting_a_record_under_a_rebuilt_snapshot_starts(docket, pin_files, capsys):
    filled(docket)
    content = docket.path.read_text().splitlines(keepends=True)
    docket.path.write_text("".join(content[:2] + content[3:]))
    starts = line_starts(docket)
    decide, custodian = docket.records[3], docket.records[1]
    anchors = {
        "decide": Anchor(starts[2], decide.seq, decide.hash),
        "custodian": Anchor(starts[1], custodian.seq, custodian.hash),
    }
    write_snapshot(snapshot_path(docket.path), forged_snapshot(docket, anchors))
    handle = start_sink(docket)
    assert handle.sink.heads["decide"].seq == 3
    handle.stop()
    code, _, err = check_snapshot(docket, pin_files, capsys)
    assert code == cli.EXIT_REFUSED
    assert "line 3 fails verification: wrong_seq" in err


def test_residual_an_omitted_anchor_lets_a_fresh_client_fork_until_verify(docket, pin_files, capsys):
    filled(docket)
    starts = line_starts(docket)
    decide = docket.records[3]
    write_snapshot(
        snapshot_path(docket.path), forged_snapshot(docket, {"decide": Anchor(starts[3], decide.seq, decide.hash)})
    )
    handle = start_sink(docket)
    forked = client(docket, "custodian", state="fresh-state").append(
        make_entry(9, hop="custodian", component="custodian")
    )
    assert forked.seq == 1
    handle.stop()
    code, _, err = verify(docket, pin_files, capsys=capsys)
    assert code == cli.EXIT_REFUSED
    assert "line 5 fails verification: wrong_seq" in err


def fill(docket, start, stop):
    for number in range(start, stop):
        docket.append("decide", make_entry(number))


def test_verify_reads_every_segment_in_order(docket, pin_files, capsys):
    fill(docket, 1, 3)
    manifest = cut(docket)
    fill(docket, 3, 5)
    cut(docket, manifest)
    fill(docket, 5, 6)
    code, out, err = verify(docket, pin_files, "--json", capsys=capsys)
    assert code == 0, err
    assert [row["line"] for row in json_rows(out)] == [1, 2, 3, 4, 5]
    assert "5 records verified, 5 printed" in err


def test_verify_starts_from_the_base_after_removed_segments(docket, pin_files, capsys):
    fill(docket, 1, 3)
    manifest = cut(docket)
    write_manifest(manifest_path(docket.path), Manifest(manifest.docket_id, 2, Base(1, 2, manifest.seeds)))
    segment_path(docket.path, 1).unlink()
    fill(docket, 3, 5)
    code, out, err = verify(docket, pin_files, "--json", capsys=capsys)
    assert code == 0, err
    assert [row["line"] for row in json_rows(out)] == [3, 4]


def test_a_bad_record_in_a_sealed_segment_fails_at_its_global_line(docket, pin_files, capsys):
    fill(docket, 1, 3)
    manifest = cut(docket)
    fill(docket, 3, 5)
    with open(docket.path, "a") as stream:
        stream.write("garbage\n")
    cut(docket, manifest)
    code, out, err = verify(docket, pin_files, capsys=capsys)
    assert code == cli.EXIT_REFUSED
    assert len(out) == 5
    assert "line 5 fails verification: malformed" in err


def forged_entry(docket, change):
    manifest = cut(docket)
    entry = manifest.segments[0]
    forged = Manifest(manifest.docket_id, manifest.generation, segments=(replace(entry, **change(entry)),))
    write_manifest(manifest_path(docket.path), forged)


@pytest.mark.parametrize(
    ("change", "difference"),
    [
        (lambda entry: {"sha256": "0" * 64}, "sha256"),
        (lambda entry: {"end_heads": {"decide": Head(2, "A" * 43)}}, "end_heads"),
        (lambda entry: {"kids": frozenset({"rogue-1"})}, "kids"),
        (lambda entry: {"entries": 3, "end_heads": {"decide": Head(3, "A" * 43)}}, "entries"),
    ],
)
def test_a_sealed_segment_that_differs_from_its_manifest_entry_fails(docket, pin_files, capsys, change, difference):
    fill(docket, 1, 3)
    forged_entry(docket, change)
    fill(docket, 3, 4)
    code, out, err = verify(docket, pin_files, capsys=capsys)
    assert code == cli.EXIT_REFUSED
    assert len(out) == 3
    assert "the docket fails verification: segment_mismatch segment 1 does not match its manifest entry" in err
    assert difference in err


def test_a_sealed_segment_with_an_incomplete_line_fails_without_the_repair_hint(docket, pin_files, capsys):
    fill(docket, 1, 3)
    with open(docket.path, "a") as stream:
        stream.write("partial")
    cut(docket)
    code, _, err = verify(docket, pin_files, capsys=capsys)
    assert code == cli.EXIT_REFUSED
    assert "segment 1 does not match its manifest entry: ends with an incomplete line" in err
    assert "repair" not in err


def test_a_sealed_segment_of_another_size_is_refused(docket, pin_files, capsys):
    fill(docket, 1, 3)
    cut(docket)
    with open(segment_path(docket.path, 1), "ab") as stream:
        stream.write(b"x")
    code, out, err = verify(docket, pin_files, "--json", capsys=capsys)
    assert code == cli.EXIT_REFUSED and out == []
    assert "bytes, not the" in err


def test_a_committed_cut_before_its_rename_is_refused_with_a_hint(docket, pin_files, capsys):
    fill(docket, 1, 3)
    cut(docket, rename=False)
    code, _, err = verify(docket, pin_files, capsys=capsys)
    assert code == cli.EXIT_REFUSED
    assert "segment 1 of" in err and "start the sink" in err


def test_a_cut_between_the_manifest_reads_is_retried(docket, pin_files, capsys, monkeypatch):
    fill(docket, 1, 3)
    cut(docket)
    fill(docket, 3, 4)
    real = segments_module.read_docket_manifest
    calls = []

    def stale_first(path):
        calls.append(path)
        return Manifest.new() if len(calls) == 1 else real(path)

    monkeypatch.setattr(segments_module, "read_docket_manifest", stale_first)
    code, out, err = verify(docket, pin_files, "--json", capsys=capsys)
    assert code == 0, err
    assert [row["line"] for row in json_rows(out)] == [1, 2, 3]


def test_a_cut_on_every_open_is_refused(docket, pin_files, capsys, monkeypatch):
    fill(docket, 1, 3)
    generations = iter(range(1, 100))
    monkeypatch.setattr(segments_module, "read_docket_manifest", lambda path: Manifest("0" * 32, next(generations)))
    code, _, err = verify(docket, pin_files, capsys=capsys)
    assert code == cli.EXIT_REFUSED and "changed on every directory listing" in err


def test_verify_refuses_a_segment_file_not_in_the_manifest(docket, pin_files, capsys):
    fill(docket, 1, 3)
    cut(docket)
    fill(docket, 3, 4)
    segment_path(docket.path, 7).write_bytes(segment_path(docket.path, 1).read_bytes())
    code, out, err = verify(docket, pin_files, "--json", capsys=capsys)
    assert code == cli.EXIT_REFUSED and out == []
    assert f"segment files not in the manifest of {docket.path}: {segment_path(docket.path, 7).name}" in err


def test_verify_accepts_the_file_of_a_removal_not_yet_unlinked(docket, pin_files, capsys):
    fill(docket, 1, 3)
    manifest = cut(docket)
    write_manifest(manifest_path(docket.path), Manifest(manifest.docket_id, 2, Base(1, 2, manifest.seeds)))
    fill(docket, 3, 5)
    code, out, err = verify(docket, pin_files, "--json", capsys=capsys)
    assert code == 0, err
    assert [row["line"] for row in json_rows(out)] == [3, 4]


def active_snapshot(docket, manifest, lines=None):
    chain = ChainState(segment=manifest.active_segment, entries=manifest.entries)
    index = build_kid_index(WRITERS)
    with open(docket.path, "rb") as stream:
        verification = Verification(stream, index, heads=manifest.seeds, entries=manifest.entries)
        for verified in verification:
            if lines is not None and verified.line > lines:
                break
            chain.add(verified.start, verified.record)
    return chain.snapshot()


@pytest.mark.parametrize("lines", [2, 3], ids=["at-the-cut", "inside-the-active-segment"])
def test_a_snapshot_of_the_active_segment_matches_after_a_cut(docket, pin_files, capsys, lines):
    fill(docket, 1, 3)
    manifest = cut(docket)
    fill(docket, 3, 5)
    snapshot = active_snapshot(docket, manifest, lines)
    path = sealed(docket, snapshot)
    code, _, err = verify(docket, pin_files, "--snapshot", str(path), capsys=capsys)
    assert code == 0, err
    assert f"snapshot at offset {snapshot.offset} matches the docket, {4 - lines} records after it" in err


def test_a_snapshot_of_a_sealed_segment_does_not_match_after_a_cut(docket, pin_files, capsys):
    fill(docket, 1, 3)
    path = sealed(docket, snapshot_at(docket))
    cut(docket)
    fill(docket, 3, 4)
    code, _, err = verify(docket, pin_files, "--snapshot", str(path), capsys=capsys)
    assert code == cli.EXIT_REFUSED
    assert "does not match the docket: segment" in err


def list_tasks(docket, pin_files, *arguments, capsys):
    pins = [item for name in ("decide", "custodian") for item in ("--pin", pin_files[name])]
    pins += ["--control-pin", pin_files["control"]]
    code = cli.main(["docket", "tasks", "--docket", str(docket.path), *map(str, pins), *arguments])
    captured = capsys.readouterr()
    return code, captured.out.splitlines(), captured.err


def task_docket(docket):
    root_a = {"tenant": "acme", "task": "task-a", "root": "root-a"}
    docket.append("decide", make_entry(1, handles=root_a, principal="alice"))
    docket.append("custodian", make_entry(2, handles=root_a, hop="custodian", component="custodian", performed=True))
    docket.append("decide", make_entry(3, handles=root_a, decision="refuse", reason="out_of_scope"))
    docket.append("decide", make_entry(4, handles={"tenant": "acme", "task": "task-b", "root": "root-b"}))
    docket.append("decide", make_entry(5, handles={"tenant": "zeta", "task": "task-a", "root": "root-z"}))
    docket.append(
        "control", make_entry(6, hop="control", decision="revoke", handles={"tenant": "acme", "task": "task-a"})
    )
    return docket


def test_tasks_prints_one_row_per_tenant_and_task(docket, pin_files, capsys):
    task_docket(docket)
    code, out, err = list_tasks(docket, pin_files, capsys=capsys)
    assert code == 0, err
    assert out[0].split("\t") == [
        "TENANT", "TASK", "PRINCIPAL", "FIRST", "LAST", "ALLOWS", "RELEASES", "REFUSALS", "STATE"
    ]  # fmt: skip
    rows = [row.split("\t") for row in out[1:]]
    assert [(row[0], row[1], *row[5:]) for row in rows] == [
        ("acme", "task-a", "1", "1", "1", "revoked"),
        ("acme", "task-b", "1", "0", "0", "-"),
        ("zeta", "task-a", "1", "0", "0", "-"),
    ]
    assert "6 records verified, 3 tasks" in err


def test_a_task_row_carries_its_last_record_for_control(docket, pin_files, capsys):
    task_docket(docket)
    code, out, err = list_tasks(docket, pin_files, "--json", capsys=capsys)
    assert code == 0, err
    row = json_rows(out)[0]
    assert row["record"] == docket.records[2].token and row["record_line"] == 3
    assert row["roots"] == ["root-a"] and row["principal"] == "alice"
    assert row["revoked_by"] == "e-6"
    assert decode_record(row["record"], build_kid_index(WRITERS)).entry.handles["task"] == "task-a"


@pytest.mark.parametrize(
    ("handles", "revoked"),
    [
        ({"root": "root-b"}, ["task-b"]),
        ({"tenant": "zeta"}, ["task-a@zeta"]),
        ({"link": "link-1"}, []),
    ],
)
def test_root_and_tenant_revocations_mark_their_tasks(docket, pin_files, capsys, handles, revoked):
    docket.append("decide", make_entry(1, handles={"tenant": "acme", "task": "task-b", "root": "root-b"}))
    docket.append("decide", make_entry(2, handles={"tenant": "zeta", "task": "task-a", "root": "root-z"}))
    docket.append("control", make_entry(3, hop="control", decision="revoke", handles=handles))
    _, out, _ = list_tasks(docket, pin_files, "--json", capsys=capsys)
    marked = [row["task"] + ("@zeta" if row["tenant"] == "zeta" else "") for row in json_rows(out) if row["revoked_by"]]
    assert marked == revoked


def test_a_revocation_from_a_writer_other_than_control_leaves_the_task_unmarked(docket, pin_files, capsys):
    handles = {"tenant": "acme", "task": "task-a", "root": "root-a"}
    docket.append("decide", make_entry(1, handles=handles))
    docket.append("decide", make_entry(2, hop="control", decision="revoke", handles=handles))
    docket.append("custodian", make_entry(3, hop="control", decision="revoke", handles={"tenant": "acme"}))
    code, out, err = list_tasks(docket, pin_files, "--json", capsys=capsys)
    assert code == 0, err
    assert [row["revoked_by"] for row in json_rows(out)] == [None]


def test_the_record_for_control_is_the_latest_decide_record_of_the_task(docket, pin_files, capsys):
    handles = {"tenant": "acme", "task": "task-a", "root": "root-a"}
    docket.append("decide", make_entry(1, handles=handles))
    docket.append("decide", make_entry(2, handles=handles, tenant="zeta"))
    docket.append("custodian", make_entry(3, handles=handles, hop="custodian", component="custodian", performed=True))
    code, out, err = list_tasks(docket, pin_files, "--json", capsys=capsys)
    assert code == 0, err
    [row] = json_rows(out)
    assert (row["record"], row["record_line"]) == (docket.records[0].token, 1)
    assert (row["allows"], row["releases"]) == (2, 1)


def test_a_task_with_no_decide_record_has_no_record_for_control(docket, pin_files, capsys):
    handles = {"tenant": "acme", "task": "task-a"}
    docket.append("custodian", make_entry(1, handles=handles, hop="custodian", component="custodian", performed=True))
    _, out, _ = list_tasks(docket, pin_files, "--json", capsys=capsys)
    [row] = json_rows(out)
    assert row["record"] is None and row["record_line"] is None


def test_tasks_requires_a_control_pin(docket, pin_files, capsys):
    with pytest.raises(SystemExit):
        cli.main(["docket", "tasks", "--docket", str(docket.path), "--pin", str(pin_files["decide"])])
    assert "--control-pin" in capsys.readouterr().err


def test_tasks_prints_nothing_from_a_docket_that_fails_verification(docket, pin_files, capsys):
    task_docket(docket)
    with open(docket.path, "a") as stream:
        stream.write("not-a-record\n")
    code, out, err = list_tasks(docket, pin_files, capsys=capsys)
    assert code != 0
    assert out == []
    assert "line 7 fails verification" in err
