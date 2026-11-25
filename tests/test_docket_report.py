import asyncio
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import replace
from pathlib import Path

import pytest
from agent_warrant.identity import encode_public_key
from agent_warrant.task_root import issue_task_root
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_docket import AT, RunningSink, make_entry

from agent_bailiff import cli
from agent_bailiff.docket import GRANT_TYP, DocketClient, DocketSink, Grant, decode_record, encode_record
from agent_bailiff.docket import segments as segments_module
from agent_bailiff.docket import tasks as tasks_module
from agent_bailiff.docket.entry import ENTRY_TYP, Head, _entry_body
from agent_bailiff.docket.manifest import Base, Manifest, SegmentEntry, manifest_path, segment_path, write_manifest
from agent_bailiff.docket.report import GRANTED, RELEASED, RecordFilter, verify_docket, verify_records
from agent_bailiff.docket.roles import WriterRoles
from agent_bailiff.docket.sink import ChainState, Verification, build_kid_index
from agent_bailiff.docket.snapshot import Anchor, Snapshot, read_snapshot, snapshot_path, write_snapshot
from agent_bailiff.keys import PublicKeyRecord, key_id
from agent_bailiff.service.settings import load_issuers
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
ISSUER_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(3, 35)))
ISSUER_PIN = PublicKeyRecord("issuer", key_id("issuer", ISSUER_KEY.public_key()), ISSUER_KEY.public_key())
GRANT_WRITERS = {**WRITERS, "issuer": {ISSUER_PIN.kid: ISSUER_PIN.public_key}}
ROOT_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(4, 36)))
ROOT_EXPIRES_AT = 1_700_086_400
ROOT_SCOPE = {"permissions": [{"tools": ["github.create_issue"], "resources": ["repo:acme/*"], "max_cost_per_call": 1}]}
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
        return self.write(writer, KEYS[writer], PINS[writer].kid, entry)

    def grant(self, grant):
        return self.write("issuer", ISSUER_KEY, ISSUER_PIN.kid, grant)

    def write(self, writer, key, kid, entry):
        seq, prev = self.heads.get(writer, (0, None))
        record = encode_record(key, kid, writer, seq + 1, prev, entry)
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


@pytest.fixture
def grant_pin_file(workdir):
    path = workdir / "issuer.pub.json"
    path.write_text(json.dumps(ISSUER_PIN.to_document()))
    os.chmod(path, 0o644)
    return path


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


def task_root(task_id, tenant="acme", key=ROOT_KEY):
    return issue_task_root(
        key,
        issuer="issuer.example",
        task_id=task_id,
        tenant_id=tenant,
        principal="carol",
        purpose="triage",
        budget=10,
        max_depth=1,
        issued_at=1_700_000_000,
        expires_at=ROOT_EXPIRES_AT,
        scope=ROOT_SCOPE,
        subject=encode_public_key(ROOT_KEY.public_key()),
    )


def issuers_document(key=ROOT_KEY, issuer="issuer.example", tenants=None):
    return {
        issuer: {
            "public_key": encode_public_key(key.public_key()),
            "max_budget": 1000,
            "max_depth": 2,
            "tenants": tenants or {"acme": {"principals": ["carol"], "principal_prefixes": []}},
        }
    }


def write_issuers(path, document):
    path.write_text(json.dumps(document))
    os.chmod(path, 0o600)
    return path


@pytest.fixture
def issuers_file(workdir):
    return write_issuers(workdir / "issuers.json", issuers_document())


def grant_of(root, number=1, at=1_700_000_003):
    return Grant(grant_id=f"g-{number}", at=at, root_token=root.encode())


def granted(docket):
    filled(docket)
    docket.grant(Grant(grant_id="g-1", at=1_700_000_003, root_token="root.token"))
    return docket


def test_a_grant_row_carries_its_type_and_note(docket, pin_files, grant_pin_file, capsys):
    granted(docket)
    code, out, err = verify(docket, pin_files, "--json", "--grant-pin", str(grant_pin_file), capsys=capsys)
    assert code == 0, err
    rows = json_rows(out)
    assert [row["typ"] for row in rows] == [ENTRY_TYP] * 4 + [GRANT_TYP]
    assert (rows[4]["writer"], rows[4]["note"], rows[4]["token"]) == ("issuer", GRANTED, docket.records[4].token)
    assert rows[4]["grant"] == {"grant_id": "g-1", "at": 1_700_000_003, "root_token": "root.token"}
    assert "entry" not in rows[4] and "grant" not in rows[0]


def test_a_grant_table_row_has_no_tool_or_resource(docket, pin_files, grant_pin_file, capsys):
    granted(docket)
    code, out, err = verify(docket, pin_files, "--grant-pin", str(grant_pin_file), capsys=capsys)
    assert code == 0, err
    assert out[5].split("\t") == ["5", "2023-11-14T22:13:23Z", "issuer", "1", "grant", "-", "-", "-", GRANTED]


@pytest.mark.parametrize(
    ("arguments", "lines"),
    [
        (["--trace", "trace-a"], [1, 2, 4]),
        (["--task", "task-a"], [1, 2, 4]),
        (["--since", "1700000003"], [3, 4, 5]),
        (["--since", "1700000004"], [4]),
    ],
)
def test_entry_filters_skip_grants_and_since_keeps_them(docket, pin_files, grant_pin_file, capsys, arguments, lines):
    granted(docket)
    code, out, err = verify(docket, pin_files, "--json", "--grant-pin", str(grant_pin_file), *arguments, capsys=capsys)
    assert code == 0, err
    assert [row["line"] for row in json_rows(out)] == lines
    assert f"5 records verified, {len(lines)} printed" in err


@pytest.mark.parametrize(
    ("selector", "lines"),
    [
        (lambda root: ["--task", root.task_id], [3, 5]),
        (lambda root: ["--task", root.binding()], [5]),
        (lambda root: ["--task", "task-a"], [1, 2, 4]),
        (lambda root: ["--task", "task-b", "--since", "1700000004"], []),
        (lambda root: ["--task", "task-b", "--trace", "trace-b"], [3]),
    ],
)
def test_task_filter_selects_the_grant_of_its_task(docket, pin_files, grant_pin_file, capsys, selector, lines):
    filled(docket)
    root = task_root("task-b")
    docket.grant(grant_of(root))
    arguments = selector(root)
    code, out, err = verify(docket, pin_files, "--json", "--grant-pin", str(grant_pin_file), *arguments, capsys=capsys)
    assert code == 0, err
    assert [row["line"] for row in json_rows(out)] == lines


def test_a_grant_from_a_writer_pinned_for_entries_fails_verification(docket, pin_files, grant_pin_file, capsys):
    granted(docket)
    code, _, err = verify(docket, pin_files, "--pin", str(grant_pin_file), capsys=capsys)
    assert code == cli.EXIT_REFUSED
    assert "line 5 fails verification: wrong_record_type" in err


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


def default_issuers(docket):
    return write_issuers(docket.path.parent / "issuers.json", issuers_document())


def list_tasks(docket, pin_files, *arguments, capsys, issuers=None):
    pins = [item for name in ("decide", "custodian", "control") for item in (f"--{name}-pin", pin_files[name])]
    issuers = issuers or default_issuers(docket)
    code = cli.main(
        ["docket", "tasks", "--docket", str(docket.path), *map(str, pins), "--issuers", str(issuers), *arguments]
    )
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
        "TENANT", "TASK", "ROOT", "PRINCIPAL", "FIRST", "LAST", "ALLOWS", "RELEASES", "REFUSALS", "STATE"
    ]  # fmt: skip
    rows = [row.split("\t") for row in out[1:]]
    assert [(row[0], row[1], row[2], *row[6:]) for row in rows] == [
        ("acme", "task-a", "unverified", "1", "1", "1", "revoked"),
        ("acme", "task-b", "unverified", "1", "0", "0", "-"),
        ("zeta", "task-a", "unverified", "1", "0", "0", "-"),
    ]
    assert "6 records verified, 3 tasks" in err


def test_tasks_count_a_grant_whose_root_does_not_decode(docket, pin_files, grant_pin_file, capsys):
    task_docket(docket)
    docket.grant(Grant(grant_id="g-1", at=1_700_000_007, root_token="root.token"))
    code, out, err = list_tasks(docket, pin_files, "--grant-pin", str(grant_pin_file), capsys=capsys)
    assert code == cli.EXIT_FORGED_GRANT, err
    assert [tuple(row.split("\t")[:2]) for row in out[1:]] == [
        ("acme", "task-a"),
        ("acme", "task-b"),
        ("zeta", "task-a"),
    ]
    assert "7 records verified, 3 tasks" in err
    assert "1 grants hold a task root that does not decode; their tasks are not listed" in err


def test_a_never_called_task_is_listed_from_its_grant(docket, pin_files, grant_pin_file, capsys):
    task_docket(docket)
    root = task_root("task-c")
    record = docket.grant(grant_of(root, at=1_700_000_007))
    code, out, err = list_tasks(docket, pin_files, "--json", "--grant-pin", str(grant_pin_file), capsys=capsys)
    assert code == 0, err
    row = json_rows(out)[-1]
    assert (row["tenant"], row["task"], row["principal"], row["roots"]) == ("acme", "task-c", None, [root.binding()])
    assert (row["allows"], row["releases"], row["refusals"]) == (0, 0, 0)
    assert (row["first"], row["last"], row["expires_at"]) == (1_700_000_007, 1_700_000_007, ROOT_EXPIRES_AT)
    assert (row["granted"], row["revoked_by"]) == (True, None)
    assert (row["record"], row["record_line"]) == (record.token, 7)
    assert [row["granted"] for row in json_rows(out)[:-1]] == [False, False, False]
    assert "7 records verified, 4 tasks" in err
    assert "do not decode" not in err


def test_a_never_called_task_shows_in_the_table(docket, pin_files, grant_pin_file, capsys):
    docket.grant(grant_of(task_root("task-c")))
    code, out, err = list_tasks(docket, pin_files, "--grant-pin", str(grant_pin_file), capsys=capsys)
    assert code == 0, err
    assert out[1].split("\t") == [
        "acme", "task-c", "verified", "-", "2023-11-14T22:13:23Z", "2023-11-14T22:13:23Z", "0", "0", "0", "-"
    ]  # fmt: skip


def test_a_called_task_keeps_its_decide_record_and_is_marked_granted(docket, pin_files, grant_pin_file, capsys):
    root = task_root("task-b")
    handles = {"tenant": "acme", "task": "task-b", "root": root.binding()}
    docket.grant(grant_of(root, at=1_700_000_001))
    decide = docket.append("decide", make_entry(2, handles=handles, principal="alice"))
    code, out, err = list_tasks(docket, pin_files, "--json", "--grant-pin", str(grant_pin_file), capsys=capsys)
    assert code == 0, err
    [row] = json_rows(out)
    assert (row["granted"], row["allows"], row["roots"]) == (True, 1, [root.binding()])
    assert (row["record"], row["record_line"]) == (decide.token, 2)
    assert (row["first"], row["last"], row["principal"]) == (1_700_000_001, 1_700_000_002, "alice")


def test_a_later_grant_does_not_replace_the_decide_record(docket, pin_files, grant_pin_file, capsys):
    handles = {"tenant": "acme", "task": "task-b", "root": "root-b"}
    decide = docket.append("decide", make_entry(1, handles=handles, principal="alice"))
    docket.grant(grant_of(task_root("task-b"), at=1_700_000_002))
    _, out, _ = list_tasks(docket, pin_files, "--json", "--grant-pin", str(grant_pin_file), capsys=capsys)
    [row] = json_rows(out)
    assert (row["granted"], row["record"], row["record_line"]) == (True, decide.token, 1)


def test_a_task_with_only_a_custodian_record_carries_its_grant(docket, pin_files, grant_pin_file, capsys):
    handles = {"tenant": "acme", "task": "task-b"}
    docket.append("custodian", make_entry(1, handles=handles, hop="custodian", component="custodian", performed=True))
    record = docket.grant(grant_of(task_root("task-b"), at=1_700_000_002))
    _, out, _ = list_tasks(docket, pin_files, "--json", "--grant-pin", str(grant_pin_file), capsys=capsys)
    [row] = json_rows(out)
    assert (row["granted"], row["releases"], row["record"], row["record_line"]) == (True, 1, record.token, 2)


@pytest.mark.parametrize(
    "handles",
    [
        lambda root: {"tenant": "acme", "task": "task-c"},
        lambda root: {"root": root.binding()},
        lambda root: {"tenant": "acme"},
    ],
)
def test_a_revocation_marks_a_never_called_task(docket, pin_files, grant_pin_file, capsys, handles):
    root = task_root("task-c")
    docket.grant(grant_of(root))
    docket.append("control", make_entry(4, hop="control", decision="revoke", handles=handles(root)))
    _, out, _ = list_tasks(docket, pin_files, "--json", "--grant-pin", str(grant_pin_file), capsys=capsys)
    [row] = json_rows(out)
    assert row["revoked_by"] == "e-4"


def test_a_task_row_carries_its_last_decide_record_naming_a_principal(docket, pin_files, capsys):
    task_docket(docket)
    code, out, err = list_tasks(docket, pin_files, "--json", capsys=capsys)
    assert code == 0, err
    row = json_rows(out)[0]
    assert row["record"] == docket.records[0].token and row["record_line"] == 1
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
    assert code == cli.EXIT_UNCOUNTED, err
    assert [row["revoked_by"] for row in json_rows(out)] == [None]
    assert "2 records claim a hop their writer is not pinned for; they are not counted" in err


def test_the_record_for_control_is_the_latest_decide_record_of_the_task(docket, pin_files, capsys):
    handles = {"tenant": "acme", "task": "task-a", "root": "root-a"}
    docket.append("decide", make_entry(1, handles=handles, principal="alice"))
    docket.append("decide", make_entry(2, handles=handles, tenant="zeta", principal="mallory"))
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


@pytest.mark.parametrize("missing", ["decide", "custodian", "control"])
def test_tasks_requires_a_pin_for_each_role(docket, pin_files, capsys, missing):
    pins = [item for name in PINS if name != missing for item in (f"--{name}-pin", str(pin_files[name]))]
    with pytest.raises(SystemExit):
        cli.main(["docket", "tasks", "--docket", str(docket.path), *pins, "--issuers", str(default_issuers(docket))])
    assert f"--{missing}-pin" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("extra", "flags"),
    [
        ("--pin", "--pin and --decide-pin"),
        ("--custodian-pin", "--decide-pin and --custodian-pin"),
        ("--control-pin", "--decide-pin and --control-pin"),
        ("--grant-pin", "--decide-pin and --grant-pin"),
    ],
)
def test_a_writer_pinned_under_two_flags_is_refused(docket, pin_files, capsys, extra, flags):
    pins = [item for name in ("decide", "custodian", "control") for item in (f"--{name}-pin", str(pin_files[name]))]
    issuers = ["--issuers", str(default_issuers(docket))]
    code = cli.main(["docket", "tasks", "--docket", str(docket.path), *pins, *issuers, extra, str(pin_files["decide"])])
    captured = capsys.readouterr()
    assert code == cli.EXIT_REFUSED
    assert captured.out == ""
    assert f"docket tasks refused: writer decide is pinned as both {flags}" in captured.err


def test_one_public_key_pinned_under_two_writer_names_is_refused(docket, workdir, pin_files, capsys):
    alias = PublicKeyRecord("alias", key_id("alias", DECIDE_KEY.public_key()), DECIDE_KEY.public_key())
    path = workdir / "alias.pub.json"
    path.write_text(json.dumps(alias.to_document()))
    pins = [item for name in ("decide", "custodian", "control") for item in (f"--{name}-pin", str(pin_files[name]))]
    issuers = ["--issuers", str(default_issuers(docket))]
    code = cli.main(["docket", "tasks", "--docket", str(docket.path), *pins, *issuers, "--pin", str(path)])
    captured = capsys.readouterr()
    assert code == cli.EXIT_REFUSED
    assert captured.out == ""
    assert "docket tasks refused: writers alias and decide are pinned with the same public key" in captured.err


TASK_ROLES = WriterRoles({name: frozenset({name}) for name in ("decide", "custodian", "control")})
EFFECTOR_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(5, 37)))
EFFECTOR_PIN = PublicKeyRecord("effector", key_id("effector", EFFECTOR_KEY.public_key()), EFFECTOR_KEY.public_key())


def task_list(docket, issuers=None):
    issuers = load_issuers(issuers or default_issuers(docket))
    tasks = tasks_module.TaskList(TASK_ROLES, issuers.resolver, issuers.trust_policy)
    writers = {**GRANT_WRITERS, "effector": {EFFECTOR_PIN.kid: EFFECTOR_PIN.public_key}}
    report = verify_records(docket.path, writers, RecordFilter(), tasks.add, grant_writers={"issuer"})
    assert report.ok, report
    return tasks


def forged(docket, writer, number, **changes):
    changes.setdefault("handles", {"tenant": "acme", "task": "task-a", "root": "root-a"})
    return docket.append(writer, make_entry(number, hop="decide", component="decide", **changes))


def test_a_custodian_record_claiming_the_decide_hop_is_not_counted(docket):
    handles = {"tenant": "acme", "task": "task-a", "root": "root-a"}
    decide = docket.append("decide", make_entry(1, handles=handles, principal="zoe"))
    for number in range(2, 7):
        forged(docket, "custodian", number, principal="mallory", handles={**handles, "root": "root-m"})
    tasks = task_list(docket)
    [row] = tasks.rows()
    assert (row.principal, row.allows, row.roots, row.first, row.last) == ("zoe", 1, {"root-a"}, AT + 1, AT + 1)
    assert (row.record, row.record_line, row.principal_conflict) == (decide.token, 1, False)
    assert tasks.role_mismatches == 5


def test_a_record_from_a_writer_not_pinned_for_its_hop_opens_no_row_and_charges_nothing(docket):
    forged(docket, "custodian", 1, principal="mallory", handles={"tenant": "zeta", "task": "task-x"})
    docket.append(
        "decide", make_entry(2, hop="custodian", component="custodian", handles={"tenant": "zeta", "task": "x"})
    )
    tasks = task_list(docket)
    assert tasks.rows() == []
    assert (tasks.role_mismatches, tasks._tracked) == (2, 0)


def test_custodian_records_count_releases_and_refusals_but_set_no_principal_or_root(docket):
    handles = {"tenant": "acme", "task": "task-a", "root": "root-m"}
    for number, decision in ((1, "allow"), (2, "refuse")):
        docket.append(
            "custodian",
            make_entry(
                number, hop="custodian", component="custodian", decision=decision, handles=handles, principal="mallory"
            ),
        )
    [row] = task_list(docket).rows()
    assert (row.releases, row.refusals, row.allows) == (1, 1, 0)
    assert (row.principal, row.roots, row.record) == (None, set(), None)


def test_principal_and_record_come_from_the_same_decide_record(docket):
    handles = {"tenant": "acme", "task": "task-a", "root": "root-a"}
    named = docket.append("decide", make_entry(1, handles=handles, principal="alice"))
    docket.append("decide", make_entry(2, handles=handles, decision="refuse"))
    [row] = task_list(docket).rows()
    assert (row.principal, row.record, row.record_line) == ("alice", named.token, 1)
    assert (row.allows, row.refusals) == (1, 1)


def test_grants_set_the_record_but_never_the_principal(docket):
    first = docket.grant(grant_of(task_root("task-c"), 1, at=1_700_000_001))
    docket.grant(grant_of(task_root("task-c"), 2, at=1_700_000_002))
    [row] = task_list(docket).rows()
    assert (row.principal, row.record, row.record_line, row.granted) == (None, first.token, 1, True)
    assert row.principal_conflict is False


def test_a_decide_record_naming_a_principal_replaces_the_grant_record(docket):
    docket.grant(grant_of(task_root("task-c"), at=1_700_000_001))
    handles = {"tenant": "acme", "task": "task-c", "root": task_root("task-c").binding()}
    decide = docket.append("decide", make_entry(2, handles=handles, principal="carol"))
    [row] = task_list(docket).rows()
    assert (row.principal, row.record, row.record_line, row.principal_conflict) == ("carol", decide.token, 2, False)


@pytest.mark.parametrize("principals", [("alice", "bob"), ("bob", "alice")])
def test_decide_records_disagreeing_on_the_principal_flag_a_conflict(docket, principals):
    handles = {"tenant": "acme", "task": "task-a", "root": "root-a"}
    for number, principal in enumerate(principals, start=1):
        docket.append("decide", make_entry(number, handles=handles, principal=principal))
    [row] = task_list(docket).rows()
    assert (row.principal, row.record_line, row.principal_conflict) == (principals[1], 2, True)


def test_effector_records_are_verified_but_not_counted(docket):
    handles = {"tenant": "acme", "task": "task-a"}
    record = make_entry(1, hop="effector", component="effector", decision="refuse", handles=handles)
    docket.write("effector", EFFECTOR_KEY, EFFECTOR_PIN.kid, record)
    tasks = task_list(docket)
    assert (tasks.rows(), tasks.role_mismatches) == ([], 0)


def test_a_replaced_principal_is_charged_its_size_difference(docket):
    handles = {"tenant": "acme", "task": "task-a", "root": "root-a"}
    short = docket.append("decide", make_entry(1, handles=handles, principal="a"))
    once = task_list(docket)._tracked
    long = docket.append("decide", make_entry(2, handles=handles, principal="a" * 4096))
    grown = (sys.getsizeof("a" * 4096) - sys.getsizeof("a")) + (len(long.token) - len(short.token))
    assert task_list(docket)._tracked == once + grown


def test_tasks_warn_of_uncounted_records_before_the_rows_and_exit_3(docket, pin_files, monkeypatch):
    handles = {"tenant": "acme", "task": "task-a", "root": "root-a"}
    docket.append("decide", make_entry(1, handles=handles, principal="zoe"))
    forged(docket, "custodian", 2, principal="mallory")
    stream = io.StringIO()
    monkeypatch.setattr(sys, "stdout", stream)
    monkeypatch.setattr(sys, "stderr", stream)
    pins = [item for name in ("decide", "custodian", "control") for item in (f"--{name}-pin", str(pin_files[name]))]
    issuers = ["--issuers", str(default_issuers(docket))]
    code = cli.main(["docket", "tasks", "--docket", str(docket.path), *pins, *issuers, "--json"])
    lines = stream.getvalue().splitlines()
    assert code == cli.EXIT_UNCOUNTED
    assert lines[:3] == [
        "agent-bailiff docket tasks: 2 records verified, 1 tasks, 0 verified, 1 unverified, 0 invalid grants",
        "agent-bailiff docket tasks: 1 tasks have no verified grant in the read segments; "
        "if segments were removed, pass --archive to read them",
        "agent-bailiff docket tasks: 1 records claim a hop their writer is not pinned for; they are not counted",
    ]
    assert [json.loads(line)["principal"] for line in lines[3:]] == ["zoe"]


def test_tasks_prints_nothing_from_a_docket_that_fails_verification(docket, pin_files, capsys):
    task_docket(docket)
    with open(docket.path, "a") as stream:
        stream.write("not-a-record\n")
    code, out, err = list_tasks(docket, pin_files, capsys=capsys)
    assert code != 0
    assert out == []
    assert "line 7 fails verification" in err


def task_state_bytes(docket, pin_files, capsys, monkeypatch):
    tracked = []
    rows = tasks_module.TaskList.rows
    monkeypatch.setattr(tasks_module.TaskList, "rows", lambda self: tracked.append(self._tracked) or rows(self))
    code, _, err = list_tasks(docket, pin_files, capsys=capsys)
    assert code == 0, err
    monkeypatch.setattr(tasks_module.TaskList, "rows", rows)
    return tracked[0]


def test_tasks_within_the_state_budget_are_listed(docket, pin_files, capsys, monkeypatch):
    task_docket(docket)
    monkeypatch.setattr(tasks_module, "MAX_TRACKED_BYTES", task_state_bytes(docket, pin_files, capsys, monkeypatch))
    code, out, err = list_tasks(docket, pin_files, capsys=capsys)
    assert code == 0, err
    assert len(out) == 4


def test_tasks_past_the_state_budget_are_refused_and_print_nothing(docket, pin_files, capsys, monkeypatch):
    task_docket(docket)
    budget = task_state_bytes(docket, pin_files, capsys, monkeypatch) - 1
    monkeypatch.setattr(tasks_module, "MAX_TRACKED_BYTES", budget)
    code, out, err = list_tasks(docket, pin_files, "--json", capsys=capsys)
    assert code == cli.EXIT_REFUSED
    assert out == []
    assert f"docket tasks refused: the report tracks at most {budget} bytes of task state and line 6 adds more" in err


def test_a_replaced_record_frees_its_share_of_the_budget(docket, pin_files, capsys, monkeypatch):
    handles = {"tenant": "acme", "task": "task-a", "root": "root-a"}
    docket.append("decide", make_entry(1, handles=handles, principal="alice"))
    once = task_state_bytes(docket, pin_files, capsys, monkeypatch)
    for number in range(2, 6):
        docket.append("decide", make_entry(number, handles=handles, principal="alice"))
    replaced = len(docket.records[-1].token) - len(docket.records[0].token)
    assert task_state_bytes(docket, pin_files, capsys, monkeypatch) == once + replaced


def test_non_ascii_task_state_is_charged_at_its_stored_size(docket, pin_files, capsys, monkeypatch):
    tenant, task, root, principal = ("\U0001f600" * 1000 + name for name in ("t", "k", "r", "p"))
    handles = {"tenant": tenant, "task": task, "root": root}
    docket.append("decide", make_entry(1, handles=handles, tenant=tenant, principal=principal))
    stored = sum(sys.getsizeof(text) for text in (tenant, task, root, principal, docket.records[0].token))
    expected = tasks_module.ROW_BYTES + tasks_module.KEY_BYTES + stored
    assert task_state_bytes(docket, pin_files, capsys, monkeypatch) == expected


FORGER_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(9, 41)))


def granted_row(docket, pin_files, grant_pin_file, capsys, issuers=None):
    code, out, err = list_tasks(
        docket, pin_files, "--json", "--grant-pin", str(grant_pin_file), capsys=capsys, issuers=issuers
    )
    return code, json_rows(out), err


def root_fields(row):
    return row["root_status"], row["root_reason"], row["invalid_grants"]


def test_tasks_requires_issuers(docket, pin_files, capsys):
    pins = [item for name in ("decide", "custodian", "control") for item in (f"--{name}-pin", str(pin_files[name]))]
    with pytest.raises(SystemExit):
        cli.main(["docket", "tasks", "--docket", str(docket.path), *pins])
    assert "--issuers" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("prepare", "message"),
    [
        (lambda path: path, "cannot open the issuers file"),
        (lambda path: write_issuers(path, issuers_document()).chmod(0o644) or path, "must have mode 0o600"),
        (lambda path: write_issuers(path, issuers_document()).write_text("{") or path, "issuers file"),
        (lambda path: write_issuers(path, {}), "issuers file must name at least one issuer"),
    ],
)
def test_tasks_refuse_an_issuers_file_they_cannot_load(docket, workdir, pin_files, capsys, prepare, message):
    docket.grant(grant_of(task_root("task-c")))
    code, out, err = list_tasks(docket, pin_files, capsys=capsys, issuers=prepare(workdir / "issuers.json"))
    assert code == cli.EXIT_REFUSED
    assert out == []
    assert "docket tasks refused:" in err and message in err


def test_a_grant_signed_by_an_allowed_issuer_is_verified(docket, pin_files, grant_pin_file, capsys):
    docket.grant(grant_of(task_root("task-c")))
    code, [row], err = granted_row(docket, pin_files, grant_pin_file, capsys)
    assert code == 0, err
    assert root_fields(row) == ("verified", None, 0)
    assert row["granted"] is True


@pytest.mark.parametrize(
    ("document", "reason"),
    [
        (issuers_document(issuer="issuer.other"), "unknown_issuer"),
        (issuers_document(key=FORGER_KEY), "bad_signature"),
        (issuers_document(tenants={"zeta": {"principals": ["carol"], "principal_prefixes": []}}), "issuer_not_allowed"),
    ],
)
def test_a_grant_root_is_invalid_with_its_reason(docket, workdir, pin_files, grant_pin_file, capsys, document, reason):
    docket.grant(grant_of(task_root("task-c")))
    issuers = write_issuers(workdir / "issuers.json", document)
    code, [row], err = granted_row(docket, pin_files, grant_pin_file, capsys, issuers=issuers)
    assert code == cli.EXIT_FORGED_GRANT
    assert root_fields(row) == ("invalid", reason, 1)
    assert "1 tasks, 0 verified, 0 unverified, 1 invalid grants" in err


def test_a_rotated_issuer_key_marks_old_roots_invalid_bad_signature(docket, workdir, pin_files, grant_pin_file, capsys):
    docket.grant(grant_of(task_root("task-c"), 1))
    docket.grant(grant_of(task_root("task-d", key=FORGER_KEY), 2, at=1_700_000_004))
    issuers = write_issuers(workdir / "issuers.json", issuers_document(key=FORGER_KEY))
    _, rows, _ = granted_row(docket, pin_files, grant_pin_file, capsys, issuers=issuers)
    assert [(row["task"], *root_fields(row)) for row in rows] == [
        ("task-c", "invalid", "bad_signature", 1),
        ("task-d", "verified", None, 0),
    ]


def test_a_task_with_no_grant_is_unverified(docket, pin_files, capsys):
    docket.append("decide", make_entry(1, handles={"tenant": "acme", "task": "task-a", "root": "root-a"}))
    docket.append(
        "custodian",
        make_entry(2, handles={"tenant": "acme", "task": "task-b"}, hop="custodian", component="custodian"),
    )
    code, out, err = list_tasks(docket, pin_files, "--json", capsys=capsys)
    assert code == 0, err
    assert [(row["task"], *root_fields(row)) for row in json_rows(out)] == [
        ("task-a", "unverified", None, 0),
        ("task-b", "unverified", None, 0),
    ]


def test_an_invalid_grant_does_not_set_granted_expiry_record_or_roots(docket, pin_files, grant_pin_file, capsys):
    docket.grant(grant_of(task_root("task-c", key=FORGER_KEY)))
    _, [row], _ = granted_row(docket, pin_files, grant_pin_file, capsys)
    assert (row["granted"], row["expires_at"], row["record"], row["record_line"]) == (False, None, None, None)
    assert row["roots"] == []
    assert root_fields(row) == ("invalid", "bad_signature", 1)


@pytest.mark.parametrize("forged_first", [True, False])
def test_a_forged_copy_beside_the_real_grant_keeps_verified(docket, pin_files, grant_pin_file, capsys, forged_first):
    grants = [grant_of(task_root("task-c", key=FORGER_KEY), 1), grant_of(task_root("task-c"), 2)]
    records = [docket.grant(grant) for grant in (grants if forged_first else grants[::-1])]
    real = records[1] if forged_first else records[0]
    code, [row], err = granted_row(docket, pin_files, grant_pin_file, capsys)
    assert code == cli.EXIT_FORGED_GRANT
    assert "1 tasks, 1 verified, 0 unverified, 1 invalid grants" in err
    assert root_fields(row) == ("verified", None, 1)
    assert (row["granted"], row["record"], row["expires_at"]) == (True, real.token, ROOT_EXPIRES_AT)


def test_a_later_invalid_grant_keeps_the_first_reason(docket, workdir, pin_files, grant_pin_file, capsys):
    docket.grant(grant_of(task_root("task-c", key=FORGER_KEY), 1))
    docket.grant(grant_of(task_root("task-c"), 2))
    document = issuers_document(tenants={"zeta": {"principals": ["carol"], "principal_prefixes": []}})
    issuers = write_issuers(workdir / "issuers.json", document)
    _, [row], _ = granted_row(docket, pin_files, grant_pin_file, capsys, issuers=issuers)
    assert root_fields(row) == ("invalid", "bad_signature", 2)


def test_role_mismatch_beside_an_invalid_grant_exits_3_and_prints_both(docket, pin_files, grant_pin_file, capsys):
    docket.grant(grant_of(task_root("task-c", key=FORGER_KEY)))
    forged(docket, "custodian", 2, principal="mallory")
    code, rows, err = granted_row(docket, pin_files, grant_pin_file, capsys)
    assert code == cli.EXIT_UNCOUNTED
    assert [(row["task"], row["root_status"]) for row in rows] == [("task-c", "invalid")]
    assert "1 invalid grants" in err
    assert "1 records claim a hop their writer is not pinned for" in err


def test_the_archive_hint_shows_only_when_rows_are_unverified(docket, workdir, pin_files, grant_pin_file, capsys):
    hint = "if segments were removed, pass --archive to read them"
    docket.grant(grant_of(task_root("task-c")))
    code, _, err = granted_row(docket, pin_files, grant_pin_file, capsys)
    assert (code, hint in err) == (0, False)
    docket.append("decide", make_entry(2, handles={"tenant": "acme", "task": "task-a", "root": "root-a"}))
    code, _, err = granted_row(docket, pin_files, grant_pin_file, capsys)
    assert code == 0, err
    assert "2 tasks, 1 verified, 1 unverified, 0 invalid grants" in err
    assert f"1 tasks have no verified grant in the read segments; {hint}" in err


def test_an_invalid_grant_does_not_move_first_or_last_of_an_existing_row(docket, pin_files, grant_pin_file, capsys):
    docket.grant(grant_of(task_root("task-c", key=FORGER_KEY), 1, at=AT + 1))
    handles = {"tenant": "acme", "task": "task-c", "root": "root-c"}
    docket.append("decide", make_entry(5, handles=handles))
    docket.grant(grant_of(task_root("task-c", key=FORGER_KEY), 2, at=AT + 9))
    _, [row], _ = granted_row(docket, pin_files, grant_pin_file, capsys)
    assert (row["first"], row["last"]) == (AT + 5, AT + 5)
    assert root_fields(row) == ("invalid", "bad_signature", 2)


def test_an_invalid_grant_alone_opens_a_row(docket, pin_files, grant_pin_file, capsys):
    docket.grant(grant_of(task_root("task-c", key=FORGER_KEY), at=AT + 3))
    _, [row], _ = granted_row(docket, pin_files, grant_pin_file, capsys)
    assert (row["tenant"], row["task"], row["first"], row["last"]) == ("acme", "task-c", AT + 3, AT + 3)


def test_a_row_opened_by_an_invalid_grant_takes_its_times_from_the_first_trusted_record(
    docket, pin_files, grant_pin_file, capsys
):
    docket.grant(grant_of(task_root("task-c", key=FORGER_KEY), 1, at=2**40))
    docket.grant(grant_of(task_root("task-c"), 2, at=AT + 3))
    docket.append("decide", make_entry(5, handles={"tenant": "acme", "task": "task-c", "root": "root-c"}))
    _, [row], _ = granted_row(docket, pin_files, grant_pin_file, capsys)
    assert (row["first"], row["last"], row["root_status"]) == (AT + 3, AT + 5, "verified")


def test_an_invalid_root_is_not_listed_and_its_revocation_does_not_mark_the_task(
    docket, pin_files, grant_pin_file, capsys
):
    forged = replace(task_root("task-c", key=FORGER_KEY), purpose="evil")
    real = task_root("task-c")
    docket.grant(grant_of(forged, 1, at=AT + 1))
    docket.grant(grant_of(real, 2, at=AT + 2))
    docket.append("control", make_entry(3, hop="control", decision="revoke", handles={"root": forged.binding()}))
    _, [row], _ = granted_row(docket, pin_files, grant_pin_file, capsys)
    assert (row["roots"], row["revoked_by"], row["root_status"]) == ([real.binding()], None, "verified")


def test_invalid_grants_are_charged_to_the_state_budget(docket):
    docket.grant(grant_of(task_root("task-c", key=FORGER_KEY)))
    tasks = task_list(docket)
    assert tasks._tracked == tasks_module.ROW_BYTES + sum(map(sys.getsizeof, ("acme", "task-c")))


def test_a_json_task_row_is_written_in_chunks_that_join_to_one_document():
    row = tasks_module.TaskRow("acme", "task-a", roots={"root-a", "root-b"})
    chunks = list(tasks_module.task_json_chunks(row))
    assert len(chunks) > 1
    assert "".join(chunks) == json.dumps(json.loads("".join(chunks)), sort_keys=True)
    assert json.loads("".join(chunks))["roots"] == ["root-a", "root-b"]


def test_a_rotated_decide_key_pinned_under_the_same_flag_is_counted(docket, workdir, pin_files, capsys):
    rotated_key = Ed25519PrivateKey.from_private_bytes(bytes(range(7, 39)))
    rotated = PublicKeyRecord("decide", key_id("decide", rotated_key.public_key()), rotated_key.public_key())
    path = workdir / "decide-rotated.pub.json"
    path.write_text(json.dumps(rotated.to_document()))
    handles = {"tenant": "acme", "task": "task-a", "root": "root-a"}
    docket.append("decide", make_entry(1, handles=handles, principal="zoe"))
    docket.write("decide", rotated_key, rotated.kid, make_entry(2, handles=handles, principal="zoe"))
    code, out, err = list_tasks(docket, pin_files, "--json", "--decide-pin", str(path), capsys=capsys)
    assert code == 0, err
    [row] = map(json.loads, out)
    assert (row["allows"], row["principal"], row["record_line"]) == (2, "zoe", 2)


def test_a_hop_no_report_reads_is_verified_and_exits_0(docket, pin_files, capsys):
    handles = {"tenant": "acme", "task": "task-a", "root": "root-a"}
    docket.append("custodian", make_entry(1, hop="alien", component="custodian", handles=handles))
    code, out, err = list_tasks(docket, pin_files, "--json", capsys=capsys)
    assert (code, out) == (0, [])
    assert "1 records verified, 0 tasks" in err
