import asyncio
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
from test_docket import make_entry

from agent_bailiff import cli
from agent_bailiff.docket import DocketSink, decode_record, encode_record
from agent_bailiff.docket.report import RELEASED
from agent_bailiff.docket.sink import build_kid_index
from agent_bailiff.keys import PublicKeyRecord, key_id

DECIDE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
CUSTODIAN_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
PINS = {
    name: PublicKeyRecord(name, key_id(name, key.public_key()), key.public_key())
    for name, key in (("decide", DECIDE_KEY), ("custodian", CUSTODIAN_KEY))
}
KEYS = {"decide": DECIDE_KEY, "custodian": CUSTODIAN_KEY}
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


def verify_as(user, docket, pin_files):
    pins = [str(item) for name in PINS for item in ("--pin", pin_files[name])]
    command = [sys.executable, "-I", "-m", "agent_bailiff.cli", "docket", "verify", "--docket", str(docket.path)]
    return run_as(user, *command, *pins, "--json")


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
