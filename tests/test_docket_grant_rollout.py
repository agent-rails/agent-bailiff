import json
import os
import shutil
import tempfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_docket import RunningSink, make_entry

from agent_bailiff import cli
from agent_bailiff.docket import ENTRY_TYP, GRANT_TYP, DocketClient, DocketCorrupt, DocketError, DocketSink, Grant
from agent_bailiff.docket.entry import ENTRY_FIELDS, RECORD_BASE
from agent_bailiff.docket.manifest import read_docket_manifest
from agent_bailiff.docket.report import verify_docket
from agent_bailiff.keys import PublicKeyRecord, key_id
from agent_bailiff.signing import verify

DECIDE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
ISSUER_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(3, 35)))
PINS = {
    name: PublicKeyRecord(name, key_id(name, key.public_key()), key.public_key())
    for name, key in (("decide", DECIDE_KEY), ("issuer", ISSUER_KEY))
}
KEYS = {"decide": DECIDE_KEY, "issuer": ISSUER_KEY}
ENTRY_WRITERS = {"decide": {PINS["decide"].kid: DECIDE_KEY.public_key()}}
WRITERS = {name: {pin.kid: pin.public_key} for name, pin in PINS.items()}
GRANT = Grant(grant_id="g-1", at=1_700_000_100, root_token="root.token")


@pytest.fixture
def workdir():
    path = Path(tempfile.mkdtemp(prefix="bg-", dir="/tmp"))
    yield path
    shutil.rmtree(path)


@pytest.fixture
def docket_path(workdir):
    return workdir / "docket.log"


@pytest.fixture
def start_sink(docket_path):
    running = []

    def start(writers, **options):
        sink = DocketSink(docket_path, docket_path.parent / "s" / "docket.sock", writers, {os.getuid()}, **options)
        handle = RunningSink(sink)
        running.append(handle)
        return handle

    yield start
    for handle in running:
        if handle.thread.is_alive():
            handle.stop()


def client(docket_path, writer):
    directory = docket_path.parent / f"state-{writer}"
    directory.mkdir(mode=0o700, exist_ok=True)
    socket_path = docket_path.parent / "s" / "docket.sock"
    return DocketClient(socket_path, writer, PINS[writer].kid, KEYS[writer], sink_uid=os.getuid(), state_dir=directory)


def v1_docket(docket_path, start_sink):
    handle = start_sink(ENTRY_WRITERS, segment_bytes=1)
    decide = client(docket_path, "decide")
    records = [decide.append(make_entry(number)) for number in (1, 2)]
    decide.close()
    handle.stop()
    return records


def granted_docket(docket_path, start_sink):
    records = v1_docket(docket_path, start_sink)
    handle = start_sink(WRITERS, grant_writers={"issuer"}, segment_bytes=1)
    issuer = client(docket_path, "issuer")
    grant = issuer.append(GRANT)
    issuer.close()
    decide = client(docket_path, "decide")
    entry = decide.append(make_entry(3))
    decide.close()
    handle.stop()
    return [*records, grant, entry]


def test_a_sink_over_v1_segments_accepts_a_grant_from_a_pinned_grant_writer(docket_path, start_sink):
    records = granted_docket(docket_path, start_sink)
    assert read_docket_manifest(docket_path).entries >= 3
    assert (records[2].writer, records[2].seq, records[2].entry) == ("issuer", 1, GRANT)
    assert (records[3].seq, records[3].prev) == (3, records[1].hash)
    report = verify_docket(docket_path, WRITERS, grant_writers={"issuer"})
    assert (report.ok, report.entries) == (True, 4)


def test_a_sink_restarts_and_reverifies_a_docket_with_a_grant(docket_path, start_sink):
    records = granted_docket(docket_path, start_sink)
    handle = start_sink(WRITERS, grant_writers={"issuer"}, segment_bytes=1)
    assert handle.sink.heads["issuer"].hash == records[2].hash
    assert handle.sink.heads["decide"].hash == records[3].hash


def test_a_sink_refuses_a_grant_from_a_writer_not_pinned_for_grants(docket_path, start_sink):
    v1_docket(docket_path, start_sink)
    start_sink(WRITERS, segment_bytes=1)
    issuer = client(docket_path, "issuer")
    with pytest.raises(DocketError) as error:
        issuer.append(GRANT)
    assert error.value.reason == "wrong_record_type"


def test_a_reader_without_the_grant_writer_pinned_refuses_the_grant(docket_path, start_sink):
    granted_docket(docket_path, start_sink)
    report = verify_docket(docket_path, ENTRY_WRITERS)
    assert (report.ok, report.line, report.reason) == (False, 3, "unknown_kid")


def test_a_sink_without_the_grant_writer_pinned_refuses_to_start_over_a_grant(docket_path, start_sink):
    handle = start_sink(WRITERS, grant_writers={"issuer"})
    issuer = client(docket_path, "issuer")
    issuer.append(GRANT)
    issuer.close()
    handle.stop()
    with pytest.raises(DocketCorrupt) as error:
        start_sink(ENTRY_WRITERS)
    assert error.value.report.reason == "snapshot_mismatch"


def test_a_reader_pinning_the_grant_writer_for_entries_refuses_the_grant(docket_path, start_sink):
    granted_docket(docket_path, start_sink)
    report = verify_docket(docket_path, WRITERS)
    assert (report.ok, report.line, report.reason) == (False, 3, "wrong_record_type")


def test_an_entry_only_decoder_refuses_a_grant(docket_path, start_sink):
    records = granted_docket(docket_path, start_sink)
    refused = verify(
        records[2].token, {PINS["issuer"].kid: ISSUER_KEY.public_key()}, ENTRY_TYP, ENTRY_FIELDS | RECORD_BASE
    )
    assert refused.reason == "malformed"


def pin_file(workdir, name):
    path = workdir / f"{name}.pub.json"
    path.write_text(json.dumps(PINS[name].to_document()))
    os.chmod(path, 0o644)
    return str(path)


def cli_verify(docket_path, workdir, capsys, *pins):
    code = cli.main(["docket", "verify", "--docket", str(docket_path), "--json", *pins])
    captured = capsys.readouterr()
    return code, [json.loads(line) for line in captured.out.splitlines()], captured.err


def test_cli_verify_accepts_the_grant_with_a_grant_pin(docket_path, workdir, start_sink, capsys):
    granted_docket(docket_path, start_sink)
    pins = ["--pin", pin_file(workdir, "decide"), "--grant-pin", pin_file(workdir, "issuer")]
    code, rows, err = cli_verify(docket_path, workdir, capsys, *pins)
    assert code == 0, err
    assert [row["typ"] for row in rows] == [ENTRY_TYP, ENTRY_TYP, GRANT_TYP, ENTRY_TYP]
    assert rows[2]["grant"] == {"grant_id": "g-1", "at": 1_700_000_100, "root_token": "root.token"}


def test_cli_verify_refuses_the_grant_without_a_grant_pin(docket_path, workdir, start_sink, capsys):
    granted_docket(docket_path, start_sink)
    pins = ["--pin", pin_file(workdir, "decide"), "--pin", pin_file(workdir, "issuer")]
    code, _, err = cli_verify(docket_path, workdir, capsys, *pins)
    assert code == cli.EXIT_REFUSED
    assert "line 3 fails verification: wrong_record_type" in err


def test_cli_verify_refuses_a_writer_pinned_in_both_roles(docket_path, workdir, start_sink, capsys):
    granted_docket(docket_path, start_sink)
    issuer = pin_file(workdir, "issuer")
    pins = ["--pin", pin_file(workdir, "decide"), "--pin", issuer, "--grant-pin", issuer]
    code, _, err = cli_verify(docket_path, workdir, capsys, *pins)
    assert code == cli.EXIT_REFUSED
    assert "both as entry and grant writers" in err
