import asyncio
import os
import shutil
import socket
import stat
import tempfile
import threading
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_bailiff.docket import (
    ENTRY_TYP,
    DocketClient,
    DocketCorrupt,
    DocketError,
    DocketSink,
    Entry,
    Head,
    decode_record,
    encode_record,
    verify_docket,
)
from agent_bailiff.docket.protocol import LENGTH, MAX_FRAME_BYTES, OP_APPEND, OP_HEAD, decode_response, encode_frame
from agent_bailiff.docket.sink import build_kid_index
from agent_bailiff.signing import Refused, sign

AT = 1_700_000_000
DECIDE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
CUSTODIAN_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
ROGUE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(2, 34)))
WRITERS = {
    "decide": {"decide-1": DECIDE_KEY.public_key()},
    "custodian": {"custodian-1": CUSTODIAN_KEY.public_key()},
}
INDEX = build_kid_index(WRITERS)


def make_entry(number=1, **changes):
    entry = Entry(
        entry_id=f"e-{number}",
        trace_id="trace-1",
        hop="decide",
        component="decide",
        decision="allow",
        at=AT + number,
        op_id="op-1",
        tenant="acme",
        task_root="root-1",
        links=("link-1",),
        agent_key="agent-1",
        tool="github.create_issue",
        resource="repo:acme/app",
        args_digest="digest-1",
        cost=1,
        policy_id="default",
        policy_version="3",
        policy_digest="pd-1",
        rule="allow-issues",
        verdict="allow",
        credential_tier="gateway-bound",
        latency_ms=4,
        handles={"task": "root-1", "tenant": "acme"},
    )
    return replace(entry, **changes)


class RunningSink:
    def __init__(self, sink):
        self.sink = sink
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.thread.start()
        asyncio.run_coroutine_threadsafe(sink.start(), self.loop).result(5)

    def stop(self):
        asyncio.run_coroutine_threadsafe(self.sink.close(), self.loop).result(5)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)
        self.loop.close()


@pytest.fixture
def workdir():
    path = Path(tempfile.mkdtemp(prefix="bf-", dir="/tmp"))
    yield path
    shutil.rmtree(path)


@pytest.fixture
def paths(workdir):
    return workdir / "docket.log", workdir / "s" / "docket.sock"


@pytest.fixture
def start_sink(paths):
    running = []

    def start(**options):
        docket_path, socket_path = paths
        options.setdefault("allowed_uids", {os.getuid()})
        sink = DocketSink(docket_path, socket_path, WRITERS, **options)
        handle = RunningSink(sink)
        running.append(handle)
        return handle

    yield start
    for handle in running:
        if handle.thread.is_alive():
            handle.stop()


def decide_client(paths, **options):
    return DocketClient(paths[1], "decide", "decide-1", DECIDE_KEY, **options)


def send_raw(socket_path, payload):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(5)
        connection.connect(str(socket_path))
        connection.sendall(payload)
        header = connection.recv(LENGTH.size)
        (length,) = LENGTH.unpack(header)
        return decode_response(connection.recv(length))


def lines(docket_path):
    return docket_path.read_text().splitlines()


def test_appended_entries_are_chained_per_writer(paths, start_sink):
    start_sink()
    decide = decide_client(paths)
    custodian = DocketClient(paths[1], "custodian", "custodian-1", CUSTODIAN_KEY)
    first = decide.append(make_entry(1))
    other = custodian.append(make_entry(2, hop="custodian", component="custodian"))
    second = decide.append(make_entry(3))
    assert (first.seq, first.prev) == (1, None)
    assert (other.seq, other.prev) == (1, None)
    assert (second.seq, second.prev) == (2, first.hash)
    assert lines(paths[0]) == [first.token, other.token, second.token]
    report = verify_docket(paths[0], WRITERS)
    assert report.ok
    assert report.entries == 3
    assert report.heads == {"decide": Head(2, second.hash), "custodian": Head(1, other.hash)}


def test_appended_record_decodes_to_the_same_entry(paths, start_sink):
    start_sink()
    entry = make_entry(1)
    record = decide_client(paths).append(entry)
    decoded = decode_record(lines(paths[0])[0], INDEX)
    assert decoded == record
    assert decoded.entry == entry


def test_head_reports_the_chain_state(paths, start_sink):
    start_sink()
    client = decide_client(paths)
    assert client.head() == Head(0, None)
    record = client.append(make_entry(1))
    assert client.head() == Head(1, record.hash)


def assert_refused(paths, token, reason):
    before = paths[0].read_bytes()
    response = send_raw(paths[1], encode_frame(OP_APPEND + token.encode("ascii")))
    assert response == {"ok": False, "reason": reason}
    assert paths[0].read_bytes() == before


def test_bad_signature_is_refused_and_not_appended(paths, start_sink):
    start_sink()
    forged = encode_record(ROGUE_KEY, "decide-1", "decide", 1, None, make_entry(1))
    assert_refused(paths, forged.token, "bad_signature")


def test_wrong_seq_is_refused_and_not_appended(paths, start_sink):
    start_sink()
    record = encode_record(DECIDE_KEY, "decide-1", "decide", 2, "x" * 43, make_entry(1))
    assert_refused(paths, record.token, "wrong_seq")


def test_replayed_entry_is_refused(paths, start_sink):
    start_sink()
    record = decide_client(paths).append(make_entry(1))
    assert_refused(paths, record.token, "wrong_seq")


def test_broken_prev_is_refused_and_not_appended(paths, start_sink):
    start_sink()
    decide_client(paths).append(make_entry(1))
    record = encode_record(DECIDE_KEY, "decide-1", "decide", 2, "x" * 43, make_entry(2))
    assert_refused(paths, record.token, "broken_prev")


def test_unknown_kid_is_refused_and_not_appended(paths, start_sink):
    start_sink()
    record = encode_record(ROGUE_KEY, "rogue-1", "decide", 1, None, make_entry(1))
    assert_refused(paths, record.token, "unknown_kid")


def test_writer_using_another_writers_key_is_refused(paths, start_sink):
    start_sink()
    record = encode_record(DECIDE_KEY, "decide-1", "custodian", 1, None, make_entry(1))
    assert_refused(paths, record.token, "unknown_writer")


def test_unknown_writer_has_no_head(paths, start_sink):
    start_sink()
    client = DocketClient(paths[1], "rogue", "decide-1", DECIDE_KEY)
    with pytest.raises(DocketError) as error:
        client.append(make_entry(1))
    assert error.value.reason == "unknown_writer"
    assert paths[0].read_bytes() == b""


def test_wrong_typ_is_refused(paths, start_sink):
    start_sink()
    token = sign(DECIDE_KEY, "decide-1", "agent-bailiff/clearance/v1", {"writer": "decide", "seq": 1})
    assert_refused(paths, token, "wrong_typ")


def test_invalid_field_value_is_refused(paths, start_sink):
    start_sink()
    record = encode_record(DECIDE_KEY, "decide-1", "decide", 1, None, make_entry(1))
    decoded = decode_record(record.token, INDEX)
    assert not isinstance(decoded, Refused)
    body = {
        **{name: getattr(decoded.entry, name) for name in decoded.entry.__dataclass_fields__},
        "links": ["link-1"],
        "handles": {"task": "root-1"},
        "credential_tier": "platinum",
        "writer": "decide",
        "seq": 1,
        "prev": None,
    }
    assert_refused(paths, sign(DECIDE_KEY, "decide-1", ENTRY_TYP, body), "invalid_field")


def test_invalid_entries_cannot_be_encoded():
    with pytest.raises(ValueError, match="credential_tier"):
        encode_record(DECIDE_KEY, "decide-1", "decide", 1, None, make_entry(1, credential_tier="platinum"))
    with pytest.raises(ValueError, match="handle"):
        encode_record(DECIDE_KEY, "decide-1", "decide", 1, None, make_entry(1, handles={"everything": "x"}))
    with pytest.raises(ValueError, match="prev"):
        encode_record(DECIDE_KEY, "decide-1", "decide", 1, "x", make_entry(1))
    with pytest.raises(ValueError, match="seq"):
        encode_record(DECIDE_KEY, "decide-1", "decide", 0, None, make_entry(1))
    with pytest.raises(ValueError, match="entry_id"):
        encode_record(DECIDE_KEY, "decide-1", "decide", 1, None, make_entry(1, entry_id=""))


def test_oversized_frame_is_refused_and_not_appended(paths, start_sink):
    start_sink()
    response = send_raw(paths[1], LENGTH.pack(MAX_FRAME_BYTES + 1))
    assert response == {"ok": False, "reason": "frame_too_large"}
    assert paths[0].read_bytes() == b""


def test_unknown_operation_is_refused(paths, start_sink):
    start_sink()
    assert send_raw(paths[1], encode_frame(b"Z")) == {"ok": False, "reason": "malformed"}
    assert send_raw(paths[1], encode_frame(OP_APPEND + b"\xff")) == {"ok": False, "reason": "malformed"}
    assert send_raw(paths[1], encode_frame(OP_HEAD + b"\xff")) == {"ok": False, "reason": "malformed"}


def test_fsync_failure_gives_no_ack_and_stops_appends(paths, start_sink):
    def failing_fsync(fd):
        raise OSError(5, "injected fsync failure")

    handle = start_sink(fsync=failing_fsync)
    client = decide_client(paths)
    with pytest.raises(DocketError) as error:
        client.append(make_entry(1))
    assert error.value.reason == "write_failed"
    assert handle.sink.heads == {}
    with pytest.raises(DocketError) as again:
        client.append(make_entry(2))
    assert again.value.reason == "sink_failed"


def test_ack_waits_for_fsync(paths, start_sink):
    entered = threading.Event()
    release = threading.Event()
    synced = []

    def slow_fsync(fd):
        entered.set()
        assert release.wait(5)
        os.fsync(fd)
        synced.append(fd)

    start_sink(fsync=slow_fsync)
    results = []
    worker = threading.Thread(target=lambda: results.append(decide_client(paths).append(make_entry(1))))
    worker.start()
    assert entered.wait(5)
    assert results == []
    assert synced == []
    release.set()
    worker.join(5)
    assert len(synced) == 1
    assert [record.seq for record in results] == [1]


def test_restart_recovers_chain_state(paths, start_sink):
    first_run = start_sink()
    old_client = decide_client(paths)
    first = old_client.append(make_entry(1))
    second = old_client.append(make_entry(2))
    first_run.stop()
    second_run = start_sink()
    assert second_run.sink.heads == {"decide": Head(2, second.hash)}
    assert_refused(paths, first.token, "wrong_seq")
    third = decide_client(paths).append(make_entry(3))
    assert (third.seq, third.prev) == (3, second.hash)
    assert verify_docket(paths[0], WRITERS).heads["decide"] == Head(3, third.hash)


def test_client_resyncs_after_a_refusal(paths, start_sink):
    start_sink()
    client = decide_client(paths)
    other = decide_client(paths)
    client.append(make_entry(1))
    other.append(make_entry(2))
    with pytest.raises(DocketError) as error:
        client.append(make_entry(3))
    assert error.value.reason == "wrong_seq"
    assert client.append(make_entry(3)).seq == 3


def write_chain(paths, start_sink, count=3):
    handle = start_sink()
    client = decide_client(paths)
    records = [client.append(make_entry(number)) for number in range(1, count + 1)]
    handle.stop()
    return records


def test_verify_detects_a_modified_line(paths, start_sink):
    write_chain(paths, start_sink)
    content = lines(paths[0])
    payload, signature = content[1].split(".")
    tampered = payload[:-2] + ("A" if payload[-2] != "A" else "B") + payload[-1]
    paths[0].write_text("\n".join([content[0], f"{tampered}.{signature}", content[2]]) + "\n")
    report = verify_docket(paths[0], WRITERS)
    assert not report.ok
    assert report.line == 2
    assert report.entries == 1


def test_verify_detects_a_resigned_line(paths, start_sink):
    records = write_chain(paths, start_sink)
    forged = encode_record(ROGUE_KEY, "decide-1", "decide", 2, records[0].hash, make_entry(2, decision="deny"))
    content = lines(paths[0])
    paths[0].write_text("\n".join([content[0], forged.token, content[2]]) + "\n")
    report = verify_docket(paths[0], WRITERS)
    assert (report.ok, report.line, report.reason) == (False, 2, "bad_signature")


def test_verify_detects_a_deleted_line(paths, start_sink):
    write_chain(paths, start_sink)
    content = lines(paths[0])
    paths[0].write_text("\n".join([content[0], content[2]]) + "\n")
    report = verify_docket(paths[0], WRITERS)
    assert (report.ok, report.line, report.reason) == (False, 2, "wrong_seq")


def test_verify_detects_reordered_lines(paths, start_sink):
    write_chain(paths, start_sink)
    content = lines(paths[0])
    paths[0].write_text("\n".join([content[1], content[0], content[2]]) + "\n")
    assert verify_docket(paths[0], WRITERS).line == 1


def test_verify_detects_a_torn_tail(paths, start_sink):
    write_chain(paths, start_sink)
    with open(paths[0], "a") as docket:
        docket.write("partial")
    report = verify_docket(paths[0], WRITERS)
    assert (report.ok, report.line, report.reason, report.entries) == (False, 4, "torn_tail", 3)


def test_sink_refuses_to_start_on_a_corrupt_docket(paths, start_sink):
    write_chain(paths, start_sink)
    with open(paths[0], "a") as docket:
        docket.write("garbage\n")
    with pytest.raises(DocketCorrupt) as error:
        start_sink()
    assert error.value.report.line == 4


def test_peer_uid_outside_the_allowlist_is_refused(paths, start_sink):
    start_sink(allowed_uids={os.getuid() + 1})
    with pytest.raises(DocketError) as error:
        decide_client(paths).append(make_entry(1))
    assert error.value.reason == "peer_not_allowed"
    assert paths[0].read_bytes() == b""


def test_socket_directory_and_socket_modes(paths, start_sink):
    start_sink()
    directory = os.lstat(paths[1].parent)
    assert stat.S_IMODE(directory.st_mode) == 0o750
    assert directory.st_gid == os.getegid()
    assert stat.S_IMODE(os.lstat(paths[1]).st_mode) == 0o660
    assert stat.S_IMODE(os.lstat(paths[0]).st_mode) == 0o600


def test_sink_refuses_a_socket_directory_with_loose_mode(paths):
    paths[1].parent.mkdir(mode=0o777)
    os.chmod(paths[1].parent, 0o777)
    sink = DocketSink(paths[0], paths[1], WRITERS, {os.getuid()})
    with pytest.raises(PermissionError, match="0750"):
        asyncio.run(sink.start())


def test_sink_refuses_a_docket_file_with_loose_mode(paths):
    paths[0].write_text("")
    os.chmod(paths[0], 0o644)
    sink = DocketSink(paths[0], paths[1], WRITERS, {os.getuid()})
    with pytest.raises(PermissionError, match="0600"):
        asyncio.run(sink.start())


def test_sink_refuses_a_symlinked_docket_file(paths, workdir):
    target = workdir / "target.log"
    target.write_text("")
    os.chmod(target, 0o600)
    paths[0].symlink_to(target)
    sink = DocketSink(paths[0], paths[1], WRITERS, {os.getuid()})
    with pytest.raises(OSError):
        asyncio.run(sink.start())


def test_connections_over_the_limit_are_closed(paths, start_sink):
    start_sink(max_connections=1)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as idle:
        idle.settimeout(5)
        idle.connect(str(paths[1]))
        idle.sendall(encode_frame(OP_HEAD + b"decide"))
        assert idle.recv(64)
        with pytest.raises(DocketError) as error:
            decide_client(paths).append(make_entry(1))
        assert error.value.reason == "no_ack"
    assert decide_client(paths).append(make_entry(1)).seq == 1


def test_stalled_frame_is_dropped_at_the_deadline(paths, start_sink):
    start_sink(frame_timeout=0.2)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stalled:
        stalled.settimeout(5)
        stalled.connect(str(paths[1]))
        stalled.sendall(LENGTH.pack(10) + b"A")
        assert stalled.recv(64) == b""
    assert paths[0].read_bytes() == b""


def test_client_raises_when_the_sink_is_down(paths):
    with pytest.raises(DocketError) as error:
        decide_client(paths, timeout=0.5).append(make_entry(1))
    assert error.value.reason == "no_ack"


def test_kid_pinned_for_two_writers_is_a_configuration_error():
    with pytest.raises(ValueError, match="more than one writer"):
        build_kid_index({"a": {"k": DECIDE_KEY.public_key()}, "b": {"k": DECIDE_KEY.public_key()}})
