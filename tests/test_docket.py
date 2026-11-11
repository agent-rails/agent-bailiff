import asyncio
import gc
import os
import shutil
import socket
import stat
import tempfile
import threading
import time
import warnings
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_bailiff.docket import (
    ENTRY_TYP,
    DocketClient,
    DocketCorrupt,
    DocketError,
    DocketLocked,
    DocketRollback,
    DocketSink,
    Entry,
    Head,
    decode_record,
    encode_record,
    repair,
    verify_docket,
)
from agent_bailiff.docket.protocol import LENGTH, MAX_FRAME_BYTES, OP_APPEND, OP_HEAD, decode_response, encode_frame
from agent_bailiff.docket.sink import build_kid_index
from agent_bailiff.signing import MAX_TOKEN_CHARS, Refused, sign

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


SETTLE_ITERATIONS = 10


class RunningSink:
    def __init__(self, sink):
        self.sink = sink
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.thread.start()
        asyncio.run_coroutine_threadsafe(sink.start(), self.loop).result(5)

    def stop(self):
        asyncio.run_coroutine_threadsafe(_settle_then_close(self.sink), self.loop).result(5)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)
        self.loop.close()


async def _settle_then_close(sink):
    for _ in range(SETTLE_ITERATIONS):
        await asyncio.sleep(0)
    await sink.close()


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


def state_dir(paths):
    directory = paths[0].parent / "state"
    directory.mkdir(mode=0o700, exist_ok=True)
    return directory


def make_client(paths, writer, kid, key, **options):
    options.setdefault("sink_uid", os.getuid())
    options.setdefault("state_dir", state_dir(paths))
    return DocketClient(paths[1], writer, kid, key, **options)


def decide_client(paths, **options):
    return make_client(paths, "decide", "decide-1", DECIDE_KEY, **options)


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
    custodian = make_client(paths, "custodian", "custodian-1", CUSTODIAN_KEY)
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
    client = make_client(paths, "rogue", "decide-1", DECIDE_KEY)
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
        if fd_kind(fd) == "file":
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
        if fd_kind(fd) == "dir":
            return
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


def test_second_sink_on_the_same_docket_refuses_to_start(paths, start_sink, workdir):
    start_sink()
    second = DocketSink(paths[0], workdir / "t" / "other.sock", WRITERS, {os.getuid()})
    with pytest.raises(DocketLocked):
        asyncio.run(second.start())
    assert decide_client(paths).append(make_entry(1)).seq == 1


def test_second_sink_on_the_same_socket_refuses_to_start(paths, start_sink, workdir):
    start_sink()
    second = DocketSink(workdir / "other.log", paths[1], WRITERS, {os.getuid()})
    with pytest.raises(DocketLocked):
        asyncio.run(second.start())
    assert decide_client(paths).append(make_entry(1)).seq == 1


def test_closing_a_sink_removes_its_socket(paths, start_sink):
    start_sink().stop()
    assert not paths[1].exists()


def test_closing_a_sink_leaves_a_socket_it_does_not_own(paths, start_sink):
    handle = start_sink()
    paths[1].unlink()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as other:
        other.bind(str(paths[1]))
        handle.stop()
        assert stat.S_ISSOCK(os.lstat(paths[1]).st_mode)


def test_sink_refuses_a_docket_directory_writable_by_others(paths, workdir):
    os.chmod(workdir, 0o777)
    sink = DocketSink(paths[0], paths[1], WRITERS, {os.getuid()})
    with pytest.raises(PermissionError, match="writable"):
        asyncio.run(sink.start())
    assert not paths[0].exists()


def test_sink_refuses_a_symlinked_docket_directory(paths, workdir):
    real = workdir / "real"
    real.mkdir(mode=0o700)
    (workdir / "link").symlink_to(real)
    sink = DocketSink(workdir / "link" / "docket.log", paths[1], WRITERS, {os.getuid()})
    with pytest.raises(OSError):
        asyncio.run(sink.start())
    assert not (real / "docket.log").exists()


def fd_kind(fd):
    return "dir" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file"


def test_docket_directory_is_synced_before_the_first_ack(paths, start_sink):
    synced = []

    def recording_fsync(fd):
        synced.append(fd_kind(fd))
        os.fsync(fd)

    start_sink(fsync=recording_fsync)
    decide_client(paths).append(make_entry(1))
    assert synced == ["dir", "file"]


def test_docket_directory_sync_failure_latches(paths, start_sink):
    def failing_dir_fsync(fd):
        if fd_kind(fd) == "dir":
            raise OSError(5, "injected directory fsync failure")
        os.fsync(fd)

    start_sink(fsync=failing_dir_fsync)
    with pytest.raises(DocketError) as error:
        decide_client(paths).append(make_entry(1))
    assert error.value.reason == "sink_failed"
    assert paths[0].read_bytes() == b""


def connect_raw(socket_path):
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(5)
    connection.connect(str(socket_path))
    return connection


def foreign_peers(monkeypatch, count):
    calls = []

    def fake_peer_uid(sock):
        calls.append(sock)
        return os.getuid() + 1 if len(calls) <= count else os.getuid()

    monkeypatch.setattr("agent_bailiff.docket.sink.peer_uid", fake_peer_uid)


def test_idle_connections_are_evicted_and_free_the_cap(paths, start_sink):
    start_sink(idle_timeout=0.3)
    idle = [connect_raw(paths[1]) for _ in range(16)]
    try:
        for connection in idle:
            assert connection.recv(64) == b""
        assert decide_client(paths).append(make_entry(1)).seq == 1
    finally:
        for connection in idle:
            connection.close()


def test_unauthorized_connections_do_not_take_a_slot(paths, start_sink, monkeypatch):
    foreign_peers(monkeypatch, 16)
    start_sink()
    held = [connect_raw(paths[1]) for _ in range(16)]
    try:
        for connection in held:
            (length,) = LENGTH.unpack(connection.recv(LENGTH.size))
            assert decode_response(connection.recv(length)) == {"ok": False, "reason": "peer_not_allowed"}
        assert decide_client(paths).append(make_entry(1)).seq == 1
    finally:
        for connection in held:
            connection.close()


def test_unauthorized_peer_is_refused_before_the_cap(paths, start_sink, monkeypatch):
    start_sink(max_connections=1)
    with connect_raw(paths[1]) as idle:
        idle.sendall(encode_frame(OP_HEAD + b"decide"))
        assert idle.recv(64)
        foreign_peers(monkeypatch, 1)
        with connect_raw(paths[1]) as foreign:
            (length,) = LENGTH.unpack(foreign.recv(LENGTH.size))
            assert decode_response(foreign.recv(length)) == {"ok": False, "reason": "peer_not_allowed"}


def test_connection_is_closed_at_its_max_lifetime(paths, start_sink):
    start_sink(max_lifetime=0.5)
    started = time.monotonic()
    with connect_raw(paths[1]) as busy:
        while True:
            try:
                busy.sendall(encode_frame(OP_HEAD + b"decide"))
                if not busy.recv(64):
                    break
            except ConnectionError:
                break
            assert time.monotonic() - started < 3
            time.sleep(0.05)
    assert time.monotonic() - started >= 0.5


def test_client_refuses_a_sink_with_the_wrong_uid(paths, start_sink):
    handle = start_sink()
    with pytest.raises(DocketError) as error:
        decide_client(paths, sink_uid=os.getuid() + 1).append(make_entry(1))
    assert error.value.reason == "sink_not_trusted"
    assert handle.sink.heads == {}
    assert paths[0].read_bytes() == b""


def roll_back_to(paths, count):
    content = lines(paths[0])
    paths[0].write_text("".join(f"{line}\n" for line in content[:count]))


def test_restarted_client_detects_a_rolled_back_sink(paths, start_sink):
    first_run = start_sink()
    client = decide_client(paths)
    client.append(make_entry(1))
    client.append(make_entry(2))
    first_run.stop()
    roll_back_to(paths, 1)
    start_sink()
    restarted = decide_client(paths)
    with pytest.raises(DocketRollback) as error:
        restarted.append(make_entry(3))
    assert error.value.reason == "rollback"
    with pytest.raises(DocketRollback):
        restarted.head()
    assert len(lines(paths[0])) == 1


def test_running_client_detects_rollback_on_a_refused_append(paths, start_sink):
    first_run = start_sink()
    client = decide_client(paths)
    client.append(make_entry(1))
    client.append(make_entry(2))
    first_run.stop()
    roll_back_to(paths, 1)
    start_sink()
    with pytest.raises(DocketRollback):
        client.append(make_entry(3))
    assert len(lines(paths[0])) == 1


def test_client_detects_a_replaced_entry_at_its_acked_seq(paths, start_sink, workdir):
    first_run = start_sink()
    client = decide_client(paths)
    client.append(make_entry(1))
    client.append(make_entry(2))
    first_run.stop()
    roll_back_to(paths, 1)
    start_sink()
    other_state = workdir / "other-state"
    other_state.mkdir(mode=0o700)
    decide_client(paths, state_dir=other_state).append(make_entry(2, decision="deny"))
    with pytest.raises(DocketRollback):
        client.head()


def test_client_state_file_is_private(paths, start_sink):
    start_sink()
    record = decide_client(paths).append(make_entry(1))
    state = state_dir(paths) / "decide.head"
    assert stat.S_IMODE(os.lstat(state).st_mode) == 0o600
    assert state.read_bytes() == f'{{"hash":"{record.hash}","seq":1}}'.encode()
    assert sorted(path.name for path in state_dir(paths).iterdir()) == ["decide.head"]


def test_client_refuses_a_state_directory_writable_by_others(paths):
    directory = state_dir(paths)
    os.chmod(directory, 0o777)
    with pytest.raises(PermissionError, match="writable"):
        decide_client(paths)


@pytest.mark.parametrize("content", [b"", b"garbage", b'{"seq":0,"hash":"x"}', b'{"seq":1}'])
def test_client_refuses_an_invalid_state_file(paths, content):
    state = state_dir(paths) / "decide.head"
    state.write_bytes(content)
    os.chmod(state, 0o600)
    with pytest.raises(DocketError) as error:
        decide_client(paths)
    assert error.value.reason == "state_invalid"


def test_client_refuses_an_unsafe_writer_name(paths):
    with pytest.raises(ValueError, match="writer"):
        make_client(paths, "../decide", "decide-1", DECIDE_KEY)


def test_repair_moves_a_torn_tail_aside(paths, start_sink, workdir):
    records = write_chain(paths, start_sink)
    with open(paths[0], "a") as docket:
        docket.write("partial")
    side = workdir / "torn.tail"
    report = repair(paths[0], side, WRITERS)
    assert (report.ok, report.entries) == (True, 3)
    assert side.read_bytes() == b"partial"
    assert stat.S_IMODE(os.lstat(side).st_mode) == 0o600
    assert lines(paths[0]) == [record.token for record in records]
    assert verify_docket(paths[0], WRITERS).ok
    start_sink()
    assert decide_client(paths).append(make_entry(4)).seq == 4


def test_repair_leaves_a_clean_docket_alone(paths, start_sink, workdir):
    write_chain(paths, start_sink)
    before = paths[0].read_bytes()
    assert repair(paths[0], workdir / "torn.tail", WRITERS).ok
    assert paths[0].read_bytes() == before
    assert not (workdir / "torn.tail").exists()


def test_repair_refuses_an_invalid_line_before_the_tail(paths, start_sink, workdir):
    write_chain(paths, start_sink)
    content = lines(paths[0])
    paths[0].write_text("\n".join([content[0], content[2], content[1]]) + "\npartial")
    before = paths[0].read_bytes()
    with pytest.raises(DocketCorrupt) as error:
        repair(paths[0], workdir / "torn.tail", WRITERS)
    assert error.value.report.line == 2
    assert paths[0].read_bytes() == before
    assert not (workdir / "torn.tail").exists()


def test_repair_refuses_an_existing_side_file(paths, start_sink, workdir):
    write_chain(paths, start_sink)
    with open(paths[0], "a") as docket:
        docket.write("partial")
    before = paths[0].read_bytes()
    side = workdir / "torn.tail"
    side.write_bytes(b"keep")
    with pytest.raises(FileExistsError):
        repair(paths[0], side, WRITERS)
    assert paths[0].read_bytes() == before
    assert side.read_bytes() == b"keep"


def test_repair_refuses_while_a_sink_holds_the_docket(paths, start_sink, workdir):
    start_sink()
    with pytest.raises(DocketLocked):
        repair(paths[0], workdir / "torn.tail", WRITERS)


def test_overlong_line_before_the_end_is_not_a_torn_tail(paths, start_sink, workdir):
    records = write_chain(paths, start_sink)
    paths[0].write_text("A" * (MAX_TOKEN_CHARS + 10) + "\n" + records[0].token + "\n")
    report = verify_docket(paths[0], WRITERS)
    assert (report.ok, report.line, report.reason) == (False, 1, "malformed")
    with pytest.raises(DocketCorrupt):
        repair(paths[0], workdir / "torn.tail", WRITERS)


def test_stopping_a_sink_right_after_a_refused_client_leaves_no_open_transport(paths):
    leaked = []
    for _ in range(40):
        handle = RunningSink(DocketSink(paths[0], paths[1], WRITERS, {os.getuid()}))
        with pytest.raises(DocketError):
            decide_client(paths, sink_uid=os.getuid() + 1).append(make_entry(1))
        handle.stop()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", ResourceWarning)
            del handle
            gc.collect()
        leaked.extend(str(item.message) for item in caught if "unclosed transport" in str(item.message))
    assert leaked == []
