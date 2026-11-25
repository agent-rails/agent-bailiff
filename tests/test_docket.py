import asyncio
import errno
import gc
import hashlib
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import tracemalloc
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
    Verification,
    decode_record,
    encode_record,
    repair,
)
from agent_bailiff.docket import client as client_module
from agent_bailiff.docket import manifest as manifest_module
from agent_bailiff.docket import sink as sink_module
from agent_bailiff.docket.client import UNACKNOWLEDGED
from agent_bailiff.docket.manifest import (
    Manifest,
    SegmentEntry,
    manifest_path,
    read_docket_manifest,
    segment_path,
    write_manifest,
)
from agent_bailiff.docket.protocol import (
    LENGTH,
    MAX_FRAME_BYTES,
    OP_APPEND,
    OP_HEAD,
    decode_response,
    encode_frame,
    encode_response,
    read_frame,
)
from agent_bailiff.docket.report import RecordFilter, verify_docket, verify_records
from agent_bailiff.docket.sink import ChainState, build_kid_index, docket_lock_path
from agent_bailiff.docket.snapshot import Snapshot, read_snapshot, snapshot_path, write_snapshot
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
    armed = threading.Event()
    entered = threading.Event()
    release = threading.Event()
    synced = []

    def slow_fsync(fd):
        if not armed.is_set() or fd_kind(fd) == "dir":
            return
        entered.set()
        assert release.wait(5)
        os.fsync(fd)
        synced.append(fd)

    start_sink(fsync=slow_fsync)
    armed.set()
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
    old_client.close()
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
    elsewhere = paths[0].parent / "state-elsewhere"
    elsewhere.mkdir(mode=0o700)
    other = decide_client(paths, state_dir=elsewhere)
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
    client.close()
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


def write_records(path, count):
    prev = None
    with open(path, "w") as docket:
        for number in range(1, count + 1):
            record = encode_record(DECIDE_KEY, "decide-1", "decide", number, prev, make_entry(number))
            docket.write(f"{record.token}\n")
            prev = record.hash


def test_verification_yields_each_record_with_its_line_and_end(paths, start_sink):
    records = write_chain(paths, start_sink)
    with open(paths[0], "rb") as docket:
        verification = Verification(docket, INDEX)
        verified = list(verification)
    ends = [len(line) + 1 for line in lines(paths[0])]
    assert [item.line for item in verified] == [1, 2, 3]
    assert [item.record.token for item in verified] == [record.token for record in records]
    assert [item.start for item in verified] == [0, ends[0], ends[0] + ends[1]]
    assert [item.end for item in verified] == [ends[0], ends[0] + ends[1], sum(ends)]
    assert verification.report == verify_docket(paths[0], WRITERS)
    assert verification.report.ok and verification.report.valid_bytes == sum(ends)


def test_verification_from_an_offset_reports_absolute_starts(paths, start_sink):
    records = write_chain(paths, start_sink)
    first = len(records[0].token) + 1
    with open(paths[0], "rb") as docket:
        docket.seek(first)
        heads = {"decide": Head(1, records[0].hash)}
        verified = list(Verification(docket, INDEX, heads=heads, entries=1, offset=first))
    assert [(item.line, item.start) for item in verified] == [(2, first), (3, first + len(records[1].token) + 1)]


def test_verification_stops_before_the_first_bad_line(paths, start_sink):
    write_chain(paths, start_sink)
    content = lines(paths[0])
    paths[0].write_text("\n".join([content[0], content[2], content[1]]) + "\n")
    with open(paths[0], "rb") as docket:
        verification = Verification(docket, INDEX)
        assert [item.line for item in verification] == [1]
    assert verification.report == verify_docket(paths[0], WRITERS)
    assert (verification.report.ok, verification.report.line, verification.report.reason) == (False, 2, "wrong_seq")


def test_verification_has_no_report_before_its_end(paths, start_sink):
    write_chain(paths, start_sink)
    with open(paths[0], "rb") as docket:
        verification = Verification(docket, INDEX)
        lines_read = iter(verification)
        next(lines_read)
        with pytest.raises(RuntimeError):
            _ = verification.report


def test_verification_can_be_iterated_only_once(paths, start_sink):
    write_chain(paths, start_sink)
    with open(paths[0], "rb") as docket:
        verification = Verification(docket, INDEX)
        list(verification)
        with pytest.raises(RuntimeError):
            iter(verification)


def peak_verification_bytes(path):
    tracemalloc.start()
    try:
        with open(path, "rb") as docket:
            for _ in Verification(docket, INDEX):
                pass
        return tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


def test_verification_memory_does_not_grow_with_the_docket(workdir):
    small, large = workdir / "small.log", workdir / "large.log"
    write_records(small, 300)
    write_records(large, 3_000)
    assert peak_verification_bytes(large) < 1.5 * peak_verification_bytes(small)


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


def test_a_refusal_sent_before_the_request_is_reported(paths, monkeypatch):
    socket_path = paths[1]
    socket_path.parent.mkdir(mode=0o700)
    closed = threading.Event()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(socket_path))
        server.listen(1)

        def refuse_and_close():
            connection, _ = server.accept()
            connection.sendall(encode_response({"ok": False, "reason": "peer_not_allowed"}))
            connection.close()
            closed.set()

        thread = threading.Thread(target=refuse_and_close)
        thread.start()
        client = decide_client(paths)
        check_sink = client._check_sink

        def check_then_wait(connection):
            check_sink(connection)
            assert closed.wait(5)

        monkeypatch.setattr(client, "_check_sink", check_then_wait)
        with pytest.raises(DocketError) as error:
            client.append(make_entry(1))
        thread.join(5)
    assert error.value.reason == "peer_not_allowed"


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


READER_GID = os.getegid()
NON_MEMBER_GID = max([*os.getgroups(), READER_GID]) + 1000


def file_mode(path):
    info = os.lstat(path)
    return stat.S_IMODE(info.st_mode), info.st_gid


def test_sink_creates_a_docket_its_reader_group_can_read(paths, start_sink):
    start_sink(reader_gid=READER_GID)
    assert decide_client(paths).append(make_entry(1)).seq == 1
    assert file_mode(paths[0]) == (0o640, READER_GID)


def test_sink_restarts_on_a_docket_shared_with_its_reader_group(paths, start_sink):
    start_sink(reader_gid=READER_GID).stop()
    start_sink(reader_gid=READER_GID)
    assert decide_client(paths).append(make_entry(1)).seq == 1


def test_sink_without_a_reader_group_still_creates_a_0600_docket(paths, start_sink):
    start_sink()
    decide_client(paths).append(make_entry(1))
    assert file_mode(paths[0])[0] == 0o600


@pytest.mark.parametrize("mode", [0o600, 0o644, 0o660, 0o740])
def test_sink_with_a_reader_group_refuses_any_mode_but_0640(paths, mode):
    paths[0].write_text("")
    os.chown(paths[0], -1, READER_GID)
    os.chmod(paths[0], mode)
    sink = DocketSink(paths[0], paths[1], WRITERS, {os.getuid()}, reader_gid=READER_GID)
    with pytest.raises(PermissionError, match="0640"):
        asyncio.run(sink.start())


def test_sink_without_a_reader_group_refuses_a_0640_docket(paths):
    paths[0].write_text("")
    os.chmod(paths[0], 0o640)
    sink = DocketSink(paths[0], paths[1], WRITERS, {os.getuid()})
    with pytest.raises(PermissionError, match="0600"):
        asyncio.run(sink.start())


def test_sink_refuses_a_0640_docket_in_another_group(paths):
    paths[0].write_text("")
    os.chown(paths[0], -1, READER_GID)
    os.chmod(paths[0], 0o640)
    sink = DocketSink(paths[0], paths[1], WRITERS, {os.getuid()}, reader_gid=NON_MEMBER_GID)
    with pytest.raises(PermissionError, match=f"group {NON_MEMBER_GID}"):
        asyncio.run(sink.start())


@pytest.mark.skipif(os.geteuid() == 0, reason="root may give a file to any group")
def test_sink_cannot_share_a_new_docket_with_a_group_it_is_not_in(paths):
    sink = DocketSink(paths[0], paths[1], WRITERS, {os.getuid()}, reader_gid=NON_MEMBER_GID)
    with pytest.raises(PermissionError):
        asyncio.run(sink.start())


def test_sink_with_a_reader_group_refuses_a_group_writable_directory(paths, workdir):
    os.chown(workdir, -1, READER_GID)
    os.chmod(workdir, 0o770)
    sink = DocketSink(paths[0], paths[1], WRITERS, {os.getuid()}, reader_gid=READER_GID)
    with pytest.raises(PermissionError, match="writable"):
        asyncio.run(sink.start())
    assert not paths[0].exists()


def test_sink_refuses_a_symlinked_docket_file(paths, workdir):
    target = workdir / "target.log"
    target.write_text("")
    os.chmod(target, 0o600)
    paths[0].symlink_to(target)
    sink = DocketSink(paths[0], paths[1], WRITERS, {os.getuid()})
    with pytest.raises(OSError):
        asyncio.run(sink.start())


def test_connections_over_the_limit_are_refused_as_overloaded(paths, start_sink):
    start_sink(max_connections=1)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as idle:
        idle.settimeout(5)
        idle.connect(str(paths[1]))
        idle.sendall(encode_frame(OP_HEAD + b"decide"))
        assert idle.recv(64)
        client = decide_client(paths)
        with pytest.raises(DocketError) as error:
            client.append(make_entry(1))
        assert error.value.reason == "overloaded"
        assert paths[0].read_bytes() == b""
        with connect_raw(paths[1]) as extra:
            (length,) = LENGTH.unpack(extra.recv(LENGTH.size))
            assert decode_response(extra.recv(length)) == {"ok": False, "reason": "overloaded"}
    assert client.append(make_entry(1)).seq == 1


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
    assert error.value.reason == "sink_unreachable"


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


def test_the_docket_lock_holds_after_the_docket_is_renamed(paths, start_sink, workdir):
    start_sink()
    paths[0].rename(workdir / "moved.log")
    second = DocketSink(paths[0], workdir / "t" / "other.sock", WRITERS, {os.getuid()})
    with pytest.raises(DocketLocked):
        asyncio.run(second.start())
    assert not paths[0].exists()


def test_the_docket_lock_is_private(paths, start_sink):
    start_sink()
    info = os.lstat(docket_lock_path(paths[0]))
    assert stat.S_ISREG(info.st_mode)
    assert stat.S_IMODE(info.st_mode) == 0o600


def test_a_symlinked_docket_lock_is_refused(paths, workdir):
    docket_lock_path(paths[0]).symlink_to(workdir / "elsewhere.lock")
    sink = DocketSink(paths[0], paths[1], WRITERS, {os.getuid()})
    with pytest.raises(OSError):
        asyncio.run(sink.start())
    assert not (workdir / "elsewhere.lock").exists()
    assert not paths[0].exists()


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
    assert not (real / "docket.log.lock").exists()


def fd_kind(fd):
    return "dir" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file"


def test_docket_directory_is_synced_before_the_first_ack(paths, start_sink):
    synced = []

    def recording_fsync(fd):
        synced.append(fd_kind(fd))
        os.fsync(fd)

    start_sink(fsync=recording_fsync)
    decide_client(paths).append(make_entry(1))
    assert synced == ["dir", "file", "file", "dir", "file"]


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


def roll_back_to(paths, count, *, keep_snapshot=False):
    content = lines(paths[0])
    paths[0].write_text("".join(f"{line}\n" for line in content[:count]))
    if not keep_snapshot:
        snapshot_path(paths[0]).unlink()


def test_rollback_under_a_newer_snapshot_refuses_start(paths, start_sink):
    write_chain(paths, start_sink)
    roll_back_to(paths, 2, keep_snapshot=True)
    with pytest.raises(DocketCorrupt) as error:
        start_sink()
    assert error.value.report.reason == "snapshot_mismatch"


def test_restarted_client_detects_a_rolled_back_sink(paths, start_sink):
    first_run = start_sink()
    client = decide_client(paths)
    client.append(make_entry(1))
    client.append(make_entry(2))
    client.close()
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


def test_a_second_client_for_one_writer_and_state_is_refused(paths, start_sink):
    start_sink()
    client = decide_client(paths)
    with pytest.raises(DocketError) as error:
        decide_client(paths)
    assert error.value.reason == "writer_locked"
    assert client.append(make_entry(1)).seq == 1


def test_a_closed_client_releases_the_writer_and_refuses_appends(paths, start_sink):
    start_sink()
    client = decide_client(paths)
    client.append(make_entry(1))
    client.close()
    client.close()
    with pytest.raises(DocketError) as error:
        client.append(make_entry(2))
    assert error.value.reason == "closed"
    with pytest.raises(DocketError) as error:
        client.head()
    assert error.value.reason == "closed"
    assert decide_client(paths).append(make_entry(2)).seq == 2


def test_another_process_cannot_take_a_held_writer(paths, start_sink):
    start_sink()
    client = decide_client(paths)
    probe = (
        "import fcntl, os, sys\n"
        "fd = os.open(sys.argv[1], os.O_RDWR)\n"
        "try:\n"
        "    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)\n"
        "except BlockingIOError:\n"
        "    sys.exit(3)\n"
    )
    lock = state_dir(paths) / "decide.lock"
    assert subprocess.run([sys.executable, "-c", probe, str(lock)], check=False).returncode == 3
    client.close()
    assert subprocess.run([sys.executable, "-c", probe, str(lock)], check=False).returncode == 0


def test_a_symlinked_writer_lock_is_refused(paths, start_sink, workdir):
    start_sink()
    (state_dir(paths) / "decide.lock").symlink_to(workdir / "elsewhere.lock")
    with pytest.raises(DocketError) as error:
        decide_client(paths)
    assert error.value.reason == "state_invalid"
    assert not (workdir / "elsewhere.lock").exists()


def test_a_writer_lock_readable_by_others_is_refused(paths, start_sink):
    start_sink()
    decide_client(paths).close()
    (state_dir(paths) / "decide.lock").chmod(0o644)
    with pytest.raises(DocketError) as error:
        decide_client(paths)
    assert error.value.reason == "state_invalid"


def test_a_lock_error_is_a_docket_error(paths, start_sink, monkeypatch):
    start_sink()

    def refuse(fd):
        raise OSError(errno.ENOLCK, os.strerror(errno.ENOLCK))

    monkeypatch.setattr("agent_bailiff.docket.client.try_lock", refuse)
    with pytest.raises(DocketError) as error:
        decide_client(paths)
    assert error.value.reason == "state_invalid"


def test_client_state_file_is_private(paths, start_sink):
    start_sink()
    record = decide_client(paths).append(make_entry(1))
    state = state_dir(paths) / "decide.head"
    assert stat.S_IMODE(os.lstat(state).st_mode) == 0o600
    assert state.read_bytes() == f'{{"hash":"{record.hash}","seq":1}}'.encode()
    assert sorted(path.name for path in state_dir(paths).iterdir()) == ["decide.head", "decide.lock"]


@pytest.mark.parametrize("mode", [0o770, 0o777])
def test_client_refuses_a_state_directory_writable_by_others(paths, mode):
    directory = state_dir(paths)
    os.chmod(directory, mode)
    with pytest.raises(DocketError, match="writable") as error:
        decide_client(paths)
    assert error.value.reason == "state_invalid"


def test_client_refuses_a_missing_state_directory(paths, workdir):
    with pytest.raises(DocketError) as error:
        decide_client(paths, state_dir=workdir / "missing")
    assert error.value.reason == "state_invalid"


def test_client_refuses_a_symlinked_state_directory(paths, workdir):
    link = workdir / "state-link"
    link.symlink_to(state_dir(paths))
    with pytest.raises(DocketError) as error:
        decide_client(paths, state_dir=link)
    assert error.value.reason == "state_invalid"
    assert list(state_dir(paths).iterdir()) == []


def test_an_unsafe_state_directory_after_an_append_is_unacknowledged(paths, start_sink):
    start_sink()
    client = decide_client(paths)
    os.chmod(state_dir(paths), 0o770)
    with pytest.raises(DocketError) as error:
        client.append(make_entry(1))
    assert error.value.reason == "state_write_failed"
    assert error.value.reason in UNACKNOWLEDGED
    assert len(lines(paths[0])) == 1


def test_a_state_name_failure_after_an_append_is_unacknowledged(paths, start_sink, monkeypatch):
    start_sink()
    client = decide_client(paths)

    def no_entropy(size):
        raise OSError(errno.EIO, "no entropy")

    monkeypatch.setattr(client_module.os, "urandom", no_entropy)
    with pytest.raises(DocketError) as error:
        client.append(make_entry(1))
    monkeypatch.undo()
    assert error.value.reason == "state_write_failed"
    assert len(lines(paths[0])) == 1
    assert sorted(path.name for path in state_dir(paths).iterdir()) == ["decide.lock"]


@pytest.mark.parametrize("reason", ["no_ack", "bad_ack", "state_write_failed"])
def test_a_sink_refusal_naming_a_client_reason_is_a_plain_refusal(paths, reason):
    socket_path = paths[1]
    socket_path.parent.mkdir(mode=0o700)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(socket_path))
        server.listen(1)

        def refuse():
            connection, _ = server.accept()
            with connection:
                read_frame(connection, MAX_FRAME_BYTES)
                connection.sendall(encode_response({"ok": False, "reason": reason}))

        thread = threading.Thread(target=refuse)
        thread.start()
        with pytest.raises(DocketError) as error:
            decide_client(paths).append(make_entry(1))
        thread.join(5)
    assert error.value.reason == "refused"
    assert error.value.reason not in UNACKNOWLEDGED


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


def test_repair_keeps_a_docket_shared_with_its_reader_group(paths, start_sink, workdir):
    handle = start_sink(reader_gid=READER_GID)
    decide_client(paths).append(make_entry(1))
    handle.stop()
    with open(paths[0], "a") as docket:
        docket.write("partial")
    assert repair(paths[0], workdir / "torn.tail", WRITERS, reader_gid=READER_GID).ok
    assert file_mode(paths[0]) == (0o640, READER_GID)
    with pytest.raises(PermissionError, match="0600"):
        repair(paths[0], workdir / "other.tail", WRITERS)


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


def chain_snapshot(docket_path):
    chain = ChainState()
    with open(docket_path, "rb") as docket:
        verification = Verification(docket, INDEX)
        for verified in verification:
            chain.add(verified.start, verified.record)
    assert verification.report.ok
    return chain.snapshot()


def seal(paths, snapshot=None):
    write_snapshot(snapshot_path(paths[0]), snapshot or chain_snapshot(paths[0]))


def write_two_writers(paths, start_sink):
    handle = start_sink()
    decide = decide_client(paths)
    custodian = make_client(paths, "custodian", "custodian-1", CUSTODIAN_KEY)
    decide.append(make_entry(1))
    custodian.append(make_entry(2, hop="custodian", component="custodian"))
    decide.append(make_entry(3))
    decide.close()
    custodian.close()
    handle.stop()


def test_first_start_verifies_the_docket_and_writes_its_snapshot(paths, start_sink):
    write_two_writers(paths, start_sink)
    snapshot_path(paths[0]).unlink()
    start_sink().stop()
    snapshot = read_snapshot(snapshot_path(paths[0]), uid=os.geteuid())
    assert snapshot == chain_snapshot(paths[0])
    assert (snapshot.offset, snapshot.entries) == (paths[0].stat().st_size, 3)
    assert snapshot.kids == {"decide-1", "custodian-1"}


def test_first_start_on_a_new_docket_writes_an_empty_snapshot(paths, start_sink):
    start_sink()
    assert read_snapshot(snapshot_path(paths[0]), uid=os.geteuid()) == Snapshot(1, 0, 0, hashlib.sha256().hexdigest())


def test_snapshot_shares_the_docket_reader_group(paths, start_sink):
    start_sink(reader_gid=READER_GID)
    assert file_mode(snapshot_path(paths[0])) == (0o640, READER_GID)


def share(paths, gid, directory_mode, file_mode):
    for path, mode in ((paths[0].parent, directory_mode), (paths[0], file_mode), (snapshot_path(paths[0]), file_mode)):
        os.chown(path, -1, gid)
        os.chmod(path, mode)


def test_reader_group_can_be_added_and_removed_as_documented(paths, start_sink):
    write_chain(paths, start_sink, count=2)
    share(paths, READER_GID, 0o750, 0o640)
    start_sink(reader_gid=READER_GID).stop()
    share(paths, READER_GID, 0o700, 0o600)
    handle = start_sink()
    assert handle.sink.heads == verify_docket(paths[0], WRITERS).heads


def test_start_from_a_snapshot_gives_the_heads_of_a_full_verify(paths, start_sink):
    write_two_writers(paths, start_sink)
    seal(paths)
    handle = start_sink()
    assert handle.sink.heads == verify_docket(paths[0], WRITERS).heads
    assert decide_client(paths).append(make_entry(4)).seq == 3


def test_start_from_a_snapshot_decodes_only_the_anchors_and_the_tail(paths, start_sink, monkeypatch):
    write_chain(paths, start_sink, count=5)
    sealed = chain_snapshot(paths[0])
    seal(paths, sealed)
    handle = start_sink()
    client = decide_client(paths)
    client.append(make_entry(6))
    client.append(make_entry(7))
    client.close()
    handle.stop()
    seal(paths, sealed)
    decoded = []
    original = sink_module.decode_record

    def counting_decode(token, index):
        decoded.append(token)
        return original(token, index)

    monkeypatch.setattr(sink_module, "decode_record", counting_decode)
    start_sink()
    assert decoded == lines(paths[0])[4:]
    assert read_snapshot(snapshot_path(paths[0]), uid=os.geteuid()) == sealed


def refuse_start(paths, start_sink):
    before = snapshot_path(paths[0]).read_bytes()
    with pytest.raises(DocketCorrupt) as error:
        start_sink()
    assert error.value.report.reason == "snapshot_mismatch"
    assert snapshot_path(paths[0]).read_bytes() == before
    return error.value


def sealed_chain(paths, start_sink):
    write_chain(paths, start_sink)
    snapshot = chain_snapshot(paths[0])
    seal(paths, snapshot)
    return snapshot


def test_start_refuses_a_snapshot_past_the_end_of_the_docket(paths, start_sink):
    sealed_chain(paths, start_sink)
    roll_back_to(paths, 2, keep_snapshot=True)
    assert "past the end" in str(refuse_start(paths, start_sink))


def test_start_refuses_a_changed_prefix(paths, start_sink):
    sealed_chain(paths, start_sink)
    content = paths[0].read_bytes()
    paths[0].write_bytes(content[:10] + bytes([content[10] ^ 1]) + content[11:])
    assert "SHA-256" in str(refuse_start(paths, start_sink))


def test_start_refuses_a_snapshot_with_another_prefix_hash(paths, start_sink):
    snapshot = sealed_chain(paths, start_sink)
    seal(paths, replace(snapshot, prefix_sha256="0" * 64))
    assert "SHA-256" in str(refuse_start(paths, start_sink))


def test_start_refuses_a_snapshot_with_an_unpinned_kid(paths, start_sink):
    snapshot = sealed_chain(paths, start_sink)
    seal(paths, replace(snapshot, kids=snapshot.kids | {"rogue-1"}))
    assert "rogue-1" in str(refuse_start(paths, start_sink))


def anchored(snapshot, **changes):
    return replace(snapshot, anchors={"decide": replace(snapshot.anchors["decide"], **changes)})


@pytest.mark.parametrize(
    ("changes", "detail"),
    [
        ({"offset": 1}, "anchor of writer decide: malformed"),
        ({"offset": 0}, "is not its record at seq 3"),
        ({"seq": 2}, "is not its record at seq 2"),
        ({"hash": "A" * 43}, "is not its record at seq 3"),
    ],
)
def test_start_refuses_an_anchor_that_is_not_the_writer_head(paths, start_sink, changes, detail):
    snapshot = sealed_chain(paths, start_sink)
    seal(paths, anchored(snapshot, **changes))
    assert detail in str(refuse_start(paths, start_sink))


def test_start_refuses_an_anchor_of_another_writer(paths, start_sink):
    write_two_writers(paths, start_sink)
    snapshot = chain_snapshot(paths[0])
    custodian = snapshot.anchors["custodian"]
    seal(paths, anchored(snapshot, offset=custodian.offset, seq=custodian.seq, hash=custodian.hash))
    assert "is not its record" in str(refuse_start(paths, start_sink))


def test_start_refuses_an_anchor_line_that_crosses_the_offset(paths, start_sink):
    snapshot = sealed_chain(paths, start_sink)
    content = paths[0].read_bytes()
    anchor = snapshot.anchors["decide"]
    offset = anchor.offset + 5
    seal(
        paths,
        replace(snapshot, offset=offset, prefix_sha256=hashlib.sha256(content[:offset]).hexdigest()),
    )
    assert "not a whole line" in str(refuse_start(paths, start_sink))


@pytest.mark.parametrize("mode", [0o644, 0o640])
def test_start_refuses_a_snapshot_file_with_the_wrong_mode(paths, start_sink, mode):
    sealed_chain(paths, start_sink)
    os.chmod(snapshot_path(paths[0]), mode)
    assert "0600" in str(refuse_start(paths, start_sink))


def test_start_refuses_a_snapshot_that_is_not_json(paths, start_sink):
    sealed_chain(paths, start_sink)
    snapshot_path(paths[0]).write_bytes(b"{")
    assert "not a valid snapshot" in str(refuse_start(paths, start_sink))


def test_start_refuses_a_symlinked_snapshot(paths, start_sink, workdir):
    sealed_chain(paths, start_sink)
    target = workdir / "elsewhere"
    snapshot_path(paths[0]).rename(target)
    snapshot_path(paths[0]).symlink_to(target)
    with pytest.raises(DocketCorrupt, match="cannot be opened"):
        start_sink()


@pytest.mark.parametrize(("tail", "reason"), [(b"partial", "torn_tail"), (b"garbage\n", "malformed")])
def test_start_from_a_snapshot_reports_a_bad_tail_line_as_before(paths, start_sink, tail, reason):
    sealed_chain(paths, start_sink)
    size = paths[0].stat().st_size
    with open(paths[0], "ab") as docket:
        docket.write(tail)
    with pytest.raises(DocketCorrupt) as error:
        start_sink()
    report = error.value.report
    assert (report.line, report.reason, report.entries, report.valid_bytes) == (4, reason, 3, size)
    assert report == verify_docket(paths[0], WRITERS)


def test_failed_full_start_writes_no_snapshot(paths, start_sink):
    write_chain(paths, start_sink)
    snapshot_path(paths[0]).unlink()
    with open(paths[0], "a") as docket:
        docket.write("garbage\n")
    with pytest.raises(DocketCorrupt):
        start_sink()
    assert not snapshot_path(paths[0]).exists()


def test_locked_docket_is_refused_before_its_snapshot_is_read(paths, start_sink):
    start_sink()
    os.chmod(snapshot_path(paths[0]), 0o644)
    with pytest.raises(DocketLocked):
        asyncio.run(DocketSink(paths[0], paths[1], WRITERS, {os.getuid()}).start())


def test_docket_fsync_failure_at_start_skips_the_snapshot(paths, start_sink):
    def failing_file_fsync(fd):
        if fd_kind(fd) == "file":
            raise OSError(5, "injected fsync failure")
        os.fsync(fd)

    start_sink(fsync=failing_file_fsync)
    assert not snapshot_path(paths[0]).exists()


def test_directory_fsync_failure_at_start_skips_the_snapshot(paths, start_sink):
    def failing_dir_fsync(fd):
        if fd_kind(fd) == "dir":
            raise OSError(5, "injected directory fsync failure")
        os.fsync(fd)

    start_sink(fsync=failing_dir_fsync)
    assert not snapshot_path(paths[0]).exists()


def test_sink_refuses_a_snapshot_cadence_below_one(paths):
    for every in (0, -1, True, 1.0):
        with pytest.raises(ValueError, match="snapshot_every"):
            DocketSink(paths[0], paths[1], WRITERS, {os.getuid()}, snapshot_every=every)


def test_sink_refuses_a_free_space_floor_below_two_frames(paths):
    for floor in (0, 2 * MAX_FRAME_BYTES - 1, True, float(2 * MAX_FRAME_BYTES)):
        with pytest.raises(ValueError, match="free_space_floor"):
            DocketSink(paths[0], paths[1], WRITERS, {os.getuid()}, free_space_floor=floor)


class FakeDisk:
    def __init__(self, free, capacity=1 << 40):
        self.free = free
        self.capacity = capacity
        self.error = None

    def statvfs(self, fd):
        if self.error is not None:
            raise self.error
        real = os.fstatvfs(fd)
        return os.statvfs_result((real.f_bsize, 1, self.capacity, 0, self.free, 0, 0, 0, 0, real.f_namemax))


FLOOR = 2 * MAX_FRAME_BYTES


def refusal(client, entry):
    with pytest.raises(DocketError) as error:
        client.append(entry)
    return error.value.reason


def test_append_below_the_free_space_floor_is_refused_without_writing(paths, start_sink):
    disk = FakeDisk(free=10 * FLOOR)
    handle = start_sink(statvfs=disk.statvfs, free_space_floor=FLOOR)
    client = decide_client(paths)
    first = client.append(make_entry(1))
    size = paths[0].stat().st_size
    disk.free = FLOOR
    assert refusal(client, make_entry(2)) == "docket_full"
    assert "docket_full" not in UNACKNOWLEDGED
    assert paths[0].stat().st_size == size
    assert handle.sink.heads == {"decide": Head(seq=first.seq, hash=first.hash)}


def test_append_resumes_once_space_returns(paths, start_sink):
    disk = FakeDisk(free=FLOOR)
    start_sink(statvfs=disk.statvfs, free_space_floor=FLOOR)
    client = decide_client(paths)
    assert refusal(client, make_entry(1)) == "docket_full"
    disk.free = 10 * FLOOR
    assert client.append(make_entry(1)).seq == 1
    assert len(lines(paths[0])) == 1


def test_floor_admits_a_record_that_leaves_exactly_the_floor(paths, start_sink, workdir):
    start_sink(statvfs=FakeDisk(free=10 * FLOOR).statvfs, free_space_floor=FLOOR)
    first = decide_client(paths)
    first.append(make_entry(1))
    first.close()
    length = paths[0].stat().st_size
    other = (workdir / "other" / "docket.log", workdir / "other" / "s" / "docket.sock")
    other[0].parent.mkdir(mode=0o700)
    for free, admitted in ((FLOOR + length - 1, False), (FLOOR + length, True)):
        disk = FakeDisk(free=free)
        handle = RunningSink(
            DocketSink(other[0], other[1], WRITERS, {os.getuid()}, statvfs=disk.statvfs, free_space_floor=FLOOR)
        )
        client = decide_client(other)
        try:
            if admitted:
                client.append(make_entry(1))
            else:
                assert refusal(client, make_entry(1)) == "docket_full"
        finally:
            client.close()
            handle.stop()
    assert other[0].read_bytes() == paths[0].read_bytes()


def test_free_space_check_failure_is_a_not_written_refusal(paths, start_sink):
    disk = FakeDisk(free=10 * FLOOR)
    start_sink(statvfs=disk.statvfs, free_space_floor=FLOOR)
    disk.error = OSError(errno.EIO, "injected statvfs failure")
    client = decide_client(paths)
    assert refusal(client, make_entry(1)) == "space_check_failed"
    assert "space_check_failed" not in UNACKNOWLEDGED
    assert lines(paths[0]) == []
    disk.error = None
    assert client.append(make_entry(1)).seq == 1


def test_a_write_failure_after_the_floor_check_still_stops_appends(paths, start_sink):
    def full_fsync(fd):
        if fd_kind(fd) == "file":
            raise OSError(errno.ENOSPC, "injected ENOSPC")

    armed = []
    start_sink(
        statvfs=FakeDisk(free=10 * FLOOR).statvfs,
        free_space_floor=FLOOR,
        fsync=lambda fd: full_fsync(fd) if armed else os.fsync(fd),
    )
    armed.append(True)
    client = decide_client(paths)
    assert refusal(client, make_entry(1)) == "write_failed"
    assert refusal(client, make_entry(1)) == "sink_failed"


def test_sink_refuses_to_start_when_the_floor_leaves_no_room(paths, start_sink):
    disk = FakeDisk(free=0, capacity=FLOOR + MAX_FRAME_BYTES)
    with pytest.raises(ValueError, match="leaves no room"):
        start_sink(statvfs=disk.statvfs, free_space_floor=FLOOR)


def test_sink_starts_below_the_floor_when_the_file_system_can_hold_it(paths, start_sink):
    disk = FakeDisk(free=0, capacity=FLOOR + MAX_FRAME_BYTES + 1)
    start_sink(statvfs=disk.statvfs, free_space_floor=FLOOR)
    assert refusal(decide_client(paths), make_entry(1)) == "docket_full"


def floor_logs(caplog):
    return [record.message for record in caplog.records if record.name == sink_module.__name__]


def test_floor_refusals_are_logged_once_per_interval(paths, start_sink, caplog):
    disk = FakeDisk(free=FLOOR)
    now = [0.0]
    start_sink(statvfs=disk.statvfs, free_space_floor=FLOOR, clock=lambda: now[0])
    disk.error = OSError(errno.EIO, "injected statvfs failure")
    client = decide_client(paths)
    for at in (0.0, 10.0, 20.0, 60.0):
        now[0] = at
        if at == 20.0:
            disk.error = None
        refusal(client, make_entry(1))
    assert floor_logs(caplog) == [
        "docket free-space check failed: [Errno 5] injected statvfs failure",
        f"docket refusing appends: {FLOOR} bytes free, floor is {FLOOR} bytes",
    ]


def test_recovery_is_logged_and_a_new_incident_is_logged_at_once(paths, start_sink, caplog):
    disk = FakeDisk(free=FLOOR)
    now = [0.0]
    start_sink(statvfs=disk.statvfs, free_space_floor=FLOOR, clock=lambda: now[0])
    client = decide_client(paths)
    refusal(client, make_entry(1))
    disk.free = 10 * FLOOR
    now[0] = 5.0
    client.append(make_entry(1))
    disk.free = FLOOR
    now[0] = 10.0
    refusal(client, make_entry(2))
    assert floor_logs(caplog) == [
        f"docket refusing appends: {FLOOR} bytes free, floor is {FLOOR} bytes",
        f"docket appends resumed: {10 * FLOOR} bytes free",
        f"docket refusing appends: {FLOOR} bytes free, floor is {FLOOR} bytes",
    ]


def current_snapshot(paths):
    return read_snapshot(snapshot_path(paths[0]), uid=os.geteuid())


def settle(handle):
    asyncio.run_coroutine_threadsafe(asyncio.sleep(0), handle.loop).result(5)


def test_snapshot_is_refreshed_every_snapshot_every_appends(paths, start_sink):
    handle = start_sink(snapshot_every=2)
    empty = current_snapshot(paths)
    client = decide_client(paths)
    client.append(make_entry(1))
    settle(handle)
    assert current_snapshot(paths) == empty
    client.append(make_entry(2))
    settle(handle)
    assert current_snapshot(paths) == chain_snapshot(paths[0])
    client.append(make_entry(3))
    settle(handle)
    assert current_snapshot(paths).entries == 2
    client.append(make_entry(4))
    settle(handle)
    assert current_snapshot(paths) == chain_snapshot(paths[0])
    assert current_snapshot(paths).entries == 4


def token_of(number, prev=None):
    return encode_record(DECIDE_KEY, "decide-1", "decide", number, prev, make_entry(number))


def run_in_sink(paths, scenario, **options):
    sink = DocketSink(paths[0], paths[1], WRITERS, {os.getuid()}, **options)

    async def run():
        await sink.start()
        try:
            return await scenario(sink)
        finally:
            await sink.close()

    return asyncio.run(run())


def test_snapshot_is_written_after_the_append_returns(paths):
    async def scenario(sink):
        empty = current_snapshot(paths)
        assert sink._append(token_of(1).token.encode())["ok"]
        assert current_snapshot(paths) == empty
        await asyncio.sleep(0)
        return current_snapshot(paths)

    snapshot = run_in_sink(paths, scenario, snapshot_every=1)
    assert snapshot == chain_snapshot(paths[0])


def test_snapshot_offset_is_the_sink_count_not_the_file_size(paths):
    async def scenario(sink):
        assert sink._append(token_of(1).token.encode())["ok"]
        with open(paths[0], "ab") as docket:
            docket.write(b"foreign")
        await asyncio.sleep(0)
        return current_snapshot(paths)

    snapshot = run_in_sink(paths, scenario, snapshot_every=1)
    assert snapshot.offset == paths[0].stat().st_size - len(b"foreign")
    assert snapshot.entries == 1


def test_append_failure_before_the_callback_skips_the_snapshot(paths):
    fail = threading.Event()

    def flaky_fsync(fd):
        if fail.is_set() and fd_kind(fd) == "file":
            raise OSError(5, "injected fsync failure")
        os.fsync(fd)

    async def scenario(sink):
        empty = current_snapshot(paths)
        first = token_of(1)
        assert sink._append(first.token.encode())["ok"]
        fail.set()
        assert sink._append(token_of(2, first.hash).token.encode())["reason"] == "write_failed"
        await asyncio.sleep(0)
        return empty

    empty = run_in_sink(paths, scenario, snapshot_every=1, fsync=flaky_fsync)
    assert current_snapshot(paths) == empty


def test_docket_fsync_failure_before_a_snapshot_keeps_the_old_one(paths, caplog):
    fail = threading.Event()

    def flaky_fsync(fd):
        if fail.is_set() and fd_kind(fd) == "file":
            fail.clear()
            raise OSError(5, "injected fsync failure")
        os.fsync(fd)

    async def scenario(sink):
        empty = current_snapshot(paths)
        first = token_of(1)
        assert sink._append(first.token.encode())["ok"]
        fail.set()
        await asyncio.sleep(0)
        assert current_snapshot(paths) == empty
        assert sink._append(token_of(2, first.hash).token.encode())["ok"]
        await asyncio.sleep(0)
        return current_snapshot(paths)

    assert run_in_sink(paths, scenario, snapshot_every=1, fsync=flaky_fsync).entries == 2
    assert "fsync before the snapshot failed" in caplog.text


def test_snapshot_write_oserror_keeps_snapshots_on(paths, caplog, monkeypatch):
    original = sink_module.write_snapshot
    failures = [OSError(28, "injected no space")]

    def flaky_write(*args, **kwargs):
        if failures:
            raise failures.pop()
        original(*args, **kwargs)

    async def scenario(sink):
        monkeypatch.setattr(sink_module, "write_snapshot", flaky_write)
        empty = current_snapshot(paths)
        first = token_of(1)
        assert sink._append(first.token.encode())["ok"]
        await asyncio.sleep(0)
        assert current_snapshot(paths) == empty
        assert sink._append(token_of(2, first.hash).token.encode())["ok"]
        await asyncio.sleep(0)
        return current_snapshot(paths)

    assert run_in_sink(paths, scenario, snapshot_every=1).entries == 2
    assert "the snapshot on disk is the old or the new one" in caplog.text


def test_unexpected_snapshot_error_turns_snapshots_off_until_restart(paths, caplog, monkeypatch):
    calls = []

    def broken_write(*args, **kwargs):
        calls.append(args)
        raise ValueError("injected bug")

    async def scenario(sink):
        monkeypatch.setattr(sink_module, "write_snapshot", broken_write)
        empty = current_snapshot(paths)
        first = token_of(1)
        assert sink._append(first.token.encode())["ok"]
        await asyncio.sleep(0)
        assert sink._append(token_of(2, first.hash).token.encode())["ok"]
        await asyncio.sleep(0)
        return empty

    empty = run_in_sink(paths, scenario, snapshot_every=1)
    assert len(calls) == 1
    assert current_snapshot(paths) == empty
    assert "snapshots are off until restart" in caplog.text


def test_clean_close_writes_the_snapshot(paths, start_sink):
    handle = start_sink()
    client = decide_client(paths)
    client.append(make_entry(1))
    client.append(make_entry(2))
    client.close()
    assert current_snapshot(paths).entries == 0
    handle.stop()
    assert current_snapshot(paths) == chain_snapshot(paths[0])


def test_close_writes_the_snapshot_after_connections_finish(paths, monkeypatch):
    order = []
    original = sink_module.write_snapshot

    def recording_write(*args, **kwargs):
        order.append("snapshot")
        original(*args, **kwargs)

    async def scenario(sink):
        monkeypatch.setattr(sink_module, "write_snapshot", recording_write)
        server = sink._server
        original_wait = server.wait_closed

        async def recording_wait():
            await original_wait()
            order.append("wait_closed")

        monkeypatch.setattr(server, "wait_closed", recording_wait)

    run_in_sink(paths, scenario)
    assert order == ["wait_closed", "snapshot"]


def test_close_of_a_failed_sink_writes_no_snapshot(paths):
    fail = threading.Event()

    def flaky_fsync(fd):
        if fail.is_set() and fd_kind(fd) == "file":
            raise OSError(5, "injected fsync failure")
        os.fsync(fd)

    async def scenario(sink):
        first = token_of(1)
        assert sink._append(first.token.encode())["ok"]
        fail.set()
        assert sink._append(token_of(2, first.hash).token.encode())["reason"] == "write_failed"

    run_in_sink(paths, scenario, fsync=flaky_fsync)
    assert current_snapshot(paths).entries == 0


def test_close_after_a_failed_start_writes_no_snapshot(paths, start_sink):
    write_chain(paths, start_sink)
    snapshot_path(paths[0]).unlink()
    with open(paths[0], "a") as docket:
        docket.write("garbage\n")
    sink = DocketSink(paths[0], paths[1], WRITERS, {os.getuid()})
    with pytest.raises(DocketCorrupt):
        asyncio.run(sink.start())
    asyncio.run(sink.close())
    assert not snapshot_path(paths[0]).exists()


def test_repair_that_truncates_replaces_the_snapshot(paths, start_sink, workdir):
    write_chain(paths, start_sink, count=2)
    stale = current_snapshot(paths)
    write_chain(paths, start_sink, count=1)
    seal(paths, stale)
    with open(paths[0], "a") as docket:
        docket.write("partial")
    repair(paths[0], workdir / "torn.tail", WRITERS)
    assert current_snapshot(paths) == chain_snapshot(paths[0])
    assert current_snapshot(paths).entries == 3
    start_sink().stop()


def test_repair_writes_the_snapshot_of_the_valid_lines_before_it_truncates(paths, start_sink, workdir, monkeypatch):
    write_chain(paths, start_sink)
    expected = chain_snapshot(paths[0])
    with open(paths[0], "a") as docket:
        docket.write("partial")
    seen = []
    original = os.ftruncate

    def recording_truncate(fd, length):
        seen.append((length, current_snapshot(paths)))
        original(fd, length)

    monkeypatch.setattr(sink_module.os, "ftruncate", recording_truncate)
    repair(paths[0], workdir / "torn.tail", WRITERS)
    assert seen == [(expected.offset, expected)]


def test_repair_interrupted_before_the_truncate_finishes_when_run_again(paths, start_sink, workdir, monkeypatch):
    write_chain(paths, start_sink)
    with open(paths[0], "a") as docket:
        docket.write("partial")

    def crashing_truncate(fd, length):
        raise OSError(errno.EIO, "injected crash before truncate")

    monkeypatch.setattr(sink_module.os, "ftruncate", crashing_truncate)
    with pytest.raises(OSError, match="injected"):
        repair(paths[0], workdir / "torn.tail", WRITERS)
    monkeypatch.undo()
    with pytest.raises(DocketCorrupt) as error:
        start_sink()
    assert error.value.report.reason == "torn_tail"
    assert repair(paths[0], workdir / "torn.tail.2", WRITERS).ok
    assert current_snapshot(paths) == chain_snapshot(paths[0])
    start_sink().stop()


def test_repair_keeps_the_snapshot_shared_with_the_reader_group(paths, start_sink, workdir):
    write_chain(paths, start_sink)
    share(paths, READER_GID, 0o750, 0o640)
    with open(paths[0], "a") as docket:
        docket.write("partial")
    repair(paths[0], workdir / "torn.tail", WRITERS, reader_gid=READER_GID)
    assert file_mode(snapshot_path(paths[0])) == (0o640, READER_GID)


def test_repair_of_a_whole_docket_keeps_the_snapshot(paths, start_sink, workdir):
    write_chain(paths, start_sink)
    before = snapshot_path(paths[0]).read_bytes()
    assert repair(paths[0], workdir / "torn.tail", WRITERS).ok
    assert snapshot_path(paths[0]).read_bytes() == before


def test_repair_without_a_snapshot_truncates_and_writes_one(paths, start_sink, workdir):
    write_chain(paths, start_sink)
    snapshot_path(paths[0]).unlink()
    with open(paths[0], "a") as docket:
        docket.write("partial")
    assert repair(paths[0], workdir / "torn.tail", WRITERS).entries == 3
    assert current_snapshot(paths) == chain_snapshot(paths[0])


def legacy_snapshot(snapshot):
    document = json.loads(snapshot.encode())
    del document["segment"]
    return {**document, "version": 1}


@pytest.mark.parametrize("legacy", [legacy_snapshot, lambda _: {"version": 1}], ids=["whole", "version-only"])
def test_a_version_1_snapshot_migrates_through_a_full_verify(paths, start_sink, caplog, monkeypatch, legacy):
    write_two_writers(paths, start_sink)
    path = snapshot_path(paths[0])
    path.write_text(json.dumps(legacy(chain_snapshot(paths[0]))))
    full = []
    original = DocketSink._full_verify

    def recording_full_verify(self, fd):
        full.append(fd)
        original(self, fd)

    monkeypatch.setattr(DocketSink, "_full_verify", recording_full_verify)
    handle = start_sink()
    assert (handle.sink.heads["decide"].seq, handle.sink.heads["custodian"].seq) == (2, 1)
    handle.stop()
    assert len(full) == 1
    assert "snapshot version 1 predates segments" in caplog.text
    assert current_snapshot(paths) == chain_snapshot(paths[0])
    assert json.loads(path.read_bytes())["version"] == 2


def test_a_version_1_snapshot_does_not_hide_a_corrupt_docket(paths, start_sink):
    write_chain(paths, start_sink)
    snapshot_path(paths[0]).write_text(json.dumps({"version": 1}))
    with open(paths[0], "a") as docket:
        docket.write("garbage\n")
    with pytest.raises(DocketCorrupt):
        start_sink()
    assert json.loads(snapshot_path(paths[0]).read_bytes()) == {"version": 1}


def test_start_refuses_a_snapshot_of_another_segment(paths, start_sink):
    write_chain(paths, start_sink)
    seal(paths, replace(chain_snapshot(paths[0]), segment=2))
    with pytest.raises(DocketCorrupt) as error:
        start_sink()
    assert error.value.report.reason == "snapshot_mismatch"
    assert "segment 2 is not the active segment 1" in error.value.report.detail


def seal_first(paths, count):
    chain = ChainState()
    with open(paths[0], "rb") as docket:
        for verified in Verification(docket, INDEX):
            if verified.line > count:
                break
            chain.add(verified.start, verified.record)
    write_snapshot(snapshot_path(paths[0]), chain.snapshot())


def timed_start(paths):
    sink = DocketSink(paths[0], paths[1], WRITERS, {os.getuid()})

    async def run():
        began = time.perf_counter()
        await sink.start()
        elapsed = time.perf_counter() - began
        await sink.close()
        return elapsed

    return asyncio.run(run())


def test_snapshot_start_of_10k_records_takes_under_half_a_full_start(paths):
    write_records(paths[0], 10_000)
    os.chmod(paths[0], 0o600)
    full, sealed = [], []
    for _ in range(2):
        snapshot_path(paths[0]).unlink(missing_ok=True)
        full.append(timed_start(paths))
        seal_first(paths, 8_000)
        sealed.append(timed_start(paths))
    assert min(sealed) / min(full) < 0.5


EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


def sealed_entry(docket_path, records):
    content = docket_path.read_bytes()
    last = records[-1]
    return SegmentEntry(
        1,
        hashlib.sha256(content).hexdigest(),
        len(content),
        1,
        len(records),
        {"decide": Head(last.seq, last.hash)},
        frozenset({"decide-1"}),
    )


def cut_first_segment(paths, records, *, commit=True, rename=True):
    entry = sealed_entry(paths[0], records)
    write_snapshot(snapshot_path(paths[0]), Snapshot(2, 0, len(records), EMPTY_SHA256))
    if commit:
        write_manifest(manifest_path(paths[0]), Manifest.new().sealed(entry))
    if rename:
        paths[0].rename(segment_path(paths[0], 1))


def test_start_continues_the_chain_after_a_sealed_segment(paths, start_sink):
    records = write_chain(paths, start_sink)
    cut_first_segment(paths, records)
    start_sink()
    fourth = decide_client(paths).append(make_entry(4))
    assert (fourth.seq, fourth.prev) == (4, records[-1].hash)
    assert len(lines(paths[0])) == 1
    assert current_snapshot(paths).segment == 2


def test_a_writer_without_state_resumes_after_its_sealed_head(paths, start_sink, workdir):
    records = write_chain(paths, start_sink)
    cut_first_segment(paths, records)
    start_sink()
    fresh = workdir / "fresh-state"
    fresh.mkdir(mode=0o700)
    client = decide_client(paths, state_dir=fresh)
    assert client.head() == Head(3, records[-1].hash)
    assert client.append(make_entry(4)).seq == 4


def test_start_finishes_a_cut_that_committed_before_the_rename(paths, start_sink):
    records = write_chain(paths, start_sink)
    sealed = paths[0].read_bytes()
    cut_first_segment(paths, records, rename=False)
    start_sink()
    assert segment_path(paths[0], 1).read_bytes() == sealed
    assert decide_client(paths).append(make_entry(4)).seq == 4
    assert len(lines(paths[0])) == 1


def test_start_ignores_the_snapshot_of_a_cut_that_did_not_commit(paths, start_sink):
    records = write_chain(paths, start_sink)
    cut_first_segment(paths, records, commit=False, rename=False)
    start_sink()
    assert decide_client(paths).append(make_entry(4)).seq == 4
    assert len(lines(paths[0])) == 4
    assert not segment_path(paths[0], 1).exists()


def test_start_removes_leftovers_of_an_interrupted_write(paths, start_sink):
    records = write_chain(paths, start_sink)
    cut_first_segment(paths, records)
    leftovers = [
        paths[0].with_name(f"{paths[0].name}.new"),
        manifest_path(paths[0]).with_name(f"{manifest_path(paths[0]).name}.tmp"),
        snapshot_path(paths[0]).with_name(f"{snapshot_path(paths[0]).name}.tmp"),
    ]
    for leftover in leftovers:
        leftover.write_bytes(b"partial")
    start_sink()
    assert not any(leftover.exists() for leftover in leftovers)


def segment_refusal(start_sink):
    with pytest.raises(DocketCorrupt) as error:
        start_sink()
    assert error.value.report.reason == "segment_mismatch"
    return error.value.report.detail


def test_start_refuses_a_segment_file_without_a_manifest(paths, start_sink):
    write_chain(paths, start_sink)
    segment_path(paths[0], 1).write_bytes(b"stray")
    assert "not in the manifest: docket.log.seg-000000000001" in segment_refusal(start_sink)


def test_start_refuses_a_segment_file_the_manifest_does_not_list(paths, start_sink):
    records = write_chain(paths, start_sink)
    cut_first_segment(paths, records)
    segment_path(paths[0], 2).write_bytes(b"stray")
    assert "docket.log.seg-000000000002" in segment_refusal(start_sink)


def test_start_refuses_a_sealed_segment_of_another_size(paths, start_sink):
    records = write_chain(paths, start_sink)
    cut_first_segment(paths, records)
    with open(segment_path(paths[0], 1), "ab") as segment:
        segment.write(b"x")
    assert "segment 1 is" in segment_refusal(start_sink)


def test_start_refuses_a_missing_sealed_segment(paths, start_sink):
    records = write_chain(paths, start_sink)
    cut_first_segment(paths, records)
    segment_path(paths[0], 1).unlink()
    assert "segment 1 is missing" in segment_refusal(start_sink)


def test_start_refuses_a_docket_that_is_not_the_missing_segment(paths, start_sink):
    records = write_chain(paths, start_sink)
    cut_first_segment(paths, records, rename=False)
    content = lines(paths[0])
    paths[0].write_text("\n".join([content[0], content[2], content[1]]) + "\n")
    assert "segment 1 is missing and the docket is not it" in segment_refusal(start_sink)


def test_start_refuses_an_invalid_manifest(paths, start_sink):
    write_chain(paths, start_sink)
    manifest_path(paths[0]).write_bytes(b"garbage")
    os.chmod(manifest_path(paths[0]), 0o600)
    assert "not a valid manifest" in segment_refusal(start_sink)


def test_start_refuses_a_snapshot_behind_the_manifest(paths, start_sink):
    records = write_chain(paths, start_sink)
    cut_first_segment(paths, records)
    write_snapshot(snapshot_path(paths[0]), Snapshot(2, 0, 2, EMPTY_SHA256))
    with pytest.raises(DocketCorrupt) as error:
        start_sink()
    assert error.value.report.reason == "snapshot_mismatch"


def test_start_refuses_an_active_segment_that_restarts_a_sealed_chain(paths, start_sink):
    records = write_chain(paths, start_sink)
    cut_first_segment(paths, records)
    snapshot_path(paths[0]).unlink()
    shutil.copy(segment_path(paths[0], 1), paths[0])
    os.chmod(paths[0], 0o600)
    with pytest.raises(DocketCorrupt):
        start_sink()


def test_repair_of_the_active_segment_keeps_the_sealed_chain(paths, start_sink, workdir):
    records = write_chain(paths, start_sink)
    cut_first_segment(paths, records)
    handle = start_sink()
    fourth = decide_client(paths).append(make_entry(4))
    handle.stop()
    with open(paths[0], "a") as docket:
        docket.write("partial")
    report = repair(paths[0], workdir / "torn.tail", WRITERS)
    assert report.ok
    assert report.heads["decide"] == Head(4, fourth.hash)
    assert (workdir / "torn.tail").read_bytes() == b"partial"
    assert current_snapshot(paths).segment == 2


def test_repair_refuses_a_missing_sealed_segment(paths, start_sink, workdir):
    records = write_chain(paths, start_sink)
    cut_first_segment(paths, records)
    segment_path(paths[0], 1).unlink()
    with pytest.raises(DocketCorrupt) as error:
        repair(paths[0], workdir / "torn.tail", WRITERS)
    assert error.value.report.reason == "segment_mismatch"


def test_sink_refuses_a_segment_size_below_one(paths):
    for size in (0, -1, True, 1.0):
        with pytest.raises(ValueError, match="segment_bytes"):
            DocketSink(paths[0], paths[1], WRITERS, {os.getuid()}, segment_bytes=size)


def current_manifest(paths):
    return read_docket_manifest(paths[0])


def verify_all(paths):
    return verify_records(paths[0], WRITERS, RecordFilter(), lambda line: None)


def test_an_append_past_segment_bytes_seals_the_segment(paths, start_sink):
    handle = start_sink(segment_bytes=1)
    client = decide_client(paths)
    first = client.append(make_entry(1))
    settle(handle)
    sealed = segment_path(paths[0], 1).read_bytes()
    assert sealed == f"{first.token}\n".encode()
    assert paths[0].read_bytes() == b""
    heads = {"decide": Head(1, first.hash)}
    digest = hashlib.sha256(sealed).hexdigest()
    assert current_manifest(paths).segments == (
        SegmentEntry(1, digest, len(sealed), 1, 1, heads, frozenset({"decide-1"})),
    )
    assert current_snapshot(paths) == Snapshot(2, 0, 1, EMPTY_SHA256)
    second = client.append(make_entry(2))
    settle(handle)
    assert (second.seq, second.prev) == (2, first.hash)
    assert [entry.segment for entry in current_manifest(paths).segments] == [1, 2]
    report = verify_all(paths)
    assert (report.ok, report.entries, report.heads) == (True, 2, {"decide": Head(2, second.hash)})


def test_a_segment_is_cut_only_once_it_reaches_segment_bytes(paths):
    first = token_of(1)
    second = token_of(2, first.hash)

    async def scenario(sink):
        assert sink._append(first.token.encode())["ok"]
        await asyncio.sleep(0)
        assert not segment_path(paths[0], 1).exists()
        assert sink._append(second.token.encode())["ok"]
        await asyncio.sleep(0)

    run_in_sink(paths, scenario, segment_bytes=len(first.token) + 2)
    assert segment_path(paths[0], 1).read_text().splitlines() == [first.token, second.token]
    assert current_manifest(paths).segments[0].entries == 2


def test_a_sealed_segment_keeps_the_heads_of_writers_absent_from_it(paths, start_sink, workdir):
    handle = start_sink(segment_bytes=1)
    first = decide_client(paths).append(make_entry(1))
    settle(handle)
    custodian = make_client(paths, "custodian", "custodian-1", CUSTODIAN_KEY).append(make_entry(2))
    settle(handle)
    handle.stop()
    assert current_manifest(paths).segments[1].end_heads == {
        "decide": Head(1, first.hash),
        "custodian": Head(1, custodian.hash),
    }
    start_sink(segment_bytes=1)
    assert_refused(paths, first.token, "wrong_seq")
    fresh = workdir / "fresh-state"
    fresh.mkdir(mode=0o700)
    assert decide_client(paths, state_dir=fresh).head() == Head(1, first.hash)


def test_a_cut_pending_after_a_failed_write_does_nothing(paths):
    fail = threading.Event()

    def flaky_fsync(fd):
        if fail.is_set() and fd_kind(fd) == "file":
            raise OSError(5, "injected fsync failure")
        os.fsync(fd)

    async def scenario(sink):
        first = token_of(1)
        assert sink._append(first.token.encode())["ok"]
        fail.set()
        assert sink._append(token_of(2, first.hash).token.encode())["reason"] == "write_failed"
        await asyncio.sleep(0)

    run_in_sink(paths, scenario, segment_bytes=1, fsync=flaky_fsync)
    assert not segment_path(paths[0], 1).exists()
    assert not manifest_path(paths[0]).exists()


def test_a_docket_of_another_size_than_the_sink_wrote_stops_appends_at_the_cut(paths, caplog):
    first = token_of(1)

    async def scenario(sink):
        assert sink._append(first.token.encode())["ok"]
        with open(paths[0], "ab") as docket:
            docket.write(b"foreign")
        await asyncio.sleep(0)
        return sink._append(token_of(2, first.hash).token.encode())

    assert run_in_sink(paths, scenario, segment_bytes=1)["reason"] == "sink_failed"
    assert not segment_path(paths[0], 1).exists()
    assert "not the" in caplog.text


def no_space(*args, **kwargs):
    raise OSError(errno.ENOSPC, "injected no space")


@pytest.mark.parametrize("failure", ["manifest_cap", "manifest_no_space", "snapshot_no_space", "docket_fsync"])
def test_a_cut_that_fails_before_the_commit_is_retried_by_the_next_append(paths, caplog, monkeypatch, failure):
    first = token_of(1)
    second = token_of(2, first.hash)
    failing = threading.Event()
    now = [0.0]

    def flaky_fsync(fd):
        if failing.is_set() and fd_kind(fd) == "file":
            raise OSError(5, "injected fsync failure")
        os.fsync(fd)

    async def scenario(sink):
        assert sink._append(first.token.encode())["ok"]
        with monkeypatch.context() as patch:
            if failure == "manifest_cap":
                patch.setattr(manifest_module, "MAX_MANIFEST_BYTES", 10)
            if failure == "manifest_no_space":
                patch.setattr(sink_module, "write_manifest", no_space)
            if failure == "snapshot_no_space":
                patch.setattr(sink_module, "write_snapshot", no_space)
            if failure == "docket_fsync":
                failing.set()
            await asyncio.sleep(0)
            failing.clear()
        assert not segment_path(paths[0], 1).exists()
        assert manifest_path(paths[0]).exists() is False
        now[0] = sink_module.CUT_RETRY_INTERVAL
        assert sink._append(second.token.encode())["ok"]
        await asyncio.sleep(0)

    run_in_sink(paths, scenario, segment_bytes=1, fsync=flaky_fsync, clock=lambda: now[0])
    assert "cut of segment 1 aborted; the first append after 30 s retries it" in caplog.text
    assert segment_path(paths[0], 1).read_text().splitlines() == [first.token, second.token]
    assert verify_all(paths).entries == 2


def test_an_aborted_cut_is_not_retried_within_the_retry_interval(paths, monkeypatch):
    tokens = [token_of(1)]
    for number in (2, 3):
        tokens.append(token_of(number, tokens[-1].hash))
    now = [0.0]
    attempts = []
    real_write_manifest = sink_module.write_manifest

    def counted_write_manifest(*args, **kwargs):
        attempts.append(now[0])
        if len(attempts) == 1:
            raise OSError(errno.ENOSPC, "injected no space")
        return real_write_manifest(*args, **kwargs)

    monkeypatch.setattr(sink_module, "write_manifest", counted_write_manifest)

    async def scenario(sink):
        assert sink._append(tokens[0].token.encode())["ok"]
        await asyncio.sleep(0)
        now[0] = sink_module.CUT_RETRY_INTERVAL - 1
        assert sink._append(tokens[1].token.encode())["ok"]
        await asyncio.sleep(0)
        assert not segment_path(paths[0], 1).exists()
        now[0] = sink_module.CUT_RETRY_INTERVAL
        assert sink._append(tokens[2].token.encode())["ok"]
        await asyncio.sleep(0)

    run_in_sink(paths, scenario, segment_bytes=1, clock=lambda: now[0])
    assert attempts == [0.0, sink_module.CUT_RETRY_INTERVAL]
    assert segment_path(paths[0], 1).read_text().splitlines() == [item.token for item in tokens]
    assert verify_all(paths).entries == 3


class Crash(BaseException):
    pass


class Faults:
    SYSCALLS = ("open", "write", "fchmod", "fchown", "rename", "replace")

    def __init__(self, target=None, error=Crash):
        self.target = target
        self.error = error
        self.calls = []
        self.armed = False

    def hit(self, name):
        if not self.armed:
            return
        self.calls.append(name)
        if len(self.calls) == self.target:
            self.armed = False
            raise self.error(f"injected failure at {name} call {self.target}")

    def install(self, monkeypatch):
        for name in self.SYSCALLS:
            monkeypatch.setattr(os, name, self.wrap(name, getattr(os, name)))

    def wrap(self, name, function):
        def wrapped(*args, **kwargs):
            self.hit(name)
            return function(*args, **kwargs)

        return wrapped

    def fsync(self, fd):
        self.hit(f"fsync {fd_kind(fd)}")
        os.fsync(fd)


def cut_under(paths, faults, monkeypatch, **options):
    first = token_of(1)
    second = token_of(2, first.hash)

    async def scenario(sink):
        assert sink._append(first.token.encode())["ok"]
        await asyncio.sleep(0)
        assert sink._append(second.token.encode())["ok"]
        with monkeypatch.context() as patch:
            faults.install(patch)
            faults.armed = True
            try:
                sink._cut()
            except Crash:
                sink._failed = True
            finally:
                faults.armed = False
        return sink._failed

    return run_in_sink(paths, scenario, segment_bytes=1, fsync=faults.fsync, **options), second


def resume_after(paths, second, **options):
    third = token_of(3, second.hash)

    async def scenario(sink):
        return sink._append(third.token.encode())

    assert run_in_sink(paths, scenario, segment_bytes=1, **options)["ok"]
    report = verify_all(paths)
    assert (report.ok, report.entries, report.heads) == (True, 3, {"decide": Head(3, third.hash)})
    snapshot = read_snapshot(snapshot_path(paths[0]), uid=os.geteuid(), reader_gid=options.get("reader_gid"))
    assert snapshot.segment == current_manifest(paths).active_segment


def cut_syscalls(paths, monkeypatch, **options):
    counting = Faults()
    cut_under(paths, counting, monkeypatch, **options)
    shutil.rmtree(paths[0].parent)
    paths[0].parent.mkdir(mode=0o700)
    return counting.calls


@pytest.mark.parametrize("reader_gid", [None, READER_GID], ids=["private", "shared"])
def test_a_crash_at_any_cut_syscall_leaves_a_docket_that_starts_without_a_fork(paths, monkeypatch, reader_gid):
    calls = cut_syscalls(paths, monkeypatch, reader_gid=reader_gid)
    assert calls.count("rename") == 2 and calls.count("replace") == 2
    for target in range(1, len(calls) + 1):
        crashed, second = cut_under(paths, Faults(target), monkeypatch, reader_gid=reader_gid)
        assert crashed, calls[target - 1]
        resume_after(paths, second, reader_gid=reader_gid)
        shutil.rmtree(paths[0].parent)
        paths[0].parent.mkdir(mode=0o700)


def test_an_error_at_any_cut_syscall_aborts_before_the_commit_and_stops_appends_after_it(paths, monkeypatch):
    calls = cut_syscalls(paths, monkeypatch)
    commit = [index for index, name in enumerate(calls, 1) if name == "replace"][1]
    for target in range(1, len(calls) + 1):
        failed, second = cut_under(paths, Faults(target, error=lambda detail: OSError(5, detail)), monkeypatch)
        assert failed == (target > commit), (target, calls[target - 1])
        assert segment_path(paths[0], 2).exists() == (target > calls.index("rename", commit) + 1)
        resume_after(paths, second)
        shutil.rmtree(paths[0].parent)
        paths[0].parent.mkdir(mode=0o700)
