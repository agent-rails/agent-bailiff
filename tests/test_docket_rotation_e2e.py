import os
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

from test_docket import make_client, make_entry, paths, workdir  # noqa: F401
from test_docket_report import DECIDE_KEY, PINS, WRITERS, pin_files, verify  # noqa: F401

from agent_bailiff.docket import DocketError
from agent_bailiff.docket.archiver import DocketArchiver
from agent_bailiff.docket.follower import DocketFollower
from agent_bailiff.docket.manifest import ManifestInvalid, read_docket_manifest, segment_path
from agent_bailiff.docket.report import RecordFilter, SeedCheck, verify_records
from agent_bailiff.docket.sink import build_kid_index

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parent
SEGMENT_BYTES = 64 << 10
RECORDS = 2_000

SINK = """
import asyncio, os, signal, sys
from pathlib import Path
from test_docket_report import WRITERS
from agent_bailiff.docket.retention import Retention
from agent_bailiff.docket.sink import DocketSink

async def main():
    segment_bytes = int(sys.argv[3])
    options = {}
    if len(sys.argv) > 4:
        retention = Retention(Path(sys.argv[4]), os.geteuid(), 2 * segment_bytes, 86400)
        options = {"reader_gid": os.getegid(), "retention": retention}
    options["segment_bytes"] = segment_bytes
    sink = DocketSink(Path(sys.argv[1]), Path(sys.argv[2]), WRITERS, {os.getuid()}, **options)
    stop = asyncio.Event()
    for number in (signal.SIGTERM, signal.SIGINT):
        asyncio.get_running_loop().add_signal_handler(number, stop.set)
    await sink.start()
    try:
        await stop.wait()
    finally:
        await sink.close()

asyncio.run(main())
"""


def listening(path):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        try:
            connection.connect(str(path))
        except (FileNotFoundError, ConnectionRefusedError):
            return False
    return True


def active_bytes(paths):  # noqa: F811
    try:
        return paths[0].stat().st_size
    except FileNotFoundError:
        return 0


def start_sink_process(paths, *options):  # noqa: F811
    environment = {**os.environ, "PYTHONPATH": os.pathsep.join([str(TESTS), str(ROOT)])}
    process = subprocess.Popen(
        [sys.executable, "-c", SINK, str(paths[0]), str(paths[1]), str(SEGMENT_BYTES), *map(str, options)],
        cwd=ROOT,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    deadline = time.monotonic() + 10
    while not listening(paths[1]):
        assert process.poll() is None, process.communicate()
        assert time.monotonic() < deadline, f"{paths[1]} did not appear"
        time.sleep(0.02)
    return process


def stop_sink_process(process):
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
    assert process.wait(10) in (0, -signal.SIGKILL), process.communicate()


def append_until_refused(client, first, last):
    acked = []
    for number in range(first, last + 1):
        try:
            acked.append(client.append(make_entry(number)))
        except DocketError:
            return acked
    return acked


def test_a_sink_killed_mid_load_restarts_on_its_segments_without_losing_an_acknowledged_record(
    paths,  # noqa: F811
    pin_files,  # noqa: F811
    capsys,
):
    process = start_sink_process(paths)
    client = make_client(paths, "decide", PINS["decide"].kid, DECIDE_KEY)
    try:
        killer = threading.Thread(target=kill_after_a_cut, args=(paths, process))
        killer.start()
        acked = append_until_refused(client, 1, RECORDS)
        killer.join(30)
        assert process.wait(10) == -signal.SIGKILL
        assert len(acked) < RECORDS
        process = start_sink_process(paths)
        acked += append_until_refused(client, len(acked) + 1, RECORDS)
    finally:
        client.close()
        stop_sink_process(process)
    assert len(acked) >= RECORDS - 1
    manifest = read_docket_manifest(paths[0])
    assert len(manifest.segments) > 2
    assert all(segment_path(paths[0], entry.segment).stat().st_size == entry.size for entry in manifest.segments)
    seen = []
    report = verify_records(paths[0], WRITERS, RecordFilter(), lambda line: seen.append(line.record.hash))
    assert (report.ok, report.entries) == (True, len(seen))
    assert {record.hash for record in acked} <= set(seen)
    assert report.heads["decide"].hash == acked[-1].hash
    code, _, error = verify(DocketFile(paths[0]), pin_files, capsys=capsys, writers=("decide",))
    assert code == 0, error


class ArchiverThread:
    def __init__(self, paths, archive, receipts, state):  # noqa: F811
        self.stop = threading.Event()
        self.errors = []
        self.archiver = DocketArchiver(
            paths[0],
            build_kid_index(WRITERS),
            archive,
            receipts,
            state / "checkpoint.json",
            poll_interval=0.02,
            device_of=lambda path: -1,
        )
        self.thread = threading.Thread(target=self._run)
        self.thread.start()

    def _run(self):
        try:
            self.archiver.run(self.stop, follow=True)
        except Exception as exc:
            self.errors.append(exc)

    def close(self):
        self.stop.set()
        self.thread.join(30)
        assert not self.thread.is_alive()
        assert self.errors == []


def archive_layout(root):
    made = []
    for name, mode in (("archive", 0o750), ("receipts", 0o750), ("archiver", 0o700), ("follower", 0o700)):
        path = root / name
        path.mkdir()
        os.chown(path, -1, os.getegid())
        os.chmod(path, mode)
        made.append(path)
    return made


def test_a_sink_killed_after_a_removal_restarts_and_the_archive_keeps_every_acknowledged_record(
    paths,  # noqa: F811
    pin_files,  # noqa: F811
    capsys,
):
    archive, receipts, state, follower = archive_layout(paths[0].parent)
    process = start_sink_process(paths, receipts)
    archiver = ArchiverThread(paths, archive, receipts, state)
    client = make_client(paths, "decide", PINS["decide"].kid, DECIDE_KEY)
    try:
        killer = threading.Thread(target=kill_after_a_removal, args=(paths, process))
        killer.start()
        acked = append_until_refused(client, 1, RECORDS)
        killer.join(30)
        assert process.wait(10) == -signal.SIGKILL
        assert len(acked) < RECORDS
        process = start_sink_process(paths, receipts)
        acked += append_until_refused(client, len(acked) + 1, RECORDS)
    finally:
        client.close()
        stop_sink_process(process)
        archiver.close()
    assert len(acked) >= RECORDS - 1
    manifest = read_docket_manifest(paths[0])
    assert manifest.base is not None and manifest.base.segment > 1
    assert not segment_path(paths[0], manifest.base.segment - 1).exists()
    seen = []
    seeds = SeedCheck(receipts)
    report = verify_records(
        paths[0], WRITERS, RecordFilter(), lambda line: seen.append(line.record.hash), archive=archive, seeds=seeds
    )
    assert (report.ok, report.entries, seeds.differences) == (True, len(seen), [])
    assert {record.hash for record in acked} <= set(seen)
    assert seeds.base == manifest.base.segment
    retained = []
    verify_records(paths[0], WRITERS, RecordFilter(), lambda line: retained.append(line.record.hash))
    assert retained == seen[manifest.base.entries :]
    code, _, error = verify(
        DocketFile(paths[0]),
        pin_files,
        "--archive",
        str(archive),
        "--receipts",
        str(receipts),
        capsys=capsys,
        writers=("decide",),
    )
    assert code == 0, error
    assert f"the base matches removed segment {manifest.base.segment}" in error
    lines = []
    DocketFollower(
        paths[0],
        build_kid_index(WRITERS),
        follower / "checkpoint.json",
        lambda batch, stop: lines.extend(line.line for line in batch),
        batch_size=256,
        archive=archive,
    ).run(threading.Event(), follow=False)
    assert lines == list(range(1, report.entries + 1))


def kill_after_a_removal(paths, process):  # noqa: F811
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            removed = read_docket_manifest(paths[0]).base is not None
        except (FileNotFoundError, ManifestInvalid):
            removed = False
        if removed and active_bytes(paths) > SEGMENT_BYTES // 2:
            break
        time.sleep(0.001)
    process.send_signal(signal.SIGKILL)


class DocketFile:
    def __init__(self, path):
        self.path = path


def kill_after_a_cut(paths, process):  # noqa: F811
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if segment_path(paths[0], 2).exists() and active_bytes(paths) > SEGMENT_BYTES // 2:
            break
        time.sleep(0.001)
    process.send_signal(signal.SIGKILL)
