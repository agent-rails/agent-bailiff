import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

from test_docket import make_client, make_entry, paths, workdir  # noqa: F401
from test_docket_report import DECIDE_KEY, PINS, WRITERS, pin_files, verify  # noqa: F401

from agent_bailiff.docket import DocketError
from agent_bailiff.docket.manifest import read_docket_manifest, segment_path
from agent_bailiff.docket.report import RecordFilter, verify_records

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parent
SEGMENT_BYTES = 64 << 10
RECORDS = 2_000

SINK = """
import asyncio, os, signal, sys
from pathlib import Path
from test_docket_report import WRITERS
from agent_bailiff.docket.sink import DocketSink

async def main():
    sink = DocketSink(Path(sys.argv[1]), Path(sys.argv[2]), WRITERS, {os.getuid()}, segment_bytes=int(sys.argv[3]))
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


def socket_inode(path):
    try:
        return path.stat().st_ino
    except FileNotFoundError:
        return None


def active_bytes(paths):  # noqa: F811
    try:
        return paths[0].stat().st_size
    except FileNotFoundError:
        return 0


def start_sink_process(paths):  # noqa: F811
    stale = socket_inode(paths[1])
    environment = {**os.environ, "PYTHONPATH": os.pathsep.join([str(TESTS), str(ROOT)])}
    process = subprocess.Popen(
        [sys.executable, "-c", SINK, str(paths[0]), str(paths[1]), str(SEGMENT_BYTES)],
        cwd=ROOT,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    deadline = time.monotonic() + 10
    while socket_inode(paths[1]) in (None, stale):
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
