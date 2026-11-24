"""Quickstart perceived-latency benchmark. It plays an MCP host: it starts `agent-bailiff proxy run` as a child
process, speaks newline-delimited JSON-RPC to it over stdio (initialize, tools/list, then tools/call), and times each
exchange as the agent would experience it. A scripted share of the calls is out of scope and must be refused."""

from __future__ import annotations

import argparse
import json
import os
import re
import statistics
import subprocess
import sys
import tempfile
import time
from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from typing import Any, BinaryIO

from agent_warrant.task_root import TaskRoot
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_bailiff.client.client import refusal_reason
from agent_bailiff.proxy.agent_key import KEY_DIR_MODE, KEY_MODE, KEY_SUFFIX
from agent_bailiff.task.task_file import TaskFile

STATE = Path("/var/lib/bailiff")
AGENT_KEY = STATE / "agent" / "agent.key"
LOAD_FILE = STATE / "tasks" / "load.json"
ROUTES_FILE = Path(__file__).resolve().parent / "upstreams" / "gitea-routes.json"
GATEWAY_URL = os.environ.get("BAILIFF_GATEWAY_URL", "http://gateway:8080/mcp")
ORG = "quickstart"
TOOL = "list_issues"
IN_SCOPE = {"owner": ORG, "repo": "demo"}
OUT_OF_SCOPE = {"owner": ORG, "repo": "payroll"}
PROTOCOL_VERSION = "2025-06-18"
SHUTDOWN_SECONDS = 30
RETRIES_LOGGED = re.compile(r"gateway client closed after (\d+) setup retries")


class BenchFailed(Exception):
    pass


def out_of_scope_calls(calls: int, percent: int) -> list[bool]:
    return [(index + 1) * percent // 100 != index * percent // 100 for index in range(calls)]


def prepare_state(task: dict[str, str], key: Ed25519PrivateKey, directory: Path) -> tuple[Path, Path]:
    task_root = TaskRoot.decode(task["task_root"])
    key_dir = directory / "keys"
    key_dir.mkdir(mode=KEY_DIR_MODE)
    key_dir.chmod(KEY_DIR_MODE)
    fd = os.open(key_dir / (task_root.subject + KEY_SUFFIX), os.O_WRONLY | os.O_CREAT | os.O_EXCL, KEY_MODE)
    with os.fdopen(fd, "wb") as target:
        target.write(key.private_bytes_raw())
    task_file = directory / "task.json"
    task_file.write_bytes(TaskFile(task_root, task["decider_id"]).encode())
    return task_file, key_dir


class Host:
    def __init__(self, command: Sequence[str], stderr: BinaryIO) -> None:
        self._process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr)
        self._next_id = 1

    def request(self, method: str, params: dict[str, Any]) -> tuple[float, dict[str, Any]]:
        request_id = self._next_id
        self._next_id += 1
        began = time.perf_counter()
        self._send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        line = self._stdout().readline()
        elapsed = time.perf_counter() - began
        if not line:
            raise BenchFailed(f"the proxy closed its output before answering {method}")
        message = json.loads(line)
        if message.get("id") != request_id or "result" not in message:
            raise BenchFailed(f"{method} returned {str(message)[:200]}")
        return elapsed, message["result"]

    def notify(self, method: str) -> None:
        self._send({"jsonrpc": "2.0", "method": method})

    def finish(self) -> int:
        self._stdin().close()
        try:
            return self._process.wait(timeout=SHUTDOWN_SECONDS)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait()
            raise BenchFailed(f"the proxy did not exit within {SHUTDOWN_SECONDS}s of EOF") from None

    def abort(self) -> None:
        if self._process.poll() is None:
            self._process.kill()
            self._process.wait()

    def _send(self, message: dict[str, Any]) -> None:
        stdin = self._stdin()
        stdin.write(json.dumps(message).encode() + b"\n")
        stdin.flush()

    def _stdin(self) -> BinaryIO:
        assert self._process.stdin is not None
        return self._process.stdin

    def _stdout(self) -> BinaryIO:
        assert self._process.stdout is not None
        return self._process.stdout


def classify(result: dict[str, Any]) -> str:
    reason = refusal_reason(result)
    if reason is not None:
        return f"refused: {reason}"
    return "error result" if result.get("isError") is True else "result"


def percentile(latencies: list[float], fraction: float) -> float:
    return statistics.quantiles(latencies, n=100, method="inclusive")[round(fraction * 100) - 1]


def milliseconds(seconds: float) -> float:
    return round(seconds * 1000, 1)


def summarize(
    setup: dict[str, float], samples: list[tuple[float, str, bool]], retries: int, percent: int
) -> dict[str, Any]:
    first, later = samples[0], samples[1:]
    latencies = [latency for latency, _, _ in later]
    outcomes = Counter(outcome for _, outcome, _ in samples)
    refusals = sum(count for outcome, count in outcomes.items() if outcome.startswith("refused"))
    allowed = [latency for latency, _, scripted in later if not scripted]
    refused = [latency for latency, _, scripted in later if scripted]
    return {
        "calls": len(samples),
        "scripted_out_of_scope_percent": percent,
        "initialize_ms": milliseconds(setup["initialize"]),
        "tools_list_ms": milliseconds(setup["tools_list"]),
        "first_call_ms": milliseconds(first[0]),
        "warm_calls": len(later),
        "p50_ms": milliseconds(percentile(latencies, 0.50)),
        "p99_ms": milliseconds(percentile(latencies, 0.99)),
        "in_scope_p50_ms": milliseconds(statistics.median(allowed)),
        "out_of_scope_p50_ms": milliseconds(statistics.median(refused)),
        "outcomes": dict(sorted(outcomes.items())),
        "refusals_per_100_calls": round(refusals * 100 / len(samples), 1),
        "setup_retries": retries,
        "retries_per_call": round(retries / len(samples), 4),
    }


def retries_logged(stderr: bytes) -> int:
    found = RETRIES_LOGGED.findall(stderr.decode("utf-8", "replace"))
    if not found:
        raise BenchFailed("the proxy did not log its setup retries on close")
    return sum(int(count) for count in found)


def run_session(command: Sequence[str], calls: int, percent: int) -> dict[str, Any]:
    scripted = out_of_scope_calls(calls, percent)
    if scripted[0] or all(scripted[1:]) or not any(scripted[1:]):
        raise BenchFailed(f"{calls} calls at {percent}% out of scope leave no warm call of one of the two kinds")
    with tempfile.TemporaryFile() as stderr:
        host = Host(command, stderr)
        try:
            setup = {
                "initialize": host.request("initialize", {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}})[0]
            }
            host.notify("notifications/initialized")
            elapsed, listed = host.request("tools/list", {})
            setup["tools_list"] = elapsed
            if TOOL not in {tool["name"] for tool in listed["tools"]}:
                raise BenchFailed(f"tools/list did not list {TOOL}")
            samples = []
            for out in scripted:
                arguments = OUT_OF_SCOPE if out else IN_SCOPE
                elapsed, result = host.request("tools/call", {"name": TOOL, "arguments": arguments})
                samples.append((elapsed, classify(result), out))
            status = host.finish()
        except BaseException:
            host.abort()
            raise
        if status != 0:
            raise BenchFailed(f"the proxy exited with status {status}")
        stderr.seek(0)
        retries = retries_logged(stderr.read())
    return summarize(setup, samples, retries, percent)


def run_bench(calls: int, percent: int) -> dict[str, Any]:
    document = json.loads(LOAD_FILE.read_text())
    if calls > document["budget"]:
        raise BenchFailed(f"{calls} calls exceed the {document['budget']} call budget of a load task")
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(AGENT_KEY.read_text().strip()))
    with tempfile.TemporaryDirectory() as directory:
        task_file, key_dir = prepare_state(document["tasks"][0], key, Path(directory))
        command = [
            sys.executable,
            "-m",
            "agent_bailiff.cli",
            "proxy",
            "run",
            "--task-file",
            str(task_file),
            "--key-dir",
            str(key_dir),
            "--gateway-url",
            GATEWAY_URL,
            "--routes",
            str(ROUTES_FILE),
        ]
        return run_session(command, calls, percent)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--calls", type=int, default=100)
    parser.add_argument("--out-of-scope-percent", type=int, default=20)
    args = parser.parse_args(argv)
    if args.calls < 3 or not 1 <= args.out_of_scope_percent <= 90:
        parser.error("--calls must be at least 3 and --out-of-scope-percent between 1 and 90")
    try:
        print(json.dumps(run_bench(args.calls, args.out_of_scope_percent)))
        return 0
    except (BenchFailed, OSError, ValueError, KeyError) as error:
        print(f"proxy bench failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
