import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest
import test_quickstart_stack
from test_quickstart_stack import b
from test_quickstart_trace import wait_for_export

pytestmark = [
    *test_quickstart_stack.pytestmark,
    pytest.mark.skipif(
        os.environ.get("AGENT_BAILIFF_TEST_QUICKSTART_LOAD") != "1",
        reason="set AGENT_BAILIFF_TEST_QUICKSTART_LOAD=1 to record the quickstart concurrency baseline",
    ),
]
stack = test_quickstart_stack.stack
PROFILES = ("gitea", "trace")

BENCHMARKS = Path(__file__).resolve().parents[1] / "benchmarks"
CLIENTS = (1, 4, 16, 32)
CALLS_PER_CLIENT = 20
ACCEPTED = {"result", "refused: docket_unavailable"}
MAX_DOCKET_UNAVAILABLE_RATE = 0.01
LOGGED_SERVICES = ("decide", "custodian", "docket", "gateway")
LOGGED_LEVELS = (" WARNING ", " ERROR ", "\twarn\t", "\terror\t", "Z Error: ", "Z Caused by:", "(os error ")
MAX_LOGGED_LINES = 60


def added_latency(level, direct):
    return {
        "baseline_p50_ms": direct["p50_ms"],
        "baseline_p99_ms": direct["p99_ms"],
        "added_p50_ms": round(level["p50_ms"] - direct["p50_ms"], 1),
        "added_p99_ms": round(level["p99_ms"] - direct["p99_ms"], 1),
    }


def measure(stack, clients):
    stack.compose("run", "--rm", "--no-deps", "gitea-task", "/app/quickstart/bootstrap.py", "issue-load")
    arguments = ["--clients", str(clients), "--calls", str(CALLS_PER_CLIENT)]
    direct = json.loads(
        stack.compose("run", "--rm", "--no-deps", "bootstrap", "/app/quickstart/baseline.py", *arguments)
    )
    level = json.loads(stack.compose("--profile", "agent", "run", "--rm", "--no-deps", "agent", "load", *arguments))
    export = wait_for_export(stack)
    return {
        **level,
        **added_latency(level, direct),
        "baseline_outcomes": direct["outcomes"],
        "exporter_backlog_records": export["backlog"],
        "exporter_catchup_seconds": round(export["seconds"], 1),
    }


def service_problems(stack):
    output = stack.compose("logs", "--no-color", "--timestamps", *LOGGED_SERVICES)
    lines = [line for line in output.splitlines() if any(level in line for level in LOGGED_LEVELS)]
    return "\n".join(lines[-MAX_LOGGED_LINES:])


def docker_version():
    return subprocess.run(
        ["docker", "version", "--format", "{{.Server.Version}}"], capture_output=True, text=True, check=True
    ).stdout.strip()


def test_quickstart_load(stack):
    assert max(CLIENTS) <= b.LOAD_TASKS and CALLS_PER_CLIENT <= b.ISSUER_MAX_BUDGET
    levels = [measure(stack, clients) for clients in CLIENTS]
    for level in levels:
        assert level["calls"] == level["clients"] * CALLS_PER_CLIENT
        assert level["baseline_outcomes"] == {"result": level["calls"]}, level
        assert set(level["outcomes"]) <= ACCEPTED, f"{level}\n{service_problems(stack)}"
        assert level["docket_unavailable_rate"] <= MAX_DOCKET_UNAVAILABLE_RATE, f"{level}\n{service_problems(stack)}"
    now = datetime.now(UTC)
    baseline = {
        "recorded_at": now.isoformat(timespec="seconds"),
        "host": {"machine": platform.machine(), "system": platform.system(), "docker": docker_version()},
        "calls_per_client": CALLS_PER_CLIENT,
        "tool": "list_issues",
        "levels": levels,
    }
    BENCHMARKS.mkdir(exist_ok=True)
    (BENCHMARKS / f"quickstart-{now:%Y-%m-%d}.json").write_text(json.dumps(baseline, indent=2) + "\n")
