import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest
import test_quickstart_stack
from test_quickstart_stack import b

pytestmark = [
    *test_quickstart_stack.pytestmark,
    pytest.mark.skipif(
        os.environ.get("AGENT_BAILIFF_TEST_QUICKSTART_LOAD") != "1",
        reason="set AGENT_BAILIFF_TEST_QUICKSTART_LOAD=1 to record the quickstart concurrency baseline",
    ),
]
stack = test_quickstart_stack.stack

BENCHMARKS = Path(__file__).resolve().parents[1] / "benchmarks"
CLIENTS = (1, 4, 16, 32)
CALLS_PER_CLIENT = 20
ACCEPTED = {"result", "refused: docket_unavailable"}


def measure(stack, clients):
    stack.compose("run", "--rm", "--no-deps", "task-issuer", "/app/quickstart/bootstrap.py", "issue-load")
    arguments = ["--clients", str(clients), "--calls", str(CALLS_PER_CLIENT)]
    return json.loads(stack.compose("--profile", "agent", "run", "--rm", "--no-deps", "agent", "load", *arguments))


def docker_version():
    return subprocess.run(
        ["docker", "version", "--format", "{{.Server.Version}}"], capture_output=True, text=True, check=True
    ).stdout.strip()


def test_quickstart_load(stack):
    assert max(CLIENTS) <= b.LOAD_TASKS and CALLS_PER_CLIENT <= b.ISSUER_MAX_BUDGET
    levels = [measure(stack, clients) for clients in CLIENTS]
    for level in levels:
        assert level["calls"] == level["clients"] * CALLS_PER_CLIENT
        assert set(level["outcomes"]) <= ACCEPTED, level
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
