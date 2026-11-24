import json
import os
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest
import test_quickstart_stack

pytestmark = [
    *test_quickstart_stack.pytestmark,
    pytest.mark.skipif(
        os.environ.get("AGENT_BAILIFF_TEST_QUICKSTART_PROXY") != "1",
        reason="set AGENT_BAILIFF_TEST_QUICKSTART_PROXY=1 to record the quickstart perceived-latency benchmark",
    ),
]
stack = test_quickstart_stack.stack
PROFILES = ("gitea",)

BENCHMARKS = Path(__file__).resolve().parents[1] / "benchmarks"
CALLS = 60
OUT_OF_SCOPE_PERCENT = 20
ACCEPTED = {"result", "refused: out_of_scope"}


def docker_version():
    return subprocess.run(
        ["docker", "version", "--format", "{{.Server.Version}}"], capture_output=True, text=True, check=True
    ).stdout.strip()


def test_quickstart_proxy_latency(stack):
    stack.compose("run", "--rm", "--no-deps", "gitea-task", "/app/quickstart/bootstrap.py", "issue-load")
    arguments = ["--calls", str(CALLS), "--out-of-scope-percent", str(OUT_OF_SCOPE_PERCENT)]
    report = json.loads(
        stack.compose(
            "--profile",
            "agent",
            "run",
            "--rm",
            "--no-deps",
            "--entrypoint",
            "python",
            "agent",
            "/app/quickstart/proxy_bench.py",
            *arguments,
        )
    )
    assert report["calls"] == CALLS
    assert set(report["outcomes"]) <= ACCEPTED, report["outcomes"]
    assert report["refusals_per_100_calls"] == OUT_OF_SCOPE_PERCENT, report
    now = datetime.now(UTC)
    document = {
        "recorded_at": now.isoformat(timespec="seconds"),
        "host": {"machine": platform.machine(), "system": platform.system(), "docker": docker_version()},
        "tool": "list_issues",
        "measured_at": "the agent container, over the stdio pipes of `agent-bailiff proxy run`",
        **report,
    }
    BENCHMARKS.mkdir(exist_ok=True)
    (BENCHMARKS / f"proxy-{now:%Y-%m-%d}.json").write_text(json.dumps(document, indent=2) + "\n")
