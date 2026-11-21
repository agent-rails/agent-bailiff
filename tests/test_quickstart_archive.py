import json
import subprocess

import test_quickstart_stack
from test_quickstart_stack import COMPOSE_FILE, RUN_TIMEOUT_SECONDS, b, identity

pytestmark = test_quickstart_stack.pytestmark
stack = test_quickstart_stack.stack
PROFILES = ("archive",)
DOCKET = "/var/lib/bailiff/docket/docket.log"
RECEIPTS = "/var/lib/bailiff/receipts"
PINS = [arg for name in ("decide", "custodian", "control", "rule") for arg in ("--pin", f"/pins/{name}/{name}.json")]


def run(stack, *arguments):
    selected = [arg for profile in stack.profiles for arg in ("--profile", profile)]
    return subprocess.run(
        ["docker", "compose", "--file", str(COMPOSE_FILE), *selected, "run", "--rm", "-T", *arguments],
        env=stack.env,
        capture_output=True,
        text=True,
        timeout=RUN_TIMEOUT_SECONDS,
        check=False,
    )


def test_the_archiver_runs_as_its_own_uid_in_the_reader_group(stack):
    assert identity(stack.container("archiver")) == {
        (b.ARCHIVER_UID, b.ARCHIVER_UID, frozenset({b.ARCHIVER_UID, b.DOCKET_READERS_GID}))
    }


def test_the_archiver_reaches_no_network_and_writes_only_receipts(stack):
    archiver = json.loads(stack.compose("config", "--format", "json"))["services"]["archiver"]
    assert archiver["network_mode"] == "none"
    assert sorted((volume["source"], volume.get("read_only", False)) for volume in archiver["volumes"]) == [
        ("docket-data", True),
        ("docket-receipts", False),
        ("pins", True),
    ]


def test_the_archiver_refuses_an_archive_on_a_named_volume(stack):
    result = run(
        stack,
        "--no-deps",
        "archiver",
        "-m",
        "agent_bailiff.cli",
        "docket",
        "archive",
        "--docket",
        DOCKET,
        *PINS,
        "--archive",
        RECEIPTS,
        "--receipts",
        RECEIPTS,
        "--checkpoint",
        "/var/lib/bailiff/archiver/checkpoint.json",
        "--once",
    )
    assert result.returncode == 1, result.stderr
    assert f"{RECEIPTS} is on the docket's device" in result.stderr


def test_the_reader_cross_checks_the_receipts(stack):
    result = run(stack, "reader", "--receipts", RECEIPTS)
    assert result.returncode == 0, result.stderr
    assert "docket verify: 0 retained segments match their receipts\n" in result.stderr
