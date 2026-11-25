import json

import test_quickstart_stack
from test_quickstart_stack import b

from agent_bailiff.docket.entry import ENTRY_TYP
from agent_bailiff.docket.grant import GRANT_TYP

pytestmark = test_quickstart_stack.pytestmark
stack = test_quickstart_stack.stack
PROFILES = ("gitea",)

DECIDE = b.NAMES["decide"]
CONTROL = b.NAMES["control"]
GRANTER = b.NAMES["issuer-docket"]
DOCKET = "/var/lib/bailiff/docket/docket.log"
GRANTS_SCRIPT = """
import json, os, subprocess, sys
sys.path.insert(0, "/app/quickstart")
import bootstrap
os.mkdir("/tmp/grants", 0o700)
fd = os.open("/tmp/grants/issuers.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
with os.fdopen(fd, "w") as issuers:
    json.dump(bootstrap.issuers(), issuers)
command = [sys.executable, "-m", "agent_bailiff.cli", "docket", "grants", "--issuers", "/tmp/grants/issuers.json"]
sys.exit(subprocess.run([*command, "--json", *sys.argv[1:]]).returncode)
"""
PAYROLL = "gitea/repos/quickstart/payroll"
SCENARIOS = {
    "allowed call reaches gitea": "result",
    "injected out-of-scope call refused": "refused: out_of_scope",
    "replayed call refused": "refused: already_issued",
    "other repository refused": "refused: out_of_scope",
    "disclosed: unrouted write tool refused": "refused: unknown_tool",
}


def agent(stack, step):
    report = json.loads(stack.compose("--profile", "agent", "run", "--rm", "--no-deps", "agent", step))
    return report["task_id"], {check["scenario"]: check["observed"] for check in report["checks"]}


def docket_rows(stack, task_id):
    reader = ["--profile", "operator", "run", "--rm", "--no-deps", "-T", "reader"]
    output = stack.compose(*reader, "--task", task_id, "--json")
    return [json.loads(line) for line in output.splitlines()]


def verified_rows(stack, task_id):
    return [row for row in docket_rows(stack, task_id) if row["typ"] == ENTRY_TYP]


def granted_roots(stack):
    pins = [
        arg
        for component in b.WRITERS
        for arg in ("--decide-pin" if component == "decide" else "--pin", b.pin_path(component))
    ]
    reader = ["--profile", "operator", "run", "--rm", "--no-deps", "-T", "--entrypoint", "python", "reader"]
    output = stack.compose(
        *reader, "-c", GRANTS_SCRIPT, "--docket", DOCKET, *map(str, pins), "--grant-pin", str(b.GRANT_PIN)
    )
    return [json.loads(line) for line in output.splitlines()]


def task_rows(stack):
    pins = [
        "--decide-pin", b.pin_path("decide"), "--custodian-pin", b.pin_path("custodian"),
        "--control-pin", b.pin_path("control"), "--control-pin", b.pin_path("rule"), "--grant-pin", b.GRANT_PIN,
    ]  # fmt: skip
    reader = ["--profile", "operator", "run", "--rm", "--no-deps", "-T", "--entrypoint", "python", "reader"]
    output = stack.compose(
        *reader, "-m", "agent_bailiff.cli", "docket", "tasks", "--docket", DOCKET, *map(str, pins),
        "--issuers", str(b.READER_ISSUERS), "--json",
    )  # fmt: skip
    return [json.loads(line) for line in output.splitlines()]


def revoke_task(stack, task_id):
    rows = task_rows(stack)
    [record] = [
        row["record"]
        for row in rows
        if row["tenant"] == b.TENANT and row["task"] == task_id and row["root_status"] == "verified"
    ]
    arguments = ["--config", "/var/lib/bailiff/control/config.json", "--actor", "operator", "--level", "task"]
    output = stack.compose(
        "--profile", "operator", "run", "--rm", "--no-deps", "-T", "control", "revoke", *arguments, "--record", "-",
        stdin=record + "\n",
    )  # fmt: skip
    return json.loads(output)


def test_quickstart(stack):
    task_id, observed = agent(stack, "run")
    assert observed == SCENARIOS
    revoked = revoke_task(stack, task_id)
    assert revoked["action"] == "revoke" and revoked["handles"] == {"task": task_id, "tenant": b.TENANT}
    after_task, after = agent(stack, "after-revoke")
    assert after_task == task_id
    assert after == {"call after revoke refused": "refused: chain_invalid"}
    [grant] = [row for row in docket_rows(stack, task_id) if row["typ"] == GRANT_TYP]
    assert (grant["writer"], grant["line"], grant["note"]) == (GRANTER, 1, "task grant")
    rows = [row["entry"] | {"writer": row["writer"]} for row in verified_rows(stack, task_id)]
    decisions = [(row["writer"], row["decision"], row["tool"], row["reason"]) for row in rows]
    resources = {(row["decision"], row["tool"], row.get("resource"), row["reason"]) for row in rows}
    assert ("refuse", "gitea.contents.read", f"{PAYROLL}/contents", "out_of_scope") in resources
    assert ("refuse", "gitea.issues.list", f"{PAYROLL}/issues", "out_of_scope") in resources
    assert (DECIDE, "refuse", "gitea.issues.list", "already_issued") in decisions
    assert (CONTROL, "revoke", None, "task") in decisions
    assert sum(decision[:2] == (DECIDE, "allow") for decision in decisions) == 2
    assert not any(decision[2] == "gitea.contents.read" and decision[1] != "refuse" for decision in decisions)


def test_docket_grants_lists_the_issued_task_as_granted(stack):
    task = stack.probe("import sys; sys.stdout.write(open('/v/tasks/task.json').read())")
    rows = {row["task"]: row for row in granted_roots(stack)}
    assert rows[task["task_id"]]["status"] == "granted"
    assert rows[task["task_id"]]["issuer"] == b.NAMES["issuer"]
