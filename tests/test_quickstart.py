import json

import test_quickstart_stack
from test_quickstart_stack import b

pytestmark = test_quickstart_stack.pytestmark
stack = test_quickstart_stack.stack

DECIDE = b.NAMES["decide"]
CONTROL = b.NAMES["control"]
SCENARIOS = {
    "allowed call reaches gitea": "result",
    "injected out-of-scope call refused": "refused: out_of_scope",
    "replayed call refused": "refused: already_issued",
    "disclosed: list_issues on payroll stays allowed": "result",
    "disclosed: unrouted write tool refused": "refused: unknown_tool",
}


def agent(stack, step):
    report = json.loads(stack.compose("--profile", "agent", "run", "--rm", "--no-deps", "agent", step))
    return report["task_id"], {check["scenario"]: check["observed"] for check in report["checks"]}


def verified_rows(stack, task_id):
    reader = ["--profile", "operator", "run", "--rm", "--no-deps", "-T", "reader"]
    output = stack.compose(*reader, "--task", task_id, "--json")
    return [json.loads(line) for line in output.splitlines()]


def revoke_task(stack, task_id):
    allows = [
        row["token"]
        for row in verified_rows(stack, task_id)
        if row["writer"] == DECIDE and row["entry"]["decision"] == "allow"
    ]
    arguments = ["--config", "/var/lib/bailiff/control/config.json", "--actor", "operator", "--level", "task"]
    output = stack.compose(
        "--profile", "operator", "run", "--rm", "--no-deps", "-T", "control", "revoke", *arguments, "--record", "-",
        stdin=allows[-1] + "\n",
    )  # fmt: skip
    return json.loads(output)


def test_quickstart(stack):
    task_id, observed = agent(stack, "run")
    assert observed == SCENARIOS
    revoked = revoke_task(stack, task_id)
    assert revoked["action"] == "revoke" and revoked["handles"] == {"task": task_id, "tenant": b.TENANT}
    after_task, after = agent(stack, "after-revoke")
    assert after_task == task_id
    assert after == {"call after operator revoke refused": "refused: chain_invalid"}
    decisions = [
        (row["writer"], row["entry"]["decision"], row["entry"]["tool"], row["entry"]["reason"])
        for row in verified_rows(stack, task_id)
    ]
    assert (DECIDE, "refuse", "gitea.contents.read", "out_of_scope") in decisions
    assert (DECIDE, "refuse", "gitea.issues.list", "already_issued") in decisions
    assert (CONTROL, "revoke", None, "task") in decisions
    assert sum(decision[:2] == (DECIDE, "allow") for decision in decisions) == 3
    assert not any(decision[2] == "gitea.contents.read" and decision[1] != "refuse" for decision in decisions)
