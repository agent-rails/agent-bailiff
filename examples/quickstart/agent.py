"""Scripted quickstart agent. It holds its own signing key and a task root, never a gitea credential, and reaches
gitea only through agentgateway. Each scenario asserts the outcome the gateway should give; the script exits 1 on any
other outcome. It shows gateway enforcement, not model behaviour."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent_warrant.identity import encode_public_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from agent_bailiff.client import BailiffClient, Holder, Outcome, PreparedCall, Refused, Result
from agent_bailiff.routes import ToolRoute, ToolRoutes

STATE = Path("/var/lib/bailiff")
AGENT_KEY = STATE / "agent" / "agent.key"
AGENT_PUBLIC_KEY = STATE / "agent-public" / "agent.pub"
TASK_FILE = STATE / "tasks" / "task.json"
GATEWAY_URL = os.environ.get("BAILIFF_GATEWAY_URL", "http://gateway:8080/mcp")
ROUTES = json.loads((Path(__file__).resolve().parent / "routes.json").read_text())["routes"]
SERVICE = "gitea"
ORG = "quickstart"
INJECTED_TOOL = "get_file_contents"


class ScenarioFailed(Exception):
    pass


@dataclass(frozen=True)
class Check:
    scenario: str
    expected: str
    observed: str
    passed: bool

    def document(self) -> dict[str, Any]:
        return {"scenario": self.scenario, "expected": self.expected, "observed": self.observed, "pass": self.passed}


def describe(outcome: Outcome) -> str:
    if isinstance(outcome, Result):
        return "error result" if outcome.is_error else "result"
    if isinstance(outcome, Refused):
        return f"refused: {outcome.reason}"
    return type(outcome).__name__


def result_text(outcome: Outcome) -> str:
    if not isinstance(outcome, Result) or outcome.is_error:
        raise ScenarioFailed(f"expected a result, got {describe(outcome)}")
    return "\n".join(item.get("text", "") for item in outcome.result.get("content", []))


def generate_key() -> str:
    if AGENT_KEY.exists():
        key = load_key()
        if AGENT_PUBLIC_KEY.read_text().strip() != encode_public_key(key.public_key()):
            raise ScenarioFailed(f"{AGENT_PUBLIC_KEY} does not match {AGENT_KEY}; run docker compose down --volumes")
        return "kept"
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()
    fd = os.open(AGENT_KEY, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "w") as target:
        target.write(raw)
        target.flush()
        os.fsync(target.fileno())
    staged = AGENT_PUBLIC_KEY.with_name(f".{AGENT_PUBLIC_KEY.name}.new")
    fd = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
    with os.fdopen(fd, "w") as target:
        target.write(encode_public_key(key.public_key()) + "\n")
    os.replace(staged, AGENT_PUBLIC_KEY)
    return "created"


def load_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(AGENT_KEY.read_text().strip()))


def open_client() -> tuple[BailiffClient, str]:
    task = json.loads(TASK_FILE.read_text())
    holder = Holder(task["task_root"], (), load_key(), task["decider_id"])
    routes = ToolRoutes([ToolRoute(**route) for route in ROUTES])
    return BailiffClient(GATEWAY_URL, holder, routes), task["task_id"]


def copy_call(call: PreparedCall) -> PreparedCall:
    return PreparedCall(call.request_id, call.tool, call.resource, call.nonce, call.headers, call.body)


def expect(scenario: str, expected: str, observed: Outcome, passed: Callable[[Outcome], bool]) -> Check:
    return Check(scenario, expected, describe(observed), passed(observed))


def refused_with(*reasons: str) -> Callable[[Outcome], bool]:
    return lambda outcome: isinstance(outcome, Refused) and outcome.reason in reasons


def refused_already(outcome: Outcome) -> bool:
    return isinstance(outcome, Refused) and outcome.reason.startswith("already_")


def is_result(outcome: Outcome) -> bool:
    return isinstance(outcome, Result) and not outcome.is_error


def run_scenarios(client: BailiffClient) -> list[Check]:
    allowed = client.prepare(SERVICE, "list_issues", {"owner": ORG, "repo": "demo"})
    retained = copy_call(allowed)
    first = client.send(allowed)
    checks = [expect("allowed call reaches gitea", "result", first, is_result)]
    number = json.loads(result_text(first))[0]["number"]
    issue = client.call(SERVICE, "issue_read", {"method": "get", "owner": ORG, "repo": "demo", "issue_number": number})
    if INJECTED_TOOL not in result_text(issue):
        raise ScenarioFailed(f"issue {number} does not carry the injected instruction to call {INJECTED_TOOL}")
    injected = client.call(SERVICE, INJECTED_TOOL, {"owner": ORG, "repo": "payroll", "path": "salaries.csv"})
    checks.append(
        expect("injected out-of-scope call refused", "refused: out_of_scope", injected, refused_with("out_of_scope"))
    )
    replayed = client.send(retained)
    checks.append(expect("replayed call refused", "refused: already_*", replayed, refused_already))
    payroll = client.call(SERVICE, "list_issues", {"owner": ORG, "repo": "payroll"})
    checks.append(expect("disclosed: list_issues on payroll stays allowed", "result", payroll, is_result))
    return checks


def run_after_revoke(client: BailiffClient) -> list[Check]:
    outcome = client.call(SERVICE, "list_issues", {"owner": ORG, "repo": "demo"})
    return [
        expect("call after operator revoke refused", "refused: chain_invalid", outcome, refused_with("chain_invalid"))
    ]


def report(task_id: str, checks: list[Check]) -> int:
    print(json.dumps({"task_id": task_id, "checks": [check.document() for check in checks]}, indent=2))
    return 0 if all(check.passed for check in checks) else 1


def run(scenarios: Callable[[BailiffClient], list[Check]]) -> int:
    client, task_id = open_client()
    try:
        return report(task_id, scenarios(client))
    finally:
        client.close()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("step", choices=["key", "run", "after-revoke"])
    args = parser.parse_args(argv)
    try:
        if args.step == "key":
            print(f"key: {generate_key()}")
            return 0
        return run(run_scenarios if args.step == "run" else run_after_revoke)
    except (ScenarioFailed, OSError, ValueError) as error:
        print(f"agent {args.step} failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
