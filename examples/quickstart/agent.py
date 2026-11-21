"""Scripted quickstart agent. It holds its own signing key and a task root, never a gitea credential, and reaches
gitea only through agentgateway. Each scenario asserts the outcome the gateway should give; the script exits 1 on any
other outcome. It shows gateway enforcement, not model behaviour."""

from __future__ import annotations

import argparse
import http.client
import json
import os
import statistics
import sys
import threading
import time
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from agent_warrant.identity import encode_public_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from agent_bailiff.client import BailiffClient, Holder, Outcome, PreparedCall, Refused, Result
from agent_bailiff.routes import ToolRoute, ToolRoutes

STATE = Path("/var/lib/bailiff")
AGENT_KEY = STATE / "agent" / "agent.key"
AGENT_PUBLIC_KEY = STATE / "agent-public" / "agent.pub"
TASK_FILE = STATE / "tasks" / "task.json"
LOAD_FILE = STATE / "tasks" / "load.json"
GATEWAY_URL = os.environ.get("BAILIFF_GATEWAY_URL", "http://gateway:8080/mcp")
ROUTES = json.loads((Path(__file__).resolve().parent / "routes.json").read_text())["routes"]
SERVICE = "gitea"
ORG = "quickstart"
INJECTED_TOOL = "get_file_contents"
UNROUTED = {"service": SERVICE, "name": "issue_write", "tool": "gitea.issues.write", "resource": "gitea/issues"}
RAW_LIMIT_BYTES = 4 * 1024 * 1024
RAW_TIMEOUT_SECONDS = 30
RAW_CASES: tuple[tuple[str, str, dict[str, Any]], ...] = (
    ("allowed", "list_issues", {"owner": ORG, "repo": "demo"}),
    ("missing issue", "issue_read", {"method": "get", "owner": ORG, "repo": "demo", "issue_number": 999999}),
    ("missing repo", "list_issues", {"owner": ORG, "repo": "missing"}),
    ("injected", INJECTED_TOOL, {"owner": ORG, "repo": "payroll", "path": "salaries.csv"}),
    ("unrouted", UNROUTED["name"], {"method": "create", "owner": ORG, "repo": "demo", "title": "written by the agent"}),
)


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


def client_for(task: dict[str, str], key: Ed25519PrivateKey, extra: Sequence[dict[str, str]] = ()) -> BailiffClient:
    holder = Holder(task["task_root"], (), key, task["decider_id"])
    return BailiffClient(GATEWAY_URL, holder, ToolRoutes([ToolRoute(**route) for route in [*ROUTES, *extra]]))


def open_client(extra: Sequence[dict[str, str]] = ()) -> tuple[BailiffClient, str]:
    task = json.loads(TASK_FILE.read_text())
    return client_for(task, load_key(), extra), task["task_id"]


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


def run_injection(client: BailiffClient) -> tuple[list[Check], PreparedCall]:
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
    return checks, retained


def run_inject(client: BailiffClient) -> list[Check]:
    return run_injection(client)[0]


def run_scenarios(client: BailiffClient) -> list[Check]:
    checks, retained = run_injection(client)
    replayed = client.send(retained)
    checks.append(expect("replayed call refused", "refused: already_*", replayed, refused_already))
    payroll = client.call(SERVICE, "list_issues", {"owner": ORG, "repo": "payroll"})
    checks.append(expect("disclosed: list_issues on payroll stays allowed", "result", payroll, is_result))
    arguments = {"method": "create", "owner": ORG, "repo": "demo", "title": "written by the agent"}
    unrouted = client.call(SERVICE, UNROUTED["name"], arguments)
    unknown = refused_with("unknown_tool")
    checks.append(expect("disclosed: unrouted write tool refused", "refused: unknown_tool", unrouted, unknown))
    return checks


def run_after_revoke(client: BailiffClient) -> list[Check]:
    outcome = client.call(SERVICE, "list_issues", {"owner": ORG, "repo": "demo"})
    return [expect("call after revoke refused", "refused: chain_invalid", outcome, refused_with("chain_invalid"))]


def percentile(latencies: list[float], fraction: float) -> float:
    return statistics.quantiles(latencies, n=100, method="inclusive")[round(fraction * 100) - 1]


def run_load(clients: int, calls: int) -> dict[str, Any]:
    document = json.loads(LOAD_FILE.read_text())
    if clients > len(document["tasks"]) or calls > document["budget"]:
        raise ScenarioFailed(f"{clients} clients of {calls} calls exceed the {len(document['tasks'])} load tasks")
    key = load_key()
    start = threading.Barrier(clients + 1)
    samples: list[list[tuple[float, str]]] = [[] for _ in range(clients)]
    errors: list[BaseException] = []

    def drive(index: int) -> None:
        try:
            client = client_for(document["tasks"][index], key)
            client.list_tools()
            start.wait()
            for _ in range(calls):
                began = time.perf_counter()
                outcome = client.call(SERVICE, "list_issues", {"owner": ORG, "repo": "demo"})
                samples[index].append((time.perf_counter() - began, describe(outcome)))
            client.close()
        except BaseException as error:
            errors.append(error)
            start.abort()

    threads = [threading.Thread(target=drive, args=(index,)) for index in range(clients)]
    for thread in threads:
        thread.start()
    start.wait()
    began = time.perf_counter()
    for thread in threads:
        thread.join()
    elapsed = time.perf_counter() - began
    if errors:
        raise ScenarioFailed(f"a load client failed: {errors[0]!r}")
    latencies = [latency for client in samples for latency, _ in client]
    outcomes = Counter(outcome for client in samples for _, outcome in client)
    return {
        "clients": clients,
        "calls": len(latencies),
        "seconds": round(elapsed, 3),
        "calls_per_second": round(len(latencies) / elapsed, 1),
        "p50_ms": round(percentile(latencies, 0.50) * 1000, 1),
        "p99_ms": round(percentile(latencies, 0.99) * 1000, 1),
        "outcomes": dict(sorted(outcomes.items())),
        "docket_unavailable_rate": round(outcomes["refused: docket_unavailable"] / len(latencies), 4),
    }


def raw_exchange(client: BailiffClient, call: PreparedCall) -> dict[str, Any]:
    call.consume()
    parts = urlsplit(GATEWAY_URL)
    headers = {"content-type": "application/json", "accept": "application/json, text/event-stream", **call.headers}
    if client.protocol_version is not None:
        headers["mcp-protocol-version"] = client.protocol_version
    if client.session_id is not None:
        headers["mcp-session-id"] = client.session_id
    connection = http.client.HTTPConnection(parts.hostname or "", parts.port, timeout=RAW_TIMEOUT_SECONDS)
    try:
        connection.request("POST", parts.path, call.body, headers)
        response = connection.getresponse()
        body = response.read(RAW_LIMIT_BYTES + 1)
    finally:
        connection.close()
    if len(body) > RAW_LIMIT_BYTES:
        raise ScenarioFailed(f"call {call.request_id} returned more than {RAW_LIMIT_BYTES} bytes")
    return {"status": response.status, "headers": response.getheaders(), "body": body.decode("latin-1")}


def run_raw() -> dict[str, Any]:
    client, task_id = open_client([UNROUTED])
    try:
        client.list_tools()
        exchanges = [
            {"case": case, **raw_exchange(client, client.prepare(SERVICE, name, arguments))}
            for case, name, arguments in RAW_CASES
        ]
    finally:
        client.close()
    return {"task_id": task_id, "exchanges": exchanges}


def report(task_id: str, checks: list[Check]) -> int:
    print(json.dumps({"task_id": task_id, "checks": [check.document() for check in checks]}, indent=2))
    return 0 if all(check.passed for check in checks) else 1


def run(scenarios: Callable[[BailiffClient], list[Check]]) -> int:
    client, task_id = open_client([UNROUTED])
    try:
        return report(task_id, scenarios(client))
    finally:
        client.close()


SCENARIO_STEPS: dict[str, Callable[[BailiffClient], list[Check]]] = {
    "run": run_scenarios,
    "inject": run_inject,
    "after-revoke": run_after_revoke,
}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("step", choices=["key", *SCENARIO_STEPS, "load", "raw"])
    parser.add_argument("--clients", type=int, default=1)
    parser.add_argument("--calls", type=int, default=20)
    args = parser.parse_args(argv)
    try:
        if args.step == "key":
            print(f"key: {generate_key()}")
            return 0
        if args.step == "load":
            print(json.dumps(run_load(args.clients, args.calls)))
            return 0
        if args.step == "raw":
            print(json.dumps(run_raw()))
            return 0
        return run(SCENARIO_STEPS[args.step])
    except (ScenarioFailed, OSError, ValueError) as error:
        print(f"agent {args.step} failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
