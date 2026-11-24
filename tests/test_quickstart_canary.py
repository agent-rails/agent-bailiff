import base64
import json
import time
from datetime import UTC, datetime, timedelta

import test_quickstart_stack
from test_quickstart import verified_rows
from test_quickstart_trace import jaeger, spans_in, wait_for_export

pytestmark = test_quickstart_stack.pytestmark
stack = test_quickstart_stack.stack
PROFILES = ("gitea", "trace")
JAEGER_TIMEOUT_SECONDS = 60

ALLOWED_LOG_SERVICES = {"gitea"}
UPSTREAM_CASES = ("allowed", "missing issue", "missing repo")
BASE64_ALIGNMENTS = 3
CONTROL = 1 + BASE64_ALIGNMENTS
CREDENTIAL_SCRIPT = """
import sys
sys.path.insert(0, "/app/quickstart")
import bootstrap
print(bootstrap.stored_credential(bootstrap.load_upstream(bootstrap.UPSTREAM_FILE)))
"""
VOLUME_SCAN = """
import json, os, stat, sys
needles = [needle.encode() for needle in json.loads(sys.argv[1])]
hits = []
for top in sorted(os.listdir("/v")):
    for root, dirs, files in os.walk(f"/v/{top}"):
        for name in files:
            path = os.path.join(root, name)
            if not stat.S_ISREG(os.lstat(path).st_mode):
                continue
            with open(path, "rb") as handle:
                data = handle.read()
            hits += [[path[3:], index] for index, needle in enumerate(needles) if needle in data]
json.dump(hits, sys.stdout)
"""
AGENT_SCAN = """
import json, os, stat, sys
needles = [needle.encode() for needle in json.loads(sys.argv[1])]
environment = " ".join(f"{key}={value}" for key, value in os.environ.items()).encode()
hits = [["env", index] for index, needle in enumerate(needles) if needle in environment]
for root, dirs, files in os.walk("/"):
    if root == "/":
        dirs[:] = [name for name in dirs if name not in ("proc", "sys", "dev")]
    for name in files:
        path = os.path.join(root, name)
        try:
            if not stat.S_ISREG(os.lstat(path).st_mode):
                continue
            with open(path, "rb") as handle:
                data = handle.read()
        except PermissionError:
            continue
        hits += [[path, index] for index, needle in enumerate(needles) if needle in data]
json.dump(hits, sys.stdout)
"""


def plaintext_credential(stack):
    output = stack.compose("run", "--rm", "--no-deps", "--entrypoint", "python", "bootstrap", "-c", CREDENTIAL_SCRIPT)
    scheme, token = output.strip().split(" ")
    assert scheme == "token" and len(token) >= 40
    return token


def needles(token):
    return [token, *(aligned_base64(token.encode(), lead) for lead in range(BASE64_ALIGNMENTS))]


def aligned_base64(secret, lead):
    encoded = base64.b64encode(bytes(lead) + secret).decode()
    return encoded[-(-8 * lead // 6) : 8 * (lead + len(secret)) // 6]


def scan_agent(stack, patterns):
    arguments = ["--profile", "agent", "run", "--rm", "--no-deps", "--entrypoint", "python", "agent"]
    return json.loads(stack.compose(*arguments, "-c", AGENT_SCAN, json.dumps(patterns)))


def log_hits(stack, patterns):
    services = stack.compose("--profile", "agent", "--profile", "operator", "config", "--services").split()
    hits = {}
    for service in services:
        logs = stack.compose("logs", "--no-color", "--no-log-prefix", service)
        found = [index for index, needle in enumerate(patterns) if needle in logs]
        if found:
            hits[service] = found
    return hits


def jaeger_spans(stack):
    exported = wait_for_export(stack)["exported"]
    deadline = time.monotonic() + JAEGER_TIMEOUT_SECONDS
    while True:
        now = datetime.now(UTC)
        window = {
            "query.start_time_min": (now - timedelta(hours=1)).isoformat(),
            "query.start_time_max": now.isoformat(),
        }
        services = [
            name for name in jaeger(stack, "/services").get("services", []) if name.startswith("agent-bailiff-")
        ]
        spans = {
            span["spanId"]: span
            for service in services
            for span in spans_in(jaeger(stack, "/traces", **{"query.service_name": service, **window}))
        }
        if len(spans) >= exported:
            return list(spans.values())
        assert time.monotonic() < deadline, f"jaeger holds {len(spans)} of {exported} exported spans"
        time.sleep(1)


def jaeger_hits(stack, patterns):
    traces = json.dumps(jaeger_spans(stack))
    return [index for index, needle in enumerate(patterns) if needle in traces]


def raw_exchanges(stack):
    output = stack.compose("--profile", "agent", "run", "--rm", "--no-deps", "agent", "raw")
    return {exchange["case"]: exchange for exchange in json.loads(output)["exchanges"]}


def raw_hits(exchanges, patterns):
    texts = {case: json.dumps(exchange) for case, exchange in exchanges.items()}
    return {case: found for case, text in texts.items() if (found := [i for i, p in enumerate(patterns) if p in text])}


def only_control(hits):
    return {index for _, index in hits} == {CONTROL}


def test_no_surface_holds_the_credential(stack):
    report = json.loads(stack.compose("--profile", "agent", "run", "--rm", "--no-deps", "agent", "run"))
    assert all(check["pass"] for check in report["checks"])
    patterns = [*needles(plaintext_credential(stack)), report["task_id"]]
    volumes = stack.probe(VOLUME_SCAN, arguments=[json.dumps(patterns)])
    assert only_control(volumes) and ["tasks/task.json", CONTROL] in volumes, volumes
    agent = scan_agent(stack, patterns)
    assert only_control(agent) and ["/var/lib/bailiff/tasks/task.json", CONTROL] in agent, agent
    logs = log_hits(stack, [*patterns[:CONTROL], "credential: "])
    assert {service for service, found in logs.items() if found != [CONTROL]} <= ALLOWED_LOG_SERVICES, logs
    assert logs["bootstrap"] == [CONTROL]
    entry_id = verified_rows(stack, report["task_id"])[0]["entry"]["entry_id"]
    assert jaeger_hits(stack, [*patterns[:CONTROL], entry_id]) == [CONTROL]


def test_no_response_to_the_agent_holds_the_credential(stack):
    patterns = [*needles(plaintext_credential(stack)), "Triage the open issues"]
    served = raw_exchanges(stack)
    assert raw_hits(served, patterns) == {"allowed": [CONTROL]}, served
    assert "status 404" in served["missing issue"]["body"] and "out_of_scope" in served["injected"]["body"], served
    stack.compose("stop", "gitea")
    failing = raw_exchanges(stack)
    assert raw_hits(failing, patterns) == {}, failing
    assert "out_of_scope" in failing["injected"]["body"] and "unknown_tool" in failing["unrouted"]["body"], failing
    assert all('"isError":true' in failing[case]["body"] for case in UPSTREAM_CASES), failing
    logs = log_hits(stack, patterns[:CONTROL])
    assert set(logs) <= ALLOWED_LOG_SERVICES, logs
