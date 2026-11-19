import base64
import json

import test_quickstart_stack

pytestmark = test_quickstart_stack.pytestmark
stack = test_quickstart_stack.stack

ALLOWED_LOG_SERVICES = {"gitea"}
CONTROL = 3
CREDENTIAL_SCRIPT = """
import sys
sys.path.insert(0, "/app/quickstart")
import bootstrap
print(bootstrap.stored_credential())
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
    return [token, base64.b64encode(token.encode()).decode(), base64.b64encode(f"token {token}".encode()).decode()]


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
