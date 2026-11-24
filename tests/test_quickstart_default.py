import json
import socket

import test_quickstart_stack
from test_quickstart_stack import b

pytestmark = test_quickstart_stack.pytestmark
stack = test_quickstart_stack.stack
GITEA_SERVICES = {"gitea", "gitea-mcp", "gitea-secret", "gitea-admin", "bootstrap", "agent-key", "gitea-task"}


def test_the_default_stack_runs_the_stub_without_gitea(stack):
    services = set(stack.compose("ps", "--all", "--services").split())
    assert {"stub-upstream", "gateway", "decide", "custodian", "docket"} <= services
    assert not services & GITEA_SERVICES


def test_the_gateway_listens_on_loopback(stack):
    with socket.create_connection(("127.0.0.1", stack.gateway_port), timeout=5):
        pass


def test_the_gateway_targets_the_stub_upstream(stack):
    script = "import sys; sys.stdout.write(open('/var/lib/bailiff/gateway/gateway.json').read())"
    output = stack.compose(
        "run", "--rm", "--no-deps", "--entrypoint", "python", "gateway-init", "-c", script
    )  # fmt: skip
    targets = json.loads(output)["mcp"]["targets"]
    upstream = b.load_upstream(b.QUICKSTART_UPSTREAMS / "stub.json")
    assert targets == [{"name": upstream.target, "mcp": {"host": upstream.url}}]


def test_the_default_init_steps_rerun_as_kept(stack):
    for service, step in [("decide-init", "decide"), ("custodian-init", "custodian"), ("gateway-init", "gateway")]:
        output = stack.compose("run", "--rm", "--no-deps", service)
        assert output.strip().splitlines()[-1] == f"{step}: kept", output
