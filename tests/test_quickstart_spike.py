import json
import os
from pathlib import Path

import pytest
import test_agentgateway_e2e
import test_custodian
from test_agentgateway_config import gateway_config
from test_agentgateway_e2e import AGENT_TOKEN, BINARY, Agent, Gateway, agent_headers, free_ports, refused
from test_custodian import NOW, docket_entries
from test_decide import CUSTODIAN_ID, TENANT, make_request, make_root

from agent_bailiff.adapters.agentgateway.config_check import GatewayExpectations, validate_gateway_config
from agent_bailiff.adapters.agentgateway.processors import CustodianProcessor, DecideProcessor, RedactorProcessor
from agent_bailiff.adapters.agentgateway.server import ProcessorServer, request_handlers, response_server
from agent_bailiff.custodian import CredentialBinding, CredentialStore, LocalBackend
from agent_bailiff.decide import CostTable, TargetBinding
from agent_bailiff.routes import ToolRoute, ToolRoutes

GITEA_MCP_URL = os.environ.get("AGENT_BAILIFF_TEST_GITEA_MCP_URL")
GITEA_TOKEN_FILE = os.environ.get("AGENT_BAILIFF_TEST_GITEA_TOKEN_FILE")
GITEA_USER = os.environ.get("AGENT_BAILIFF_TEST_GITEA_USER")
pytestmark = [
    pytest.mark.skipif(BINARY is None, reason="agentgateway v1.7.0 binary not cached; run fetch_gateway.sh"),
    pytest.mark.skipif(
        not (GITEA_MCP_URL and GITEA_TOKEN_FILE and GITEA_USER),
        reason="set AGENT_BAILIFF_TEST_GITEA_MCP_URL, _GITEA_TOKEN_FILE and _GITEA_USER (examples/quickstart)",
    ),
]

TOOL, RESOURCE = "gitea.user.read", "gitea/user/self"
ROUTES = ToolRoutes([ToolRoute("gitea", "get_me", TOOL, RESOURCE)])
SCOPE = {"tools": ["gitea.user.read"], "resources": ["gitea/user/*"], "max_cost_per_call": 5}
CREDENTIAL = "gitea-pat"
TARGET = "gitea"

binary = test_agentgateway_e2e.binary
ledger_path = test_custodian.ledger_path
make_custodian = test_custodian.make_custodian
make_decider = test_custodian.make_decider
open_docket = test_custodian.open_docket
private = test_custodian.private
reader = test_custodian.reader
sink = test_custodian.sink
state = test_custodian.state
workdir = test_custodian.workdir
writer = test_custodian.writer


@pytest.fixture
def token():
    return Path(GITEA_TOKEN_FILE).read_text().strip()


@pytest.fixture
def stack(binary, workdir, private, state, token, make_decider, make_custodian):
    store = CredentialStore.open(state / "credentials.db", LocalBackend.load(state / "kek"))
    store.put(TENANT, CREDENTIAL, TARGET, f"token {token}".encode())
    store.close()
    decider = make_decider(
        bindings=(TargetBinding(TENANT, TOOL, "gitea/user/*", CREDENTIAL, TARGET, CUSTODIAN_ID),),
        costs=CostTable(1, {TOOL: 1}),
    )
    custodian = make_custodian(
        bindings=(CredentialBinding(TENANT, TOOL, "gitea/user/*", CREDENTIAL, TARGET, "Authorization", False),)
    )
    sockets = {
        "decide": workdir / "d" / "decide.sock",
        "custodian": workdir / "c" / "custodian.sock",
        "redactor": workdir / "c" / "redactor.sock",
    }
    servers = [
        ProcessorServer(
            request_handlers(DecideProcessor(decider, ROUTES, clock=lambda: NOW)),
            sockets["decide"],
            private("decide-grpc"),
            gateway_uid=os.geteuid(),
        ),
        ProcessorServer(
            request_handlers(
                CustodianProcessor(custodian, ROUTES, frozenset({"Authorization"}), clock=lambda: NOW + 1)
            ),
            sockets["custodian"],
            private("custodian-grpc"),
            gateway_uid=os.geteuid(),
        ),
        response_server(
            RedactorProcessor(custodian, clock=lambda: NOW + 2),
            sockets["redactor"],
            private("redactor-grpc"),
            gateway_uid=os.geteuid(),
        ),
    ]
    for server in servers:
        server.start()
    config = gateway_config(
        sockets["decide"], sockets["custodian"], GITEA_MCP_URL, ["Authorization"], sockets["redactor"]
    )
    config["mcp"]["targets"][0]["name"] = "gitea"
    admin, stats, readiness, config["mcp"]["port"] = free_ports(4)
    config["config"] = {
        "adminAddr": f"127.0.0.1:{admin}",
        "statsAddr": f"127.0.0.1:{stats}",
        "readinessAddr": f"127.0.0.1:{readiness}",
    }
    expected = GatewayExpectations(
        sockets["decide"], sockets["custodian"], sockets["redactor"], ROUTES.services, frozenset({"Authorization"})
    )
    assert validate_gateway_config(config, expected) == ()
    gateway = Gateway(binary, config, workdir)
    try:
        yield {"agent": Agent(gateway.port), "gateway": gateway}
    finally:
        gateway.stop()
        for server in servers:
            server.close()


def gitea_request(nonce="n-1"):
    return make_request(make_root(scope=SCOPE), tool=TOOL, resource=RESOURCE, args={}, nonce=nonce)


def result_text(body):
    return body["result"]["content"][0]["text"]


def test_tools_list_returns_the_gitea_tools(stack):
    status, body = stack["agent"].post({"method": "tools/list"})
    assert status == 200, body
    assert "get_me" in {tool["name"] for tool in body["result"]["tools"]}


def test_an_allowed_call_reaches_gitea_with_the_injected_token(stack, workdir, token):
    request = gitea_request()
    status, body = stack["agent"].call("get_me", request.args, agent_headers(request))
    assert status == 200 and not body["result"].get("isError"), body
    assert json.loads(result_text(body))["login"] == GITEA_USER
    decisions = [(entry.hop, entry.decision) for entry in docket_entries(workdir)]
    assert ("decide", "allow") in decisions and ("custodian", "release") in decisions
    assert token not in (workdir / "docket.log").read_text()
    assert token not in stack["gateway"].log()
    assert token not in json.dumps(body)


def test_a_call_without_chain_headers_is_refused(stack):
    status, body = stack["agent"].call("get_me", {}, {"authorization": AGENT_TOKEN})
    assert refused(body, "malformed_request"), body


def test_a_replayed_call_is_refused(stack):
    request = gitea_request()
    first = stack["agent"].call("get_me", request.args, agent_headers(request))
    second = stack["agent"].call("get_me", request.args, agent_headers(request))
    assert json.loads(result_text(first[1]))["login"] == GITEA_USER, first
    assert refused(second[1], "already_issued"), second
