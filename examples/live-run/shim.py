"""The agent's side of agent-bailiff: a stdio MCP server that signs a leaf proof for each call and sends it
through agentgateway. It holds the agent's signing key and task root, never a service credential."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_bailiff.client import (
    BailiffClient,
    GatewayError,
    Holder,
    NeedsApproval,
    Outcome,
    OutcomeUnknown,
    PreparedCall,
    Refused,
    Result,
)
from agent_bailiff.effector.catalog import OperationCatalog, shipped_catalog
from agent_bailiff.routes import ToolRoutes

PROTOCOL = "2025-11-25"
TOOLS = [
    {
        "name": "deploy_service",
        "description": "Deploy a version of the api service to staging.",
        "inputSchema": {"type": "object", "properties": {"version": {"type": "string"}}, "required": ["version"]},
    },
    {
        "name": "withdraw_funds",
        "description": "Withdraw funds from a wallet.",
        "inputSchema": {
            "type": "object",
            "properties": {"amount": {"type": "number"}, "wallet": {"type": "string"}},
            "required": ["amount", "wallet"],
        },
    },
    {
        "name": "read_document",
        "description": "Read a document from the workspace.",
        "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]},
    },
]


class Shim:
    def __init__(self, state: dict[str, Any]) -> None:
        self.state = state
        self.client = client_for(state)
        self.services = {route["name"]: route["service"] for route in state["routes"]}
        for catalog in state.get("catalogs", []):
            operations = OperationCatalog.load(shipped_catalog(catalog["name"])).operations
            self.services.update((operation.name, catalog["service"]) for operation in operations)

    def handle(self, message: dict[str, Any]) -> dict[str, Any] | None:
        method = message.get("method")
        if "id" not in message:
            return None
        if method == "initialize":
            result: dict[str, Any] = {
                "protocolVersion": message.get("params", {}).get("protocolVersion", PROTOCOL),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "bailiff-agent", "version": "1"},
            }
        elif method == "tools/list":
            result = {"tools": self.state.get("tools", TOOLS)}
        elif method == "tools/call":
            result = self.call(message["params"]["name"], message["params"].get("arguments") or {})
        else:
            return {"jsonrpc": "2.0", "id": message["id"], "error": {"code": -32601, "message": "method not found"}}
        return {"jsonrpc": "2.0", "id": message["id"], "result": result}

    def call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name == "read_document":
            return self.read_document(str(arguments.get("name", "")))
        if name not in self.services:
            return text(f"unknown tool {name}", error=True)
        try:
            call = self.client.prepare(self.services[name], name, arguments)
        except ValueError as error:
            return text(str(error), error=True)
        with open(self.state["request_log"], "a") as log:
            record = {"headers": dict(call.headers), "body": json.loads(call.body), "raw": call.body.decode()}
            log.write(json.dumps(record) + "\n")
        return send(self.client, call)

    def read_document(self, name: str) -> dict[str, Any]:
        workspace = Path(self.state["workspace"]).resolve()
        path = (workspace / name).resolve()
        if path.parent != workspace or not path.is_file():
            return text(f"no document named {name}", error=True)
        return text(path.read_text())


def client_for(state: dict[str, Any]) -> BailiffClient:
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(Path(state["agent_key"]).read_text().strip()))
    holder = Holder(state["task_root"], (), key, state["decider_id"])
    routes = ToolRoutes.from_document({"routes": state["routes"], "catalogs": state.get("catalogs", [])})
    return BailiffClient(state["gateway_url"], holder, routes)


def replay(state: dict[str, Any], sent: dict[str, Any]) -> dict[str, Any]:
    call = PreparedCall(
        sent["body"]["id"], "", "", sent["headers"]["x-bailiff-nonce"], sent["headers"], sent["raw"].encode()
    )
    client = client_for(state)
    try:
        return send(client, call)
    finally:
        client.close()


def send(client: BailiffClient, call: PreparedCall) -> dict[str, Any]:
    try:
        return mcp_result(client.send(call))
    except GatewayError as error:
        return text(f"gateway_error: {error}", error=True)


GUIDANCE = {
    "stop": "agent-bailiff refused this call and the gateway did not forward it; "
    "do not retry it or get its effect another way; tell the user",
    "ask_user": "agent-bailiff needs a human to approve this call; the gateway did not forward it; "
    "stop and tell the user",
    "retry_later": "an agent-bailiff component was unavailable and the gateway did not forward the call; "
    "budget for this attempt may already be spent; retry at most twice with backoff, then stop and tell the user",
}
SUSPENDED_GUIDANCE = (
    "an operator suspended agent-bailiff and the gateway did not forward the call; "
    "stop, tell the user, and do not retry until it is resumed"
)


def guidance(outcome: Refused | NeedsApproval) -> str:
    if outcome.reason == "suspended":
        return SUSPENDED_GUIDANCE
    return GUIDANCE[outcome.action]


def mcp_result(outcome: Outcome) -> dict[str, Any]:
    if isinstance(outcome, Result):
        return dict(outcome.result)
    if isinstance(outcome, Refused | NeedsApproval):
        return text(f"{outcome.reason}: {guidance(outcome)}", error=True)
    if isinstance(outcome, OutcomeUnknown):
        return text(f"outcome_unknown: {outcome.detail}", error=True)
    raise AssertionError(f"unexpected outcome {outcome!r}")


def text(value: str, *, error: bool = False) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": value}], "isError": error}


def main() -> None:
    shim = Shim(json.loads(Path(sys.argv[1]).read_text()))
    for line in sys.stdin:
        if not line.strip():
            continue
        reply = shim.handle(json.loads(line))
        if reply is not None:
            sys.stdout.write(json.dumps(reply) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
