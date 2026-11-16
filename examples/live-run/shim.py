"""The agent's side of agent-bailiff: a stdio MCP server that signs a leaf proof for each call and sends it
through agentgateway. It holds the agent's signing key and task root, never a service credential."""

from __future__ import annotations

import json
import secrets
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from agent_warrant.chain import prove_leaf
from agent_warrant.task_root import TaskRoot
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_bailiff.decide.identity import request_digest

PROTOCOL = "2025-06-18"
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
        self.key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(Path(state["agent_key"]).read_text().strip()))
        self.root = TaskRoot.decode(state["task_root"])
        self.next_id = 1

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
            result = {"tools": TOOLS}
        elif method == "tools/call":
            result = self.call(message["params"]["name"], message["params"].get("arguments") or {})
        else:
            return {"jsonrpc": "2.0", "id": message["id"], "error": {"code": -32601, "message": "method not found"}}
        return {"jsonrpc": "2.0", "id": message["id"], "result": result}

    def call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name == "read_document":
            return self.read_document(str(arguments.get("name", "")))
        route = self.state["routes"].get(name)
        if route is None:
            return text(f"unknown tool {name}", error=True)
        nonce = secrets.token_hex(8)
        digest = request_digest(route["tool"], route["resource"], arguments, nonce)
        proof = prove_leaf(
            self.root, self.key, int(time.time()), audience=self.state["decider_id"], request_digest=digest
        )
        headers = {
            "x-bailiff-task-root": self.state["task_root"],
            "x-bailiff-leaf-proof": proof.encode(),
            "x-bailiff-nonce": nonce,
            "traceparent": f"00-{secrets.token_hex(16)}-{secrets.token_hex(8)}-01",
        }
        body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": arguments}}
        with open(self.state["request_log"], "a") as log:
            log.write(json.dumps({"headers": headers, "body": body}) + "\n")
        return gateway_result(post(self.state["gateway_url"], body, headers))

    def read_document(self, name: str) -> dict[str, Any]:
        workspace = Path(self.state["workspace"]).resolve()
        path = (workspace / name).resolve()
        if path.parent != workspace or not path.is_file():
            return text(f"no document named {name}", error=True)
        return text(path.read_text())


def post(url: str, body: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
    initialize = {
        "jsonrpc": "2.0",
        "id": 0,
        "method": "initialize",
        "params": {"protocolVersion": PROTOCOL, "capabilities": {}, "clientInfo": {"name": "agent", "version": "1"}},
    }
    send(url, initialize, {})
    return send(url, body, headers)


def send(url: str, body: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        json.dumps(body).encode(),
        {
            "content-type": "application/json",
            "accept": "application/json, text/event-stream",
            "mcp-protocol-version": PROTOCOL,
            **headers,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return parse(response.read().decode())
    except urllib.error.HTTPError as error:
        return {"error": {"message": f"HTTP {error.code}: {error.read().decode()[:200]}"}}


def parse(raw: str) -> dict[str, Any]:
    for line in raw.splitlines():
        if line.startswith("data: "):
            return json.loads(line[len("data: ") :])
    return json.loads(raw) if raw.strip() else {}


def gateway_result(response: dict[str, Any]) -> dict[str, Any]:
    if "result" in response:
        return response["result"]
    return text(f"refused: {response.get('error', {}).get('message', 'no response')}", error=True)


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
