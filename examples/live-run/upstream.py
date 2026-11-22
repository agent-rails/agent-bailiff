"""A fake upstream MCP server that records every request it receives, including headers. While the hold file
exists it holds each deploy response, so the harness can act between a deploy and the agent seeing its result."""

from __future__ import annotations

import argparse
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

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
]
HOLD_SECONDS = 20


class Upstream(ThreadingHTTPServer):
    def __init__(self, port: int, log: Path, hold: Path) -> None:
        super().__init__(("127.0.0.1", port), Handler)
        self.log = log
        self.hold = hold
        self.lock = threading.Lock()

    def released(self) -> bool:
        deadline = time.monotonic() + HOLD_SECONDS
        while self.hold.exists():
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.05)
        return True


class Handler(BaseHTTPRequestHandler):
    server: Upstream

    def log_message(self, *args: object) -> None:
        pass

    def do_POST(self) -> None:
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        headers = {key.lower(): value for key, value in self.headers.items()}
        params = body.get("params") or {}
        with self.server.lock, open(self.server.log, "a") as log:
            record = {"method": body.get("method"), "tool": params.get("name"), "arguments": params.get("arguments")}
            log.write(json.dumps({**record, "headers": headers}) + "\n")
        if "id" not in body:
            self.send_response(202)
            self.end_headers()
            return
        method = body.get("method")
        if method == "initialize":
            result = {
                "protocolVersion": params.get("protocolVersion", "2025-06-18"),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "fake-ops", "version": "1"},
            }
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call" and params.get("name") == "deploy_service":
            if not self.server.released():
                self.reply(
                    {"jsonrpc": "2.0", "id": body["id"], "error": {"code": -32000, "message": "hold not released"}}
                )
                return
            version = (params.get("arguments") or {}).get("version", "unknown")
            result = {"content": [{"type": "text", "text": f"deployed api {version} to staging"}]}
        elif method == "tools/call" and params.get("name") == "withdraw_funds":
            result = {"content": [{"type": "text", "text": "withdrawal submitted"}]}
        else:
            result = {}
        self.reply({"jsonrpc": "2.0", "id": body["id"], "result": result})

    def reply(self, message: dict[str, object]) -> None:
        data = json.dumps(message).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        self.send_response(405)
        self.end_headers()

    def do_DELETE(self) -> None:
        self.send_response(200)
        self.end_headers()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--hold", type=Path, required=True)
    args = parser.parse_args()
    Upstream(args.port, args.log, args.hold).serve_forever()


if __name__ == "__main__":
    main()
