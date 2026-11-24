"""A minimal Streamable HTTP MCP server for the default quickstart stack: notes kept in memory, readable and writable
by name. It refuses every tool call that arrives without an Authorization header, so a successful call shows that
the custodian injected the credential. Each request is logged to stdout as one JSON line, with the credential only
as a SHA-256 digest."""

from __future__ import annotations

import argparse
import hashlib
import json
import socketserver
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

PROTOCOL_VERSION = "2025-06-18"
MAX_BODY_BYTES = 1 << 20
MAX_NOTES = 1024
MAX_NOTE_BYTES = 4096
NOTE = {"type": "string", "pattern": "^[a-z0-9-]{1,64}$"}
TOOLS = [
    {
        "name": "read_note",
        "description": "Read a note by name.",
        "inputSchema": {"type": "object", "properties": {"note": NOTE}, "required": ["note"]},
    },
    {
        "name": "write_note",
        "description": "Write a note by name, replacing any earlier text.",
        "inputSchema": {
            "type": "object",
            "properties": {"note": NOTE, "text": {"type": "string", "maxLength": MAX_NOTE_BYTES}},
            "required": ["note", "text"],
        },
    },
    {
        "name": "delete_all_notes",
        "description": "Delete every note.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


class StubUpstream(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port: int) -> None:
        super().__init__(("0.0.0.0", port), Handler)
        self.notes: dict[str, str] = {}
        self.lock = threading.Lock()

    def server_bind(self) -> None:
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]

    def call(self, name: str, arguments: dict[str, Any]) -> tuple[str, bool]:
        note = arguments.get("note")
        with self.lock:
            if name == "read_note" and isinstance(note, str):
                return self.notes.get(note, ""), False
            if name == "write_note" and isinstance(note, str) and isinstance(arguments.get("text"), str):
                if note not in self.notes and len(self.notes) >= MAX_NOTES:
                    return "too many notes", True
                self.notes[note] = arguments["text"][:MAX_NOTE_BYTES]
                return f"wrote {note}", False
            if name == "delete_all_notes":
                self.notes.clear()
                return "deleted every note", False
        return f"unknown tool or arguments: {name}", True


class Handler(BaseHTTPRequestHandler):
    server: StubUpstream

    def log_message(self, *args: object) -> None:
        pass

    def do_POST(self) -> None:
        length = int(self.headers.get("content-length") or 0)
        if length <= 0 or length > MAX_BODY_BYTES:
            self.send_error(413 if length > MAX_BODY_BYTES else 400)
            return
        try:
            body = json.loads(self.rfile.read(length))
        except (UnicodeDecodeError, ValueError):
            self.send_error(400)
            return
        if not isinstance(body, dict):
            self.send_error(400)
            return
        params = body.get("params") if isinstance(body.get("params"), dict) else {}
        authorization = self.headers.get("authorization")
        log(body.get("method"), params.get("name"), authorization)
        if "id" not in body:
            self.send_response(202)
            self.end_headers()
            return
        self.reply(body["id"], self.result(body.get("method"), params, authorization))

    def result(self, method: object, params: dict[str, Any], authorization: str | None) -> dict[str, Any]:
        if method == "initialize":
            return {
                "protocolVersion": params.get("protocolVersion", PROTOCOL_VERSION),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "stub-upstream", "version": "1"},
            }
        if method == "tools/list":
            return {"tools": TOOLS}
        if method == "tools/call":
            if not authorization:
                return text("missing credential", True)
            arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
            return text(*self.server.call(str(params.get("name")), arguments))
        return {}

    def reply(self, request_id: object, result: dict[str, Any]) -> None:
        data = json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result}).encode()
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


def text(message: str, is_error: bool) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": message}], "isError": is_error}


def log(method: object, tool: object, authorization: str | None) -> None:
    digest = hashlib.sha256(authorization.encode()).hexdigest() if authorization else None
    print(json.dumps({"method": method, "tool": tool, "credential_sha256": digest}), file=sys.stdout, flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, required=True)
    StubUpstream(parser.parse_args().port).serve_forever()


if __name__ == "__main__":
    main()
