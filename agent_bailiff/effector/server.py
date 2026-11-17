from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from agent_bailiff.custodian.release import RELEASE_HEADER
from agent_bailiff.decide.decider import DocketWriter, SuspensionCheck
from agent_bailiff.docket.entry import Entry, Record
from agent_bailiff.effector.catalog import LABEL, CatalogOperation, OperationCatalog
from agent_bailiff.effector.kubernetes import KubernetesClient, KubernetesUnavailable
from agent_bailiff.effector.release import CheckedCall, ReleaseCheck, ReleaseRefused
from agent_bailiff.strict_json import parse_strict_json

HOP = "effector"
PROTOCOL_VERSION = "2025-06-18"
MAX_BODY_BYTES = 65536
SESSION_METHODS = frozenset({"initialize", "ping", "tools/list"})

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class EffectorConfig:
    component: str
    docket_writer: str


class Effector:
    def __init__(
        self,
        config: EffectorConfig,
        catalog: OperationCatalog,
        check: ReleaseCheck,
        client: KubernetesClient,
        suspension: SuspensionCheck,
        docket: DocketWriter,
    ) -> None:
        self._config = config
        self._catalog = catalog
        self._check = check
        self._client = client
        self._suspension = suspension
        self._docket = docket

    def tools(self) -> list[dict[str, Any]]:
        return [_tool(item) for item in self._catalog.operations]

    def call(self, params: object, release_token: object, now: int) -> dict[str, Any]:
        if not isinstance(params, dict) or not params.keys() <= {"name", "arguments", "_meta"}:
            return _error("malformed_request")
        if self._suspension.suspended is not False:
            return _error("suspended")
        try:
            checked = self._check.check(params.get("name"), params.get("arguments", {}), release_token, now)
        except ReleaseRefused as refusal:
            logger.warning("effector refused a call: %s", refusal.reason)
            return _error(refusal.reason)
        attempt = self._entry(checked, "attempt", now)
        if not self._record(attempt):
            return _error("docket_unavailable")
        try:
            result = self._client.call(
                checked.operation,
                checked.arguments,
                checked.release.tenant,
                checked.release.op_id,
                checked.clearance.trace_id,
            )
        except KubernetesUnavailable:
            logger.exception("kubernetes call failed; the outcome is unknown")
            self._record(
                replace(self._entry(checked, "outcome", now), parent_entry=attempt.entry_id, outcome="outcome_unknown")
            )
            return _error("outcome_unknown")
        performed = result.status < 400
        outcome = "done" if performed else ("outcome_unknown" if result.status >= 500 else "refused")
        recorded = self._record(
            replace(
                self._entry(checked, "outcome", now),
                parent_entry=attempt.entry_id,
                performed=performed and outcome == "done",
                outcome=outcome,
                reason=str(result.status),
            )
        )
        if outcome != "done":
            return _error(f"kubernetes_{result.status}" if outcome == "refused" else "outcome_unknown")
        if not recorded:
            return _error("outcome_unknown")
        text = result.payload if isinstance(result.payload, str) else json.dumps(result.payload, sort_keys=True)
        return {"content": [{"type": "text", "text": text}], "isError": False}

    def _entry(self, checked: CheckedCall, decision: str, now: int) -> Entry:
        release, clearance = checked.release, checked.clearance
        return Entry(
            entry_id=uuid.uuid4().hex,
            trace_id=clearance.trace_id or uuid.uuid4().hex,
            hop=HOP,
            component=self._config.component,
            decision=decision,
            at=now,
            op_id=release.op_id,
            parent_entry=release.entry_id,
            tenant=release.tenant,
            tool=release.tool,
            resource=release.resource,
            args_digest=release.args_digest,
            credential_tier="effector",
        )

    def _record(self, entry: Entry) -> bool:
        try:
            record = self._docket.append(entry)
        except Exception:
            logger.exception("effector docket entry was not acknowledged")
            return False
        return isinstance(record, Record) and record.entry == entry and record.writer == self._config.docket_writer


def _error(reason: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": reason}], "isError": True}


def _tool(operation: CatalogOperation) -> dict[str, Any]:
    properties: dict[str, Any] = {}
    for argument in operation.arguments:
        if argument.kind == "label":
            properties[argument.name] = {"type": "string", "pattern": f"^{LABEL.pattern}$", "maxLength": 63}
        else:
            properties[argument.name] = {"type": "integer", "minimum": argument.minimum, "maximum": argument.maximum}
    return {
        "name": operation.name,
        "inputSchema": {
            "type": "object",
            "properties": properties,
            "required": sorted(properties),
            "additionalProperties": False,
        },
    }


class EffectorServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, effector: Effector, port: int, clock: Callable[[], int] = lambda: int(time.time())) -> None:
        super().__init__(("127.0.0.1", port), _Handler)
        self.effector = effector
        self.clock = clock
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self.shutdown()
        self.server_close()


class _Handler(BaseHTTPRequestHandler):
    server: EffectorServer

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def do_GET(self) -> None:
        self._reply(405, None)

    def do_DELETE(self) -> None:
        self._reply(405, None)

    def do_POST(self) -> None:
        if self.path != "/mcp" or self.headers.get("Origin") is not None:
            self._reply(403, None)
            return
        length = self.headers.get("Content-Length")
        if length is None or not length.isdigit() or int(length) > MAX_BODY_BYTES:
            self._reply(413, None)
            return
        try:
            message = parse_strict_json(self.rfile.read(int(length)))
        except (ValueError, UnicodeDecodeError):
            self._reply(400, None)
            return
        if (
            not isinstance(message, dict)
            or message.get("jsonrpc") != "2.0"
            or not isinstance(message.get("method"), str)
        ):
            self._reply(400, None)
            return
        if "id" not in message:
            self._reply(202, None)
            return
        result = self._dispatch(message)
        self._reply(200, {"jsonrpc": "2.0", "id": message["id"], **result})

    def _dispatch(self, message: dict[str, Any]) -> dict[str, Any]:
        method = message["method"]
        params = message.get("params") or {}
        if method == "initialize":
            return {
                "result": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "agent-bailiff-effector", "version": "1"},
                }
            }
        if method == "ping":
            return {"result": {}}
        if method == "tools/list":
            return {"result": {"tools": self.server.effector.tools()}}
        if method == "tools/call":
            release = self.headers.get_all(RELEASE_HEADER) or []
            token = release[0] if len(release) == 1 else None
            return {"result": self.server.effector.call(params, token, self.server.clock())}
        return {"error": {"code": -32601, "message": "method not found"}}

    def _reply(self, status: int, document: dict[str, Any] | None) -> None:
        data = json.dumps(document).encode() if document is not None else b""
        self.send_response(status)
        if document is not None:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
