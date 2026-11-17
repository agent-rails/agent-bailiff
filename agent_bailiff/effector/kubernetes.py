from __future__ import annotations

import http.client
import json
import ssl
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from agent_bailiff.custodian.files import read_owned
from agent_bailiff.effector.catalog import CatalogOperation

TIMEOUT_SECONDS = 10
MAX_TOKEN_BYTES = 16384
TOKEN_LABEL = "effector token file"
USER_PREFIX = "bailiff"
OP_ID_EXTRA = "bailiff.dev/op-id"
TRACE_EXTRA = "bailiff.dev/trace-id"


class KubernetesUnavailable(Exception):
    pass


@dataclass(frozen=True)
class KubernetesResult:
    status: int
    payload: Any


class Transport(Protocol):
    def request(self, method: str, path: str, headers: Mapping[str, str], body: bytes | None) -> tuple[int, bytes]: ...


class HttpsTransport:
    def __init__(self, host: str, port: int, ca_file: Path, max_response_bytes: int = 1 << 20) -> None:
        self._host = host
        self._port = port
        self._context = ssl.create_default_context(cafile=str(ca_file))
        self._max = max_response_bytes

    def request(self, method: str, path: str, headers: Mapping[str, str], body: bytes | None) -> tuple[int, bytes]:
        connection = http.client.HTTPSConnection(self._host, self._port, timeout=TIMEOUT_SECONDS, context=self._context)
        try:
            connection.request(method, path, body=body, headers=dict(headers))
            response = connection.getresponse()
            data = response.read(self._max + 1)
            if len(data) > self._max:
                raise KubernetesUnavailable("response larger than the limit")
            return response.status, data
        except (OSError, http.client.HTTPException) as exc:
            raise KubernetesUnavailable(str(exc)) from None
        finally:
            connection.close()


class KubernetesClient:
    def __init__(self, transport: Transport, token_file: Path) -> None:
        self._transport = transport
        self._token_file = token_file

    def call(
        self, operation: CatalogOperation, arguments: Mapping[str, Any], tenant: str, op_id: str, trace_id: str
    ) -> KubernetesResult:
        token = read_token(self._token_file)
        call = operation.call
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "text/plain" if call.subresource == "log" else "application/json",
            "Impersonate-User": f"{USER_PREFIX}:{tenant}:{operation.identity}",
            f"Impersonate-Extra-{urllib.parse.quote(OP_ID_EXTRA, safe='')}": op_id,
            f"Impersonate-Extra-{urllib.parse.quote(TRACE_EXTRA, safe='')}": trace_id or "none",
        }
        body = call.body(arguments)
        payload = None
        if body is not None:
            payload = json.dumps(body).encode()
            headers["Content-Type"] = "application/merge-patch+json"
        method = {"list": "GET", "get": "GET", "patch": "PATCH"}[call.verb]
        status, data = self._transport.request(method, request_path(operation, arguments), headers, payload)
        if not 200 <= status < 300:
            return KubernetesResult(status, None)
        if call.subresource == "log":
            return KubernetesResult(status, data[: operation.max_response_bytes].decode("utf-8", "replace"))
        try:
            document = json.loads(data)
        except ValueError:
            raise KubernetesUnavailable("response is not JSON") from None
        return KubernetesResult(status, project(operation, document))


def read_token(path: Path) -> str:
    try:
        return read_owned(path, TOKEN_LABEL, MAX_TOKEN_BYTES).decode("ascii").strip()
    except (OSError, ValueError) as exc:
        raise KubernetesUnavailable(f"cannot read the token file {path}: {exc}") from None


def request_path(operation: CatalogOperation, arguments: Mapping[str, Any]) -> str:
    call = operation.call
    base = f"/api/{call.version}" if call.group == "" else f"/apis/{call.group}/{call.version}"
    path = f"{base}/namespaces/{arguments['namespace']}/{call.resource}"
    if call.named:
        path += f"/{arguments['name']}"
    if call.subresource:
        path += f"/{call.subresource}"
    query = {parameter: str(arguments[argument]) for parameter, argument in sorted(call.query.items())}
    return f"{path}?{urllib.parse.urlencode(query)}" if query else path


def project(operation: CatalogOperation, document: Any) -> Any:
    if operation.call.verb == "list":
        items = document.get("items", []) if isinstance(document, dict) else []
        return [_fields(operation.response_fields, item) for item in items if isinstance(item, dict)]
    return _fields(operation.response_fields, document) if isinstance(document, dict) else {}


def _fields(paths: tuple[str, ...], document: Mapping[str, Any]) -> dict[str, Any]:
    projected: dict[str, Any] = {}
    for path in paths:
        value: Any = document
        for part in path.split("."):
            value = value.get(part) if isinstance(value, dict) else None
        if isinstance(value, (str, int, float, bool)) or value is None:
            projected[path] = value
    return projected
