from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agent_warrant.canonical import canonicalize
from agent_warrant.encoding import sha256_b64u
from agent_warrant.scope import validate_entry

from agent_bailiff.strict_json import parse_strict_json

CATALOG_VERSION = 1
SHIPPED_CATALOGS = frozenset({"kubernetes"})
CATALOG_TOOL_PREFIX = "k8s."
MAX_CATALOG_BYTES = 1 << 20
MAX_RESPONSE_BYTES = 1 << 20
LABEL = re.compile(r"[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?")
IDENTIFIER = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,99}")
TOOL_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}")
ARGUMENT_NAME = re.compile(r"[a-z][A-Za-z0-9]{0,31}")
FIELD_PATH = re.compile(r"[A-Za-z][A-Za-z0-9]*(\.[A-Za-z][A-Za-z0-9]*)*")
OPERATION_KEYS = frozenset({"name", "call", "arguments", "response"})
CALL_KEYS = frozenset({"group", "version", "resource", "subresource", "verb", "query"})
RESPONSE_KEYS = frozenset({"fields", "max_bytes"})
RESTARTED_AT = "kubectl.kubernetes.io/restartedAt"
RESTART_OP = "bailiff.dev/restart-op"


@dataclass(frozen=True)
class CallShape:
    tool: str
    identity: str
    named: bool
    query: frozenset[str]
    body_argument: str | None
    restarts: bool = False


ALLOWED_CALLS: Mapping[tuple[str, str, str, str | None, str], CallShape] = {
    ("", "v1", "pods", None, "list"): CallShape("k8s.pods.list", "read", False, frozenset({"limit"}), None),
    ("", "v1", "pods", "log", "get"): CallShape("k8s.pods.log", "read", True, frozenset({"tailLines"}), None),
    ("apps", "v1", "deployments", None, "get"): CallShape("k8s.deployments.get", "read", True, frozenset(), None),
    ("apps", "v1", "deployments", "scale", "get"): CallShape(
        "k8s.deployments.scale.get", "read", True, frozenset(), None
    ),
    ("apps", "v1", "deployments", "scale", "patch"): CallShape(
        "k8s.deployments.scale", "scale", True, frozenset(), "replicas"
    ),
    ("apps", "v1", "deployments", None, "patch"): CallShape(
        "k8s.deployments.restart", "restart", True, frozenset(), None, restarts=True
    ),
}


class CatalogError(ValueError):
    pass


@dataclass(frozen=True)
class Argument:
    name: str
    kind: str
    minimum: int | None = None
    maximum: int | None = None

    def accepts(self, value: object) -> bool:
        if self.kind == "label":
            return isinstance(value, str) and LABEL.fullmatch(value) is not None
        if self.kind == "identifier":
            return isinstance(value, str) and IDENTIFIER.fullmatch(value) is not None
        return (
            isinstance(value, int)
            and not isinstance(value, bool)
            and self.minimum is not None
            and self.maximum is not None
            and self.minimum <= value <= self.maximum
        )


@dataclass(frozen=True)
class KubernetesCall:
    group: str
    version: str
    resource: str
    subresource: str | None
    verb: str
    query: Mapping[str, str]
    body_argument: str | None
    named: bool
    tool: str
    identity: str
    restarts: bool

    def body(self, arguments: Mapping[str, Any], issued_at: int, op_id: str | None = None) -> dict[str, Any] | None:
        if self.restarts:
            if not isinstance(op_id, str) or not op_id:
                raise ValueError("restart requires an op-id")
            restarted = datetime.fromtimestamp(issued_at, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
            return {
                "apiVersion": f"{self.group}/{self.version}",
                "kind": "Deployment",
                "metadata": {"name": arguments["name"]},
                "spec": {"template": {"metadata": {"annotations": {RESTARTED_AT: restarted, RESTART_OP: op_id}}}},
            }
        if self.body_argument is None:
            return None
        return {"spec": {"replicas": arguments[self.body_argument]}}


@dataclass(frozen=True)
class CatalogOperation:
    name: str
    tool: str
    identity: str
    call: KubernetesCall
    arguments: tuple[Argument, ...]
    response_fields: tuple[str, ...]
    max_response_bytes: int

    @property
    def resource(self) -> str:
        template = f"k8s/{{namespace}}/{self.call.resource}"
        return f"{template}/{{name}}" if self.call.named else template

    def argument(self, name: str) -> Argument | None:
        return next((item for item in self.arguments if item.name == name), None)

    def accepts(self, arguments: object) -> bool:
        if not isinstance(arguments, dict) or set(arguments) != {item.name for item in self.arguments}:
            return False
        return all(item.accepts(arguments[item.name]) for item in self.arguments)


class OperationCatalog:
    def __init__(self, document: object) -> None:
        if not isinstance(document, dict) or set(document) != {"version", "target", "operations"}:
            raise CatalogError('a catalog must be an object with exactly "version", "target" and "operations"')
        if isinstance(document["version"], bool) or document["version"] != CATALOG_VERSION:
            raise CatalogError(f"catalog version must be {CATALOG_VERSION}")
        if document["target"] != "kubernetes":
            raise CatalogError('catalog target must be "kubernetes"')
        items = document["operations"]
        if not isinstance(items, list) or not items:
            raise CatalogError("operations must be a non-empty list")
        operations = tuple(_operation(item) for item in items)
        for attribute in ("name", "tool"):
            values = [getattr(item, attribute) for item in operations]
            if len(set(values)) != len(values):
                raise CatalogError(f"operation {attribute}s must be unique")
        self._operations = {item.name: item for item in operations}
        self.digest = sha256_b64u(canonicalize(document))

    @classmethod
    def load(cls, path: Path) -> OperationCatalog:
        raw = path.read_bytes()
        if len(raw) > MAX_CATALOG_BYTES:
            raise CatalogError(f"catalog is larger than {MAX_CATALOG_BYTES} bytes")
        try:
            return cls(parse_strict_json(raw))
        except (UnicodeDecodeError, CatalogError) as exc:
            raise CatalogError(f"{path} is not a valid catalog: {exc}") from None
        except ValueError as exc:
            raise CatalogError(f"{path} is not valid JSON: {exc}") from None

    @property
    def operations(self) -> tuple[CatalogOperation, ...]:
        return tuple(self._operations.values())

    def operation(self, name: str) -> CatalogOperation | None:
        return self._operations.get(name)


def _operation(item: object) -> CatalogOperation:
    if not isinstance(item, dict) or set(item) != OPERATION_KEYS:
        raise CatalogError(f"each operation must have exactly the fields {', '.join(sorted(OPERATION_KEYS))}")
    name = _text(item, "name", TOOL_NAME)
    call = _call(name, item["call"])
    arguments = _arguments(name, item["arguments"], call)
    fields, max_bytes = _response(name, item["response"], call)
    operation = CatalogOperation(name, call.tool, call.identity, call, arguments, fields, max_bytes)
    if validate_entry(operation.resource.replace("{namespace}", "x").replace("{name}", "x")):
        raise CatalogError(f"{name}: derived resource is not a valid scope id")
    return operation


def _text(item: Mapping[str, Any], key: str, pattern: re.Pattern[str]) -> str:
    value = item[key]
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise CatalogError(f"{key} {value!r} is not valid")
    return value


def _call(operation: str, document: object) -> KubernetesCall:
    if not isinstance(document, dict) or set(document) != CALL_KEYS:
        raise CatalogError(f"{operation}: call must have exactly the fields {', '.join(sorted(CALL_KEYS))}")
    key = (document["group"], document["version"], document["resource"], document["subresource"], document["verb"])
    if not all(part is None or isinstance(part, str) for part in key):
        raise CatalogError(f"{operation}: call fields must be strings or null")
    shape = ALLOWED_CALLS.get(key)
    if shape is None:
        raise CatalogError(f"{operation}: call {key!r} is not in the allowed set")
    query = document["query"]
    if not isinstance(query, dict) or set(query) != shape.query:
        raise CatalogError(f"{operation}: query must name exactly {', '.join(sorted(shape.query)) or 'nothing'}")
    for parameter, argument in query.items():
        if not isinstance(argument, str) or not ARGUMENT_NAME.fullmatch(argument):
            raise CatalogError(f"{operation}: query {parameter} must name an integer argument")
    group, version, resource, subresource, verb = key
    return KubernetesCall(
        group,
        version,
        resource,
        subresource,
        verb,
        dict(query),
        shape.body_argument,
        shape.named,
        shape.tool,
        shape.identity,
        shape.restarts,
    )


def _arguments(operation: str, document: object, call: KubernetesCall) -> tuple[Argument, ...]:
    if not isinstance(document, dict):
        raise CatalogError(f"{operation}: arguments must be an object")
    labels = {"namespace", "name"} if call.named else {"namespace"}
    integers = set(call.query.values()) | ({call.body_argument} if call.body_argument else set())
    if set(document) != labels | integers or labels & integers:
        raise CatalogError(f"{operation}: arguments must be exactly {', '.join(sorted(labels | integers))}")
    arguments = []
    for name in sorted(document):
        spec = document[name]
        if name in labels:
            if spec != {"kind": "label"}:
                raise CatalogError(f'{operation}: argument {name} must be {{"kind": "label"}}')
            arguments.append(Argument(name, "label"))
            continue
        if not isinstance(spec, dict) or set(spec) != {"kind", "minimum", "maximum"} or spec["kind"] != "integer":
            raise CatalogError(f"{operation}: argument {name} must be an integer with minimum and maximum")
        minimum, maximum = spec["minimum"], spec["maximum"]
        if not all(isinstance(value, int) and not isinstance(value, bool) for value in (minimum, maximum)):
            raise CatalogError(f"{operation}: bounds of {name} must be integers")
        floor = 1 if name == call.body_argument else 0
        if not floor <= minimum <= maximum <= 100_000:
            raise CatalogError(f"{operation}: bounds of {name} must satisfy {floor} <= minimum <= maximum <= 100000")
        arguments.append(Argument(name, "integer", minimum, maximum))
    return tuple(arguments)


def _response(operation: str, document: object, call: KubernetesCall) -> tuple[tuple[str, ...], int]:
    if not isinstance(document, dict) or set(document) != RESPONSE_KEYS:
        raise CatalogError(f"{operation}: response must have exactly fields and max_bytes")
    fields, max_bytes = document["fields"], document["max_bytes"]
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or not 0 < max_bytes <= MAX_RESPONSE_BYTES:
        raise CatalogError(f"{operation}: max_bytes must be between 1 and {MAX_RESPONSE_BYTES}")
    if not isinstance(fields, list) or not all(isinstance(item, str) and FIELD_PATH.fullmatch(item) for item in fields):
        raise CatalogError(f"{operation}: fields must be a list of dotted field paths")
    if (call.subresource == "log") != (not fields):
        raise CatalogError(f"{operation}: logs return text with no fields; every other call lists its fields")
    return tuple(fields), max_bytes


def shipped_catalog(name: str) -> Path:
    if name not in SHIPPED_CATALOGS:
        raise CatalogError(f"{name!r} is not a shipped catalog; choose from {', '.join(sorted(SHIPPED_CATALOGS))}")
    return Path(__file__).resolve().parent / "catalogs" / f"{name}.json"
