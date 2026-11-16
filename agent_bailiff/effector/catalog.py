from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent_warrant.canonical import canonicalize
from agent_warrant.encoding import sha256_b64u
from agent_warrant.scope import validate_entry

from agent_bailiff.strict_json import parse_strict_json

CATALOG_VERSION = 1
MAX_CATALOG_BYTES = 1 << 20
MAX_RESPONSE_BYTES = 1 << 20
LABEL = re.compile(r"[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?")
TOOL_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}")
ARGUMENT_NAME = re.compile(r"[a-z][A-Za-z0-9]{0,31}")
PLACEHOLDER = re.compile(r"\{([a-z][A-Za-z0-9]{0,31})\}")
API_GROUP = re.compile(r"([a-z0-9]([-a-z0-9]*[a-z0-9])?)(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*")
API_VERSION = re.compile(r"v[1-9][0-9]*((alpha|beta)[1-9][0-9]*)?")
API_RESOURCE = re.compile(r"[a-z][a-z0-9]{0,62}")
FIELD_PATH = re.compile(r"[A-Za-z][A-Za-z0-9]*(\.[A-Za-z][A-Za-z0-9]*)*")
ALLOWED_CALLS = {
    ("list", None): frozenset({"limit"}),
    ("get", None): frozenset(),
    ("get", "scale"): frozenset(),
    ("get", "log"): frozenset({"tailLines"}),
    ("patch", "scale"): frozenset(),
}
PATH_ARGUMENTS = ("namespace", "name")
OPERATION_KEYS = frozenset({"name", "tool", "resource", "identity", "request", "arguments", "response"})
REQUEST_KEYS = frozenset({"group", "version", "resource", "subresource", "verb", "query", "body"})
RESPONSE_KEYS = frozenset({"fields", "max_bytes"})


class CatalogError(ValueError):
    pass


@dataclass(frozen=True)
class Argument:
    name: str
    kind: str
    minimum: int | None = None
    maximum: int | None = None


@dataclass(frozen=True)
class KubernetesRequest:
    group: str
    version: str
    resource: str
    subresource: str | None
    verb: str
    query: Mapping[str, str]
    body: Any


@dataclass(frozen=True)
class CatalogOperation:
    name: str
    tool: str
    resource: str
    identity: str
    request: KubernetesRequest
    arguments: tuple[Argument, ...]
    response_fields: tuple[str, ...]
    max_response_bytes: int

    def argument(self, name: str) -> Argument | None:
        return next((item for item in self.arguments if item.name == name), None)


class OperationCatalog:
    def __init__(self, document: object) -> None:
        if not isinstance(document, dict) or set(document) != {"version", "target", "operations"}:
            raise CatalogError('a catalog must be an object with exactly "version", "target" and "operations"')
        if document["version"] != CATALOG_VERSION or isinstance(document["version"], bool):
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
    tool = item["tool"]
    if not isinstance(tool, str) or validate_entry(tool) or "*" in tool:
        raise CatalogError(f"{name}: tool must be an exact scope id")
    identity = _text(item, "identity", LABEL)
    arguments = _arguments(name, item["arguments"])
    request = _request(name, item["request"], arguments)
    resource = _resource_template(name, item["resource"], arguments)
    fields, max_bytes = _response(name, item["response"], request)
    _check_every_argument_used(name, arguments, request, resource)
    return CatalogOperation(name, tool, resource, identity, request, arguments, fields, max_bytes)


def _text(item: Mapping[str, Any], key: str, pattern: re.Pattern[str]) -> str:
    value = item[key]
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise CatalogError(f"{key} {value!r} is not valid")
    return value


def _arguments(operation: str, document: object) -> tuple[Argument, ...]:
    if not isinstance(document, dict):
        raise CatalogError(f"{operation}: arguments must be an object")
    arguments = []
    for name, spec in document.items():
        if not ARGUMENT_NAME.fullmatch(name):
            raise CatalogError(f"{operation}: argument name {name!r} is not valid")
        if not isinstance(spec, dict) or spec.get("kind") not in ("label", "integer"):
            raise CatalogError(f'{operation}: argument {name} must have kind "label" or "integer"')
        if spec["kind"] == "label":
            if set(spec) != {"kind"}:
                raise CatalogError(f"{operation}: label argument {name} takes no other fields")
            arguments.append(Argument(name, "label"))
            continue
        if set(spec) != {"kind", "minimum", "maximum"}:
            raise CatalogError(f"{operation}: integer argument {name} needs exactly minimum and maximum")
        minimum, maximum = spec["minimum"], spec["maximum"]
        if not all(isinstance(value, int) and not isinstance(value, bool) for value in (minimum, maximum)):
            raise CatalogError(f"{operation}: bounds of {name} must be integers")
        if not 0 <= minimum <= maximum <= 100_000:
            raise CatalogError(f"{operation}: bounds of {name} must satisfy 0 <= minimum <= maximum <= 100000")
        arguments.append(Argument(name, "integer", minimum, maximum))
    if "namespace" not in document or document["namespace"].get("kind") != "label":
        raise CatalogError(f"{operation}: a namespace label argument is required")
    return tuple(arguments)


def _request(operation: str, document: object, arguments: tuple[Argument, ...]) -> KubernetesRequest:
    if not isinstance(document, dict) or set(document) != REQUEST_KEYS:
        raise CatalogError(f"{operation}: request must have exactly the fields {', '.join(sorted(REQUEST_KEYS))}")
    group, version, resource = document["group"], document["version"], document["resource"]
    if not isinstance(group, str) or (group and not API_GROUP.fullmatch(group)):
        raise CatalogError(f"{operation}: request group is not valid")
    if not isinstance(version, str) or not API_VERSION.fullmatch(version):
        raise CatalogError(f"{operation}: request version is not valid")
    if not isinstance(resource, str) or not API_RESOURCE.fullmatch(resource):
        raise CatalogError(f"{operation}: request resource is not valid")
    subresource, verb = document["subresource"], document["verb"]
    if (verb, subresource) not in ALLOWED_CALLS:
        raise CatalogError(f"{operation}: verb {verb!r} with subresource {subresource!r} is not allowed")
    has_name = any(item.name == "name" and item.kind == "label" for item in arguments)
    if (verb == "list") == has_name:
        raise CatalogError(f"{operation}: a name label argument is required for {verb} and refused for list")
    query = document["query"]
    if not isinstance(query, dict) or not set(query) <= ALLOWED_CALLS[(verb, subresource)]:
        raise CatalogError(f"{operation}: query parameters are not allowed for this call")
    for parameter, value in query.items():
        _integer_slot(operation, f"query {parameter}", value, arguments)
    body = document["body"]
    if (verb == "patch") != (body is not None):
        raise CatalogError(f"{operation}: a body is required for patch and refused otherwise")
    if body is not None:
        _check_body(operation, body, arguments)
    return KubernetesRequest(group, version, resource, subresource, verb, dict(query), body)


def _integer_slot(operation: str, where: str, value: object, arguments: tuple[Argument, ...]) -> str:
    match = PLACEHOLDER.fullmatch(value) if isinstance(value, str) else None
    argument = next((item for item in arguments if match and item.name == match.group(1)), None)
    if argument is None or argument.kind != "integer":
        raise CatalogError(f"{operation}: {where} must be one integer argument placeholder")
    return argument.name


def _check_body(operation: str, body: object, arguments: tuple[Argument, ...]) -> None:
    if isinstance(body, dict):
        if not body:
            raise CatalogError(f"{operation}: body objects must not be empty")
        for key, value in body.items():
            if not FIELD_PATH.fullmatch(key) or "." in key:
                raise CatalogError(f"{operation}: body key {key!r} is not a plain field name")
            _check_body(operation, value, arguments)
        return
    _integer_slot(operation, "a body value", body, arguments)


def _resource_template(operation: str, template: object, arguments: tuple[Argument, ...]) -> str:
    if not isinstance(template, str):
        raise CatalogError(f"{operation}: resource must be a string")
    labels = {item.name for item in arguments if item.kind == "label"}
    filled = template
    for name in PLACEHOLDER.findall(template):
        if name not in labels:
            raise CatalogError(f"{operation}: resource placeholder {{{name}}} must be a label argument")
        filled = filled.replace(f"{{{name}}}", "x")
    if any(character in filled for character in "{}*") or validate_entry(filled):
        raise CatalogError(f"{operation}: resource template is not a concrete scope id")
    if "{namespace}" not in template:
        raise CatalogError(f"{operation}: resource must contain the namespace")
    return template


def _response(operation: str, document: object, request: KubernetesRequest) -> tuple[tuple[str, ...], int]:
    if not isinstance(document, dict) or set(document) != RESPONSE_KEYS:
        raise CatalogError(f"{operation}: response must have exactly fields and max_bytes")
    fields, max_bytes = document["fields"], document["max_bytes"]
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or not 0 < max_bytes <= MAX_RESPONSE_BYTES:
        raise CatalogError(f"{operation}: max_bytes must be between 1 and {MAX_RESPONSE_BYTES}")
    if not isinstance(fields, list) or not all(isinstance(item, str) and FIELD_PATH.fullmatch(item) for item in fields):
        raise CatalogError(f"{operation}: fields must be a list of dotted field paths")
    if (request.subresource == "log") != (not fields):
        raise CatalogError(f"{operation}: logs return text with no fields; every other call lists its fields")
    return tuple(fields), max_bytes


def _check_every_argument_used(
    operation: str, arguments: tuple[Argument, ...], request: KubernetesRequest, resource: str
) -> None:
    used = set(PLACEHOLDER.findall(resource)) | set(PATH_ARGUMENTS) & {item.name for item in arguments}
    for value in request.query.values():
        used |= _body_placeholders(value)
    used |= _body_placeholders(request.body)
    unused = {item.name for item in arguments} - used
    if unused:
        raise CatalogError(f"{operation}: arguments {', '.join(sorted(unused))} are not used")
    for item in arguments:
        if item.kind == "label" and item.name not in PATH_ARGUMENTS:
            raise CatalogError(f"{operation}: label argument {item.name} must be namespace or name")


def _body_placeholders(body: object) -> set[str]:
    if isinstance(body, dict):
        return set().union(*(_body_placeholders(value) for value in body.values()))
    if isinstance(body, str):
        match = PLACEHOLDER.fullmatch(body)
        return {match.group(1)} if match else set()
    return set()
