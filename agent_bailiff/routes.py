from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from agent_warrant.scope import validate_entry

from agent_bailiff.effector.catalog import CATALOG_TOOL_PREFIX, Argument, OperationCatalog, shipped_catalog

PLACEHOLDER = re.compile(r"\{([a-z][A-Za-z0-9]{0,31})\}")


@dataclass(frozen=True)
class ToolRoute:
    service: str
    name: str
    tool: str
    resource: str
    schema: tuple[Argument, ...] | None = None
    strict: bool = True

    def __post_init__(self) -> None:
        for name in ("service", "name", "tool", "resource"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value or not all("!" <= character <= "~" for character in value):
                raise ValueError(f"{name} must be a non-empty ASCII printable str without whitespace")
        problem = validate_entry(self.tool)
        if problem or "*" in self.tool:
            raise ValueError(f"tool must be a concrete scope id: {problem or 'no wildcards'}")
        if not isinstance(self.strict, bool):
            raise ValueError("strict must be a bool")
        placeholders = set(PLACEHOLDER.findall(self.resource))
        if self.schema is None and placeholders:
            raise ValueError("a resource template needs an argument schema")
        if (self.schema is None or not self.strict) and self.tool.startswith(CATALOG_TOOL_PREFIX):
            raise ValueError(f"{CATALOG_TOOL_PREFIX}* tools are routed only from their catalog")
        if self.schema is not None:
            object.__setattr__(self, "schema", tuple(self.schema))
            _check_schema(self.schema, self.resource, self.strict)
        filled = PLACEHOLDER.sub("x", self.resource)
        problem = validate_entry(filled)
        if problem or any(character in filled for character in "*{}"):
            raise ValueError(f"resource must be a concrete scope id or template: {problem or 'no wildcards'}")

    def resource_for(self, arguments: dict[str, Any]) -> str | None:
        if self.schema is None:
            return self.resource
        names = {item.name for item in self.schema}
        if self.strict and set(arguments) != names:
            return None
        if not names <= set(arguments):
            return None
        if not all(item.accepts(arguments[item.name]) for item in self.schema):
            return None
        resource = PLACEHOLDER.sub(lambda match: str(arguments[match.group(1)]), self.resource)
        return None if validate_entry(resource) else resource


def _check_schema(schema: tuple[Argument, ...], resource: str, strict: bool) -> None:
    placeholders = set(PLACEHOLDER.findall(resource))
    if any("{" in segment and not PLACEHOLDER.fullmatch(segment) for segment in resource.split("/")):
        raise ValueError("a resource placeholder must be a whole resource segment")
    if strict:
        labels = {item.name for item in schema if item.kind == "label"}
        if not placeholders <= labels:
            raise ValueError("every resource placeholder must be a label argument in the schema")
        return
    if not all(isinstance(item, Argument) and item.kind == "identifier" for item in schema):
        raise ValueError("a route document schema names identifier arguments only")
    names = [item.name for item in schema]
    if len(set(names)) != len(names):
        raise ValueError("a route document schema names each argument once")
    if set(names) != placeholders:
        raise ValueError("a route document schema names exactly the resource placeholders")


def _document_route(item: object) -> ToolRoute:
    if not isinstance(item, dict) or not DOCUMENT_ROUTE_FIELDS <= set(item) <= DOCUMENT_ROUTE_KEYS:
        raise ValueError(
            f"each route must have exactly the fields {', '.join(sorted(DOCUMENT_ROUTE_FIELDS))}"
            f" and optionally {DOCUMENT_SCHEMA_FIELD}"
        )
    fields = {key: item[key] for key in DOCUMENT_ROUTE_FIELDS}
    schema = _document_schema(item[DOCUMENT_SCHEMA_FIELD]) if DOCUMENT_SCHEMA_FIELD in item else None
    return ToolRoute(**fields, schema=schema, strict=False)


def _document_schema(document: object) -> tuple[Argument, ...]:
    if not isinstance(document, list):
        raise ValueError("a route schema must be a list")
    arguments = []
    for item in document:
        if not isinstance(item, dict) or set(item) != SCHEMA_ITEM_FIELDS:
            raise ValueError("each schema item must have exactly the fields kind, name")
        if not isinstance(item["name"], str) or not isinstance(item["kind"], str):
            raise ValueError("a schema item's name and kind must be strings")
        arguments.append(Argument(item["name"], item["kind"]))
    return tuple(arguments)


DOCUMENT_ROUTE_FIELDS = frozenset({"service", "name", "tool", "resource"})
DOCUMENT_SCHEMA_FIELD = "schema"
SCHEMA_ITEM_FIELDS = frozenset({"name", "kind"})
DOCUMENT_ROUTE_KEYS = DOCUMENT_ROUTE_FIELDS | {DOCUMENT_SCHEMA_FIELD}
DOCUMENT_CATALOG_FIELDS = frozenset({"service", "name"})


class ToolRoutes:
    def __init__(self, routes: Iterable[ToolRoute]) -> None:
        table: dict[tuple[str, str], ToolRoute] = {}
        operations: set[tuple[str, str]] = set()
        for route in routes:
            if not isinstance(route, ToolRoute):
                raise TypeError("routes must be ToolRoute records")
            key = (route.service, route.name)
            if key in table:
                raise ValueError(f"duplicate route for tool {route.name!r} on service {route.service!r}")
            operation = (route.tool, route.resource)
            if operation in operations:
                raise ValueError(f"tool {route.tool!r} on resource {route.resource!r} is routed more than once")
            table[key] = route
            operations.add(operation)
        self._table = table

    @classmethod
    def from_document(cls, document: object) -> ToolRoutes:
        if (
            not isinstance(document, dict)
            or not {"routes"} <= set(document) <= {"routes", "catalogs"}
            or not isinstance(document["routes"], list)
            or not isinstance(document.get("catalogs", []), list)
        ):
            raise ValueError('a route document must be an object with a "routes" list and optionally a "catalogs" list')
        routes = []
        for index, item in enumerate(document["routes"]):
            name = item.get("name") if isinstance(item, dict) else None
            try:
                routes.append(_document_route(item))
            except ValueError as error:
                raise ValueError(f"route {index} ({name!r}): {error}") from None
        for item in document.get("catalogs", []):
            if not isinstance(item, dict) or set(item) != DOCUMENT_CATALOG_FIELDS:
                raise ValueError("each catalog must have exactly the fields name, service")
            if not isinstance(item["service"], str) or not isinstance(item["name"], str):
                raise ValueError("a catalog's service and name must be strings")
            catalog = OperationCatalog.load(shipped_catalog(item["name"]))
            routes.extend(
                ToolRoute(item["service"], operation.name, operation.tool, operation.resource, operation.arguments)
                for operation in catalog.operations
            )
        return cls(routes)

    @property
    def services(self) -> frozenset[str]:
        return frozenset(service for service, _ in self._table)

    @property
    def catalog_services(self) -> frozenset[str]:
        return frozenset(
            service for (service, _), route in self._table.items() if route.tool.startswith(CATALOG_TOOL_PREFIX)
        )

    def route(self, service: str, name: str) -> ToolRoute | None:
        return self._table.get((service, name))


def routes_from_catalog(service: str, catalog: OperationCatalog) -> ToolRoutes:
    return ToolRoutes(
        ToolRoute(service, item.name, item.tool, item.resource, item.arguments) for item in catalog.operations
    )
