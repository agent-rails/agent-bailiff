from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, fields
from pathlib import Path

from agent_warrant.scope import covers, validate_entry

from agent_bailiff.custodian.files import read_owned
from agent_bailiff.scope_pattern import is_bounded
from agent_bailiff.strict_json import parse_strict_json

BINDINGS_LABEL = "binding table"
MAX_BINDINGS_BYTES = 1 << 20
HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
TEXT_FIELDS = ("tenant", "tool", "resource", "credential_id", "target", "header_name")
CATALOG_DIGEST = re.compile(r"[A-Za-z0-9_-]{43}")


class BindingTableError(ValueError):
    pass


@dataclass(frozen=True)
class CredentialBinding:
    tenant: str
    tool: str
    resource: str
    credential_id: str
    target: str
    header_name: str
    canary: bool

    def __post_init__(self) -> None:
        for name in TEXT_FIELDS:
            value = getattr(self, name)
            if not isinstance(value, str) or not value or not all("!" <= character <= "~" for character in value):
                raise BindingTableError(f"{name} must be a non-empty ASCII printable str without whitespace")
        if validate_entry(self.tool) or "*" in self.tool:
            raise BindingTableError("tool must be an exact scope id")
        reason = validate_entry(self.resource)
        if reason:
            raise BindingTableError(f"resource is not a valid scope entry: {reason}")
        if not is_bounded(self.resource):
            raise BindingTableError("resource pattern must end at /")
        if not HEADER_NAME.fullmatch(self.header_name):
            raise BindingTableError("header_name must be an HTTP field name token")
        if not isinstance(self.canary, bool):
            raise BindingTableError("canary must be a bool")

    def matches(self, tenant: str, tool: str, resource: str) -> bool:
        scope = {"tools": [self.tool], "resources": [self.resource], "max_cost_per_call": 0}
        return self.tenant == tenant and covers(scope, tool, resource)


BINDING_FIELDS = frozenset(item.name for item in fields(CredentialBinding))


@dataclass(frozen=True)
class EffectorBinding:
    tenant: str
    tool: str
    resource: str
    credential_id: str
    target: str
    catalog: str

    def __post_init__(self) -> None:
        for name in ("tenant", "tool", "resource", "credential_id", "target"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value or not all("!" <= character <= "~" for character in value):
                raise BindingTableError(f"{name} must be a non-empty ASCII printable str without whitespace")
        if validate_entry(self.tool) or "*" in self.tool:
            raise BindingTableError("tool must be an exact scope id")
        reason = validate_entry(self.resource)
        if reason:
            raise BindingTableError(f"resource is not a valid scope entry: {reason}")
        if not is_bounded(self.resource):
            raise BindingTableError("resource pattern must end at /")
        if not isinstance(self.catalog, str) or not CATALOG_DIGEST.fullmatch(self.catalog):
            raise BindingTableError("catalog must be the effector catalog digest")

    def matches(self, tenant: str, tool: str, resource: str) -> bool:
        scope = {"tools": [self.tool], "resources": [self.resource], "max_cost_per_call": 0}
        return self.tenant == tenant and covers(scope, tool, resource)


EFFECTOR_BINDING_FIELDS = frozenset(item.name for item in fields(EffectorBinding))
Binding = CredentialBinding | EffectorBinding


class BindingTable:
    def __init__(self, bindings: Iterable[Binding]) -> None:
        self._bindings = tuple(bindings)
        if not all(isinstance(item, (CredentialBinding, EffectorBinding)) for item in self._bindings):
            raise TypeError("bindings must be CredentialBinding or EffectorBinding records")
        self._by_tool: dict[tuple[str, str], list[Binding]] = {}
        for item in self._bindings:
            self._by_tool.setdefault((item.tenant, item.tool), []).append(item)

    @classmethod
    def load(cls, path: Path) -> BindingTable:
        content = read_owned(path, BINDINGS_LABEL, MAX_BINDINGS_BYTES)
        try:
            document = parse_strict_json(content)
        except (UnicodeDecodeError, ValueError) as exc:
            raise BindingTableError(f"the {BINDINGS_LABEL} is not valid JSON: {exc}") from None
        if (
            not isinstance(document, dict)
            or set(document) != {"bindings"}
            or not isinstance(document["bindings"], list)
        ):
            raise BindingTableError('the binding table must be an object with only a "bindings" list')
        return cls(_binding(item) for item in document["bindings"])

    @property
    def bindings(self) -> tuple[Binding, ...]:
        return self._bindings

    @property
    def credential_bindings(self) -> tuple[CredentialBinding, ...]:
        return tuple(item for item in self._bindings if isinstance(item, CredentialBinding))

    def resolve(self, tenant: str, tool: str, resource: str) -> Binding | None:
        if not isinstance(tenant, str) or not isinstance(tool, str):
            return None
        candidates = self._by_tool.get((tenant, tool), ())
        matches = [item for item in candidates if item.matches(tenant, tool, resource)]
        return matches[0] if len(matches) == 1 else None


def _binding(item: object) -> Binding:
    if isinstance(item, dict) and set(item) == EFFECTOR_BINDING_FIELDS:
        return EffectorBinding(**item)
    if not isinstance(item, dict) or set(item) != BINDING_FIELDS:
        raise BindingTableError(
            f"each binding must have exactly the fields {', '.join(sorted(BINDING_FIELDS))} "
            f"or {', '.join(sorted(EFFECTOR_BINDING_FIELDS))}"
        )
    return CredentialBinding(**item)
