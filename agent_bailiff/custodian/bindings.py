from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any

from agent_warrant.scope import covers, validate_entry

from agent_bailiff.custodian.files import read_owned

BINDINGS_LABEL = "binding table"
MAX_BINDINGS_BYTES = 1 << 20
HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
TEXT_FIELDS = ("tenant", "tool", "resource", "credential_id", "target", "header_name")


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
        if not HEADER_NAME.fullmatch(self.header_name):
            raise BindingTableError("header_name must be an HTTP field name token")
        if not isinstance(self.canary, bool):
            raise BindingTableError("canary must be a bool")

    def matches(self, tenant: str, tool: str, resource: str) -> bool:
        scope = {"tools": [self.tool], "resources": [self.resource], "max_cost_per_call": 0}
        return self.tenant == tenant and covers(scope, tool, resource)


BINDING_FIELDS = frozenset(item.name for item in fields(CredentialBinding))


class BindingTable:
    def __init__(self, bindings: Iterable[CredentialBinding]) -> None:
        self._bindings = tuple(bindings)
        if not all(isinstance(item, CredentialBinding) for item in self._bindings):
            raise TypeError("bindings must be CredentialBinding records")

    @classmethod
    def load(cls, path: Path) -> BindingTable:
        content = read_owned(path, BINDINGS_LABEL, MAX_BINDINGS_BYTES)
        try:
            document = json.loads(content, object_pairs_hook=_unique_keys)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BindingTableError(f"the {BINDINGS_LABEL} is not valid JSON: {exc}") from None
        if (
            not isinstance(document, dict)
            or set(document) != {"bindings"}
            or not isinstance(document["bindings"], list)
        ):
            raise BindingTableError('the binding table must be an object with only a "bindings" list')
        return cls(_binding(item) for item in document["bindings"])

    @property
    def bindings(self) -> tuple[CredentialBinding, ...]:
        return self._bindings

    def resolve(self, tenant: str, tool: str, resource: str) -> CredentialBinding | None:
        matches = [item for item in self._bindings if item.matches(tenant, tool, resource)]
        return matches[0] if len(matches) == 1 else None


def _binding(item: object) -> CredentialBinding:
    if not isinstance(item, dict) or set(item) != BINDING_FIELDS:
        raise BindingTableError(f"each binding must have exactly the fields {', '.join(sorted(BINDING_FIELDS))}")
    return CredentialBinding(**item)


def _unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BindingTableError(f"duplicate key {key!r} in the {BINDINGS_LABEL}")
        result[key] = value
    return result
