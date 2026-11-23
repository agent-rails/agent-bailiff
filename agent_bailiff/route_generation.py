"""Drafts a route table from an upstream's tools/list. Tool names are untrusted upstream input, so each becomes a
concrete scope id or is rejected; resources are left empty for the owner to fill, never guessed."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent_warrant.scope import validate_entry

from agent_bailiff.effector.catalog import CATALOG_TOOL_PREFIX

GENERATED_MODE = 0o644
MAX_TOOLS_BYTES = 4 * 1024 * 1024
DUPLICATE = "the upstream lists this name more than once"


@dataclass(frozen=True)
class Rejected:
    name: str
    reason: str


def generate_routes(tools: object, service: str) -> tuple[dict[str, Any], list[Rejected]]:
    if not isinstance(tools, dict) or set(tools) != {"tools"} or not isinstance(tools["tools"], list):
        raise ValueError('the tools document must be an object with exactly a "tools" list')
    problem = service_problem(service)
    if problem:
        raise ValueError(problem)
    names: set[str] = set()
    rejected: list[Rejected] = []
    for item in tools["tools"]:
        name = item.get("name") if isinstance(item, dict) else None
        if not isinstance(name, str):
            rejected.append(Rejected(repr(name)[:80], "the tool has no string name"))
            continue
        reason = name_problem(service, name, names)
        if reason:
            rejected.append(Rejected(name[:80], reason))
            continue
        names.add(name)
    duplicates = {item.name for item in rejected if item.reason == DUPLICATE}
    routes = [
        {"service": service, "name": name, "tool": f"{service}.{name}", "resource": ""}
        for name in sorted(names)
        if name not in duplicates
    ]
    return {"routes": routes}, rejected


def service_problem(service: str) -> str | None:
    if f"{service}.".startswith(CATALOG_TOOL_PREFIX):
        return f"{CATALOG_TOOL_PREFIX}* tools are routed only from their catalog"
    if not service or not all("!" <= character <= "~" for character in service) or "*" in service:
        return "the service must be a non-empty ASCII printable name without whitespace or wildcards"
    return None


def name_problem(service: str, name: str, accepted: set[str]) -> str | None:
    if name in accepted:
        return DUPLICATE
    if not name or not all("!" <= character <= "~" for character in name):
        return "the name is not ASCII printable without whitespace"
    if "*" in name:
        return "the name contains a wildcard"
    problem = validate_entry(f"{service}.{name}")
    return f"the name is not a scope id: {problem}" if problem else None


def write_new(path: Path, content: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, GENERATED_MODE)
    try:
        written = os.write(fd, content)
        if written != len(content):
            raise OSError(f"wrote {written} of {len(content)} bytes to {path}")
        os.fsync(fd)
    except OSError:
        os.close(fd)
        os.unlink(path)
        raise
    os.close(fd)
