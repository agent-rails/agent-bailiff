from __future__ import annotations

from typing import Any

RESOURCE_PATTERN_SUFFIX = "/*"
TOOL_PATTERN_SUFFIX = ".*"


def is_bounded_resource(entry: str) -> bool:
    return "*" not in entry or entry.endswith(RESOURCE_PATTERN_SUFFIX)


def is_bounded_tool(entry: str) -> bool:
    return "*" not in entry or entry.endswith(TOOL_PATTERN_SUFFIX)


def is_bounded_scope(scope: dict[str, Any]) -> bool:
    return all(is_bounded_tool(pattern) for pattern in scope["tools"]) and all(
        is_bounded_resource(pattern) for pattern in scope["resources"]
    )
