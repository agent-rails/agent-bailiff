from __future__ import annotations

from collections.abc import Sequence

from agent_warrant.chain import ChainLink
from agent_warrant.scope import Permission, check_call
from agent_warrant.task_root import TaskRoot

RESOURCE_PATTERN_SUFFIX = "/*"
TOOL_PATTERN_SUFFIX = ".*"


def is_bounded_resource(entry: str) -> bool:
    return "*" not in entry or entry.endswith(RESOURCE_PATTERN_SUFFIX)


def is_bounded_tool(entry: str) -> bool:
    return "*" not in entry or entry.endswith(TOOL_PATTERN_SUFFIX)


def is_bounded_scope(permissions: tuple[Permission, ...]) -> bool:
    return all(
        all(is_bounded_tool(pattern) for pattern in permission.tools)
        and all(is_bounded_resource(pattern) for pattern in permission.resources)
        for permission in permissions
    )


def scope_refusal(records: Sequence[TaskRoot | ChainLink], tool: str, resource: str, cost: int) -> str | None:
    if not records:
        raise ValueError("records must hold the task root and its links")
    if not all(is_bounded_scope(record.permissions) for record in records):
        return "unbounded_scope"
    refusal = check_call(records[-1].permissions, tool, resource, cost)
    return None if refusal is None else refusal.value
