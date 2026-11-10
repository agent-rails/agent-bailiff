from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from agent_warrant.canonical import MAX_SAFE_INTEGER


class CostError(Exception):
    pass


@dataclass(frozen=True)
class CostTable:
    version: int
    tools: Mapping[str, int | str]

    def __post_init__(self) -> None:
        if isinstance(self.version, bool) or not isinstance(self.version, int) or self.version < 0:
            raise ValueError("version must be a non-negative integer")
        for tool, rule in self.tools.items():
            if not isinstance(tool, str) or not tool:
                raise ValueError("tool names must be non-empty str")
            if isinstance(rule, bool) or not isinstance(rule, int | str):
                raise ValueError(f"cost rule for {tool!r} must be an integer or an argument name")
            if isinstance(rule, int) and not 0 <= rule <= MAX_SAFE_INTEGER:
                raise ValueError(f"cost for {tool!r} must be between 0 and {MAX_SAFE_INTEGER}")
            if isinstance(rule, str) and not rule:
                raise ValueError(f"argument name for {tool!r} must be non-empty")
        object.__setattr__(self, "tools", MappingProxyType(dict(self.tools)))

    def cost(self, tool: str, args: Mapping[str, Any]) -> int:
        if tool not in self.tools:
            raise CostError(f"tool {tool!r} is not in cost table v{self.version}")
        rule = self.tools[tool]
        if isinstance(rule, int):
            return rule
        value = args.get(rule)
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_SAFE_INTEGER:
            raise CostError(f"argument {rule!r} must be a non-negative integer to price {tool!r}")
        return value
