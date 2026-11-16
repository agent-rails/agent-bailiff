from __future__ import annotations

import json
from typing import Any


def parse_strict_json(raw: bytes | str) -> Any:
    return json.loads(raw, object_pairs_hook=_unique_keys, parse_constant=_no_constant)


def _unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key {key!r}")
        result[key] = value
    return result


def _no_constant(name: str) -> Any:
    raise ValueError(f"{name} is not valid JSON")
