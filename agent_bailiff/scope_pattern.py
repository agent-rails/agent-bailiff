from __future__ import annotations

RESOURCE_PATTERN_SUFFIX = "/*"


def is_bounded_resource(entry: str) -> bool:
    return "*" not in entry or entry.endswith(RESOURCE_PATTERN_SUFFIX)
