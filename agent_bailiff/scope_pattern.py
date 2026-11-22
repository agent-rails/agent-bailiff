from __future__ import annotations

SEGMENT_PATTERN_SUFFIX = "/*"


def is_bounded(entry: str) -> bool:
    return "*" not in entry or entry.endswith(SEGMENT_PATTERN_SUFFIX)
