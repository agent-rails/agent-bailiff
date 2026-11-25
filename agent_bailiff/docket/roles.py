from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass


@dataclass(frozen=True)
class WriterRoles:
    writers: Mapping[str, frozenset[str]]

    def __post_init__(self) -> None:
        holders: dict[str, str] = {}
        for hop, names in sorted(self.writers.items()):
            if not names:
                raise ValueError(f"no writer is pinned for hop {hop}")
            for name in sorted(names):
                if name in holders:
                    raise ValueError(f"writer {name} is pinned for both hops {holders[name]} and {hop}")
                holders[name] = hop

    def reads(self, hop: str) -> bool:
        return hop in self.writers

    def holds(self, writer: str, hop: str) -> bool:
        return writer in self.writers.get(hop, frozenset())
