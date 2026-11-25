from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

GRANT_TYP = "agent-bailiff/docket-grant/v1"
MAX_ROOT_TOKEN_CHARS = 16384
GRANT_FIELDS = frozenset({"grant_id", "at", "root_token"})


@dataclass(frozen=True)
class Grant:
    grant_id: str
    at: int
    root_token: str


def grant_body(grant: Grant) -> dict[str, Any]:
    return {"grant_id": grant.grant_id, "at": grant.at, "root_token": grant.root_token}


def check_grant_body(body: Mapping[str, Any]) -> None:
    grant_id = body["grant_id"]
    if not isinstance(grant_id, str) or not grant_id:
        raise ValueError("grant_id must be a non-empty str")
    at = body["at"]
    if not isinstance(at, int) or isinstance(at, bool) or at < 0:
        raise ValueError("at must be a non-negative integer")
    root_token = body["root_token"]
    if not isinstance(root_token, str) or not root_token.isascii() or not 1 <= len(root_token) <= MAX_ROOT_TOKEN_CHARS:
        raise ValueError(f"root_token must be an ASCII str of 1 to {MAX_ROOT_TOKEN_CHARS} characters")
