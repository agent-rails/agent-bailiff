from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agent_warrant.scope import validate_entry

from agent_bailiff.decide.identity import args_problem, request_digest

MAX_LINKS = 16
MAX_NONCE_CHARACTERS = 64


@dataclass(frozen=True)
class OperationRequest:
    tool: str
    resource: str
    args: dict[str, Any]
    nonce: str
    task_root: str
    links: tuple[str, ...]
    leaf_proof: str
    trace_id: str
    audience: str

    def digest(self) -> str:
        return request_digest(self.tool, self.resource, self.args, self.nonce)

    def refusal(self) -> str | None:
        for name in ("tool", "resource"):
            value = getattr(self, name)
            problem = validate_entry(value)
            if problem or "*" in value:
                return f"{name} must be a concrete id: {problem or 'no wildcards'}"
        problem = args_problem(self.args)
        if problem:
            return f"args: {problem}"
        nonce = self.nonce
        if not isinstance(nonce, str) or not 0 < len(nonce) <= MAX_NONCE_CHARACTERS:
            return f"nonce must be a non-empty str of at most {MAX_NONCE_CHARACTERS} characters"
        if not all("!" <= character <= "~" for character in nonce):
            return "nonce must be ASCII printable without whitespace"
        links = self.links
        if not isinstance(links, tuple) or len(links) > MAX_LINKS or not all(isinstance(item, str) for item in links):
            return f"links must be a tuple of at most {MAX_LINKS} str"
        for name in ("task_root", "leaf_proof", "trace_id", "audience"):
            if not isinstance(getattr(self, name), str):
                return f"{name} must be a str"
        return None
