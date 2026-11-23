"""The task file: version 1 wire format the operator's task issue writes and the agent's proxy reads."""

from __future__ import annotations

import json
from dataclasses import dataclass

from agent_warrant.task_root import TaskRoot

from agent_bailiff.strict_json import parse_strict_json

TASK_FILE_VERSION = 1
MAX_TASK_FILE_BYTES = 4096
MAX_ID_CHARACTERS = 256
TASK_FILE_FIELDS = frozenset({"version", "task_id", "task_root", "decider_id", "expires_at"})


class TaskFileError(ValueError):
    pass


@dataclass(frozen=True)
class TaskFile:
    root: TaskRoot
    decider_id: str

    def __post_init__(self) -> None:
        check_id("decider_id", self.decider_id)

    def encode(self) -> bytes:
        document = {
            "version": TASK_FILE_VERSION,
            "task_id": self.root.task_id,
            "task_root": self.root.encode(),
            "decider_id": self.decider_id,
            "expires_at": self.root.expires_at,
        }
        encoded = (json.dumps(document, sort_keys=True) + "\n").encode()
        if len(encoded) > MAX_TASK_FILE_BYTES:
            raise TaskFileError(f"the task file would be larger than {MAX_TASK_FILE_BYTES} bytes")
        return encoded

    @classmethod
    def decode(cls, raw: bytes) -> TaskFile:
        if len(raw) > MAX_TASK_FILE_BYTES:
            raise TaskFileError(f"the task file is larger than {MAX_TASK_FILE_BYTES} bytes")
        try:
            document = parse_strict_json(raw)
        except (UnicodeDecodeError, ValueError) as exc:
            raise TaskFileError(f"the task file is not strict JSON: {exc}") from None
        if not isinstance(document, dict) or set(document) != TASK_FILE_FIELDS:
            raise TaskFileError(f"the task file must have exactly the fields {', '.join(sorted(TASK_FILE_FIELDS))}")
        version = document["version"]
        if isinstance(version, bool) or version != TASK_FILE_VERSION:
            raise TaskFileError(f"the task file version must be {TASK_FILE_VERSION}")
        if not isinstance(document["task_root"], str):
            raise TaskFileError("task_root must be a string")
        try:
            root = TaskRoot.decode(document["task_root"])
        except (TypeError, ValueError) as exc:
            raise TaskFileError(f"the task root does not decode: {exc}") from None
        if isinstance(document["expires_at"], bool):
            raise TaskFileError("expires_at must be an integer")
        if document["task_id"] != root.task_id or document["expires_at"] != root.expires_at:
            raise TaskFileError("task_id and expires_at must match the task root")
        return cls(root, document["decider_id"])


def check_id(name: str, value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_ID_CHARACTERS:
        raise TaskFileError(f"{name} must be a non-empty string of at most {MAX_ID_CHARACTERS} characters")
    if not all("!" <= character <= "~" for character in value):
        raise TaskFileError(f"{name} must be ASCII printable without whitespace")
    return value
