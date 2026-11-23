"""The proxy's current task: the operator's task file plus the agent key its root is bound to."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from agent_bailiff.client import Holder
from agent_bailiff.proxy.agent_key import AgentKeyError, load_agent_key
from agent_bailiff.task.task_file import MAX_TASK_FILE_BYTES, TaskFile, TaskFileError


class NoTask(Exception):
    pass


class TaskUnavailable(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class TaskState:
    raw: bytes
    task: TaskFile
    holder: Holder

    @classmethod
    def load(cls, task_file: Path, key_dir: Path) -> TaskState:
        return cls.from_bytes(read_task_bytes(task_file), key_dir)

    @classmethod
    def from_bytes(cls, raw: bytes, key_dir: Path) -> TaskState:
        try:
            task = TaskFile.decode(raw)
        except TaskFileError as exc:
            raise TaskUnavailable(f"the task file is invalid: {exc}") from None
        try:
            key = load_agent_key(key_dir, task.root.subject)
        except AgentKeyError as exc:
            raise TaskUnavailable(f"no usable agent key for this task: {exc}") from None
        return cls(raw, task, Holder(task.root.encode(), (), key, task.decider_id))

    @property
    def subject(self) -> str:
        return self.task.root.subject

    def expired(self, now: int) -> bool:
        return now >= self.task.root.expires_at


def read_task_bytes(task_file: Path) -> bytes:
    try:
        fd = os.open(task_file, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        raise NoTask(f"no task file at {task_file}") from None
    except OSError as exc:
        raise TaskUnavailable(f"cannot open the task file {task_file}: {exc.strerror}") from None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise TaskUnavailable(f"the task file {task_file} is not a regular file")
        raw = os.read(fd, MAX_TASK_FILE_BYTES + 1)
    finally:
        os.close(fd)
    if len(raw) > MAX_TASK_FILE_BYTES:
        raise TaskUnavailable(f"the task file is larger than {MAX_TASK_FILE_BYTES} bytes")
    return raw
