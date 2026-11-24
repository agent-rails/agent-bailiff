"""Issues a task root bound to the agent's per-task key and writes it to the operator-owned task directory."""

from __future__ import annotations

import fcntl
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent_warrant.identity import is_valid_public_key
from agent_warrant.scope import validate_scope
from agent_warrant.task_root import issue_task_root
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_bailiff.custodian.files import OwnedFileError, replace_at
from agent_bailiff.scope_pattern import (
    RESOURCE_PATTERN_SUFFIX,
    TOOL_PATTERN_SUFFIX,
    is_bounded_resource,
    is_bounded_tool,
)
from agent_bailiff.task.task_file import MAX_TASK_FILE_BYTES, TaskFile, TaskFileError, check_id

DEFAULT_TENANT = "quickstart"
DEFAULT_PRINCIPAL = "user:operator"
DEFAULT_TTL_SECONDS = 3600
MAX_TTL_SECONDS = 86_400
MAX_DELEGATION_DEPTH = 2
TASK_FILE_NAME = "task.json"
TASK_FILE_MODE = 0o644
FORBIDDEN_DIR_BITS = 0o022


class TaskIssueError(Exception):
    pass


@dataclass(frozen=True)
class TaskRequest:
    purpose: str
    scope: dict[str, Any]
    budget: int
    subject: str
    tenant: str = DEFAULT_TENANT
    principal: str = DEFAULT_PRINCIPAL
    ttl: int = DEFAULT_TTL_SECONDS
    max_depth: int = 0

    def __post_init__(self) -> None:
        for name in ("tenant", "principal", "purpose"):
            check_id(name, getattr(self, name))
        refusal = validate_scope(self.scope)
        if refusal:
            raise ValueError(f"scope: {refusal}")
        for tool in self.scope["tools"]:
            if not is_bounded_tool(tool):
                raise ValueError(f"scope: tool grant {tool} must be exact or end at {TOOL_PATTERN_SUFFIX}")
        for resource in self.scope["resources"]:
            if not is_bounded_resource(resource):
                raise ValueError(f"scope: resource grant {resource} must be exact or end at {RESOURCE_PATTERN_SUFFIX}")
        _check_integer("budget", self.budget, 1, None)
        _check_integer("ttl", self.ttl, 1, MAX_TTL_SECONDS)
        _check_integer("max_depth", self.max_depth, 0, MAX_DELEGATION_DEPTH)
        if not is_valid_public_key(self.subject):
            raise ValueError("subject must be the agent's public key as printed by proxy keygen")


def issue_task(issuer_key: Ed25519PrivateKey, issuer: str, decider_id: str, request: TaskRequest, now: int) -> TaskFile:
    root = issue_task_root(
        issuer_key,
        issuer=issuer,
        task_id=f"task-{secrets.token_hex(8)}",
        tenant_id=request.tenant,
        principal=request.principal,
        purpose=request.purpose,
        budget=request.budget,
        max_depth=request.max_depth,
        issued_at=now,
        expires_at=now + request.ttl,
        scope=request.scope,
        subject=request.subject,
    )
    return TaskFile(root, decider_id)


def write_task_file(out_dir: Path, task: TaskFile) -> Path:
    content = task.encode()
    dir_fd = _open_task_dir(out_dir)
    try:
        _lock(dir_fd, out_dir)
        current = _read_current(dir_fd, out_dir)
        if current is not None and current.root.subject == task.root.subject:
            raise TaskIssueError(
                f"{out_dir / TASK_FILE_NAME} already holds a task for this agent key; "
                "run proxy keygen for a new key and issue to that"
            )
        replace_at(dir_fd, TASK_FILE_NAME, "task file", content, TASK_FILE_MODE)
    except OwnedFileError as exc:
        raise TaskIssueError(str(exc)) from None
    finally:
        os.close(dir_fd)
    return out_dir / TASK_FILE_NAME


def _lock(dir_fd: int, out_dir: Path) -> None:
    try:
        fcntl.flock(dir_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise TaskIssueError(f"another task issue is running in {out_dir}; retry when it finishes") from None


def _open_task_dir(out_dir: Path) -> int:
    try:
        dir_fd = os.open(out_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        raise TaskIssueError(f"cannot open the task directory {out_dir}: {exc.strerror}") from None
    info = os.fstat(dir_fd)
    if info.st_uid != os.geteuid() or info.st_mode & FORBIDDEN_DIR_BITS:
        os.close(dir_fd)
        raise TaskIssueError(
            f"the task directory {out_dir} must be owned by uid {os.geteuid()} and not writable by group or others"
        )
    return dir_fd


def _read_current(dir_fd: int, out_dir: Path) -> TaskFile | None:
    try:
        fd = os.open(TASK_FILE_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise TaskIssueError(f"cannot open the current task file: {exc.strerror}") from None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise TaskIssueError(f"{out_dir / TASK_FILE_NAME} is not a regular file")
        raw = os.read(fd, MAX_TASK_FILE_BYTES + 1)
    finally:
        os.close(fd)
    try:
        return TaskFile.decode(raw)
    except TaskFileError as exc:
        raise TaskIssueError(f"{out_dir / TASK_FILE_NAME} is not a task file ({exc}); remove it to issue") from None


def _check_integer(name: str, value: object, low: int, high: int | None) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < low or (high is not None and value > high):
        bound = f"at least {low}" if high is None else f"between {low} and {high}"
        raise ValueError(f"{name} must be an integer {bound}")
