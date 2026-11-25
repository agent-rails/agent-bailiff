"""Issues a task root bound to the agent's per-task key, records its grant and writes it to the task directory."""

from __future__ import annotations

import fcntl
import json
import os
import secrets
import stat
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from agent_warrant.identity import is_valid_public_key
from agent_warrant.scope import validate_scope
from agent_warrant.task_root import TaskRoot, issue_task_root
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_bailiff.custodian.files import OwnedFileError, commit_at, discard_at, replace_at, stage_at
from agent_bailiff.docket.client import UNACKNOWLEDGED, DocketError
from agent_bailiff.docket.entry import Record
from agent_bailiff.docket.grant import Grant
from agent_bailiff.scope_pattern import (
    RESOURCE_PATTERN_SUFFIX,
    TOOL_PATTERN_SUFFIX,
    is_bounded_resource,
    is_bounded_tool,
)
from agent_bailiff.strict_json import parse_strict_json
from agent_bailiff.task.task_file import MAX_TASK_FILE_BYTES, TASK_FILE_VERSION, TaskFile, TaskFileError, check_id

DEFAULT_TENANT = "quickstart"
DEFAULT_PRINCIPAL = "user:operator"
DEFAULT_TTL_SECONDS = 3600
MAX_TTL_SECONDS = 86_400
MAX_DELEGATION_DEPTH = 2
TASK_FILE_NAME = "task.json"
TASK_FILE_MODE = 0o644
PENDING_FILE_NAME = "task.json.pending"
PENDING_FILE_MODE = 0o600
PENDING_FIELDS = frozenset({"version", "grant_id", "task_root", "decider_id"})
FORBIDDEN_DIR_BITS = 0o022
SIGNATURE_PLACEHOLDER = "A" * 86


class TaskIssueError(Exception):
    pass


class GrantWriter(Protocol):
    def append(self, entry: Grant) -> Record: ...


@dataclass(frozen=True)
class IssuedTask:
    path: Path
    task: TaskFile
    grant_id: str


@dataclass(frozen=True)
class PendingTask:
    grant_id: str
    task: TaskFile

    def encode(self) -> bytes:
        document = {
            "version": TASK_FILE_VERSION,
            "grant_id": self.grant_id,
            "task_root": self.task.root.encode(),
            "decider_id": self.task.decider_id,
        }
        return (json.dumps(document, sort_keys=True) + "\n").encode()

    @classmethod
    def decode(cls, raw: bytes) -> PendingTask:
        try:
            document = parse_strict_json(raw)
        except (UnicodeDecodeError, ValueError) as exc:
            raise TaskFileError(f"not strict JSON: {exc}") from None
        if not isinstance(document, dict) or set(document) != PENDING_FIELDS:
            raise TaskFileError(f"it must have exactly the fields {', '.join(sorted(PENDING_FIELDS))}")
        version = document["version"]
        if isinstance(version, bool) or version != TASK_FILE_VERSION:
            raise TaskFileError(f"its version must be {TASK_FILE_VERSION}")
        if not isinstance(document["task_root"], str):
            raise TaskFileError("task_root must be a string")
        try:
            root = TaskRoot.decode(document["task_root"])
        except (TypeError, ValueError) as exc:
            raise TaskFileError(f"the task root does not decode: {exc}") from None
        return cls(check_id("grant_id", document["grant_id"]), TaskFile(root, document["decider_id"]))


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
        for permission in self.scope["permissions"]:
            for tool in permission["tools"]:
                if not is_bounded_tool(tool):
                    raise ValueError(f"scope: tool grant {tool} must be exact or end at {TOOL_PATTERN_SUFFIX}")
            for resource in permission["resources"]:
                if not is_bounded_resource(resource):
                    raise ValueError(
                        f"scope: resource grant {resource} must be exact or end at {RESOURCE_PATTERN_SUFFIX}"
                    )
        _check_integer("budget", self.budget, 1, None)
        _check_integer("ttl", self.ttl, 1, MAX_TTL_SECONDS)
        _check_integer("max_depth", self.max_depth, 0, MAX_DELEGATION_DEPTH)
        if not is_valid_public_key(self.subject):
            raise ValueError("subject must be the agent's public key as printed by proxy keygen")


def issue_task(issuer_key: Ed25519PrivateKey, issuer: str, decider_id: str, request: TaskRequest, now: int) -> TaskFile:
    fields: dict[str, Any] = {
        "issuer": issuer,
        "task_id": f"task-{secrets.token_hex(8)}",
        "tenant_id": request.tenant,
        "principal": request.principal,
        "purpose": request.purpose,
        "budget": request.budget,
        "max_depth": request.max_depth,
        "issued_at": now,
        "expires_at": now + request.ttl,
        "scope": request.scope,
        "subject": request.subject,
    }
    _check_task_file_size(TaskFile(TaskRoot(**fields, proof=SIGNATURE_PLACEHOLDER), decider_id))
    return TaskFile(issue_task_root(issuer_key, **fields), decider_id)


def _check_task_file_size(unsigned: TaskFile) -> None:
    try:
        unsigned.encode()
    except TaskFileError:
        raise ValueError(
            f"scope: the task file would exceed the {MAX_TASK_FILE_BYTES} byte limit; "
            "narrow the scope or split the work across tasks"
        ) from None


def write_task_file(out_dir: Path, task: TaskFile, docket: GrantWriter, now: int) -> IssuedTask:
    dir_fd = _open_task_dir(out_dir)
    try:
        _lock(dir_fd, out_dir)
        return _issue_locked(dir_fd, out_dir, task, docket, now)
    except OwnedFileError as exc:
        raise TaskIssueError(str(exc)) from None
    finally:
        os.close(dir_fd)


def _issue_locked(dir_fd: int, out_dir: Path, task: TaskFile, docket: GrantWriter, now: int) -> IssuedTask:
    current = _read_current(dir_fd, out_dir)
    pending = _read_pending(dir_fd, out_dir)
    if pending is not None and current is not None and current.root == pending.task.root:
        discard_at(dir_fd, PENDING_FILE_NAME)
        os.fsync(dir_fd)
        pending = None
    if current is not None and current.root.subject == task.root.subject:
        raise TaskIssueError(
            f"{out_dir / TASK_FILE_NAME} already holds a task for this agent key; "
            "run proxy keygen for a new key and issue to that"
        )
    resumed = pending is not None
    if pending is None:
        pending = PendingTask(uuid.uuid4().hex, task)
        replace_at(dir_fd, PENDING_FILE_NAME, "pending task file", pending.encode(), PENDING_FILE_MODE)
    else:
        _check_resumable(pending, task, out_dir, now)
    try:
        staged = stage_at(dir_fd, TASK_FILE_NAME, "task file", pending.task.encode(), TASK_FILE_MODE)
    except OwnedFileError as exc:
        raise _unrecorded(dir_fd, out_dir, pending, resumed, str(exc)) from None
    try:
        docket.append(Grant(pending.grant_id, now, pending.task.root.encode()))
    except DocketError as exc:
        discard_at(dir_fd, staged)
        if exc.reason in UNACKNOWLEDGED:
            raise TaskIssueError(
                f"docket did not acknowledge the grant ({exc}); grant may be recorded: grant_id {pending.grant_id}; "
                f"check docket grants; revoke via control; or rerun the same command to finish from "
                f"{out_dir / PENDING_FILE_NAME}"
            ) from None
        raise _unrecorded(dir_fd, out_dir, pending, resumed, f"docket refused the grant: {exc}") from None
    try:
        commit_at(dir_fd, staged, TASK_FILE_NAME, "task file")
        discard_at(dir_fd, PENDING_FILE_NAME)
        os.fsync(dir_fd)
    except (OwnedFileError, OSError) as exc:
        raise TaskIssueError(
            f"{exc}; grant recorded: grant_id {pending.grant_id}; task.json may be written; "
            f"rerun the same command to finish from {out_dir / PENDING_FILE_NAME}"
        ) from None
    return IssuedTask(out_dir / TASK_FILE_NAME, pending.task, pending.grant_id)


def _check_resumable(pending: PendingTask, task: TaskFile, out_dir: Path, now: int) -> None:
    path = out_dir / PENDING_FILE_NAME
    if _request_of(pending.task) != _request_of(task):
        raise TaskIssueError(
            f"{path} holds an unfinished issue of grant_id {pending.grant_id} for another request; "
            "rerun that command to finish it, or check docket grants, revoke via control and remove it"
        )
    if pending.task.root.expires_at <= now:
        raise TaskIssueError(
            f"{path} holds an unfinished issue whose root expired at {pending.task.root.expires_at}; "
            f"grant may be recorded: grant_id {pending.grant_id}; check docket grants; remove it to issue"
        )


def _request_of(task: TaskFile) -> tuple[Any, ...]:
    root = task.root
    return (
        task.decider_id,
        root.issuer,
        root.tenant_id,
        root.principal,
        root.purpose,
        root.budget,
        root.max_depth,
        root.scope,
        root.subject,
        root.expires_at - root.issued_at,
    )


def _unrecorded(dir_fd: int, out_dir: Path, pending: PendingTask, resumed: bool, problem: str) -> TaskIssueError:
    if resumed:
        return TaskIssueError(
            f"{problem}; an earlier run may have recorded grant_id {pending.grant_id}; "
            f"{out_dir / PENDING_FILE_NAME} kept, rerun the same command to finish"
        )
    discard_at(dir_fd, PENDING_FILE_NAME)
    return TaskIssueError(f"{problem}; no grant recorded, no task file written")


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
    raw = _read_at(dir_fd, out_dir, TASK_FILE_NAME, "current task file")
    if raw is None:
        return None
    try:
        return TaskFile.decode(raw)
    except TaskFileError as exc:
        raise TaskIssueError(f"{out_dir / TASK_FILE_NAME} is not a task file ({exc}); remove it to issue") from None


def _read_pending(dir_fd: int, out_dir: Path) -> PendingTask | None:
    raw = _read_at(dir_fd, out_dir, PENDING_FILE_NAME, "pending task file")
    if raw is None:
        return None
    if len(raw) > MAX_TASK_FILE_BYTES:
        raise TaskIssueError(f"{out_dir / PENDING_FILE_NAME} is larger than {MAX_TASK_FILE_BYTES} bytes")
    try:
        return PendingTask.decode(raw)
    except TaskFileError as exc:
        raise TaskIssueError(
            f"{out_dir / PENDING_FILE_NAME} is not a pending task file ({exc}); remove it to issue"
        ) from None


def _read_at(dir_fd: int, out_dir: Path, name: str, label: str) -> bytes | None:
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise TaskIssueError(f"cannot open the {label}: {exc.strerror}") from None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise TaskIssueError(f"{out_dir / name} is not a regular file")
        return os.read(fd, MAX_TASK_FILE_BYTES + 1)
    finally:
        os.close(fd)


def _check_integer(name: str, value: object, low: int, high: int | None) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < low or (high is not None and value > high):
        bound = f"at least {low}" if high is None else f"between {low} and {high}"
        raise ValueError(f"{name} must be an integer {bound}")
