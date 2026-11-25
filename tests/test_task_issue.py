import errno
import fcntl
import json
import os
import re
import shutil
import stat
import tempfile
from pathlib import Path

import pytest
from agent_warrant.encoding import b64u_decode
from agent_warrant.identity import encode_public_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_docket import RunningSink

from agent_bailiff.cli import main
from agent_bailiff.custodian import files
from agent_bailiff.docket import DocketError, DocketSink, Grant, decode_record
from agent_bailiff.docket import client as client_module
from agent_bailiff.docket.sink import build_kid_index
from agent_bailiff.keys import generate_signing_key
from agent_bailiff.task import issue as issue_module
from agent_bailiff.task.issue import PendingTask, TaskIssueError, TaskRequest, issue_task, write_task_file
from agent_bailiff.task.task_file import TaskFile

NOW = 1_800_000_000
ISSUER = "issuer.quickstart"
DECIDER = "decide.quickstart"
PERMISSION = {"tools": ["gitea.list_issues"], "resources": ["repo:demo/*"], "max_cost_per_call": 1}
SCOPE = {"permissions": [PERMISSION]}
SCOPE_TEXT = json.dumps(SCOPE)
ISSUER_KEY = Ed25519PrivateKey.generate()
MAX_BOUND_SCOPE = {
    "permissions": [
        {
            "tools": [f"tool.{index:02d}.{side}{'t' * 118}" for side in "ab"],
            "resources": [f"repo/{index:02d}/{side}{'r' * 118}" for side in "ab"],
            "max_cost_per_call": 9_007_199_254_740_991,
        }
        for index in range(16)
    ]
}
TWO_PERMISSIONS_TWENTY_REPOS = {
    "permissions": [
        {
            "tools": ["gitea.issues.list", "gitea.issues.read"],
            "resources": [f"gitea/repos/acme/service-{index:02d}/*" for index in range(10)],
            "max_cost_per_call": 1,
        },
        {
            "tools": ["gitea.issues.comment"],
            "resources": [f"gitea/repos/acme/service-{index:02d}/*" for index in range(10, 20)],
            "max_cost_per_call": 2,
        },
    ]
}
SIXTEEN_SINGLE_PAIRS = {
    "permissions": [
        {
            "tools": [f"gitea.issues.op{index:02d}"],
            "resources": [f"gitea/repos/acme/service-{index:02d}/*"],
            "max_cost_per_call": 1,
        }
        for index in range(16)
    ]
}


GRANT_WRITER = "issuer.docket"


class Crash(BaseException):
    pass


class FakeDocket:
    def __init__(self, out_dir, refuse=None, record_then=None):
        self.out_dir = out_dir
        self.refuse = refuse
        self.record_then = record_then
        self.grants = []
        self.files_at_append = []

    def append(self, grant):
        self.files_at_append.append(
            {name: (self.out_dir / name).read_bytes() for name in sorted(os.listdir(self.out_dir))}
        )
        if self.refuse is not None:
            raise DocketError(self.refuse)
        self.grants.append(grant)
        if self.record_then is not None:
            raise self.record_then


def write(out_dir, task, docket=None, now=NOW):
    return write_task_file(out_dir, task, FakeDocket(out_dir) if docket is None else docket, now)


def pending_of(out_dir):
    return PendingTask.decode((out_dir / "task.json.pending").read_bytes())


def current(out_dir):
    return TaskFile.decode((out_dir / "task.json").read_bytes())


def new_subject():
    return encode_public_key(Ed25519PrivateKey.generate().public_key())


def dash_subject():
    for _ in range(10_000):
        subject = new_subject()
        if subject.startswith("-"):
            return subject
    raise AssertionError("no public key starting with a dash in 10000 tries")


def request(**overrides):
    fields = {"purpose": "triage", "scope": SCOPE, "budget": 10, "subject": new_subject()} | overrides
    return TaskRequest(**fields)


def issued(**overrides):
    return issue_task(ISSUER_KEY, ISSUER, DECIDER, request(**overrides), NOW)


@pytest.fixture
def out_dir(tmp_path):
    directory = tmp_path / "tasks"
    directory.mkdir()
    os.chmod(directory, 0o755)
    return directory


@pytest.mark.parametrize(
    "overrides",
    [
        {"purpose": ""},
        {"purpose": "has space"},
        {"tenant": "ténant"},
        {"principal": ""},
        {"scope": {"permissions": [{"tools": ["a*b"], "resources": [], "max_cost_per_call": 1}]}},
        {"scope": {"tools": []}},
        {"scope": {"tools": ["gitea.list_issues"], "resources": ["repo:demo/*"], "max_cost_per_call": 1}},
        {"budget": 0},
        {"budget": True},
        {"ttl": 0},
        {"ttl": 86_401},
        {"max_depth": -1},
        {"max_depth": 3},
        {"subject": "not-a-key"},
        {"subject": encode_public_key(Ed25519PrivateKey.generate().public_key()) + "="},
    ],
)
def test_a_bad_request_is_refused(overrides):
    with pytest.raises(ValueError):
        request(**overrides)


@pytest.mark.parametrize("tool", ["gitea.issues_*", "gitea.issues-*", "gitea:*", "gitea/*"])
def test_a_tool_grant_that_stops_inside_a_name_is_refused(tool):
    with pytest.raises(ValueError, match=rf"scope: tool grant {re.escape(tool)} must be exact or end at \.\*"):
        request(scope={"permissions": [{**PERMISSION, "tools": ["notes.read_note", tool]}]})


@pytest.mark.parametrize("resource", ["repo:demo-*", "repo:demo/a.*", "repo:*"])
def test_a_resource_grant_that_stops_inside_a_segment_is_refused(resource):
    with pytest.raises(ValueError, match=rf"scope: resource grant {re.escape(resource)} must be exact or end at /\*"):
        request(scope={"permissions": [{**PERMISSION, "resources": ["repo:demo/*", resource]}]})


@pytest.mark.parametrize("tools", [["notes.read_note"], ["notes.*"], ["notes.read_note", "notes.*"]])
def test_exact_and_dot_tool_grants_are_issued(tools):
    assert (
        issued(scope={"permissions": [{**PERMISSION, "tools": tools}]}).root.scope["permissions"][0]["tools"] == tools
    )


class RefusingKey:
    def sign(self, data):
        raise AssertionError("an oversize scope must be refused before signing")


def test_a_max_bound_scope_is_refused_before_signing():
    with pytest.raises(ValueError, match="task file would exceed the 4096 byte limit"):
        issue_task(RefusingKey(), ISSUER, DECIDER, request(scope=MAX_BOUND_SCOPE), NOW)


@pytest.mark.parametrize("scope", [TWO_PERMISSIONS_TWENTY_REPOS, SIXTEEN_SINGLE_PAIRS])
def test_realistic_multi_permission_scopes_are_issued(scope):
    task = issued(scope=scope)
    assert task.root.scope == scope and len(task.encode()) <= 4096


def test_request_defaults_are_short_lived_and_undelegable():
    made = request()
    assert (made.ttl, made.max_depth, made.tenant, made.principal) == (3600, 0, "quickstart", "user:operator")


def test_the_root_is_bound_to_the_subject_and_expires_after_the_ttl():
    subject = new_subject()
    task = issue_task(ISSUER_KEY, ISSUER, DECIDER, request(subject=subject, ttl=120), NOW)
    root = task.root
    assert (root.subject, root.issued_at, root.expires_at, root.max_depth) == (subject, NOW, NOW + 120, 0)
    assert (root.issuer, root.tenant_id, root.scope, root.budget) == (ISSUER, "quickstart", SCOPE, 10)
    assert root.task_id.startswith("task-") and len(root.task_id) == 21
    assert task.decider_id == DECIDER
    ISSUER_KEY.public_key().verify(b64u_decode(root.proof), root.signing_bytes())


def test_each_issue_has_a_new_task_id():
    assert issued().root.task_id != issued().root.task_id


def test_the_task_file_is_written_whole_and_world_readable(out_dir):
    task = issued()
    written = write(out_dir, task)
    assert written.path == out_dir / "task.json" and written.task == task
    assert stat.S_IMODE(written.path.stat().st_mode) == 0o644
    raw = written.path.read_bytes()
    assert TaskFile.decode(raw) == task
    assert json.loads(raw) == {
        "version": 1,
        "task_id": task.root.task_id,
        "task_root": task.root.encode(),
        "decider_id": DECIDER,
        "expires_at": NOW + 3600,
    }
    assert os.listdir(out_dir) == ["task.json"]


def test_the_grant_is_recorded_after_the_pending_file_and_before_the_task_file(out_dir):
    first = issued()
    write(out_dir, first)
    task = issued()
    docket = FakeDocket(out_dir)
    written = write(out_dir, task, docket)
    assert docket.grants == [Grant(written.grant_id, NOW, task.root.encode())]
    [seen] = docket.files_at_append
    assert TaskFile.decode(seen["task.json"]) == first
    assert PendingTask.decode(seen["task.json.pending"]) == PendingTask(written.grant_id, task)
    [staged] = [name for name in seen if name.startswith(".task.json.")]
    assert TaskFile.decode(seen[staged]) == task
    assert current(out_dir) == task
    assert os.listdir(out_dir) == ["task.json"]


def test_the_pending_file_is_private_and_holds_the_root_and_grant_id(out_dir):
    task = issued()
    modes = []

    class Inspect(FakeDocket):
        def append(self, grant):
            modes.append(stat.S_IMODE(os.stat(out_dir / "task.json.pending").st_mode))
            raw = json.loads((out_dir / "task.json.pending").read_bytes())
            modes.append(raw)
            return super().append(grant)

    written = write(out_dir, task, Inspect(out_dir))
    assert modes == [
        0o600,
        {"version": 1, "grant_id": written.grant_id, "task_root": task.root.encode(), "decider_id": DECIDER},
    ]


def test_a_new_key_replaces_the_current_task(out_dir):
    write(out_dir, issued())
    renewed = issued()
    write(out_dir, renewed)
    assert current(out_dir) == renewed


def test_a_second_task_for_the_same_key_is_refused_before_the_docket(out_dir):
    subject = new_subject()
    first = issued(subject=subject)
    write(out_dir, first)
    docket = FakeDocket(out_dir)
    with pytest.raises(TaskIssueError, match="already holds a task for this agent key"):
        write(out_dir, issued(subject=subject), docket)
    assert docket.files_at_append == []
    assert current(out_dir) == first
    assert os.listdir(out_dir) == ["task.json"]


def test_a_symlinked_task_dir_is_refused(out_dir, tmp_path):
    link = tmp_path / "link"
    link.symlink_to(out_dir)
    with pytest.raises(TaskIssueError, match="cannot open the task directory"):
        write(link, issued(), FakeDocket(out_dir))


@pytest.mark.parametrize("mode", [0o775, 0o757, 0o777])
def test_a_task_dir_others_can_write_is_refused(out_dir, mode):
    os.chmod(out_dir, mode)
    with pytest.raises(TaskIssueError, match="not writable by group or others"):
        write(out_dir, issued())
    assert os.listdir(out_dir) == []


def test_a_task_dir_another_uid_owns_is_refused(out_dir, monkeypatch):
    monkeypatch.setattr(issue_module.os, "geteuid", lambda: os.getuid() + 1)
    with pytest.raises(TaskIssueError, match="must be owned by uid"):
        write(out_dir, issued())


def test_a_symlinked_task_file_is_refused(out_dir, tmp_path):
    target = tmp_path / "elsewhere.json"
    target.write_bytes(issued().encode())
    (out_dir / "task.json").symlink_to(target)
    with pytest.raises(TaskIssueError, match="cannot open the current task file"):
        write(out_dir, issued())


def test_a_current_file_that_is_not_a_task_file_is_refused(out_dir):
    (out_dir / "task.json").write_text("{}")
    with pytest.raises(TaskIssueError, match="remove it to issue"):
        write(out_dir, issued())
    assert (out_dir / "task.json").read_text() == "{}"


def failing_rename(*args, **kwargs):
    raise OSError(errno.ENOSPC, "No space left on device")


def test_a_failed_pending_write_keeps_the_current_task_and_records_nothing(out_dir, monkeypatch):
    first = issued()
    write(out_dir, first)
    monkeypatch.setattr(files.os, "rename", failing_rename)
    docket = FakeDocket(out_dir)
    with pytest.raises(TaskIssueError, match="cannot write the pending task file"):
        write(out_dir, issued(), docket)
    assert docket.files_at_append == []
    assert current(out_dir) == first
    assert os.listdir(out_dir) == ["task.json"]


@pytest.mark.parametrize(("failing_call", "label"), [(1, "pending task file"), (3, "task file")])
def test_no_space_while_staging_records_nothing(out_dir, monkeypatch, failing_call, label):
    real_fsync = files.os.fsync
    calls = []

    def fsync(fd):
        calls.append(fd)
        if len(calls) == failing_call:
            raise OSError(errno.ENOSPC, "No space left on device")
        real_fsync(fd)

    monkeypatch.setattr(files.os, "fsync", fsync)
    docket = FakeDocket(out_dir)
    with pytest.raises(TaskIssueError, match=f"cannot write the {label}: No space left on device") as error:
        write(out_dir, issued(), docket)
    assert docket.files_at_append == []
    assert os.listdir(out_dir) == []
    if label == "task file":
        assert str(error.value).endswith("; no grant recorded, no task file written")


def test_a_read_only_task_dir_records_nothing(out_dir):
    os.chmod(out_dir, 0o555)
    docket = FakeDocket(out_dir)
    try:
        with pytest.raises(TaskIssueError, match="cannot create the pending task file"):
            write(out_dir, issued(), docket)
    finally:
        os.chmod(out_dir, 0o755)
    assert docket.files_at_append == []
    assert os.listdir(out_dir) == []


def test_a_refused_grant_writes_no_task_file_and_removes_the_pending_file(out_dir):
    first = issued()
    write(out_dir, first)
    with pytest.raises(TaskIssueError) as error:
        write(out_dir, issued(), FakeDocket(out_dir, refuse="sink_unreachable"))
    assert str(error.value) == "docket refused the grant: sink_unreachable; no grant recorded, no task file written"
    assert current(out_dir) == first
    assert os.listdir(out_dir) == ["task.json"]


@pytest.mark.parametrize("reason", ["no_ack", "bad_ack", "state_write_failed", "write_failed"])
def test_an_unacknowledged_grant_keeps_the_pending_file_and_names_the_grant(out_dir, reason):
    task = issued()
    docket = FakeDocket(out_dir, record_then=DocketError(reason))
    with pytest.raises(TaskIssueError) as error:
        write(out_dir, task, docket)
    [grant] = docket.grants
    message = str(error.value)
    assert f"grant may be recorded: grant_id {grant.grant_id}; check docket grants; revoke via control" in message
    assert f"rerun the same command to finish from {out_dir / 'task.json.pending'}" in message
    assert pending_of(out_dir) == PendingTask(grant.grant_id, task)
    assert os.listdir(out_dir) == ["task.json.pending"]


def test_a_retry_after_an_unacknowledged_grant_reuses_the_root_and_grant_id(out_dir):
    made = request()
    first = issue_task(ISSUER_KEY, ISSUER, DECIDER, made, NOW)
    lost = FakeDocket(out_dir, record_then=DocketError("no_ack"))
    with pytest.raises(TaskIssueError):
        write(out_dir, first, lost)
    docket = FakeDocket(out_dir)
    written = write(out_dir, issue_task(ISSUER_KEY, ISSUER, DECIDER, made, NOW + 5), docket, NOW + 5)
    assert written.task == first and written.grant_id == lost.grants[0].grant_id
    assert docket.grants == [Grant(written.grant_id, NOW + 5, first.root.encode())]
    assert current(out_dir) == first
    assert os.listdir(out_dir) == ["task.json"]


@pytest.mark.parametrize(
    "changes",
    [
        {"subject": new_subject()},
        {"budget": 11},
        {"ttl": 60},
        {"purpose": "other"},
        {"tenant": "other"},
        {"principal": "user:other"},
        {"max_depth": 1},
        {"scope": {"permissions": [{**PERMISSION, "max_cost_per_call": 2}]}},
    ],
)
def test_a_retry_with_another_request_is_refused_and_keeps_the_pending_file(out_dir, changes):
    made = request()
    first = issue_task(ISSUER_KEY, ISSUER, DECIDER, made, NOW)
    lost = FakeDocket(out_dir, record_then=DocketError("no_ack"))
    with pytest.raises(TaskIssueError):
        write(out_dir, first, lost)
    other = TaskRequest(**{**made.__dict__, **changes})
    docket = FakeDocket(out_dir)
    with pytest.raises(TaskIssueError, match="holds an unfinished issue of grant_id .* for another request"):
        write(out_dir, issue_task(ISSUER_KEY, ISSUER, DECIDER, other, NOW), docket)
    assert docket.files_at_append == []
    assert pending_of(out_dir) == PendingTask(lost.grants[0].grant_id, first)
    assert os.listdir(out_dir) == ["task.json.pending"]


def test_a_retry_for_another_decider_is_refused(out_dir):
    made = request()
    with pytest.raises(TaskIssueError):
        write(out_dir, issue_task(ISSUER_KEY, ISSUER, DECIDER, made, NOW), FakeDocket(out_dir, refuse="no_ack"))
    with pytest.raises(TaskIssueError, match="for another request"):
        write(out_dir, issue_task(ISSUER_KEY, ISSUER, "decide.other", made, NOW))


def test_a_retry_after_the_pending_root_expired_is_refused(out_dir):
    made = request(ttl=60)
    first = issue_task(ISSUER_KEY, ISSUER, DECIDER, made, NOW)
    lost = FakeDocket(out_dir, record_then=DocketError("no_ack"))
    with pytest.raises(TaskIssueError):
        write(out_dir, first, lost)
    with pytest.raises(TaskIssueError) as error:
        write(out_dir, issue_task(ISSUER_KEY, ISSUER, DECIDER, made, NOW + 60), FakeDocket(out_dir), NOW + 60)
    grant_id = lost.grants[0].grant_id
    assert f"root expired at {NOW + 60}; grant may be recorded: grant_id {grant_id}" in str(error.value)
    assert os.listdir(out_dir) == ["task.json.pending"]


def test_a_refused_retry_keeps_the_pending_file_of_the_earlier_run(out_dir):
    made = request()
    first = issue_task(ISSUER_KEY, ISSUER, DECIDER, made, NOW)
    lost = FakeDocket(out_dir, record_then=DocketError("no_ack"))
    with pytest.raises(TaskIssueError):
        write(out_dir, first, lost)
    with pytest.raises(TaskIssueError) as error:
        write(out_dir, issue_task(ISSUER_KEY, ISSUER, DECIDER, made, NOW), FakeDocket(out_dir, refuse="rollback"))
    grant_id = lost.grants[0].grant_id
    assert str(error.value) == (
        f"docket refused the grant: rollback; an earlier run may have recorded grant_id {grant_id}; "
        f"{out_dir / 'task.json.pending'} kept, rerun the same command to finish"
    )
    assert os.listdir(out_dir) == ["task.json.pending"]


def test_a_crash_after_the_grant_and_before_the_rename_finishes_on_retry(out_dir):
    made = request()
    first = issue_task(ISSUER_KEY, ISSUER, DECIDER, made, NOW)
    crashed = FakeDocket(out_dir, record_then=Crash())
    with pytest.raises(Crash):
        write(out_dir, first, crashed)
    assert "task.json" not in os.listdir(out_dir)
    docket = FakeDocket(out_dir)
    written = write(out_dir, issue_task(ISSUER_KEY, ISSUER, DECIDER, made, NOW), docket)
    [recorded] = crashed.grants
    assert written.grant_id == recorded.grant_id and written.task == first
    assert [(grant.grant_id, grant.root_token) for grant in docket.grants] == [(recorded.grant_id, recorded.root_token)]
    assert current(out_dir) == first
    assert [name for name in os.listdir(out_dir) if not name.startswith(".")] == ["task.json"]


def test_a_failed_rename_after_the_grant_names_the_grant_and_finishes_on_retry(out_dir, monkeypatch):
    task = issued()
    real_rename = files.os.rename

    def rename(source, target, **kwargs):
        if target == "task.json":
            raise OSError(errno.EIO, "Input/output error")
        real_rename(source, target, **kwargs)

    monkeypatch.setattr(files.os, "rename", rename)
    docket = FakeDocket(out_dir)
    with pytest.raises(TaskIssueError) as error:
        write(out_dir, task, docket)
    [grant] = docket.grants
    assert str(error.value) == (
        f"cannot write the task file: Input/output error; grant recorded: grant_id {grant.grant_id}; "
        f"task.json may be written; rerun the same command to finish from {out_dir / 'task.json.pending'}"
    )
    assert os.listdir(out_dir) == ["task.json.pending"]
    monkeypatch.setattr(files.os, "rename", real_rename)
    written = write(out_dir, task)
    assert (written.grant_id, current(out_dir)) == (grant.grant_id, task)
    assert os.listdir(out_dir) == ["task.json"]


def test_a_pending_file_left_after_the_rename_is_removed_by_the_next_issue(out_dir):
    subject = new_subject()
    task = issued(subject=subject)
    write(out_dir, task)
    (out_dir / "task.json.pending").write_bytes(PendingTask("g-left", task).encode())
    with pytest.raises(TaskIssueError, match="already holds a task for this agent key"):
        write(out_dir, issued(subject=subject))
    assert os.listdir(out_dir) == ["task.json"]
    (out_dir / "task.json.pending").write_bytes(PendingTask("g-left", task).encode())
    renewed = issued()
    written = write(out_dir, renewed)
    assert written.task == renewed and written.grant_id != "g-left"
    assert os.listdir(out_dir) == ["task.json"]


@pytest.mark.parametrize("content", [b"{}", b"not json", b'{"version": 1}'])
def test_a_pending_file_that_does_not_decode_is_refused(out_dir, content):
    (out_dir / "task.json.pending").write_bytes(content)
    docket = FakeDocket(out_dir)
    with pytest.raises(TaskIssueError, match="is not a pending task file .*; remove it to issue"):
        write(out_dir, issued(), docket)
    assert docket.files_at_append == []


def test_a_concurrent_issue_is_refused_while_another_holds_the_lock(out_dir):
    fd = os.open(out_dir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        with pytest.raises(TaskIssueError, match="another task issue is running"):
            write(out_dir, issued())
    finally:
        os.close(fd)
    assert os.listdir(out_dir) == []


def test_concurrent_writers_never_share_a_staged_file(out_dir, monkeypatch):
    first, second = issued(), issued()
    real_fsync = files.os.fsync
    nested = []

    def fsync_then_interleave(fd):
        real_fsync(fd)
        if not nested:
            nested.append(True)
            dir_fd = os.open(out_dir, os.O_RDONLY | os.O_DIRECTORY)
            try:
                files.replace_at(dir_fd, "task.json", "task file", second.encode(), 0o644)
            finally:
                os.close(dir_fd)

    monkeypatch.setattr(files.os, "fsync", fsync_then_interleave)
    dir_fd = os.open(out_dir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        files.replace_at(dir_fd, "task.json", "task file", first.encode(), 0o644)
    finally:
        os.close(dir_fd)
    assert TaskFile.decode((out_dir / "task.json").read_bytes()) == first
    assert os.listdir(out_dir) == ["task.json"]


class Issuer:
    def __init__(self, root):
        self.root = root
        self.dir = root / "issuer"
        self.dir.mkdir(mode=0o700)
        generate_signing_key(self.dir / "issuer.key", "issuer")
        self.writer_pin = generate_signing_key(self.dir / "docket.key", GRANT_WRITER)
        self.state = root / "docket-state"
        self.state.mkdir(mode=0o700)
        self.docket = root / "docket.log"
        self.socket = root / "s" / "docket.sock"
        self.writers = {GRANT_WRITER: {self.writer_pin.kid: self.writer_pin.public_key}}
        self.sink = None

    def start(self):
        sink = DocketSink(self.docket, self.socket, self.writers, {os.getuid()}, grant_writers={GRANT_WRITER})
        self.sink = RunningSink(sink)

    def stop(self):
        if self.sink is not None and self.sink.thread.is_alive():
            self.sink.stop()

    def grants(self):
        index = build_kid_index(self.writers, {GRANT_WRITER})
        if not self.docket.exists():
            return []
        return [decode_record(line, index).entry for line in self.docket.read_text().splitlines()]

    def arguments(self, out_dir, *, scope=SCOPE_TEXT, subject=None, docket_key=None):
        return [
            "task", "issue", "--issuer-key", str(self.dir / "issuer.key"), "--issuer", ISSUER,
            "--decider-id", DECIDER, "--purpose", "triage", "--scope", scope, "--budget", "5", "--ttl", "60",
            f"--subject={subject or new_subject()}",
            "--out-dir", str(out_dir), "--docket-socket", str(self.socket), "--docket-uid", str(os.getuid()),
            "--docket-writer", GRANT_WRITER, "--docket-key", str(docket_key or self.dir / "docket.key"),
            "--docket-state-dir", str(self.state),
        ]  # fmt: skip


@pytest.fixture
def issuer():
    made = Issuer(Path(tempfile.mkdtemp(prefix="bt-", dir="/tmp")))
    yield made
    made.stop()
    shutil.rmtree(made.root)


def test_the_cli_records_the_grant_and_prints_the_task_id(out_dir, issuer, capsys):
    issuer.start()
    subject = new_subject()
    assert main(issuer.arguments(out_dir, subject=subject)) == 0
    task = current(out_dir)
    captured = capsys.readouterr()
    assert captured.out == f"{task.root.task_id}\n"
    assert (task.root.subject, task.root.budget, task.root.max_depth) == (subject, 5, 0)
    assert task.root.expires_at - task.root.issued_at == 60
    [grant] = issuer.grants()
    assert (grant.root_token, grant.at) == (task.root.encode(), task.root.issued_at)
    assert f"grant_id {grant.grant_id}" in captured.err
    assert os.listdir(out_dir) == ["task.json"]


def test_the_cli_issues_to_a_subject_starting_with_a_dash(out_dir, issuer):
    issuer.start()
    subject = dash_subject()
    assert main(issuer.arguments(out_dir, subject=subject)) == 0
    assert current(out_dir).root.subject == subject


def test_the_cli_refuses_when_the_docket_is_down_and_writes_nothing(out_dir, issuer, capsys):
    assert main(issuer.arguments(out_dir)) == 1
    err = capsys.readouterr().err
    assert "task issue refused: docket refused the grant: sink_unreachable" in err
    assert err.rstrip().endswith("; no grant recorded, no task file written")
    assert os.listdir(out_dir) == []


def test_the_cli_refuses_the_issuer_key_as_the_docket_key(out_dir, issuer, capsys):
    issuer.start()
    assert main(issuer.arguments(out_dir, docket_key=issuer.dir / "issuer.key")) == 1
    assert "--docket-key must be the docket writer's own key, not the issuer key" in capsys.readouterr().err
    assert issuer.grants() == [] and os.listdir(out_dir) == []


def test_the_cli_refuses_a_docket_writer_the_sink_does_not_pin_for_grants(out_dir, issuer, capsys):
    sink = DocketSink(issuer.docket, issuer.socket, issuer.writers, {os.getuid()})
    issuer.sink = RunningSink(sink)
    assert main(issuer.arguments(out_dir)) == 1
    assert "docket refused the grant: wrong_record_type" in capsys.readouterr().err
    assert os.listdir(out_dir) == []


def test_the_cli_retry_after_a_lost_ack_records_the_same_grant(out_dir, issuer, monkeypatch, capsys):
    issuer.start()
    subject = new_subject()
    real_save = client_module.DocketClient._save_acked

    def fail_save(self, head):
        raise DocketError("state_write_failed", "disk full")

    monkeypatch.setattr(client_module.DocketClient, "_save_acked", fail_save)
    assert main(issuer.arguments(out_dir, subject=subject)) == 1
    assert "grant may be recorded: grant_id" in capsys.readouterr().err
    assert os.listdir(out_dir) == ["task.json.pending"]
    monkeypatch.setattr(client_module.DocketClient, "_save_acked", real_save)
    assert main(issuer.arguments(out_dir, subject=subject)) == 0
    first, second = issuer.grants()
    assert (first.grant_id, first.root_token) == (second.grant_id, second.root_token)
    assert current(out_dir).root.encode() == first.root_token
    assert os.listdir(out_dir) == ["task.json"]


@pytest.mark.parametrize(
    "scope",
    [
        "not json",
        '{"tools": [], "tools": []}',
        "[]",
        json.dumps({"permissions": [{**PERMISSION, "tools": ["gitea.issues_*"]}]}),
        json.dumps({"permissions": [{**PERMISSION, "resources": ["repo:demo-*"]}]}),
        json.dumps(MAX_BOUND_SCOPE),
    ],
)
def test_the_cli_refuses_a_bad_scope(out_dir, issuer, scope, capsys):
    issuer.start()
    assert main(issuer.arguments(out_dir, scope=scope)) == 1
    assert "task issue refused" in capsys.readouterr().err
    assert issuer.grants() == [] and os.listdir(out_dir) == []
