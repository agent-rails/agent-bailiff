import errno
import fcntl
import json
import os
import re
import stat

import pytest
from agent_warrant.encoding import b64u_decode
from agent_warrant.identity import encode_public_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_bailiff.cli import main
from agent_bailiff.custodian import files
from agent_bailiff.keys import generate_signing_key
from agent_bailiff.task import issue as issue_module
from agent_bailiff.task.issue import TaskIssueError, TaskRequest, issue_task, write_task_file
from agent_bailiff.task.task_file import TaskFile

NOW = 1_800_000_000
ISSUER = "issuer.quickstart"
DECIDER = "decide.quickstart"
PERMISSION = {"tools": ["gitea.list_issues"], "resources": ["repo:demo/*"], "max_cost_per_call": 1}
SCOPE = {"permissions": [PERMISSION]}
ISSUER_KEY = Ed25519PrivateKey.generate()


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
    path = write_task_file(out_dir, task)
    assert path == out_dir / "task.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o644
    raw = path.read_bytes()
    assert TaskFile.decode(raw) == task
    assert json.loads(raw) == {
        "version": 1,
        "task_id": task.root.task_id,
        "task_root": task.root.encode(),
        "decider_id": DECIDER,
        "expires_at": NOW + 3600,
    }
    assert os.listdir(out_dir) == ["task.json"]


def test_a_new_key_replaces_the_current_task(out_dir):
    write_task_file(out_dir, issued())
    renewed = issued()
    write_task_file(out_dir, renewed)
    assert TaskFile.decode((out_dir / "task.json").read_bytes()) == renewed


def test_a_second_task_for_the_same_key_is_refused(out_dir):
    subject = new_subject()
    first = issued(subject=subject)
    write_task_file(out_dir, first)
    with pytest.raises(TaskIssueError, match="already holds a task for this agent key"):
        write_task_file(out_dir, issued(subject=subject))
    assert TaskFile.decode((out_dir / "task.json").read_bytes()) == first


def test_a_symlinked_task_dir_is_refused(out_dir, tmp_path):
    link = tmp_path / "link"
    link.symlink_to(out_dir)
    with pytest.raises(TaskIssueError, match="cannot open the task directory"):
        write_task_file(link, issued())


@pytest.mark.parametrize("mode", [0o775, 0o757, 0o777])
def test_a_task_dir_others_can_write_is_refused(out_dir, mode):
    os.chmod(out_dir, mode)
    with pytest.raises(TaskIssueError, match="not writable by group or others"):
        write_task_file(out_dir, issued())
    assert os.listdir(out_dir) == []


def test_a_task_dir_another_uid_owns_is_refused(out_dir, monkeypatch):
    monkeypatch.setattr(issue_module.os, "geteuid", lambda: os.getuid() + 1)
    with pytest.raises(TaskIssueError, match="must be owned by uid"):
        write_task_file(out_dir, issued())


def test_a_symlinked_task_file_is_refused(out_dir, tmp_path):
    target = tmp_path / "elsewhere.json"
    target.write_bytes(issued().encode())
    (out_dir / "task.json").symlink_to(target)
    with pytest.raises(TaskIssueError, match="cannot open the current task file"):
        write_task_file(out_dir, issued())


def test_a_current_file_that_is_not_a_task_file_is_refused(out_dir):
    (out_dir / "task.json").write_text("{}")
    with pytest.raises(TaskIssueError, match="remove it to issue"):
        write_task_file(out_dir, issued())
    assert (out_dir / "task.json").read_text() == "{}"


def failing_rename(*args, **kwargs):
    raise OSError(errno.ENOSPC, "No space left on device")


def test_a_failed_write_keeps_the_current_task(out_dir, monkeypatch):
    first = issued()
    write_task_file(out_dir, first)
    monkeypatch.setattr(files.os, "rename", failing_rename)
    with pytest.raises(TaskIssueError, match="cannot write the task file"):
        write_task_file(out_dir, issued())
    assert TaskFile.decode((out_dir / "task.json").read_bytes()) == first
    assert os.listdir(out_dir) == ["task.json"]


def test_a_concurrent_issue_is_refused_while_another_holds_the_lock(out_dir):
    fd = os.open(out_dir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        with pytest.raises(TaskIssueError, match="another task issue is running"):
            write_task_file(out_dir, issued())
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


def test_the_cli_issues_and_prints_the_task_id(out_dir, tmp_path, capsys):
    key_dir = tmp_path / "issuer"
    key_dir.mkdir(mode=0o700)
    generate_signing_key(key_dir / "issuer.key", "issuer")
    subject = new_subject()
    arguments = [
        "task", "issue", "--issuer-key", str(key_dir / "issuer.key"), "--issuer", ISSUER, "--decider-id", DECIDER,
        "--purpose", "triage", "--scope", json.dumps(SCOPE), "--budget", "5", "--ttl", "60",
        f"--subject={subject}", "--out-dir", str(out_dir),
    ]  # fmt: skip
    assert main(arguments) == 0
    task = TaskFile.decode((out_dir / "task.json").read_bytes())
    assert capsys.readouterr().out == f"{task.root.task_id}\n"
    assert (task.root.subject, task.root.budget, task.root.max_depth) == (subject, 5, 0)
    assert task.root.expires_at - task.root.issued_at == 60


def test_the_cli_issues_to_a_subject_starting_with_a_dash(out_dir, tmp_path):
    key_dir = tmp_path / "issuer"
    key_dir.mkdir(mode=0o700)
    generate_signing_key(key_dir / "issuer.key", "issuer")
    subject = dash_subject()
    arguments = [
        "task", "issue", "--issuer-key", str(key_dir / "issuer.key"), "--issuer", ISSUER, "--decider-id", DECIDER,
        "--purpose", "triage", "--scope", json.dumps(SCOPE), "--budget", "5", f"--subject={subject}",
        "--out-dir", str(out_dir),
    ]  # fmt: skip
    assert main(arguments) == 0
    assert TaskFile.decode((out_dir / "task.json").read_bytes()).root.subject == subject


@pytest.mark.parametrize(
    "scope",
    [
        "not json",
        '{"tools": [], "tools": []}',
        "[]",
        json.dumps({"permissions": [{**PERMISSION, "tools": ["gitea.issues_*"]}]}),
        json.dumps({"permissions": [{**PERMISSION, "resources": ["repo:demo-*"]}]}),
    ],
)
def test_the_cli_refuses_a_bad_scope(out_dir, tmp_path, scope, capsys):
    key_dir = tmp_path / "issuer"
    key_dir.mkdir(mode=0o700)
    generate_signing_key(key_dir / "issuer.key", "issuer")
    arguments = [
        "task", "issue", "--issuer-key", str(key_dir / "issuer.key"), "--issuer", ISSUER, "--decider-id", DECIDER,
        "--purpose", "triage", "--scope", scope, "--budget", "5", f"--subject={new_subject()}",
        "--out-dir", str(out_dir),
    ]  # fmt: skip
    assert main(arguments) == 1
    assert "task issue refused" in capsys.readouterr().err
    assert os.listdir(out_dir) == []
