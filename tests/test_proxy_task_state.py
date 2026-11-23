import json
import os

import pytest
from agent_warrant.identity import encode_public_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_bailiff.proxy import agent_key
from agent_bailiff.proxy.agent_key import generate_agent_key
from agent_bailiff.proxy.task_state import NoTask, TaskState, TaskUnavailable
from agent_bailiff.task.issue import TaskRequest, issue_task

NOW = 1_800_000_000
SCOPE = {"tools": ["gitea.list_issues"], "resources": ["repo:demo/*"], "max_cost_per_call": 1}
ISSUER_KEY = Ed25519PrivateKey.generate()


@pytest.fixture
def key_dir(tmp_path):
    directory = tmp_path / "keys"
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)
    return directory


@pytest.fixture
def task_file(tmp_path):
    return tmp_path / "task.json"


def issue(subject):
    request = TaskRequest(purpose="triage", scope=SCOPE, budget=10, subject=subject, ttl=600)
    return issue_task(ISSUER_KEY, "issuer.quickstart", "decide.quickstart", request, NOW)


def write_task(task_file, key_dir):
    task = issue(generate_agent_key(key_dir))
    task_file.write_bytes(task.encode())
    return task


def document(task):
    return json.loads(task.encode())


def test_load_builds_a_holder_for_the_root_subject(task_file, key_dir):
    task = write_task(task_file, key_dir)
    state = TaskState.load(task_file, key_dir)
    assert state.task == task
    assert state.subject == task.root.subject
    assert encode_public_key(state.holder.key.public_key()) == task.root.subject
    assert (state.holder.task_root, state.holder.links, state.holder.audience) == (
        task.root.encode(),
        (),
        "decide.quickstart",
    )
    assert state.raw == task_file.read_bytes()


def test_a_missing_task_file_is_no_task(task_file, key_dir):
    with pytest.raises(NoTask):
        TaskState.load(task_file, key_dir)


def test_expiry_starts_at_expires_at(task_file, key_dir):
    write_task(task_file, key_dir)
    state = TaskState.load(task_file, key_dir)
    assert not state.expired(NOW + 599)
    assert state.expired(NOW + 600)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda doc: doc | {"version": 2},
        lambda doc: doc | {"version": True},
        lambda doc: doc | {"extra": 1},
        lambda doc: {key: value for key, value in doc.items() if key != "decider_id"},
        lambda doc: doc | {"task_root": "not.a-root"},
        lambda doc: doc | {"task_root": 7},
        lambda doc: doc | {"task_id": "task-0000000000000000"},
        lambda doc: doc | {"expires_at": doc["expires_at"] + 1},
        lambda doc: doc | {"decider_id": ""},
        lambda doc: doc | {"decider_id": 5},
        lambda doc: [doc],
    ],
)
def test_a_malformed_task_file_is_unavailable(task_file, key_dir, mutate):
    task = write_task(task_file, key_dir)
    task_file.write_text(json.dumps(mutate(document(task))))
    with pytest.raises(TaskUnavailable, match="the task file is invalid"):
        TaskState.load(task_file, key_dir)


@pytest.mark.parametrize(
    "raw",
    [b"\xff\xfe", b"not json", b'{"version": 1, "version": 1}', b'{"version": NaN}'],
)
def test_a_task_file_that_is_not_strict_json_is_unavailable(task_file, key_dir, raw):
    task_file.write_bytes(raw)
    with pytest.raises(TaskUnavailable, match="not strict JSON"):
        TaskState.load(task_file, key_dir)


def test_an_oversized_task_file_is_unavailable(task_file, key_dir):
    task_file.write_bytes(b" " * 4097)
    with pytest.raises(TaskUnavailable, match="larger than 4096 bytes"):
        TaskState.load(task_file, key_dir)


def test_a_symlinked_task_file_is_unavailable(task_file, key_dir, tmp_path):
    target = tmp_path / "real.json"
    target.write_bytes(issue(generate_agent_key(key_dir)).encode())
    task_file.symlink_to(target)
    with pytest.raises(TaskUnavailable, match="cannot open the task file"):
        TaskState.load(task_file, key_dir)


def test_a_task_file_that_is_a_directory_is_unavailable(task_file, key_dir):
    task_file.mkdir()
    with pytest.raises(TaskUnavailable, match="not a regular file"):
        TaskState.load(task_file, key_dir)


def test_a_root_without_its_key_is_unavailable(task_file, key_dir):
    task_file.write_bytes(issue(encode_public_key(Ed25519PrivateKey.generate().public_key())).encode())
    with pytest.raises(TaskUnavailable, match="no usable agent key"):
        TaskState.load(task_file, key_dir)


def key_path(task, key_dir):
    return key_dir / f"{task.root.subject}.key"


def test_a_key_others_can_read_is_unavailable(task_file, key_dir):
    task = write_task(task_file, key_dir)
    os.chmod(key_path(task, key_dir), 0o644)
    with pytest.raises(TaskUnavailable, match="must have mode 0o600"):
        TaskState.load(task_file, key_dir)


def test_a_symlinked_key_is_unavailable(task_file, key_dir, tmp_path):
    task = write_task(task_file, key_dir)
    moved = tmp_path / "moved.key"
    os.rename(key_path(task, key_dir), moved)
    key_path(task, key_dir).symlink_to(moved)
    with pytest.raises(TaskUnavailable, match="cannot open"):
        TaskState.load(task_file, key_dir)


def test_a_hard_linked_key_is_unavailable(task_file, key_dir):
    task = write_task(task_file, key_dir)
    os.link(key_path(task, key_dir), key_dir / "copy")
    with pytest.raises(TaskUnavailable, match="multiple hard links"):
        TaskState.load(task_file, key_dir)


def test_a_key_another_uid_owns_is_unavailable(task_file, key_dir, monkeypatch):
    write_task(task_file, key_dir)
    real = os.geteuid()
    monkeypatch.setattr(agent_key.os, "geteuid", lambda: real + 1)
    with pytest.raises(TaskUnavailable, match="must be owned by uid"):
        TaskState.load(task_file, key_dir)


def test_a_key_file_holding_another_key_is_unavailable(task_file, key_dir):
    task = write_task(task_file, key_dir)
    path = key_path(task, key_dir)
    os.chmod(path, 0o600)
    with open(path, "wb") as target:
        target.write(Ed25519PrivateKey.generate().private_bytes_raw())
    with pytest.raises(TaskUnavailable, match="holds a different key"):
        TaskState.load(task_file, key_dir)


def test_a_short_key_file_is_unavailable(task_file, key_dir):
    task = write_task(task_file, key_dir)
    with open(key_path(task, key_dir), "wb") as target:
        target.write(b"short")
    with pytest.raises(TaskUnavailable, match="exactly 32 bytes"):
        TaskState.load(task_file, key_dir)


def test_a_key_dir_others_can_open_is_unavailable(task_file, key_dir):
    write_task(task_file, key_dir)
    os.chmod(key_dir, 0o755)
    with pytest.raises(TaskUnavailable, match="mode 0o700"):
        TaskState.load(task_file, key_dir)
