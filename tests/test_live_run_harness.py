import json
import os
import signal
import subprocess
import sys
from pathlib import Path

import pytest

LIVE_RUN = Path(__file__).resolve().parent.parent / "examples" / "live-run"
sys.path.insert(0, str(LIVE_RUN))
import kubernetes  # noqa: E402
import run  # noqa: E402


@pytest.fixture
def cache(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_BAILIFF_CACHE", str(tmp_path))
    return tmp_path / "agentgateway" / "v1.7.0"


def place(cache, name):
    cache.mkdir(parents=True)
    binary = cache / f"agentgateway-{name}"
    binary.write_bytes(b"")
    return binary


@pytest.mark.parametrize(
    ("system", "machine", "name"), [("darwin", "arm64", "darwin-arm64"), ("linux", "x86_64", "linux-amd64")]
)
def test_the_gateway_binary_is_the_pinned_one_for_the_platform(cache, monkeypatch, system, machine, name):
    binary = place(cache, name)
    monkeypatch.setattr(run.sys, "platform", system)
    monkeypatch.setattr(run.platform, "machine", lambda: machine)
    assert run.gateway_binary() == binary


@pytest.mark.parametrize(("system", "machine"), [("linux", "aarch64"), ("darwin", "x86_64"), ("win32", "AMD64")])
def test_the_gateway_binary_is_refused_for_an_unpinned_platform(cache, monkeypatch, system, machine):
    monkeypatch.setattr(run.sys, "platform", system)
    monkeypatch.setattr(run.platform, "machine", lambda: machine)
    with pytest.raises(RuntimeError, match="no pinned agentgateway"):
        run.gateway_binary()


def test_a_missing_gateway_binary_is_refused(cache, monkeypatch):
    monkeypatch.setattr(run.sys, "platform", "linux")
    monkeypatch.setattr(run.platform, "machine", lambda: "x86_64")
    with pytest.raises(RuntimeError, match="fetch_gateway.sh"):
        run.gateway_binary()


def test_the_cache_defaults_to_the_fetch_script_location(tmp_path, monkeypatch):
    monkeypatch.delenv("AGENT_BAILIFF_CACHE", raising=False)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    monkeypatch.setattr(run.sys, "platform", "linux")
    monkeypatch.setattr(run.platform, "machine", lambda: "x86_64")
    binary = place(tmp_path / "agent-bailiff" / "agentgateway" / "v1.7.0", "linux-amd64")
    assert run.gateway_binary() == binary


def make_layout(root, files=run.WORK_FILES):
    root.mkdir(exist_ok=True)
    work, receipts = root / "work", root / "receipts"
    work.mkdir(mode=0o700)
    receipts.mkdir()
    os.chmod(receipts, 0o750)
    for name in files:
        if name == "home":
            (work / name).mkdir()
        else:
            (work / name).write_text("x")
    return work, receipts


def test_the_entrypoint_layout_is_accepted(tmp_path):
    run.require_layout(*make_layout(tmp_path), run.WORK_FILES)


def test_the_kubernetes_layout_needs_the_kubeconfig(tmp_path):
    work, receipts = make_layout(tmp_path)
    with pytest.raises(RuntimeError, match="must hold only"):
        run.require_layout(work, receipts, run.WORK_FILES | {"kubeconfig"})


@pytest.mark.parametrize(
    "change",
    [
        lambda work, receipts: (work.parent / "extra").mkdir(),
        lambda work, receipts: (receipts / "planted").write_text("x"),
        lambda work, receipts: os.chmod(receipts, 0o770),
        lambda work, receipts: (work / "claude-token").unlink(),
        lambda work, receipts: (work / "extra").write_text("x"),
    ],
    ids=["extra-entry", "receipts-not-empty", "receipts-mode", "missing-token", "extra-work-file"],
)
def test_a_layout_other_than_the_entrypoints_is_refused(tmp_path, change):
    work, receipts = make_layout(tmp_path)
    change(work, receipts)
    with pytest.raises(RuntimeError):
        run.require_layout(work, receipts, run.WORK_FILES)


def test_a_symlinked_work_dir_is_refused(tmp_path):
    work, receipts = make_layout(tmp_path / "layout")
    os.rename(work, tmp_path / "elsewhere")
    os.symlink(tmp_path / "elsewhere", work)
    with pytest.raises(RuntimeError, match="not a link"):
        run.require_layout(work, receipts, run.WORK_FILES)


def test_the_archiver_uid_must_differ_from_the_harness_uid(tmp_path):
    with pytest.raises(RuntimeError, match="harness's own uid"):
        run.Deployment(tmp_path, receipt_dir=tmp_path, archiver_uid=os.geteuid())


def test_the_archiver_uid_is_keyword_only(tmp_path):
    with pytest.raises(TypeError):
        run.Deployment(tmp_path, tmp_path, os.geteuid() + 1)


def test_the_receipt_dir_owned_by_the_archiver_is_accepted(tmp_path):
    os.chmod(tmp_path, 0o750)
    run.check_receipt_dir(tmp_path, os.geteuid(), os.lstat(tmp_path).st_gid)


@pytest.mark.parametrize(
    ("uid_offset", "gid_offset", "mode"), [(1, 0, 0o750), (0, 1, 0o750), (0, 0, 0o770)], ids=["owner", "gid", "mode"]
)
def test_a_receipt_dir_the_archiver_does_not_hold_is_refused(tmp_path, uid_offset, gid_offset, mode):
    os.chmod(tmp_path, mode)
    gid = os.lstat(tmp_path).st_gid
    with pytest.raises(RuntimeError, match="must be owned by"):
        run.check_receipt_dir(tmp_path, os.geteuid() + uid_offset, gid + gid_offset)


@pytest.mark.parametrize(("failures", "status"), [([], "ok"), (["docket verifies"], "failed")])
def test_the_result_is_one_compact_line_whose_status_follows_the_checks(capsys, failures, status):
    run.print_result("r1", "m", [run.Outcome("s", "p")], {"docket verifies": True}, failures)
    out = capsys.readouterr().out
    assert out.count("\n") == 1
    result = json.loads(out)
    assert (result["run_id"], result["status"], result["failures"]) == ("r1", status, failures)


RUN_SUMMARY = {
    "every upstream deploy carried the credential header": True,
    "upstream deploys carrying any x-bailiff header": 0,
    "credential seen by the agent or the model": False,
    "credential in the docket": False,
    "docket verifies": True,
}


@pytest.mark.parametrize(
    ("change", "failure"),
    [
        ({}, None),
        ({"every upstream deploy carried the credential header": False}, "every upstream deploy carried"),
        ({"upstream deploys carrying any x-bailiff header": 1}, "x-bailiff header"),
        ({"credential seen by the agent or the model": True}, "credential seen"),
        ({"credential in the docket": True}, "credential in the docket"),
        ({"docket verifies": False}, "docket verifies"),
    ],
)
def test_the_run_fails_on_any_broken_invariant(change, failure):
    failures = run.failed_checks({**RUN_SUMMARY, **change})
    assert failures == ([] if failure is None else [next(name for name in failures if failure in name)])


KUBERNETES_SUMMARY = {
    "effector token seen by the agent or the model": False,
    "effector token in the docket": False,
    "effector token in the gateway log": False,
    "docket verifies": True,
    "final replicas": {"staging": 3, "prod": 1},
}


@pytest.mark.parametrize(
    ("change", "failure"),
    [
        ({}, None),
        ({"effector token seen by the agent or the model": True}, "effector token seen by the agent or the model"),
        ({"effector token in the docket": True}, "effector token in the docket"),
        ({"effector token in the gateway log": True}, "effector token in the gateway log"),
        ({"docket verifies": False}, "docket verifies"),
        ({"final replicas": {"staging": 2, "prod": 5}}, "final replicas"),
    ],
)
def test_the_kubernetes_run_fails_on_any_broken_invariant(change, failure):
    assert kubernetes.failed_checks({**KUBERNETES_SUMMARY, **change}) == ([] if failure is None else [failure])


def status_file(tmp_path, cap_eff, no_new_privs):
    path = tmp_path / "status"
    path.write_text(f"Name:\tpython\nCapInh:\t0000000000000000\nCapEff:\t{cap_eff}\nNoNewPrivs:\t{no_new_privs}\n")
    return path


def test_a_confined_harness_is_accepted(tmp_path):
    run.require_confined(status_file(tmp_path, "0000000000000000", 1))


@pytest.mark.parametrize(("cap_eff", "no_new_privs"), [("00000000000000c0", 1), ("0000000000000000", 0)])
def test_an_unconfined_harness_is_refused(tmp_path, cap_eff, no_new_privs):
    with pytest.raises(RuntimeError, match="no effective capabilities"):
        run.require_confined(status_file(tmp_path, cap_eff, no_new_privs))


@pytest.fixture
def secret_environment(monkeypatch):
    for key in run.CLAUDE_ENVIRONMENT_KEYS:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-host")
    monkeypatch.setenv(run.TOKEN_VARIABLE, "host-token")
    monkeypatch.setenv("KUBECONFIG", "/root/.kube/config")
    monkeypatch.setenv("PATH", "/usr/bin")


def test_a_component_gets_only_the_minimal_environment(tmp_path, monkeypatch, secret_environment):
    seen = {}

    class Started:
        def __init__(self, command, stdout, stderr, env):
            seen.update(env)

        def poll(self):
            return None

    monkeypatch.setattr(run.subprocess, "Popen", Started)
    deployment = run.Deployment(tmp_path, receipt_dir=tmp_path, archiver_uid=os.geteuid() + 1)
    deployment.spawn("docket", ["true"], path=tmp_path)
    assert seen == {"PATH": "/usr/bin"}


def test_claude_gets_the_token_from_its_file_and_no_api_key(tmp_path, monkeypatch, secret_environment):
    token = tmp_path / "claude-token"
    token.write_text("file-token\n")
    seen = {}

    def complete(command, cwd, env, **options):
        seen.update(env)
        return run.subprocess.CompletedProcess(command, 0, stdout=json.dumps({"result": "done"}), stderr="")

    monkeypatch.setattr(run.subprocess, "run", complete)
    task = {"mcp_config": tmp_path / "mcp.json", "workspace": tmp_path, "claude_token": token}
    assert run.run_claude("p", task, "m")["result"] == "done"
    assert seen == {"PATH": "/usr/bin", run.TOKEN_VARIABLE: "file-token"}


def test_an_empty_token_file_is_refused(tmp_path):
    token = tmp_path / "claude-token"
    token.write_text("\n")
    with pytest.raises(RuntimeError, match="is empty"):
        run.run_claude("p", {"mcp_config": tmp_path, "workspace": tmp_path, "claude_token": token}, "m")


SIGTERM_CHILD = """import sys, time
import run
run.install_sigterm()
try:
    print("ready", flush=True)
    time.sleep(30)
finally:
    run.ignore_sigterm()
    print("tearing down", flush=True)
    time.sleep(1)
    open(sys.argv[1], "w").write("finally ran")
"""


def test_sigterm_runs_the_finally_block_and_a_second_one_does_not_stop_it(tmp_path):
    marker = tmp_path / "marker"
    child = subprocess.Popen(
        [sys.executable, "-c", SIGTERM_CHILD, str(marker)], cwd=LIVE_RUN, stdout=subprocess.PIPE, text=True
    )
    assert child.stdout.readline() == "ready\n"
    child.send_signal(signal.SIGTERM)
    assert child.stdout.readline() == "tearing down\n"
    child.send_signal(signal.SIGTERM)
    assert child.wait(10) == 143
    assert marker.read_text() == "finally ran"


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


def test_the_deadline_gives_each_call_the_remaining_time():
    clock = Clock()
    deadline = kubernetes.Deadline(240, clock)
    clock.now = 100
    assert deadline.remaining() == 140
    clock.now = 300
    assert deadline.remaining() == 0


def test_teardown_continues_past_an_expired_deadline_and_names_every_step(tmp_path, monkeypatch):
    clock = Clock()
    timeouts = []

    def slow_kubectl(context, *args, stdin=None, timeout=120):
        timeouts.append(timeout)
        clock.now += 200
        return ""

    monkeypatch.setattr(kubernetes, "kubectl", slow_kubectl)
    deadline = kubernetes.Deadline
    monkeypatch.setattr(kubernetes, "Deadline", lambda seconds: deadline(seconds, clock))
    cluster = bare_cluster(tmp_path, created=True)
    with pytest.raises(RuntimeError, match="cleanup incomplete") as raised:
        cluster.down()
    assert timeouts == [240, 40]
    assert "skipped: teardown deadline" in str(raised.value)
    assert "unchecked" in str(raised.value)
    assert "agent-bailiff-lock kept" in str(raised.value)


def bare_cluster(tmp_path, created=False):
    cluster = object.__new__(kubernetes.Cluster)
    cluster.context, cluster.run_id, cluster.directory = "orbstack", "r1", tmp_path
    cluster.created = cluster.locked = created
    cluster.namespaces = {key: f"bl-x-{key}" for key in ("sys", "hook", "staging", "prod")}
    cluster.manifests = cluster.webhook_manifests = tmp_path / "absent.json"
    return cluster


def test_a_held_lock_fails_fast_and_names_its_owner(tmp_path, monkeypatch):
    def locked(context, *args, stdin=None, timeout=120):
        if args[0] == "create":
            raise RuntimeError('Error from server (AlreadyExists): namespaces "agent-bailiff-lock" already exists')
        return "r0"

    monkeypatch.setattr(kubernetes, "kubectl", locked)
    cluster = bare_cluster(tmp_path)
    with pytest.raises(RuntimeError, match="locked by run r0.*bl-r0 is not running"):
        cluster.acquire_lock()
    assert not cluster.locked


def test_the_lock_counts_as_held_while_its_create_runs(tmp_path, monkeypatch):
    cluster = bare_cluster(tmp_path)

    def interrupted(context, *args, stdin=None, timeout=120):
        assert cluster.locked
        raise SystemExit(143)

    monkeypatch.setattr(kubernetes, "kubectl", interrupted)
    with pytest.raises(SystemExit):
        cluster.acquire_lock()
    assert cluster.locked


def test_the_lock_carries_the_owner_and_run_label(tmp_path, monkeypatch):
    sent = []
    monkeypatch.setattr(kubernetes, "kubectl", lambda context, *args, stdin=None, timeout=120: sent.append(stdin))
    cluster = bare_cluster(tmp_path)
    cluster.acquire_lock()
    metadata = json.loads(sent[0])["metadata"]
    assert metadata["name"] == "agent-bailiff-lock"
    assert metadata["annotations"] == {"agent-bailiff/owner": "r1"}
    assert metadata["labels"] == {"agent-bailiff/run": "r1"}
    assert cluster.locked


def test_every_listed_object_gets_the_run_label():
    document = {"items": [{"metadata": {}}, {"metadata": {"labels": {"app": "x"}}}]}
    labels = [item["metadata"]["labels"] for item in kubernetes.labelled(document, "r1")["items"]]
    assert labels == [{"agent-bailiff/run": "r1"}, {"app": "x", "agent-bailiff/run": "r1"}]


def test_a_clean_teardown_deletes_the_lock_last(tmp_path, monkeypatch):
    calls = []

    def record(context, *args, stdin=None, timeout=120):
        calls.append(args)
        return "r1" if args[:3] == ("get", "namespace", "agent-bailiff-lock") else ""

    monkeypatch.setattr(kubernetes, "kubectl", record)
    cluster = bare_cluster(tmp_path, created=True)
    cluster.down()
    assert calls[-1][:3] == ("delete", "namespace", "agent-bailiff-lock")


@pytest.mark.parametrize("owner", ["r0", ""])
def test_a_lock_this_run_does_not_own_is_never_deleted(tmp_path, monkeypatch, owner):
    calls = []

    def record(context, *args, stdin=None, timeout=120):
        calls.append(args)
        return owner if args[:3] == ("get", "namespace", "agent-bailiff-lock") else ""

    monkeypatch.setattr(kubernetes, "kubectl", record)
    cluster = bare_cluster(tmp_path)
    cluster.locked = True
    cluster.down()
    assert calls == [("get", "namespace", "agent-bailiff-lock", "--ignore-not-found", "-o",
                      "jsonpath={.metadata.annotations.agent-bailiff/owner}")]  # fmt: skip


def test_an_unlocked_cluster_tears_down_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(kubernetes, "kubectl", lambda *args, **options: pytest.fail("kubectl called"))
    bare_cluster(tmp_path).down()


@pytest.mark.parametrize(
    "image", ["agent-bailiff-webhook:live", "agent-bailiff-webhook@sha256:abc", "sha256:" + "a" * 64]
)
def test_the_webhook_image_must_be_a_digest_ref(tmp_path, monkeypatch, image):
    monkeypatch.setattr(kubernetes, "kubectl", lambda *args, **options: pytest.fail("kubectl called"))
    with pytest.raises(RuntimeError, match="pinned by sha256 digest"):
        bare_cluster(tmp_path).deploy_webhook({}, image)
