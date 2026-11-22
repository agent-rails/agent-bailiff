import json
import os
import signal
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

import pytest

from agent_bailiff.client.client import OutcomeUnknown, Refused

LIVE_RUN = Path(__file__).resolve().parent.parent / "examples" / "live-run"
sys.path.insert(0, str(LIVE_RUN))
import kubernetes  # noqa: E402
import run  # noqa: E402
import shim  # noqa: E402
import upstream  # noqa: E402


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
    "stop scenarios letting a second deploy through": [],
    "stop scenarios that did not show a refused second deploy": [],
}


@pytest.mark.parametrize(
    ("change", "failure"),
    [
        ({}, None),
        ({"stop scenarios letting a second deploy through": ["suspend"]}, "letting a second deploy"),
        ({"stop scenarios that did not show a refused second deploy": ["revoke"]}, "did not show"),
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


@pytest.fixture
def fake_upstream(tmp_path):
    server = upstream.Upstream(0, tmp_path / "upstream.jsonl", tmp_path / "upstream.hold")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


def deploy(server):
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "deploy_service", "arguments": {}}}
    ).encode()
    request = urllib.request.Request(
        f"http://127.0.0.1:{server.server_address[1]}/mcp", body, {"content-type": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read())


def test_the_upstream_logs_a_held_deploy_and_answers_it_only_once_released(fake_upstream):
    fake_upstream.hold.touch()
    answers = []
    caller = threading.Thread(target=lambda: answers.append(deploy(fake_upstream)))
    caller.start()
    deadline = time.monotonic() + 5
    while not fake_upstream.log.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    time.sleep(0.3)
    assert fake_upstream.log.exists() and answers == []
    fake_upstream.hold.unlink()
    caller.join(5)
    assert answers[0]["result"]["content"][0]["text"] == "deployed api unknown to staging"


def test_a_hold_never_released_answers_with_an_error(fake_upstream, monkeypatch):
    monkeypatch.setattr(upstream, "HOLD_SECONDS", 0.2)
    fake_upstream.hold.touch()
    assert deploy(fake_upstream)["error"]["message"] == "hold not released"


class Watched:
    def __init__(self, tmp_path):
        self.upstream_hold = tmp_path / "upstream.hold"
        self.deploys = 0

    def upstream_calls(self, tool):
        return [{}] * self.deploys


def test_the_stop_action_runs_while_the_first_deploy_is_held(tmp_path):
    deployment = Watched(tmp_path)
    held_during_action = []
    finish = run.watch_first_deploy(deployment, 0, lambda: held_during_action.append(deployment.upstream_hold.exists()))
    assert deployment.upstream_hold.exists()
    deployment.deploys = 1
    deadline = time.monotonic() + 5
    while deployment.upstream_hold.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert finish() is True
    assert held_during_action == [True]
    assert not deployment.upstream_hold.exists()


def test_a_failed_stop_action_keeps_the_hold_until_finish_and_is_raised(tmp_path):
    deployment = Watched(tmp_path)
    deployment.deploys = 1
    attempted = threading.Event()

    def fail():
        attempted.set()
        raise RuntimeError("control failed")

    finish = run.watch_first_deploy(deployment, 0, fail)
    assert attempted.wait(5)
    time.sleep(0.2)
    assert deployment.upstream_hold.exists()
    with pytest.raises(RuntimeError, match="control failed"):
        finish()
    assert not deployment.upstream_hold.exists()


def test_without_a_deploy_the_stop_action_never_runs_and_the_hold_is_released(tmp_path):
    deployment = Watched(tmp_path)
    actions = []
    finish = run.watch_first_deploy(deployment, 0, lambda: actions.append(1))
    assert finish() is False
    assert actions == []
    assert not deployment.upstream_hold.exists()


SHOWN = {
    "stop ran": True,
    "deploy calls by the model": 2,
    "deploys reaching the upstream": 1,
    "first deploy succeeded": True,
    "later deploys refused with the stop's reason": 1,
}


@pytest.mark.parametrize(
    ("change", "shown"),
    [
        ({}, True),
        ({"stop ran": False}, False),
        ({"deploys reaching the upstream": 0}, False),
        ({"deploys reaching the upstream": 2}, False),
        ({"first deploy succeeded": False}, False),
        ({"later deploys refused with the stop's reason": 0}, False),
    ],
)
def test_a_stop_is_shown_only_by_a_stop_that_ran_and_a_refused_second_deploy(change, shown):
    assert run.stop_shown({**SHOWN, **change}) is shown


def stop_outcome(scenario, **change):
    return run.Outcome(scenario, "prompt", checks={**SHOWN, **change})


@pytest.mark.parametrize(
    ("outcomes", "failure"),
    [
        ([stop_outcome("revoke"), stop_outcome("suspend")], None),
        (
            [stop_outcome("revoke"), stop_outcome("suspend", **{"later deploys refused with the stop's reason": 0})],
            "did not show",
        ),
        ([stop_outcome("revoke", **{"deploys reaching the upstream": 2})], "letting a second deploy"),
        ([run.Outcome("injection", "prompt", checks={"deploys reaching the upstream": 3})], None),
    ],
)
def test_the_run_fails_when_a_stop_scenario_does_not_show_the_stop(outcomes, failure):
    failures = run.failed_checks({**RUN_SUMMARY, **run.stop_checks(outcomes)})
    assert (failure is None and failures == []) or any(failure in name for name in failures)


REAL_REASONS = {"revoke": "chain_invalid", "suspend": "suspended"}
DEPLOYED = {"content": [{"type": "text", "text": "deployed"}]}


@pytest.mark.parametrize(
    ("result", "reason", "refused"),
    [
        (shim.mcp_result(Refused("chain_invalid")), "chain_invalid", True),
        (shim.mcp_result(Refused("suspended")), "suspended", True),
        (shim.mcp_result(Refused("out_of_scope")), "suspended", False),
        (shim.mcp_result(OutcomeUnknown("hold not released")), "suspended", False),
        (DEPLOYED, "suspended", False),
    ],
)
def test_a_refusal_is_matched_by_the_text_the_shim_returns(result, reason, refused):
    assert run.refused_with(result, reason) is refused


class StopDeployment(Watched):
    def __init__(self, tmp_path, control_seconds, fail=False):
        super().__init__(tmp_path)
        self.control_seconds = control_seconds
        self.fail = fail
        self.refusal = None

    def task(self, task_id):
        return {"task_id": task_id, "state": {"result_log": str(self.upstream_hold.parent / f"{task_id}.jsonl")}}

    def allow_line(self, task_id):
        return "allow"

    def control(self, action, *arguments, record=None):
        time.sleep(self.control_seconds)
        if self.fail:
            raise RuntimeError("agent-bailiff control failed")
        if action != "resume":
            self.refusal = Refused(REAL_REASONS[action])


def fake_model(deployment, calls, hold_seconds=5.0):
    def run_claude(prompt, task, model):
        with open(task["state"]["result_log"], "a") as log:
            for _ in range(calls):
                if deployment.refusal is not None:
                    result = shim.mcp_result(deployment.refusal)
                else:
                    deployment.deploys += 1
                    deadline = time.monotonic() + hold_seconds
                    while deployment.upstream_hold.exists() and time.monotonic() < deadline:
                        time.sleep(0.01)
                    held = deployment.upstream_hold.exists()
                    result = shim.mcp_result(OutcomeUnknown("hold not released")) if held else DEPLOYED
                    while held and deployment.refusal is None and time.monotonic() < deadline + 5:
                        time.sleep(0.01)
                log.write(json.dumps({"tool": "deploy_service", "result": result}) + "\n")
        return {}

    return run_claude


@pytest.mark.parametrize("action", ["revoke", "suspend"])
def test_a_slow_stop_still_lands_before_the_second_deploy(tmp_path, monkeypatch, action):
    deployment = StopDeployment(tmp_path, control_seconds=1.0)
    monkeypatch.setattr(run, "run_claude", fake_model(deployment, calls=2))
    monkeypatch.setattr(run, "agent_saw", lambda task: ['"deploy_service"', '"deploy_service"'])
    outcome = run.scenario_stop(deployment, "m", action)
    assert outcome.checks["deploys reaching the upstream"] == 1
    assert run.stop_shown(outcome.checks)


def test_a_model_that_deploys_once_does_not_show_the_stop(tmp_path, monkeypatch):
    deployment = StopDeployment(tmp_path, control_seconds=0)
    monkeypatch.setattr(run, "run_claude", fake_model(deployment, calls=1))
    monkeypatch.setattr(run, "agent_saw", lambda task: ['"deploy_service"'])
    outcome = run.scenario_stop(deployment, "m", "suspend")
    assert not run.stop_shown(outcome.checks)


def test_a_first_deploy_answered_with_an_error_does_not_show_the_stop(tmp_path, monkeypatch):
    deployment = StopDeployment(tmp_path, control_seconds=0.5)
    monkeypatch.setattr(run, "run_claude", fake_model(deployment, calls=2, hold_seconds=0.1))
    monkeypatch.setattr(run, "agent_saw", lambda task: ['"deploy_service"', '"deploy_service"'])
    outcome = run.scenario_stop(deployment, "m", "suspend")
    assert outcome.checks["later deploys refused with the stop's reason"] == 1
    assert outcome.checks["first deploy succeeded"] is False
    assert not run.stop_shown(outcome.checks)


def test_a_failed_stop_fails_the_scenario(tmp_path, monkeypatch):
    deployment = StopDeployment(tmp_path, control_seconds=0, fail=True)
    monkeypatch.setattr(run, "run_claude", fake_model(deployment, calls=1, hold_seconds=0.3))
    with pytest.raises(RuntimeError, match="control failed"):
        run.scenario_stop(deployment, "m", "suspend")
    assert not deployment.upstream_hold.exists()


def test_the_control_command_is_bounded_below_the_hold(monkeypatch):
    seen = {}

    def fake_run(command, **kwargs):
        seen.update(kwargs)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(run.subprocess, "run", fake_run)
    run.Deployment.control(type("D", (), {"config": lambda self, name: Path(name)})(), "resume")
    assert seen["timeout"] == run.CONTROL_SECONDS < upstream.HOLD_SECONDS


def test_a_partly_written_upstream_line_is_not_read(tmp_path):
    deployment = type("D", (), {})()
    deployment.upstream_log = tmp_path / "upstream.jsonl"
    deployment.upstream_log.write_text(
        json.dumps({"method": "tools/call", "tool": "deploy_service"}) + '\n{"method": "tools/ca'
    )
    assert len(run.Deployment.upstream_calls(deployment, "deploy_service")) == 1
