import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "examples" / "live-run"))
import gke_probe  # noqa: E402

from agent_bailiff.effector.platform import Action  # noqa: E402


@pytest.fixture
def gcloud(monkeypatch):
    calls = []
    answers = {"list": "", "describe": None, "create": None}

    def run(command, **options):
        calls.append(command)
        verb = command[3]
        if isinstance(answers.get(verb), BaseException):
            raise answers[verb]
        if verb == "describe":
            labels = answers["describe"]
            if labels is None:
                return subprocess.CompletedProcess(command, 1, stdout="", stderr="ERROR: code=404, message=Not found")
            if isinstance(labels, str):
                return subprocess.CompletedProcess(command, 1, stdout="", stderr=labels)
            return subprocess.CompletedProcess(command, 0, stdout=json.dumps({"resourceLabels": labels}), stderr="")
        return subprocess.CompletedProcess(command, 0, stdout=answers["list"] if verb == "list" else "", stderr="")

    monkeypatch.setattr(gke_probe.subprocess, "run", run)
    monkeypatch.setattr(gke_probe.secrets, "token_hex", lambda size: "run0001")
    return calls, answers


def verbs(calls):
    return [command[3] for command in calls if command[:3] == ["gcloud", "container", "clusters"]]


def test_an_existing_probe_cluster_is_refused_and_never_deleted(gcloud, tmp_path):
    calls, answers = gcloud
    answers["list"] = "other\nbailiff-probe\n"
    with pytest.raises(RuntimeError, match="bailiff-probe already exists in demo"):
        gke_probe.run("demo", "europe-west1-b", tmp_path / "out.json", lambda *args: {})
    assert verbs(calls) == ["list"]


def test_the_cluster_is_created_with_the_probe_label_and_deleted_after_the_probe(gcloud, tmp_path):
    calls, _ = gcloud
    result = gke_probe.run("demo", "europe-west1-b", tmp_path / "out.json", lambda *args: {"ok": True})
    assert verbs(calls) == ["list", "create", "delete"]
    [create] = [command for command in calls if command[3] == "create"]
    assert create[create.index("--labels") + 1] == "purpose=bailiff-probe,bailiff-probe-run=run0001"
    assert create[4] == "bailiff-probe" and create[-3:] == ["--project", "demo", "--quiet"]
    assert json.loads((tmp_path / "out.json").read_text()) == result and result["ok"] is True


def test_the_cluster_is_deleted_when_the_probe_fails(gcloud, tmp_path):
    calls, _ = gcloud

    def fail(*args):
        raise RuntimeError("probe failed")

    with pytest.raises(RuntimeError, match="probe failed"):
        gke_probe.run("demo", "europe-west1-b", tmp_path / "out.json", fail)
    assert verbs(calls) == ["list", "create", "delete"]
    assert not (tmp_path / "out.json").exists()


def test_a_cluster_left_by_a_failed_create_is_deleted_when_it_carries_this_runs_label(gcloud, tmp_path):
    calls, answers = gcloud
    answers["create"] = subprocess.TimeoutExpired(["gcloud"], 900)
    answers["describe"] = {"purpose": "bailiff-probe", "bailiff-probe-run": "run0001"}
    with pytest.raises(subprocess.TimeoutExpired):
        gke_probe.run("demo", "europe-west1-b", tmp_path / "out.json", lambda *args: {})
    assert verbs(calls) == ["list", "create", "describe", "delete"]


@pytest.mark.parametrize("labels", [None, {"purpose": "bailiff-probe", "bailiff-probe-run": "other"}])
def test_a_failed_create_never_deletes_a_cluster_this_run_did_not_make(gcloud, tmp_path, labels):
    calls, answers = gcloud
    answers["create"] = subprocess.CalledProcessError(1, ["gcloud"], stderr="Already exists")
    answers["describe"] = labels
    with pytest.raises(subprocess.CalledProcessError):
        gke_probe.run("demo", "europe-west1-b", tmp_path / "out.json", lambda *args: {})
    assert verbs(calls) == ["list", "create", "describe"]


def test_an_undecidable_owner_after_a_failed_create_is_reported_without_deleting(gcloud, tmp_path):
    calls, answers = gcloud
    answers["create"] = subprocess.CalledProcessError(1, ["gcloud"])
    answers["describe"] = "ERROR: code=403, message=Permission denied"
    with pytest.raises(RuntimeError, match="cannot tell whether bailiff-probe is this run's: ERROR: code=403"):
        gke_probe.run("demo", "europe-west1-b", tmp_path / "out.json", lambda *args: {})
    assert verbs(calls) == ["list", "create", "describe"]


def test_sigterm_exits_through_the_cleanup_path():
    with pytest.raises(SystemExit) as raised:
        gke_probe.terminate(15, None)
    assert raised.value.code == 143


@pytest.mark.parametrize(
    ("action", "namespace", "attributes"),
    [
        (Action("get", "", "secrets"), None, {"verb": "get", "group": "", "resource": "secrets"}),
        (
            Action("create", "", "pods", "exec"),
            "bailiff-probe",
            {"verb": "create", "group": "", "resource": "pods", "subresource": "exec", "namespace": "bailiff-probe"},
        ),
    ],
)
def test_an_access_review_names_the_action_and_only_the_given_namespace(action, namespace, attributes):
    review = json.loads(gke_probe.review_body(action, namespace))
    assert review["kind"] == "SelfSubjectAccessReview"
    assert review["spec"] == {"resourceAttributes": attributes}


def test_statuses_are_tallied_by_their_exact_fields():
    statuses = [
        {"allowed": False},
        {"allowed": False, "evaluationError": "x"},
        {"allowed": False},
        {"allowed": False, "reason": "r"},
    ]
    assert gke_probe.tally(statuses) == [
        {"status": {"allowed": False, "evaluationError": "x"}, "count": 1},
        {"status": {"allowed": False, "reason": "r"}, "count": 1},
        {"status": {"allowed": False}, "count": 2},
    ]


def test_latency_percentiles_use_the_nearest_rank():
    values = [index / 1000 for index in range(1, 101)]
    assert gke_probe.latency(values) == {"p50_ms": 50.0, "p95_ms": 95.0, "p99_ms": 99.0, "max_ms": 100.0}
