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
    listed = {"value": ""}

    def run(command, **options):
        calls.append(command)
        stdout = listed["value"] if command[:4] == ["gcloud", "container", "clusters", "list"] else ""
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

    monkeypatch.setattr(gke_probe.subprocess, "run", run)
    return calls, listed


def verbs(calls):
    return [command[3] for command in calls if command[:3] == ["gcloud", "container", "clusters"]]


def test_an_existing_probe_cluster_is_refused_and_never_deleted(gcloud, tmp_path):
    calls, listed = gcloud
    listed["value"] = "other\nbailiff-probe\n"
    with pytest.raises(RuntimeError, match="bailiff-probe already exists in demo"):
        gke_probe.run("demo", "europe-west1-b", tmp_path / "out.json", lambda *args: {})
    assert verbs(calls) == ["list"]


def test_the_cluster_is_created_with_the_probe_label_and_deleted_after_the_probe(gcloud, tmp_path):
    calls, _ = gcloud
    result = gke_probe.run("demo", "europe-west1-b", tmp_path / "out.json", lambda *args: {"ok": True})
    assert verbs(calls) == ["list", "create", "delete"]
    [create] = [command for command in calls if command[3] == "create"]
    assert create[create.index("--labels") + 1] == "purpose=bailiff-probe"
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


def test_the_cluster_is_deleted_when_creation_fails(monkeypatch, tmp_path):
    calls = []

    def run(command, **options):
        calls.append(command[3])
        if command[3] == "create":
            raise subprocess.TimeoutExpired(command, 900)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(gke_probe.subprocess, "run", run)
    with pytest.raises(subprocess.TimeoutExpired):
        gke_probe.run("demo", "europe-west1-b", tmp_path / "out.json", lambda *args: {})
    assert calls == ["list", "create", "delete"]


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
