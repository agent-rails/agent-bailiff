import copy
import json
from dataclasses import replace
from datetime import UTC, datetime

import pytest
from test_effector import CATALOG, CONFIG, NOW, clearance_for, release_for

from agent_bailiff.webhook.admission import Admission, MalformedReview


def review(token=None, *, replicas=3):
    old = {
        "apiVersion": "autoscaling/v1",
        "kind": "Scale",
        "metadata": {"namespace": "staging", "name": "api", "resourceVersion": "1"},
        "spec": {"replicas": 1},
        "status": {"replicas": 1},
    }
    new = copy.deepcopy(old)
    new["spec"]["replicas"] = replicas
    return {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {
            "uid": "uid-1",
            "kind": {"group": "autoscaling", "version": "v1", "kind": "Scale"},
            "resource": {"group": "apps", "version": "v1", "resource": "deployments"},
            "subResource": "scale",
            "operation": "UPDATE",
            "name": "api",
            "namespace": "staging",
            "userInfo": {
                "username": "bailiff:tenant-a:scale",
                "extra": {
                    "bailiff.dev/op-id": ["op-scale_deployment-3"],
                    "bailiff.dev/release": [release_for() if token is None else token],
                },
            },
            "object": new,
            "oldObject": old,
        },
    }


def decide(document, *, enforce=True):
    webhook = Admission(replace(CONFIG, skew_seconds=2), CATALOG, enforce=enforce)
    return webhook.review(json.dumps(document).encode(), NOW + 2)["response"]


def restart_review(change=None):
    arguments = {"namespace": "staging", "name": "api"}
    op_id = "op-restart_deployment-0"
    clearance = clearance_for("restart_deployment", arguments, op_id=op_id)
    token = release_for(clearance)
    old = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "namespace": "staging",
            "name": "api",
            "resourceVersion": "4",
            "generation": 2,
            "managedFields": [{"manager": "other"}],
        },
        "spec": {
            "replicas": 2,
            "selector": {"matchLabels": {"app": "api"}},
            "template": {
                "metadata": {"labels": {"app": "api"}, "annotations": {"existing": "keep"}},
                "spec": {"containers": [{"name": "api", "image": "api:v1"}]},
            },
        },
        "status": {"observedGeneration": 2},
    }
    new = copy.deepcopy(old)
    new["metadata"]["resourceVersion"] = "5"
    new["metadata"]["generation"] = 3
    new["metadata"]["managedFields"].append({"manager": "bailiff-effector"})
    new["spec"]["template"]["metadata"]["annotations"].update(
        {
            "kubectl.kubernetes.io/restartedAt": datetime.fromtimestamp(NOW + 1, UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "bailiff.dev/restart-op": op_id,
        }
    )
    document = {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {
            "uid": "uid-restart",
            "kind": {"group": "apps", "version": "v1", "kind": "Deployment"},
            "resource": {"group": "apps", "version": "v1", "resource": "deployments"},
            "operation": "UPDATE",
            "name": "api",
            "namespace": "staging",
            "userInfo": {
                "username": "bailiff:tenant-a:restart",
                "extra": {"bailiff.dev/op-id": [op_id], "bailiff.dev/release": [token]},
            },
            "object": new,
            "oldObject": old,
        },
    }
    if change:
        change(document)
    return document


def test_exact_released_scale_is_admitted():
    assert decide(review()) == {"uid": "uid-1", "allowed": True}


def test_exact_released_restart_is_admitted():
    assert decide(restart_review()) == {"uid": "uid-restart", "allowed": True}


@pytest.mark.parametrize(
    "change",
    [
        lambda r: r["request"]["object"]["spec"]["template"]["metadata"]["annotations"].update(extra="changed"),
        lambda r: r["request"]["object"]["spec"]["template"]["spec"]["containers"][0].update(image="evil:v2"),
        lambda r: r["request"]["object"]["spec"]["template"]["metadata"]["annotations"].update(
            {"bailiff.dev/restart-op": "wrong"}
        ),
        lambda r: r["request"]["userInfo"]["extra"]["bailiff.dev/op-id"].__setitem__(0, "wrong"),
        lambda r: r["request"].update(subResource="scale"),
    ],
)
def test_restart_release_must_bind_exact_template_change(change):
    assert decide(restart_review(change))["allowed"] is False


@pytest.mark.parametrize("replicas", ["3", 3.0, True, 4])
def test_replica_type_and_digest_are_bound(replicas):
    assert decide(review(replicas=replicas))["allowed"] is False


@pytest.mark.parametrize(
    "change",
    [
        lambda r: r["request"].update(operation="CREATE"),
        lambda r: r["request"].update(subResource=""),
        lambda r: r["request"]["kind"].update(kind="Deployment"),
        lambda r: r["request"]["resource"].update(resource="pods"),
        lambda r: r["request"]["userInfo"].update(username="bailiff:tenant-b:scale"),
        lambda r: r["request"]["userInfo"]["extra"].update({"bailiff.dev/op-id": ["wrong"]}),
        lambda r: r["request"]["userInfo"]["extra"].update({"bailiff.dev/release": []}),
        lambda r: r["request"]["object"]["metadata"].update(name="other"),
        lambda r: r["request"]["object"]["status"].update(replicas=3),
    ],
)
def test_operation_and_object_are_bound(change):
    document = review()
    change(document)
    assert decide(document)["allowed"] is False


def test_audit_reports_a_deny_but_allows_the_call(caplog):
    document = review()
    document["request"]["userInfo"]["extra"]["bailiff.dev/release"] = []
    assert decide(document, enforce=False)["allowed"] is True
    assert "would_deny" in caplog.text
    assert "bailiff.dev/release" in caplog.text


def test_duplicate_json_keys_are_rejected():
    webhook = Admission(replace(CONFIG, skew_seconds=2), CATALOG, enforce=True)
    with pytest.raises(MalformedReview):
        webhook.review(b'{"apiVersion":"admission.k8s.io/v1","apiVersion":"x"}', NOW)
