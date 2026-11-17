import copy
import json
from dataclasses import replace

import pytest
from test_effector import CATALOG, CONFIG, NOW, release_for

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


def test_exact_released_scale_is_admitted():
    assert decide(review()) == {"uid": "uid-1", "allowed": True}


@pytest.mark.parametrize("replicas", ["3", 3.0, True, 4])
def test_replica_type_and_digest_are_bound(replicas):
    assert decide(review(replicas=replicas))["allowed"] is False


@pytest.mark.parametrize("change", [
    lambda r: r["request"].update(operation="CREATE"),
    lambda r: r["request"].update(subResource=""),
    lambda r: r["request"]["kind"].update(kind="Deployment"),
    lambda r: r["request"]["resource"].update(resource="pods"),
    lambda r: r["request"]["userInfo"].update(username="bailiff:tenant-b:scale"),
    lambda r: r["request"]["userInfo"]["extra"].update({"bailiff.dev/op-id": ["wrong"]}),
    lambda r: r["request"]["userInfo"]["extra"].update({"bailiff.dev/release": []}),
    lambda r: r["request"]["object"]["metadata"].update(name="other"),
    lambda r: r["request"]["object"]["status"].update(replicas=3),
])
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
