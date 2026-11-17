import copy
import json
import os
from pathlib import Path

import pytest

from agent_bailiff.effector.catalog import ALLOWED_CALLS, CatalogError, OperationCatalog

SHIPPED = Path(__file__).resolve().parent.parent / "agent_bailiff" / "effector" / "catalogs" / "kubernetes.json"


RESTART = {
    "name": "restart_deployment",
    "call": {
        "group": "apps",
        "version": "v1",
        "resource": "deployments",
        "subresource": None,
        "verb": "patch",
        "query": {},
    },
    "arguments": {"namespace": {"kind": "label"}, "name": {"kind": "label"}},
    "response": {"fields": ["metadata.name", "metadata.generation", "status.observedGeneration"], "max_bytes": 4096},
}


def shipped():
    return json.loads(SHIPPED.read_text())


def with_restart():
    document = shipped()
    if not any(item["name"] == RESTART["name"] for item in document["operations"]):
        document["operations"].append(copy.deepcopy(RESTART))
    return document


def named(document, name):
    return next(item for item in document["operations"] if item["name"] == name)


def scale(document):
    return named(document, "scale_deployment")


def listing(document):
    return named(document, "list_pods")


def refused(change, match):
    document = shipped()
    change(document)
    with pytest.raises(CatalogError, match=match):
        OperationCatalog(document)


def test_the_shipped_catalog_loads_with_derived_resources_and_bodies():
    catalog = OperationCatalog.load(SHIPPED)
    resources = {item.name: item.resource for item in catalog.operations}
    assert resources == {
        "list_pods": "k8s/{namespace}/pods",
        "read_pod_log": "k8s/{namespace}/pods/{name}",
        "get_deployment": "k8s/{namespace}/deployments/{name}",
        "scale_deployment": "k8s/{namespace}/deployments/{name}",
        "restart_deployment": "k8s/{namespace}/deployments/{name}",
    }
    operation = catalog.operation("scale_deployment")
    assert operation.call.body({"namespace": "staging", "name": "api", "replicas": 3}, 0) == {"spec": {"replicas": 3}}
    assert catalog.operation("list_pods").call.body({}, 0) is None


def test_tool_ids_and_identities_are_derived_from_the_call():
    catalog = OperationCatalog(shipped())
    assert {item.name: (item.tool, item.identity) for item in catalog.operations} == {
        "list_pods": ("k8s.pods.list", "read"),
        "read_pod_log": ("k8s.pods.log", "read"),
        "get_deployment": ("k8s.deployments.get", "read"),
        "scale_deployment": ("k8s.deployments.scale", "scale"),
        "restart_deployment": ("k8s.deployments.restart", "restart"),
    }
    refused(lambda d: scale(d).update(tool="k8s.deployments.get"), "exactly the fields")
    refused(lambda d: scale(d).update(identity="read"), "exactly the fields")


def test_scale_cannot_reach_zero_replicas():
    refused(lambda d: scale(d)["arguments"].update(replicas={"kind": "integer", "minimum": 0, "maximum": 3}), "1 <=")


def test_only_the_listed_calls_are_allowed():
    assert set(ALLOWED_CALLS) == {
        ("", "v1", "pods", None, "list"),
        ("", "v1", "pods", "log", "get"),
        ("apps", "v1", "deployments", None, "get"),
        ("apps", "v1", "deployments", "scale", "get"),
        ("apps", "v1", "deployments", "scale", "patch"),
        ("apps", "v1", "deployments", None, "patch"),
    }


@pytest.mark.parametrize(
    "call",
    [
        {"resource": "secrets", "group": "", "subresource": None, "verb": "get"},
        {"resource": "configmaps", "group": "", "subresource": None, "verb": "get"},
        {"resource": "deployments", "group": "apps", "subresource": None, "verb": "delete"},
        {"resource": "statefulsets", "group": "apps", "subresource": "scale", "verb": "patch"},
        {"resource": "deployments", "group": "", "subresource": "scale", "verb": "patch"},
        {"resource": "deployments", "group": "apps", "subresource": "status", "verb": "patch"},
        {"resource": "serviceaccounts", "group": "", "subresource": "token", "verb": "create"},
        {"version": "v1beta1"},
        {"resource": ["deployments"]},
    ],
)
def test_calls_outside_the_allowed_set_are_refused(call):
    refused(lambda d: scale(d)["call"].update(call), "allowed set|strings or null")


def test_unknown_operation_or_call_fields_are_refused():
    refused(lambda d: scale(d).update(resource="k8s/prod/pods/{namespace}"), "exactly the fields")
    refused(lambda d: scale(d).update(body={"spec": {"paused": "{replicas}"}}), "exactly the fields")
    refused(lambda d: scale(d)["call"].update(body={}), "exactly the fields")


def test_the_query_must_name_exactly_the_allowed_parameters():
    refused(lambda d: listing(d)["call"]["query"].update(fieldSelector="limit"), "query must name exactly")
    refused(lambda d: listing(d)["call"].update(query={}), "query must name exactly")
    refused(lambda d: scale(d)["call"].update(query={"limit": "replicas"}), "query must name exactly")


def test_the_arguments_must_match_the_call_exactly():
    refused(lambda d: listing(d)["arguments"].update(name={"kind": "label"}), "arguments must be exactly")
    refused(lambda d: scale(d)["arguments"].pop("name"), "arguments must be exactly")
    refused(lambda d: scale(d)["arguments"].pop("replicas"), "arguments must be exactly")
    refused(
        lambda d: scale(d)["arguments"].update(paused={"kind": "integer", "minimum": 0, "maximum": 1}),
        "arguments must be exactly",
    )

    def query_names_a_missing_argument(document):
        listing(document)["call"]["query"]["limit"] = "count"

    refused(query_names_a_missing_argument, "arguments must be exactly")


def test_argument_kinds_and_bounds_are_strict():
    refused(lambda d: scale(d)["arguments"].update(namespace={"kind": "label", "default": "x"}), "label")
    refused(lambda d: scale(d)["arguments"].update(name={"kind": "string"}), "label")
    refused(lambda d: scale(d)["arguments"].update(replicas={"kind": "label"}), "integer")
    refused(lambda d: scale(d)["arguments"].update(replicas={"kind": "integer"}), "integer")
    refused(lambda d: scale(d)["arguments"].update(replicas={"kind": "integer", "minimum": 5, "maximum": 1}), "bounds")
    refused(
        lambda d: scale(d)["arguments"].update(replicas={"kind": "integer", "minimum": True, "maximum": 5}),
        "integers",
    )


def test_response_rules():
    refused(lambda d: scale(d)["response"].update(fields=[]), "lists its fields")
    refused(lambda d: scale(d)["response"].update(max_bytes=0), "max_bytes")
    refused(lambda d: scale(d)["response"].update(max_bytes=(1 << 20) + 1), "max_bytes")
    refused(lambda d: scale(d)["response"].update(fields=["spec..replicas"]), "dotted")
    refused(lambda d: named(d, "read_pod_log")["response"].update(fields=["x"]), "logs return text")


def test_names_and_tools_must_be_unique():
    def duplicate(document):
        document["operations"].append(copy.deepcopy(scale(document)))

    refused(duplicate, "unique")

    def same_call(document):
        other = copy.deepcopy(scale(document))
        other["name"] = "scale_again"
        document["operations"].append(other)

    refused(same_call, "tools must be unique")


def test_top_level_rules():
    refused(lambda d: d.update(extra=1), "exactly")
    refused(lambda d: d.update(version=2), "version")
    refused(lambda d: d.update(version=True), "version")
    refused(lambda d: d.update(target="aws"), "target")
    refused(lambda d: d.update(operations=[]), "non-empty")


def test_operation_arguments_are_checked_against_the_schema():
    operation = OperationCatalog(shipped()).operation("scale_deployment")
    assert operation.accepts({"namespace": "staging", "name": "api", "replicas": 3})
    for arguments in (
        {"namespace": "staging", "name": "api"},
        {"namespace": "staging", "name": "api", "replicas": 11},
        {"namespace": "staging", "name": "api", "replicas": True},
        {"namespace": "staging", "name": "api", "replicas": "3"},
        {"namespace": "Staging", "name": "api", "replicas": 3},
        {"namespace": "staging", "name": "api", "replicas": 3, "kind": "StatefulSet"},
        ["staging"],
    ):
        assert not operation.accepts(arguments), arguments


def test_the_digest_is_stable_and_changes_with_the_catalog():
    assert OperationCatalog(shipped()).digest == OperationCatalog(shipped()).digest
    changed = shipped()
    scale(changed)["arguments"]["replicas"]["maximum"] = 9
    assert OperationCatalog(changed).digest != OperationCatalog(shipped()).digest


def test_load_refuses_invalid_json_and_oversized_files(tmp_path):
    path = tmp_path / "catalog.json"
    path.write_text('{"version": 1, "version": 1}')
    os.chmod(path, 0o600)
    with pytest.raises(CatalogError, match="not valid JSON"):
        OperationCatalog.load(path)
    path.write_text(" " * ((1 << 20) + 1))
    with pytest.raises(CatalogError, match="larger"):
        OperationCatalog.load(path)


def test_restart_sets_only_the_restarted_at_annotation_to_the_release_time():
    operation = OperationCatalog(with_restart()).operation("restart_deployment")
    assert (operation.tool, operation.identity, operation.resource) == (
        "k8s.deployments.restart",
        "restart",
        "k8s/{namespace}/deployments/{name}",
    )
    assert operation.call.body({"namespace": "staging", "name": "api"}, 1_800_000_001) == {
        "spec": {
            "template": {"metadata": {"annotations": {"kubectl.kubernetes.io/restartedAt": "2027-01-15T08:00:01Z"}}}
        }
    }


def test_restart_takes_no_other_arguments():
    def with_replicas(document):
        document["operations"].append(copy.deepcopy(RESTART))
        document["operations"][-1]["arguments"]["replicas"] = {"kind": "integer", "minimum": 1, "maximum": 3}

    refused(with_replicas, "arguments must be exactly")
