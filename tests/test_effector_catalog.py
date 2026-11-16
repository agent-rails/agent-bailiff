import copy
import json
import os
from pathlib import Path

import pytest

from agent_bailiff.effector.catalog import CatalogError, OperationCatalog

SHIPPED = Path(__file__).resolve().parent.parent / "agent_bailiff" / "effector" / "catalogs" / "kubernetes.json"


def shipped():
    return json.loads(SHIPPED.read_text())


def scale(document):
    return next(item for item in document["operations"] if item["name"] == "scale_deployment")


def listing(document):
    return next(item for item in document["operations"] if item["name"] == "list_pods")


def test_the_shipped_catalog_loads():
    catalog = OperationCatalog.load(SHIPPED)
    assert {item.name for item in catalog.operations} == {
        "list_pods",
        "read_pod_log",
        "get_deployment",
        "scale_deployment",
    }
    operation = catalog.operation("scale_deployment")
    assert operation.request.subresource == "scale" and operation.request.verb == "patch"
    assert operation.argument("replicas").maximum == 10


def test_the_digest_is_stable_and_changes_with_the_catalog():
    assert OperationCatalog(shipped()).digest == OperationCatalog(shipped()).digest
    changed = shipped()
    scale(changed)["arguments"]["replicas"]["maximum"] = 11
    assert OperationCatalog(changed).digest != OperationCatalog(shipped()).digest


def refused(change, match):
    document = shipped()
    change(document)
    with pytest.raises(CatalogError, match=match):
        OperationCatalog(document)


def test_an_unknown_top_level_field_is_refused():
    refused(lambda d: d.update(extra=1), "exactly")


def test_another_version_or_target_is_refused():
    refused(lambda d: d.update(version=2), "version")
    refused(lambda d: d.update(target="aws"), "target")


def test_an_unknown_operation_field_is_refused():
    refused(lambda d: scale(d).update(extra=1), "exactly the fields")


@pytest.mark.parametrize(
    ("verb", "subresource"),
    [("delete", None), ("patch", None), ("update", "scale"), ("create", None), ("patch", "status"), ("get", "exec")],
)
def test_calls_outside_the_allowed_set_are_refused(verb, subresource):
    def change(document):
        scale(document)["request"].update(verb=verb, subresource=subresource)

    refused(change, "not allowed")


def test_a_list_without_a_namespace_argument_is_refused():
    def change(document):
        del listing(document)["arguments"]["namespace"]
        listing(document)["resource"] = "k8s/all/pods"

    refused(change, "namespace label argument is required")


def test_a_list_with_a_name_argument_is_refused():
    def change(document):
        listing(document)["arguments"]["name"] = {"kind": "label"}

    refused(change, "refused for list")


def test_a_get_without_a_name_argument_is_refused():
    def change(document):
        operation = scale(document)
        del operation["arguments"]["name"]
        operation["resource"] = "k8s/{namespace}/deployments"

    refused(change, "name label argument is required")


def test_a_free_string_argument_is_refused():
    refused(lambda d: scale(d)["arguments"].update(reason={"kind": "string"}), "kind")


def test_an_integer_argument_needs_bounds():
    refused(lambda d: scale(d)["arguments"].update(replicas={"kind": "integer"}), "minimum and maximum")
    refused(
        lambda d: scale(d)["arguments"].update(replicas={"kind": "integer", "minimum": 5, "maximum": 1}),
        "bounds",
    )
    refused(
        lambda d: scale(d)["arguments"].update(replicas={"kind": "integer", "minimum": True, "maximum": 5}),
        "integers",
    )


def test_a_label_argument_other_than_namespace_or_name_is_refused():
    def change(document):
        operation = scale(document)
        operation["arguments"]["container"] = {"kind": "label"}
        operation["resource"] = "k8s/{namespace}/deployments/{name}/{container}"

    refused(change, "must be namespace or name")


def test_an_unused_argument_is_refused():
    refused(
        lambda d: scale(d)["arguments"].update(extra={"kind": "integer", "minimum": 0, "maximum": 1}),
        "not used",
    )


def test_a_body_with_a_literal_or_a_dotted_key_is_refused():
    refused(lambda d: scale(d)["request"].update(body={"spec": {"replicas": 3}}), "placeholder")
    refused(lambda d: scale(d)["request"].update(body={"spec": {"template": "x"}}), "placeholder")
    refused(lambda d: scale(d)["request"].update(body={"spec.replicas": "{replicas}"}), "plain field name")
    refused(lambda d: scale(d)["request"].update(body={"spec": {}}), "empty")


def test_a_body_is_required_for_patch_and_refused_otherwise():
    refused(lambda d: scale(d)["request"].update(body=None), "body is required")
    refused(lambda d: listing(d)["request"].update(body={"x": "{limit}"}), "body is required")


def test_a_query_parameter_outside_the_call_is_refused():
    refused(lambda d: listing(d)["request"]["query"].update(fieldSelector="{limit}"), "query parameters")
    refused(lambda d: listing(d)["request"]["query"].update(limit="50"), "placeholder")


def test_a_resource_template_must_be_concrete_and_contain_the_namespace():
    refused(lambda d: scale(d).update(resource="k8s/*/deployments/{name}"), "concrete")
    refused(lambda d: scale(d).update(resource="k8s/deployments/{name}"), "namespace")
    refused(lambda d: scale(d).update(resource="k8s/{namespace}/deployments/{replicas}"), "label argument")


def test_response_rules():
    refused(lambda d: scale(d)["response"].update(fields=[]), "lists its fields")
    refused(lambda d: scale(d)["response"].update(max_bytes=0), "max_bytes")
    refused(lambda d: scale(d)["response"].update(max_bytes=(1 << 20) + 1), "max_bytes")
    refused(lambda d: scale(d)["response"].update(fields=["spec..replicas"]), "dotted")

    def log_with_fields(document):
        next(item for item in document["operations"] if item["name"] == "read_pod_log")["response"]["fields"] = ["x"]

    refused(log_with_fields, "logs return text")


def test_names_and_tools_must_be_unique():
    def duplicate(document):
        document["operations"].append(copy.deepcopy(scale(document)))

    refused(duplicate, "unique")

    def same_tool(document):
        other = copy.deepcopy(scale(document))
        other["name"] = "scale_again"
        document["operations"].append(other)

    refused(same_tool, "tools must be unique")


@pytest.mark.parametrize(
    ("field", "value"),
    [("group", "Apps"), ("version", "1"), ("version", "v1beta"), ("resource", "Deployments"), ("resource", "")],
)
def test_invalid_api_coordinates_are_refused(field, value):
    refused(lambda d: scale(d)["request"].update({field: value}), field)


def test_load_refuses_invalid_json_and_oversized_files(tmp_path):
    path = tmp_path / "catalog.json"
    path.write_text('{"version": 1, "version": 1}')
    os.chmod(path, 0o600)
    with pytest.raises(CatalogError, match="not valid JSON"):
        OperationCatalog.load(path)
    path.write_text(" " * ((1 << 20) + 1))
    with pytest.raises(CatalogError, match="larger"):
        OperationCatalog.load(path)
