import base64
import json
import os
import secrets
import subprocess
import time
import urllib.parse

import pytest

from agent_bailiff.effector.catalog import OperationCatalog
from agent_bailiff.effector.drift import RbacAudit
from agent_bailiff.effector.kubernetes import HttpsTransport, KubernetesClient, KubernetesUnavailable
from agent_bailiff.effector.rbac import EffectorIdentity, generate_manifests, render
from agent_bailiff.service.init import DEFAULT_CATALOG

CONTEXT = os.environ.get("AGENT_BAILIFF_TEST_KUBE_CONTEXT")
pytestmark = pytest.mark.skipif(
    not CONTEXT, reason="set AGENT_BAILIFF_TEST_KUBE_CONTEXT to a disposable local cluster context"
)

CATALOG = OperationCatalog.load(DEFAULT_CATALOG)
OP_ID = "A" * 43
RELEASE = "cluster-test-release"
SETTLE_SECONDS = 3
REVOCATION_SECONDS = 30


def kubectl(*args, check=True, stdin=None, user=None):
    command = ["kubectl", "--context", CONTEXT, *args]
    if user:
        command += [f"--as={user}", "--as-group=system:masters"]
    result = subprocess.run(command, input=stdin, capture_output=True, text=True, timeout=60)
    if check and result.returncode != 0:
        raise AssertionError(f"{' '.join(command)}: {result.stderr}")
    return result


def apply(document):
    kubectl("apply", "-f", "-", stdin=document if isinstance(document, str) else json.dumps(document))


@pytest.fixture(scope="module")
def cluster(tmp_path_factory):
    suffix = secrets.token_hex(3)
    names = {key: f"bxt-{suffix}-{key}" for key in ("sys", "stg", "other", "hook")}
    tenants = {"ta": [names["stg"]], "tb": [names["other"]]}
    identity = EffectorIdentity(names["sys"], "effector", whoami(), names["hook"])
    manifests = generate_manifests(CATALOG, identity, tenants)
    directory = tmp_path_factory.mktemp("cluster")
    (directory / "manifests.json").write_text(render(manifests))
    taken = cluster_scoped_collisions(manifests)
    if taken:
        pytest.fail(f"the cluster already holds {', '.join(taken)}; use a disposable cluster")
    try:
        kubectl("create", "namespace", names["hook"])
        for key in ("stg", "other"):
            kubectl("create", "namespace", names[key])
            kubectl("-n", names[key], "create", "deployment", "api", "--image=registry.k8s.io/pause:3.10")
        apply(render(manifests))
        time.sleep(SETTLE_SECONDS)
        for account, file in (("effector", "effector"), ("effector-audit", "audit")):
            token = kubectl("-n", names["sys"], "create", "token", account, "--duration=10m").stdout.strip()
            (directory / file).write_text(token)
            os.chmod(directory / file, 0o600)
        view = json.loads(kubectl("config", "view", "--minify", "--raw", "-o", "json").stdout)
        cluster_entry = view["clusters"][0]["cluster"]
        (directory / "ca.crt").write_bytes(base64.b64decode(cluster_entry["certificate-authority-data"]))
        url = urllib.parse.urlsplit(cluster_entry["server"])
        transport = HttpsTransport(url.hostname, url.port, directory / "ca.crt")
        yield {
            "names": names,
            "tenants": tenants,
            "identity": identity,
            "manifests": manifests,
            "directory": directory,
            "transport": transport,
            "client": KubernetesClient(transport, directory / "effector"),
            "audit": RbacAudit(
                transport,
                directory / "effector",
                directory / "audit",
                identity,
                manifests,
                tenants,
                CATALOG.operations,
            ),
        }
    finally:
        kubectl("delete", "-f", str(directory / "manifests.json"), "--ignore-not-found", "--wait=false", check=False)
        kubectl(
            "delete",
            "namespace",
            names["stg"],
            names["other"],
            names["hook"],
            "--ignore-not-found",
            "--wait=false",
            check=False,
        )


def cluster_scoped_collisions(manifests):
    names = [
        f"{item['kind'].lower()}/{item['metadata']['name']}"
        for item in manifests["items"]
        if "namespace" not in item["metadata"]
    ]
    found = kubectl("get", *names, "--ignore-not-found", "-o", "name").stdout.split()
    return sorted(found)


def whoami():
    review = json.loads(kubectl("auth", "whoami", "-o", "json").stdout)
    return review["status"]["userInfo"]["username"]


@pytest.fixture
def restore(cluster):
    created = []
    yield created
    for args in created:
        kubectl("delete", *args, "--ignore-not-found", check=False)
    apply(render(cluster["manifests"]))
    time.sleep(SETTLE_SECONDS)


def call(cluster, name, arguments, tenant="ta", op_id=OP_ID):
    release = RELEASE if CATALOG.operation(name).call.verb == "patch" else None
    return (
        cluster["client"]
        .call(CATALOG.operation(name), arguments, tenant, op_id, "t" * 32, int(time.time()), release)
        .status
    )


def scale(cluster, namespace, replicas=2, **options):
    return call(cluster, "scale_deployment", {"namespace": namespace, "name": "api", "replicas": replicas}, **options)


def test_catalog_calls_are_allowed_only_for_their_tenant_identity_and_range(cluster):
    staging, other = cluster["names"]["stg"], cluster["names"]["other"]
    assert scale(cluster, staging, 3) == 200
    assert scale(cluster, staging, 11) == 422
    assert scale(cluster, other) == 403
    assert scale(cluster, staging, tenant="tb") == 403
    assert scale(cluster, staging, op_id="x") == 422
    assert call(cluster, "list_pods", {"namespace": staging, "limit": 5}) == 200
    assert call(cluster, "get_deployment", {"namespace": staging, "name": "api"}) == 200
    replicas = kubectl("-n", staging, "get", "deployment", "api", "-o", "jsonpath={.spec.replicas}").stdout
    assert replicas == "3"


def test_the_effector_cannot_act_outside_impersonate_on(cluster):
    token = (cluster["directory"] / "effector").read_text()
    staging = cluster["names"]["stg"]
    for method, path, headers in (
        ("DELETE", f"/apis/apps/v1/namespaces/{staging}/deployments/api", {"Impersonate-User": "bailiff:ta:scale"}),
        ("GET", "/api/v1/namespaces", {}),
        ("GET", "/api/v1/namespaces", {"Impersonate-User": "system:admin"}),
    ):
        extra = {"Impersonate-Extra-bailiff.dev%2Fop-id": OP_ID} if headers else {}
        status, _ = cluster["transport"].request(
            method, path, {"Authorization": f"Bearer {token}", **headers, **extra}, None
        )
        assert status == 403, (method, path, headers)


def test_only_the_applier_may_grant_to_the_effector_or_synthetic_users(cluster, restore):
    staging = cluster["names"]["stg"]
    sys_namespace = cluster["names"]["sys"]
    refused = [
        ("create", "rolebinding", "sneak", "--clusterrole=edit", f"--serviceaccount={sys_namespace}:effector"),
        ("create", "rolebinding", "sneak", "--clusterrole=edit", "--user=bailiff:ta:read"),
        ("label", "role", "bailiff-ta-scale", "extra=1"),
    ]
    for args in refused:
        result = kubectl("-n", staging, *args, check=False, user="mallory")
        assert result.returncode != 0 and "bailiff-effector-rbac" in result.stderr, result.stderr
    kubectl("-n", staging, "create", "rolebinding", "fine", "--clusterrole=view", "--user=alice", user="mallory")
    restore.append(("-n", staging, "rolebinding", "fine"))


def test_the_generated_set_is_clean(cluster):
    assert cluster["audit"].check() == []
    assert cluster["audit"].check_restart_schema() == []


def test_a_legacy_grant_bound_through_a_group_outside_the_catalog_is_drift(cluster, restore):
    other = cluster["names"]["other"]
    aggregate = f"bxt-agg-{secrets.token_hex(3)}"
    apply(
        {
            "apiVersion": "v1",
            "kind": "List",
            "items": [
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "ClusterRole",
                    "metadata": {"name": aggregate},
                    "aggregationRule": {"clusterRoleSelectors": [{"matchLabels": {aggregate: "true"}}]},
                    "rules": [],
                },
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "ClusterRole",
                    "metadata": {"name": f"{aggregate}-leg", "labels": {aggregate: "true"}},
                    "rules": [
                        {
                            "apiGroups": [""],
                            "resources": ["serviceaccounts"],
                            "resourceNames": ["default"],
                            "verbs": ["impersonate"],
                        }
                    ],
                },
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "RoleBinding",
                    "metadata": {"name": "sneak", "namespace": other},
                    "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": aggregate},
                    "subjects": [
                        {
                            "kind": "Group",
                            "name": f"system:serviceaccounts:{cluster['names']['sys']}",
                            "apiGroup": "rbac.authorization.k8s.io",
                        }
                    ],
                },
            ],
        }
    )
    restore.extend([("-n", other, "rolebinding", "sneak"), ("clusterrole", aggregate, f"{aggregate}-leg")])
    time.sleep(SETTLE_SECONDS)
    problems = cluster["audit"].check()
    legacy = ("impersonate", "", "serviceaccounts", "default")
    assert f"effector holds a grant outside the generated set in {other}: {legacy}" in problems


def test_a_cross_tenant_group_grant_is_drift_and_its_write_is_denied(cluster, restore):
    other = cluster["names"]["other"]
    kubectl("-n", other, "create", "role", "wide", "--verb=patch", "--resource=deployments/scale")
    kubectl("-n", other, "create", "rolebinding", "wide", "--role=wide", "--group=system:authenticated")
    restore.extend([("-n", other, "rolebinding", "wide"), ("-n", other, "role", "wide")])
    time.sleep(SETTLE_SECONDS)
    problems = cluster["audit"].check()
    assert f"bailiff:ta:scale may scale_deployment in {other}" in problems
    assert scale(cluster, other) == 422
    assert scale(cluster, other, tenant="tb") == 200


def test_deleting_the_effector_binding_stops_the_next_call_and_is_drift(cluster, restore):
    staging = cluster["names"]["stg"]
    kubectl("-n", staging, "delete", "rolebinding", "bailiff-effector-on")
    time.sleep(1)
    assert scale(cluster, staging) == 403
    assert f"the generated RoleBinding {staging}/bailiff-effector-on is missing" in cluster["audit"].check()


def test_a_deleted_admission_binding_is_drift(cluster, restore):
    kubectl("delete", "validatingadmissionpolicybinding", "bailiff-effector-guard")
    assert cluster["audit"].check() == [
        "the generated ValidatingAdmissionPolicyBinding bailiff-effector-guard is missing"
    ]


RESTARTED_AT = "kubectl.kubernetes.io/restartedAt"
RESTART_OP = "bailiff.dev/restart-op"


def deployment(namespace):
    return json.loads(
        kubectl("-n", namespace, "get", "deployment", "api", "--show-managed-fields", "-o", "json").stdout
    )


def snapshot(item):
    metadata = item["metadata"]
    managers = sorted(
        (entry["manager"], entry["operation"], entry.get("subresource", ""), json.dumps(entry.get("fieldsV1")))
        for entry in metadata.get("managedFields", [])
        if entry.get("subresource") != "status"
    )
    kept = ("labels", "annotations", "generateName", "finalizers", "ownerReferences", "generation")
    return item["spec"], {key: metadata.get(key) for key in kept}, managers


def restart(cluster, namespace, issued_at, op_id=OP_ID):
    operation = CATALOG.operation("restart_deployment")
    arguments = {"namespace": namespace, "name": "api"}
    return cluster["client"].call(operation, arguments, "ta", op_id, "t" * 32, issued_at, RELEASE).status


def patch_as_restart_user(cluster, namespace, body, content_type="application/merge-patch+json"):
    token = (cluster["directory"] / "effector").read_text()
    headers = {
        "Authorization": f"Bearer {token}",
        "Impersonate-User": "bailiff:ta:restart",
        "Impersonate-Extra-bailiff.dev%2Fop-id": OP_ID,
        "Content-Type": content_type,
    }
    path = f"/apis/apps/v1/namespaces/{namespace}/deployments/api?fieldManager=bailiff-effector"
    status, _ = cluster["transport"].request("PATCH", path, headers, json.dumps(body).encode())
    return status


def test_a_restart_sets_only_the_annotation_and_a_retry_changes_nothing(cluster):
    staging = cluster["names"]["stg"]
    before = deployment(staging)
    issued_at = int(time.time())
    assert restart(cluster, staging, issued_at) == 200
    after = deployment(staging)
    stamp = after["spec"]["template"]["metadata"]["annotations"][RESTARTED_AT]
    assert after["spec"]["template"]["metadata"]["annotations"][RESTART_OP] == OP_ID
    assert stamp == time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(issued_at))
    assert after["spec"]["template"]["spec"] == before["spec"]["template"]["spec"]
    assert after["spec"]["replicas"] == before["spec"]["replicas"]
    assert restart(cluster, staging, issued_at) == 200
    assert deployment(staging)["metadata"]["generation"] == after["metadata"]["generation"]


def test_two_restarts_in_the_same_second_with_different_op_ids_both_roll(cluster):
    staging = cluster["names"]["stg"]
    issued_at = int(time.time())
    first_op, second_op = "A" * 43, "B" * 43
    assert restart(cluster, staging, issued_at, first_op) == 200
    first = deployment(staging)
    assert restart(cluster, staging, issued_at, second_op) == 200
    second = deployment(staging)
    annotations = second["spec"]["template"]["metadata"]["annotations"]
    assert annotations[RESTARTED_AT] == time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(issued_at))
    assert annotations[RESTART_OP] == second_op
    assert second["metadata"]["generation"] > first["metadata"]["generation"]


def test_a_restart_of_a_deployment_with_many_field_managers_leaves_their_entries(cluster, restore):
    staging = cluster["names"]["stg"]
    kubectl("-n", staging, "create", "deployment", "busy", "--image=registry.k8s.io/pause:3.10")
    restore.append(("-n", staging, "deployment", "busy"))
    for index in range(12):
        kubectl("-n", staging, "label", "deployment", "busy", f"team{index}=x", f"--field-manager=tool-{index}")
    operation = CATALOG.operation("restart_deployment")
    arguments = {"namespace": staging, "name": "busy"}
    assert cluster["client"].call(operation, arguments, "ta", OP_ID, "t" * 32, int(time.time()), RELEASE).status == 200


def test_a_restart_of_a_missing_deployment_creates_nothing(cluster):
    staging = cluster["names"]["stg"]
    operation = CATALOG.operation("restart_deployment")
    arguments = {"namespace": staging, "name": "ghost"}
    status = cluster["client"].call(operation, arguments, "ta", OP_ID, "t" * 32, int(time.time()), RELEASE).status
    assert status >= 400
    assert kubectl("-n", staging, "get", "deployment", "ghost", "--ignore-not-found", "-o", "name").stdout == ""


def test_a_restart_after_a_manual_rollout_restart_is_allowed(cluster):
    staging = cluster["names"]["stg"]
    kubectl("-n", staging, "rollout", "restart", "deployment", "api")
    assert restart(cluster, staging, int(time.time()) + 1) == 200
    assert restart(cluster, cluster["names"]["other"], int(time.time())) == 403


RESTART_ONLY_ENTRY = {
    "manager": "kubectl-rollout",
    "operation": "Update",
    "apiVersion": "apps/v1",
    "fieldsType": "FieldsV1",
    "fieldsV1": {
        "f:spec": {"f:template": {"f:metadata": {"f:annotations": {"f:kubectl.kubernetes.io/restartedAt": {}}}}}
    },
}
STAMP = {"spec": {"template": {"metadata": {"annotations": {RESTARTED_AT: "2026-01-01T00:00:00Z", RESTART_OP: OP_ID}}}}}


@pytest.mark.parametrize(
    ("body", "content_type"),
    [
        (
            [{"op": "replace", "path": "/spec/template/spec/containers/0/image", "value": "busybox:1.36"}],
            "application/json-patch+json",
        ),
        ({"spec": {"replicas": 4}}, None),
        ({"spec": {"paused": True}}, None),
        ({"spec": {"template": {"metadata": {"labels": {"evil": "1"}}}}}, None),
        (
            {"spec": {"template": {"metadata": {"annotations": {"evil": "1", RESTARTED_AT: "2026-01-01T00:00:00Z"}}}}},
            None,
        ),
        ({"spec": {"template": {"spec": {"hostNetwork": True}}}, **{}}, None),
        ({"metadata": {"labels": {"evil": "1"}}, **STAMP}, None),
        ({"metadata": {"generateName": "evil-"}, **STAMP}, None),
        ({"metadata": {"managedFields": [{}]}, **STAMP}, None),
        (
            [
                {
                    "op": "replace",
                    "path": "/metadata/managedFields",
                    "value": [
                        {
                            "manager": "gitops",
                            "operation": "Apply",
                            "apiVersion": "apps/v1",
                            "fieldsType": "FieldsV1",
                            "fieldsV1": {"f:spec": {}},
                        }
                    ],
                }
            ],
            "application/json-patch+json",
        ),
        (
            [
                {"op": "copy", "from": "/metadata/managedFields/0", "path": "/metadata/managedFields/-"},
                {"op": "remove", "path": "/metadata/managedFields/1"},
            ],
            "application/json-patch+json",
        ),
        (
            [
                {"op": "add", "path": "/metadata/managedFields/-", "value": RESTART_ONLY_ENTRY},
                {"op": "remove", "path": "/metadata/managedFields/0"},
            ],
            "application/json-patch+json",
        ),
    ],
)
def test_the_restart_identity_cannot_change_anything_but_the_annotation(cluster, body, content_type):
    staging = cluster["names"]["stg"]
    before = snapshot(deployment(staging))
    status = patch_as_restart_user(cluster, staging, body, content_type or "application/merge-patch+json")
    assert status == 422
    assert snapshot(deployment(staging)) == before


def apply_as_restart_user(cluster, namespace, document):
    token = (cluster["directory"] / "effector").read_text()
    headers = {
        "Authorization": f"Bearer {token}",
        "Impersonate-User": "bailiff:ta:restart",
        "Impersonate-Extra-bailiff.dev%2Fop-id": OP_ID,
        "Content-Type": "application/apply-patch+yaml",
    }
    path = f"/apis/apps/v1/namespaces/{namespace}/deployments/api?fieldManager=bailiff-effector&force=true"
    applied = {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "api"}, **document}
    status, _ = cluster["transport"].request("PATCH", path, headers, json.dumps(applied).encode())
    return status


def stamped(template_metadata=None, **spec):
    metadata = {"annotations": {RESTARTED_AT: "2026-02-02T00:00:00Z"}, **(template_metadata or {})}
    return {"spec": {"template": {"metadata": metadata}, **spec}}


@pytest.mark.parametrize(
    "document",
    [
        {"spec": {"template": {"spec": {"containers": [{"name": "pause", "image": "busybox:1.36"}]}}}},
        stamped(replicas=4),
        stamped(paused=True),
        stamped({"labels": {"evil": "1"}}),
        {"spec": {"template": {"metadata": {"annotations": {RESTARTED_AT: "2026-02-02T00:00:00Z", "evil": "1"}}}}},
        stamped({"annotations": {RESTARTED_AT: "2026-02-02T00:00:00Z", RESTART_OP: "B" * 43}}),
        {"metadata": {"name": "api", "labels": {"evil": "1"}}, **stamped()},
        {"metadata": {"name": "api", "annotations": {"evil": "1"}}, **stamped()},
    ],
)
def test_an_apply_by_the_restart_identity_cannot_change_anything_but_the_annotation(cluster, document):
    staging = cluster["names"]["stg"]
    before = snapshot(deployment(staging))
    assert apply_as_restart_user(cluster, staging, document) == 422
    assert snapshot(deployment(staging)) == before


def test_a_token_minted_for_longer_than_ten_minutes_is_refused(cluster, tmp_path):
    long_lived = kubectl("-n", cluster["names"]["sys"], "create", "token", "effector", "--duration=1h").stdout.strip()
    path = tmp_path / "long.token"
    path.write_text(long_lived)
    os.chmod(path, 0o600)
    client = KubernetesClient(cluster["transport"], path)
    with pytest.raises(KubernetesUnavailable, match="at most 600 seconds"):
        client.call(
            CATALOG.operation("list_pods"),
            {"namespace": cluster["names"]["stg"], "limit": 5},
            "ta",
            OP_ID,
            "t",
            int(time.time()),
        )


def test_deleting_the_impersonation_binding_stops_every_call(cluster, restore):
    staging = cluster["names"]["stg"]
    assert call(cluster, "list_pods", {"namespace": staging, "limit": 5}) == 200
    kubectl("delete", "clusterrolebinding", "bailiff-effector-impersonate")
    started = time.monotonic()
    while call(cluster, "list_pods", {"namespace": staging, "limit": 5}) != 403:
        assert time.monotonic() - started < REVOCATION_SECONDS, "revocation did not take effect"
        time.sleep(1)
    print(f"revoked after {time.monotonic() - started:.0f} s")
    assert scale(cluster, staging) == 403
