import json
import os
import secrets
import subprocess
import time

import pytest
from test_effector_cluster import CONTEXT, apply, kubectl, whoami

from agent_bailiff.webhook.guard import guard_policies

pytestmark = pytest.mark.skipif(
    not CONTEXT, reason="set AGENT_BAILIFF_TEST_KUBE_CONTEXT to a disposable local cluster context"
)
IMAGE = os.environ.get("AGENT_BAILIFF_TEST_PAUSE_IMAGE", "registry.k8s.io/pause:3.10")
NODE_LOSS = os.environ.get("AGENT_BAILIFF_TEST_NODE_LOSS_CONTAINER_RUNTIME")
ATTACKER = "guard-attacker"
APP = "guarded"


def _workload(namespace):
    labels = {"app": APP}
    return [
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": APP, "namespace": namespace},
            "spec": {
                "replicas": 2,
                "strategy": {"type": "RollingUpdate", "rollingUpdate": {"maxSurge": 1, "maxUnavailable": 0}},
                "selector": {"matchLabels": labels},
                "template": {
                    "metadata": {"labels": labels},
                    "spec": {
                        "automountServiceAccountToken": False,
                        "terminationGracePeriodSeconds": 1,
                        "tolerations": [
                            {"key": key, "operator": "Exists", "effect": "NoExecute", "tolerationSeconds": 5}
                            for key in ("node.kubernetes.io/not-ready", "node.kubernetes.io/unreachable")
                        ],
                        "affinity": {
                            "podAntiAffinity": {
                                "preferredDuringSchedulingIgnoredDuringExecution": [
                                    {
                                        "weight": 100,
                                        "podAffinityTerm": {
                                            "labelSelector": {"matchLabels": labels},
                                            "topologyKey": "kubernetes.io/hostname",
                                        },
                                    }
                                ]
                            }
                        },
                        "containers": [{"name": "pause", "image": IMAGE, "resources": {"requests": {"cpu": "1m"}}}],
                    },
                },
            },
        },
        {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": APP, "namespace": namespace},
            "spec": {"selector": labels, "ports": [{"port": 80, "targetPort": 8080}]},
        },
        {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": APP, "namespace": namespace},
            "data": {"a": "1"},
        },
        {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": APP, "namespace": namespace},
            "stringData": {"a": "1"},
        },
    ]


def _registration(name):
    return {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingWebhookConfiguration",
        "metadata": {"name": name},
    }


def _wait(condition, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(1)
    return False


def _ready_endpoints(namespace):
    slices = json.loads(
        kubectl(
            "-n", namespace, "get", "endpointslices", "-l", f"kubernetes.io/service-name={APP}", "-o", "json"
        ).stdout
    )
    return sorted(
        endpoint["targetRef"]["name"]
        for item in slices["items"]
        for endpoint in item.get("endpoints") or []
        if endpoint.get("conditions", {}).get("ready")
    )


def _pods(namespace):
    pods = json.loads(kubectl("-n", namespace, "get", "pods", "-l", f"app={APP}", "-o", "json").stdout)["items"]
    return [pod for pod in pods if "deletionTimestamp" not in pod["metadata"]]


def _rolled_out(namespace):
    return (
        kubectl("-n", namespace, "rollout", "status", f"deployment/{APP}", "--timeout=90s", check=False).returncode == 0
    )


def _denied(result, user=ATTACKER):
    return (
        result.returncode != 0
        and "ValidatingAdmissionPolicy 'bailiff-release-webhook-" in result.stderr
        and (f"denied for {user}" in result.stderr or "exec, attach and port-forward are denied" in result.stderr)
    )


@pytest.fixture
def guarded(request):
    enforce = request.param
    namespace = "bxg-" + secrets.token_hex(3)
    webhook = namespace + "-hook"
    kubectl("create", "namespace", namespace)
    policies = guard_policies(namespace, webhook, [whoami()], enforce)
    try:
        for item in policies:
            apply(item)
        time.sleep(3)
        apply(_registration(webhook))
        for item in _workload(namespace):
            apply(item)
        yield namespace, webhook
    finally:
        for item in reversed(policies):
            kubectl("delete", item["kind"], item["metadata"]["name"], "--ignore-not-found", check=False)
        kubectl("delete", "validatingwebhookconfiguration", webhook, "--ignore-not-found", check=False)
        kubectl("delete", "namespace", namespace, "--wait=false", check=False)


@pytest.mark.parametrize("guarded", [True], indirect=True)
def test_the_controllers_run_the_deployment_under_an_enforced_guard(guarded):
    namespace, _ = guarded

    def events():
        return kubectl("-n", namespace, "get", "events", "--sort-by=.lastTimestamp").stdout

    assert _rolled_out(namespace), events()
    assert _wait(lambda: len(_ready_endpoints(namespace)) == 2), events()
    kubectl("-n", namespace, "rollout", "restart", f"deployment/{APP}")
    assert _rolled_out(namespace), events()
    victim = _pods(namespace)[0]["metadata"]["name"]
    kubectl("-n", namespace, "delete", "pod", victim, "--wait=false")
    assert _wait(lambda: victim not in _ready_endpoints(namespace) and len(_ready_endpoints(namespace)) == 2), events()
    kubectl("-n", namespace, "scale", f"deployment/{APP}", "--replicas=3")
    assert _wait(lambda: len(_ready_endpoints(namespace)) == 3), events()
    kubectl("-n", namespace, "scale", f"deployment/{APP}", "--replicas=2")
    assert _wait(lambda: len(_ready_endpoints(namespace)) == 2), events()


@pytest.mark.parametrize("guarded", [True], indirect=True)
def test_a_cluster_admin_cannot_get_into_the_guarded_namespace(guarded):
    namespace, webhook = guarded
    assert _rolled_out(namespace)
    pod = _pods(namespace)[0]
    name = pod["metadata"]["name"]
    pod_ip = pod["status"]["podIP"]
    attempts = {
        "run a pod": ("-n", namespace, "run", "rogue", f"--image={IMAGE}"),
        "create a job": ("-n", namespace, "create", "job", "rogue", f"--image={IMAGE}"),
        "create a deployment": ("-n", namespace, "create", "deployment", "rogue", f"--image={IMAGE}"),
        "exec": ("-n", namespace, "exec", name, "--", "/pause"),
        "attach": ("-n", namespace, "attach", name),
        "debug": ("-n", namespace, "debug", name, f"--image={IMAGE}", "--attach=false"),
        "change the image": ("-n", namespace, "set", "image", f"pod/{name}", f"pause={IMAGE}-other"),
        "change pod status": (
            "-n",
            namespace,
            "patch",
            "pod",
            name,
            "--subresource=status",
            "--type=merge",
            "-p",
            json.dumps({"status": {"podIP": "10.9.9.9", "podIPs": [{"ip": "10.9.9.9"}]}}),
        ),
        "edit the config": ("-n", namespace, "patch", "configmap", APP, "--type=merge", "-p", '{"data":{"a":"2"}}'),
        "edit the secret": ("-n", namespace, "patch", "secret", APP, "--type=merge", "-p", '{"stringData":{"a":"2"}}'),
        "widen the service": (
            "-n",
            namespace,
            "patch",
            "service",
            APP,
            "--type=merge",
            "-p",
            '{"spec":{"selector":{"app":"rogue"}}}',
        ),
        "scale": ("-n", namespace, "scale", f"deployment/{APP}", "--replicas=5"),
        "resize a pod": (
            "-n",
            namespace,
            "patch",
            "pod",
            name,
            "--subresource=resize",
            "--type=merge",
            "-p",
            '{"spec":{"containers":[{"name":"pause","resources":{"requests":{"cpu":"2m"}}}]}}',
        ),
        "change a service account": (
            "-n",
            namespace,
            "patch",
            "serviceaccount",
            "default",
            "--type=merge",
            "-p",
            '{"automountServiceAccountToken":true}',
        ),
        "create a quota": ("-n", namespace, "create", "quota", "rogue", "--hard=pods=0"),
        "delete the webhook": ("delete", "validatingwebhookconfiguration", webhook),
        "change the webhook": (
            "label",
            "validatingwebhookconfiguration",
            webhook,
            "rogue=yes",
        ),
    }
    endpoint_slice = {
        "apiVersion": "discovery.k8s.io/v1",
        "kind": "EndpointSlice",
        "metadata": {"name": "rogue", "namespace": namespace, "labels": {"kubernetes.io/service-name": APP}},
        "addressType": "IPv4",
        "endpoints": [{"addresses": ["10.9.9.9"]}],
        "ports": [{"port": 8080}],
    }
    results = {label: kubectl(*arguments, check=False, user=ATTACKER) for label, arguments in attempts.items()}
    results["bind a pod"] = kubectl(
        "create",
        "--raw",
        f"/api/v1/namespaces/{namespace}/pods/{name}/binding",
        "-f",
        "-",
        check=False,
        user=ATTACKER,
        stdin=json.dumps(
            {
                "apiVersion": "v1",
                "kind": "Binding",
                "metadata": {"name": name, "namespace": namespace},
                "target": {"apiVersion": "v1", "kind": "Node", "name": pod["spec"]["nodeName"]},
            }
        ),
    )
    results["create a network policy"] = kubectl(
        "create",
        "-f",
        "-",
        check=False,
        user=ATTACKER,
        stdin=json.dumps(
            {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": {"name": "rogue", "namespace": namespace},
                "spec": {"podSelector": {}, "policyTypes": ["Ingress"]},
            }
        ),
    )
    results["create an endpoint slice"] = kubectl(
        "create", "-f", "-", check=False, user=ATTACKER, stdin=json.dumps(endpoint_slice)
    )
    allowed = {label: result.stderr or result.stdout for label, result in results.items() if not _denied(result)}
    assert allowed == {}
    forged = kubectl(
        "-n",
        namespace,
        "patch",
        "pod",
        name,
        "--subresource=status",
        "--type=merge",
        "-p",
        json.dumps({"status": {"podIP": "10.9.9.9", "podIPs": [{"ip": "10.9.9.9"}]}}),
        check=False,
        user="system:serviceaccount:kube-system:node-controller",
    )
    assert forged.returncode != 0 and "only the Pod's own node may set its IPs" in forged.stderr, forged.stderr
    direct = kubectl("-n", namespace, "run", "direct", f"--image={IMAGE}", check=False)
    assert direct.returncode != 0 and "controller manager" in direct.stderr, direct.stderr
    assert json.loads(kubectl("-n", namespace, "get", "pod", name, "-o", "json").stdout)["status"]["podIP"] == pod_ip


@pytest.mark.parametrize("guarded", [False], indirect=True)
def test_audit_mode_warns_but_allows(guarded):
    namespace, _ = guarded
    result = kubectl(
        "-n", namespace, "patch", "configmap", APP, "--type=merge", "-p", '{"data":{"a":"3"}}', user=ATTACKER
    )
    assert "Warning" in result.stderr and "the webhook's objects may be changed only by the deployer" in result.stderr


@pytest.mark.parametrize("guarded", [True], indirect=True)
def test_the_generated_guard_round_trips_unchanged(guarded):
    namespace, webhook = guarded
    for item in guard_policies(namespace, webhook, [whoami()], True):
        live = json.loads(kubectl("get", item["kind"], item["metadata"]["name"], "-o", "json").stdout)
        assert live["spec"] == item["spec"], (item["kind"], live["spec"])


@pytest.mark.skipif(not NODE_LOSS, reason="set to the container runtime (docker) of a multi-node kind cluster")
@pytest.mark.parametrize("guarded", [True], indirect=True)
def test_pods_on_a_lost_node_leave_the_endpoints_and_are_replaced(guarded):
    namespace, _ = guarded
    assert _rolled_out(namespace)
    assert _wait(lambda: len(_ready_endpoints(namespace)) == 2)
    pods = _pods(namespace)
    nodes = {pod["spec"]["nodeName"] for pod in pods}
    control_planes = json.loads(
        kubectl("get", "nodes", "-l", "node-role.kubernetes.io/control-plane", "-o", "json").stdout
    )["items"]
    lost = next(node for node in sorted(nodes) if node not in {item["metadata"]["name"] for item in control_planes})
    lost_pods = {pod["metadata"]["name"] for pod in pods if pod["spec"]["nodeName"] == lost}
    subprocess.run([NODE_LOSS, "stop", lost], check=True, capture_output=True, timeout=60)
    try:
        assert _wait(lambda: not lost_pods & set(_ready_endpoints(namespace)), timeout=180)
        assert _wait(
            lambda: len([name for name in _ready_endpoints(namespace) if name not in lost_pods]) == 2, timeout=240
        ), kubectl("-n", namespace, "get", "events", "--sort-by=.lastTimestamp").stdout
    finally:
        subprocess.run([NODE_LOSS, "start", lost], check=False, capture_output=True, timeout=60)
