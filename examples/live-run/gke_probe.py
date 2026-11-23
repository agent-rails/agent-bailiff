from __future__ import annotations

import argparse
import base64
import json
import math
import os
import subprocess
import sys
import tempfile
import time
from collections import Counter
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from launch import PROBE_CLUSTER, PROBE_LABEL  # noqa: E402

from agent_bailiff.effector.drift import REVIEW_WORKERS  # noqa: E402
from agent_bailiff.effector.kubernetes import PooledTransport  # noqa: E402
from agent_bailiff.effector.platform import DANGEROUS_ACTIONS, Action  # noqa: E402

ZONE = "europe-west1-b"
NAMESPACE = "bailiff-probe"
ACCOUNT = "probe"
ACCOUNTS = 2
ROUNDS = 3
ACCESS_REVIEWS = "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"
RULES_REVIEWS = "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews"


def gcloud(*args: str, project: str, timeout: int = 900) -> str:
    command = ["gcloud", *args, "--project", project, "--quiet"]
    return subprocess.run(command, capture_output=True, text=True, check=True, timeout=timeout).stdout


def kubectl(kubeconfig: Path, *args: str) -> str:
    command = ["kubectl", "--kubeconfig", str(kubeconfig), *args]
    return subprocess.run(command, capture_output=True, text=True, check=True, timeout=120).stdout


def refuse_existing(project: str) -> None:
    command = ["gcloud", "container", "clusters", "list", "--project", project, "--format", "value(name)"]
    listed = subprocess.run(command, capture_output=True, text=True, check=True, timeout=120).stdout.split()
    if PROBE_CLUSTER in listed:
        raise RuntimeError(f"{PROBE_CLUSTER} already exists in {project}; delete it or probe it by hand")


def create_cluster(project: str, zone: str) -> None:
    gcloud(
        "container", "clusters", "create", PROBE_CLUSTER, "--zone", zone, "--num-nodes", "1",
        "--machine-type", "e2-small", "--release-channel", "regular", "--labels", f"{PROBE_LABEL}={PROBE_CLUSTER}",
        project=project,
    )  # fmt: skip


def delete_cluster(project: str, zone: str) -> None:
    gcloud("container", "clusters", "delete", PROBE_CLUSTER, "--zone", zone, project=project)


def review_body(action: Action, namespace: str | None) -> bytes:
    attributes = {"verb": action.verb, "group": action.group, "resource": action.resource}
    if action.subresource:
        attributes["subresource"] = action.subresource
    if namespace is not None:
        attributes["namespace"] = namespace
    review = {"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectAccessReview"}
    return json.dumps(review | {"spec": {"resourceAttributes": attributes}}).encode()


def tally(statuses: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    counts = Counter(json.dumps(status, sort_keys=True) for status in statuses)
    return [{"status": json.loads(key), "count": count} for key, count in sorted(counts.items())]


def percentile(values: Sequence[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(fraction * len(ordered)) - 1)]


def latency(values: Sequence[float]) -> dict[str, float]:
    return {
        "p50_ms": round(percentile(values, 0.5) * 1000, 1),
        "p95_ms": round(percentile(values, 0.95) * 1000, 1),
        "p99_ms": round(percentile(values, 0.99) * 1000, 1),
        "max_ms": round(max(values) * 1000, 1),
    }


class Reviewer:
    def __init__(self, transport: PooledTransport, token: str) -> None:
        self._transport = transport
        self._headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def post(self, path: str, body: bytes) -> tuple[dict[str, Any], float]:
        started = time.monotonic()
        code, data = self._transport.request("POST", path, self._headers, body)
        elapsed = time.monotonic() - started
        if code != 201:
            raise RuntimeError(f"POST {path} returned {code}")
        return json.loads(data)["status"], elapsed

    def access(self, action: Action, namespace: str | None) -> tuple[dict[str, Any], float]:
        return self.post(ACCESS_REVIEWS, review_body(action, namespace))


def timed_round(reviewer: Reviewer, workers: int) -> tuple[float, list[float]]:
    actions = [action for _ in range(ACCOUNTS) for action in DANGEROUS_ACTIONS]
    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=workers) as executor:
        results = list(executor.map(lambda action: reviewer.access(action, None), actions))
    return time.monotonic() - started, [elapsed for _, elapsed in results]


def probe(project: str, zone: str, work: Path, rounds: int = ROUNDS) -> dict[str, Any]:
    kubeconfig = work / "kubeconfig"
    env = os.environ | {"KUBECONFIG": str(kubeconfig)}
    subprocess.run(
        ["gcloud", "container", "clusters", "get-credentials", PROBE_CLUSTER, "--zone", zone, "--project", project],
        capture_output=True, text=True, check=True, timeout=120, env=env,
    )  # fmt: skip
    cluster = json.loads(
        gcloud("container", "clusters", "describe", PROBE_CLUSTER, "--zone", zone, "--format", "json", project=project)
    )
    ca = work / "ca.crt"
    ca.write_bytes(base64.b64decode(cluster["masterAuth"]["clusterCaCertificate"]))
    kubectl(kubeconfig, "create", "namespace", NAMESPACE)
    kubectl(kubeconfig, "-n", NAMESPACE, "create", "serviceaccount", ACCOUNT)
    token = kubectl(kubeconfig, "-n", NAMESPACE, "create", "token", ACCOUNT, "--duration=10m").strip()
    transport = PooledTransport(cluster["endpoint"], 443, ca, REVIEW_WORKERS)
    try:
        reviewer = Reviewer(transport, token)
        cluster_scope = [reviewer.access(action, None)[0] for action in DANGEROUS_ACTIONS]
        in_namespace = [reviewer.access(action, NAMESPACE)[0] for action in DANGEROUS_ACTIONS]
        rules, _ = reviewer.post(
            RULES_REVIEWS,
            json.dumps(
                {
                    "apiVersion": "authorization.k8s.io/v1",
                    "kind": "SelfSubjectRulesReview",
                    "spec": {"namespace": NAMESPACE},
                }
            ).encode(),
        )
        timings = [timed_round(reviewer, REVIEW_WORKERS) for _ in range(rounds)]
    finally:
        transport.close()
    return {
        "cluster_version": cluster["currentMasterVersion"],
        "zone": zone,
        "account": f"system:serviceaccount:{NAMESPACE}:{ACCOUNT} with no RBAC",
        "dangerous_actions": len(DANGEROUS_ACTIONS),
        "cluster_scope_statuses": tally(cluster_scope),
        "namespace_statuses": tally(in_namespace),
        "rules_review": {key: rules.get(key) for key in ("incomplete", "evaluationError")},
        "fan_out": {
            "reviews_per_round": ACCOUNTS * len(DANGEROUS_ACTIONS),
            "workers": REVIEW_WORKERS,
            "round_seconds": [round(seconds, 2) for seconds, _ in timings],
            "latency": latency([value for _, values in timings for value in values]),
        },
    }


def run(
    project: str,
    zone: str,
    out: Path,
    probe_cluster: Callable[[str, str, Path], dict[str, Any]] = probe,
) -> dict[str, Any]:
    refuse_existing(project)
    try:
        create_cluster(project, zone)
        with tempfile.TemporaryDirectory(prefix="bailiff-gke-probe-") as work:
            result = probe_cluster(project, zone, Path(work))
    finally:
        delete_cluster(project, zone)
    result["probed_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    out.write_text(json.dumps(result, indent=2) + "\n")
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create a disposable GKE cluster, run access reviews, delete it.")
    parser.add_argument("--project", required=True)
    parser.add_argument("--zone", default=ZONE)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    print(json.dumps(run(args.project, args.zone, args.out), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
