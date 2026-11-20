from __future__ import annotations

import base64
import copy
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

from agent_bailiff.effector.catalog import LABEL, OperationCatalog
from agent_bailiff.effector.rbac import LABELS, reserved_namespace
from agent_bailiff.webhook.guard import guard_policies

IMAGE_DIGEST = re.compile(r"[^@\s]+@sha256:[0-9a-f]{64}")
NAME = "bailiff-release-webhook"
MODE_LABEL = "bailiff.dev/webhook-mode"
WEBHOOK = "release.bailiff.dev"
SERVICE_PATH = "/validate"
SERVICE_PORT = 443
REVIEW_VERSIONS = ["v1"]
TIMEOUT_SECONDS = 3
POD_LABELS = {"app.kubernetes.io/name": NAME}
ENFORCE_SELECTOR = {**POD_LABELS, MODE_LABEL: "enforce"}
MATCH_CONDITIONS = [{"name": "bailiff-user", "expression": "request.userInfo.username.startsWith('bailiff:')"}]
RULES = [
    {
        "operations": ["CREATE", "UPDATE", "DELETE"],
        "apiGroups": ["*"],
        "apiVersions": ["*"],
        "resources": ["*/*"],
        "scope": "*",
    }
]


def generate_manifests(
    *,
    namespace: str,
    image: str,
    ca_pem: bytes,
    pins: Mapping[str, Any],
    catalog: OperationCatalog,
    enforce: bool,
    deployers: Sequence[str],
    phase: str = "all",
) -> dict[str, Any]:
    if phase not in {"all", "prepare", "register", "target"}:
        raise ValueError("phase must be all, prepare, register, or target")
    if enforce and phase == "all":
        raise ValueError("--enforce requires --phase prepare, register, or target; do not apply Enforce as one bundle")
    if LABEL.fullmatch(namespace) is None:
        raise ValueError(f"{namespace!r} is not a Kubernetes name")
    if reserved_namespace(namespace):
        raise ValueError("the webhook needs a dedicated namespace, not default or kube-*")
    if IMAGE_DIGEST.fullmatch(image) is None:
        raise ValueError("image must be pinned by sha256 digest")
    if not ca_pem.startswith(b"-----BEGIN CERTIFICATE-----"):
        raise ValueError("ca_pem must be a PEM certificate")
    if pins.get("catalog_digest") != catalog.digest:
        raise ValueError("pins catalog digest does not match the loaded catalog")
    service = {"name": NAME, "namespace": namespace, "path": SERVICE_PATH, "port": SERVICE_PORT}
    labels = {**LABELS, "app.kubernetes.io/name": NAME}
    pod_labels = dict(POD_LABELS)
    mode = "enforce" if enforce else "audit"
    template_labels = {**pod_labels, MODE_LABEL: mode}
    serving_selector = template_labels if enforce and phase in {"register", "target"} else pod_labels
    config = dict(pins)
    config["enforce"] = enforce
    items: list[dict[str, Any]] = [
        {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": NAME + "-pins", "namespace": namespace, "labels": labels},
            "data": {"webhook.json": json.dumps(config, sort_keys=True)},
        },
        {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": NAME, "namespace": namespace, "labels": labels},
            "spec": {
                "selector": serving_selector,
                "ports": [{"port": 443, "targetPort": 9443, "protocol": "TCP"}],
            },
        },
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": NAME, "namespace": namespace, "labels": labels},
            "spec": {
                "replicas": 2,
                "strategy": {"type": "RollingUpdate", "rollingUpdate": {"maxSurge": 1, "maxUnavailable": 0}},
                "selector": {"matchLabels": pod_labels},
                "template": {
                    "metadata": {
                        "labels": template_labels,
                        "annotations": {
                            "bailiff.dev/catalog-digest": catalog.digest,
                            "bailiff.dev/enforce-mode": str(enforce).lower(),
                        },
                    },
                    "spec": {
                        "automountServiceAccountToken": False,
                        "securityContext": {"runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532},
                        "affinity": {
                            "podAntiAffinity": {
                                "preferredDuringSchedulingIgnoredDuringExecution": [
                                    {
                                        "weight": 100,
                                        "podAffinityTerm": {
                                            "topologyKey": "kubernetes.io/hostname",
                                            "labelSelector": {"matchLabels": pod_labels},
                                        },
                                    }
                                ]
                            }
                        },
                        "containers": [
                            {
                                "name": "webhook",
                                "image": image,
                                "imagePullPolicy": "IfNotPresent",
                                "command": [
                                    "python",
                                    "-m",
                                    "agent_bailiff.webhook.cli",
                                    "serve",
                                    "--config",
                                    "/etc/bailiff/webhook.json",
                                    "--mode",
                                    "enforce" if enforce else "audit",
                                    "--cert",
                                    "/etc/bailiff/tls/tls.crt",
                                    "--key",
                                    "/etc/bailiff/tls/tls.key",
                                ],
                                "ports": [{"containerPort": 9443, "name": "https"}],
                                "readinessProbe": {
                                    "httpGet": {
                                        "path": "/readyz/" + ("enforce" if enforce else "audit"),
                                        "port": "https",
                                        "scheme": "HTTPS",
                                    }
                                },
                                "resources": {
                                    "requests": {"cpu": "50m", "memory": "64Mi"},
                                    "limits": {"cpu": "500m", "memory": "256Mi"},
                                },
                                "securityContext": {
                                    "allowPrivilegeEscalation": False,
                                    "readOnlyRootFilesystem": True,
                                    "capabilities": {"drop": ["ALL"]},
                                },
                                "volumeMounts": [
                                    {"name": "pins", "mountPath": "/etc/bailiff", "readOnly": True},
                                    {"name": "tls", "mountPath": "/etc/bailiff/tls", "readOnly": True},
                                ],
                            }
                        ],
                        "volumes": [
                            {"name": "pins", "configMap": {"name": NAME + "-pins"}},
                            {"name": "tls", "secret": {"secretName": NAME + "-tls"}},
                        ],
                    },
                },
            },
        },
        {
            "apiVersion": "policy/v1",
            "kind": "PodDisruptionBudget",
            "metadata": {"name": NAME, "namespace": namespace, "labels": labels},
            "spec": {
                "minAvailable": 1,
                "selector": {"matchLabels": pod_labels},
                "unhealthyPodEvictionPolicy": "AlwaysAllow",
            },
        },
        {
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingWebhookConfiguration",
            "metadata": {"name": NAME, "labels": labels},
            "webhooks": [
                {
                    "name": WEBHOOK,
                    "admissionReviewVersions": list(REVIEW_VERSIONS),
                    "sideEffects": "None",
                    "failurePolicy": "Fail" if enforce else "Ignore",
                    "timeoutSeconds": TIMEOUT_SECONDS,
                    "matchPolicy": "Exact",
                    "matchConditions": copy.deepcopy(MATCH_CONDITIONS),
                    "rules": copy.deepcopy(RULES),
                    "clientConfig": {"service": service, "caBundle": base64.b64encode(ca_pem).decode("ascii")},
                }
            ],
        },
    ]
    for guard in guard_policies(namespace, NAME, deployers, enforce):
        guard["metadata"]["labels"] = labels
        items.append(guard)
    if phase == "prepare":
        items = [item for item in items if item["kind"] != "ValidatingWebhookConfiguration"]
    elif phase == "register":
        items = [item for item in items if item["kind"] not in {"ConfigMap", "Deployment", "PodDisruptionBudget"}]
    elif phase == "target":
        return {"apiVersion": "bailiff.dev/v1", "kind": "WebhookAuditTarget", "items": items}
    return {"apiVersion": "v1", "kind": "List", "items": items}
