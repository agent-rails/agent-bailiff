from __future__ import annotations

import base64
import json
import re
from collections.abc import Mapping
from typing import Any

from agent_bailiff.effector.catalog import OperationCatalog
from agent_bailiff.effector.rbac import LABELS

IMAGE_DIGEST = re.compile(r"[^@\s]+@sha256:[0-9a-f]{64}")
NAME = "bailiff-release-webhook"


def generate_manifests(
    *, namespace: str, image: str, ca_pem: bytes, pins: Mapping[str, Any], catalog: OperationCatalog,
    enforce: bool,
) -> dict[str, Any]:
    if IMAGE_DIGEST.fullmatch(image) is None:
        raise ValueError("image must be pinned by sha256 digest")
    if not ca_pem.startswith(b"-----BEGIN CERTIFICATE-----"):
        raise ValueError("ca_pem must be a PEM certificate")
    if pins.get("catalog_digest") != catalog.digest:
        raise ValueError("pins catalog digest does not match the loaded catalog")
    service = {"name": NAME, "namespace": namespace, "path": "/validate", "port": 443}
    labels = {**LABELS, "app.kubernetes.io/name": NAME}
    pod_labels = {"app.kubernetes.io/name": NAME}
    config = dict(pins)
    config["enforce"] = enforce
    items: list[dict[str, Any]] = [
        {
            "apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": NAME + "-pins", "namespace": namespace, "labels": labels},
            "data": {"webhook.json": json.dumps(config, sort_keys=True)},
        },
        {
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": NAME, "namespace": namespace, "labels": labels},
            "spec": {"selector": pod_labels, "ports": [{"port": 443, "targetPort": 9443, "protocol": "TCP"}]},
        },
        {
            "apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": NAME, "namespace": namespace, "labels": labels},
            "spec": {
                "replicas": 2,
                "strategy": {"type": "RollingUpdate", "rollingUpdate": {"maxSurge": 1, "maxUnavailable": 0}},
                "selector": {"matchLabels": pod_labels},
                "template": {
                    "metadata": {"labels": pod_labels, "annotations": {"bailiff.dev/catalog-digest": catalog.digest}},
                    "spec": {
                        "automountServiceAccountToken": False,
                        "securityContext": {"runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532},
                        "affinity": {"podAntiAffinity": {"preferredDuringSchedulingIgnoredDuringExecution": [
                            {"weight": 100, "podAffinityTerm": {
                                "topologyKey": "kubernetes.io/hostname", "labelSelector": {"matchLabels": pod_labels},
                            }}
                        ]}},
                        "containers": [{
                            "name": "webhook", "image": image, "imagePullPolicy": "IfNotPresent",
                            "command": [
                                "python", "-m", "agent_bailiff.webhook.cli", "serve",
                                "--config", "/etc/bailiff/webhook.json",
                                "--cert", "/etc/bailiff/tls/tls.crt",
                                "--key", "/etc/bailiff/tls/tls.key",
                            ],
                            "ports": [{"containerPort": 9443, "name": "https"}],
                            "readinessProbe": {"httpGet": {"path": "/readyz", "port": "https", "scheme": "HTTPS"}},
                            "resources": {"requests": {"cpu": "50m", "memory": "64Mi"},
                                          "limits": {"cpu": "500m", "memory": "256Mi"}},
                            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                                "capabilities": {"drop": ["ALL"]}},
                            "volumeMounts": [
                                {"name": "pins", "mountPath": "/etc/bailiff", "readOnly": True},
                                {"name": "tls", "mountPath": "/etc/bailiff/tls", "readOnly": True},
                            ],
                        }],
                        "volumes": [
                            {"name": "pins", "configMap": {"name": NAME + "-pins"}},
                            {"name": "tls", "secret": {"secretName": NAME + "-tls"}},
                        ],
                    },
                },
            },
        },
        {
            "apiVersion": "policy/v1", "kind": "PodDisruptionBudget",
            "metadata": {"name": NAME, "namespace": namespace, "labels": labels},
            "spec": {"minAvailable": 1, "selector": {"matchLabels": pod_labels},
                     "unhealthyPodEvictionPolicy": "AlwaysAllow"},
        },
        {
            "apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingWebhookConfiguration",
            "metadata": {"name": NAME, "labels": labels},
            "webhooks": [{
                "name": "release.bailiff.dev", "admissionReviewVersions": ["v1"], "sideEffects": "None",
                "failurePolicy": "Fail" if enforce else "Ignore", "timeoutSeconds": 3,
                "matchPolicy": "Exact",
                "matchConditions": [{"name": "bailiff-user",
                                     "expression": "request.userInfo.username.startsWith('bailiff:')"}],
                "rules": [{"operations": ["CREATE", "UPDATE", "DELETE"], "apiGroups": ["*"],
                           "apiVersions": ["*"], "resources": ["*/*"], "scope": "*"}],
                "clientConfig": {"service": service, "caBundle": base64.b64encode(ca_pem).decode("ascii")},
            }],
        },
    ]
    return {"apiVersion": "v1", "kind": "List", "items": items}
