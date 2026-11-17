from __future__ import annotations

import copy
import logging
from collections.abc import Mapping
from typing import Any

from agent_bailiff.effector.catalog import LABEL, OperationCatalog
from agent_bailiff.effector.kubernetes import OP_ID_EXTRA, RELEASE_EXTRA
from agent_bailiff.effector.release import ReleaseCheckConfig, ReleaseRefused, verify_operation
from agent_bailiff.strict_json import parse_strict_json

logger = logging.getLogger(__name__)
MAX_BODY_BYTES = 3 << 20


class MalformedReview(ValueError):
    pass


def _map(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise MalformedReview("expected an object")
    return value


def _string(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise MalformedReview("expected a nonempty string")
    return value


def _extra(user: Mapping[str, Any], name: str) -> str:
    extras = _map(user.get("extra"))
    values = extras.get(name)
    if not isinstance(values, list) or len(values) != 1:
        raise MalformedReview(f"missing or duplicate {name}")
    return _string(values[0])


def _gvk(value: object) -> tuple[str, str, str]:
    item = _map(value)
    return (
        _string(item.get("group")) if item.get("group") else "",
        _string(item.get("version")),
        _string(item.get("kind")),
    )


def _gvr(value: object) -> tuple[str, str, str]:
    item = _map(value)
    return (
        _string(item.get("group")) if item.get("group") else "",
        _string(item.get("version")),
        _string(item.get("resource")),
    )


class Admission:
    def __init__(self, config: ReleaseCheckConfig, catalog: OperationCatalog, *, enforce: bool) -> None:
        if config.skew_seconds > 2:
            raise ValueError("webhook clock skew bound must be at most 2 seconds")
        self._config = config
        self._catalog = catalog
        self._enforce = enforce

    def review(self, body: bytes, now: int) -> dict[str, Any]:
        if len(body) > MAX_BODY_BYTES:
            raise MalformedReview("review too large")
        try:
            document = _map(parse_strict_json(body))
            if document.get("apiVersion") != "admission.k8s.io/v1" or document.get("kind") != "AdmissionReview":
                raise MalformedReview("wrong review version")
            request = _map(document.get("request"))
            uid = _string(request.get("uid"))
        except (ValueError, UnicodeDecodeError, TypeError) as exc:
            raise MalformedReview("invalid AdmissionReview") from exc
        try:
            self._verify(request, now)
            reason = None
        except (MalformedReview, ReleaseRefused) as exc:
            reason = str(exc) if isinstance(exc, MalformedReview) else exc.reason
            logger.warning("admission %s: %s", "deny" if self._enforce else "would_deny", reason)
        allowed = reason is None or not self._enforce
        response: dict[str, Any] = {"uid": uid, "allowed": allowed}
        if not allowed:
            response["status"] = {"code": 403, "message": "released operation required"}
        return {"apiVersion": "admission.k8s.io/v1", "kind": "AdmissionReview", "response": response}

    def _verify(self, request: dict[str, Any], now: int) -> None:
        user = _map(request.get("userInfo"))
        username = _string(user.get("username"))
        if not username.startswith("bailiff:"):
            raise MalformedReview("unexpected user")
        token = _extra(user, RELEASE_EXTRA)
        op_id = _extra(user, OP_ID_EXTRA)
        namespace = _string(request.get("namespace"))
        name = _string(request.get("name"))
        if LABEL.fullmatch(namespace) is None or LABEL.fullmatch(name) is None:
            raise MalformedReview("invalid resource name")
        if request.get("operation") != "UPDATE" or request.get("subResource") != "scale":
            raise MalformedReview("operation not allowed")
        if _gvr(request.get("resource")) != ("apps", "v1", "deployments"):
            raise MalformedReview("resource not allowed")
        if _gvk(request.get("kind")) != ("autoscaling", "v1", "Scale"):
            raise MalformedReview("kind not allowed")
        obj = _map(request.get("object"))
        old = _map(request.get("oldObject"))
        if obj.get("apiVersion") != "autoscaling/v1" or obj.get("kind") != "Scale":
            raise MalformedReview("object kind not allowed")
        if old.get("apiVersion") != "autoscaling/v1" or old.get("kind") != "Scale":
            raise MalformedReview("old object kind not allowed")
        for item in (obj, old):
            metadata = _map(item.get("metadata"))
            if metadata.get("namespace") != namespace or metadata.get("name") != name:
                raise MalformedReview("object identity mismatch")
        replicas = _map(obj.get("spec")).get("replicas")
        if isinstance(replicas, bool) or not isinstance(replicas, int):
            raise MalformedReview("replicas must be an integer")
        expected = copy.deepcopy(old)
        _map(expected.get("spec"))["replicas"] = replicas
        if expected != obj:
            raise MalformedReview("unexpected object change")
        operation = self._catalog.operation("scale_deployment")
        if operation is None or operation.call.verb != "patch":
            raise MalformedReview("scale operation absent")
        arguments = {"namespace": namespace, "name": name, "replicas": replicas}
        checked = verify_operation(self._config, self._catalog, operation.name, arguments, token, now)
        if username != f"bailiff:{checked.release.tenant}:{operation.identity}" or op_id != checked.release.op_id:
            raise MalformedReview("release identity mismatch")
