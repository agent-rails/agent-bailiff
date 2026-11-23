from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import TYPE_CHECKING, Any, Literal, NamedTuple

if TYPE_CHECKING:
    from agent_bailiff.effector.catalog import CatalogOperation

Platform = Literal["upstream", "gke", "eks"]
PLATFORMS: tuple[Platform, ...] = ("upstream", "gke", "eks")
VERSION_PATH = "/version"
GKE_VERSION_MARKER = "-gke."
READ_VERBS = frozenset({"get", "list"})


class Action(NamedTuple):
    verb: str
    group: str
    resource: str
    subresource: str = ""
    namespaced: bool = True


def _actions(verbs: tuple[str, ...], group: str, resources: tuple[str, ...], **kind: Any) -> tuple[Action, ...]:
    return tuple(Action(verb, group, resource, **kind) for resource in resources for verb in verbs)


AUTHENTICATION = "authentication.k8s.io"
WRITES = ("create", "update", "patch", "delete")
CLUSTER: dict[str, Any] = {"namespaced": False}
DANGEROUS_ACTIONS: tuple[Action, ...] = (
    *_actions(("*",), "*", ("*",)),
    *_actions(("get", "list", "watch"), "", ("secrets",)),
    *_actions(("create",), "", ("pods",)),
    *_actions(("get", "create"), "", ("pods",), subresource="exec"),
    *_actions(("get", "create"), "", ("pods",), subresource="attach"),
    *_actions(("get", "create"), "", ("pods",), subresource="portforward"),
    *_actions(("update", "patch"), "", ("pods",), subresource="ephemeralcontainers"),
    *_actions(("create",), "", ("serviceaccounts",), subresource="token"),
    *_actions(WRITES, "apps", ("deployments",)),
    *_actions(("update", "patch"), "apps", ("deployments",), subresource="scale"),
    *_actions(("create",), "apps", ("daemonsets", "statefulsets", "replicasets")),
    *_actions(("create",), "batch", ("jobs", "cronjobs")),
    *_actions(("create",), "rbac.authorization.k8s.io", ("roles", "rolebindings")),
    *_actions(("bind", "escalate"), "rbac.authorization.k8s.io", ("roles",)),
    *_actions(("impersonate",), "", ("serviceaccounts",)),
    *_actions(("impersonate", "impersonate:serviceaccount"), AUTHENTICATION, ("serviceaccounts",)),
    *_actions(("impersonate-on:user-info:get", "impersonate-on:user-info:list"), "", ("secrets",)),
    *_actions(("impersonate-on:user-info:create",), "", ("pods",)),
    *_actions(("impersonate-on:user-info:delete",), "apps", ("deployments",)),
    *_actions(("impersonate-on:user-info:create",), "rbac.authorization.k8s.io", ("rolebindings",)),
    *_actions(("create",), "rbac.authorization.k8s.io", ("clusterroles", "clusterrolebindings"), **CLUSTER),
    *_actions(("bind", "escalate"), "rbac.authorization.k8s.io", ("clusterroles",), **CLUSTER),
    *_actions(("impersonate",), "", ("users", "groups"), **CLUSTER),
    *_actions(("impersonate", "impersonate:user-info"), AUTHENTICATION, ("users", "groups", "uids"), **CLUSTER),
    *_actions(("impersonate",), AUTHENTICATION, ("userextras",), **CLUSTER),
    *_actions(("impersonate:arbitrary-node", "impersonate:associated-node"), AUTHENTICATION, ("nodes",), **CLUSTER),
    *_actions(("get", "create"), "", ("nodes",), subresource="proxy", **CLUSTER),
    *_actions(("patch",), "", ("nodes",), **CLUSTER),
    *_actions(("delete",), "", ("namespaces",), **CLUSTER),
    *_actions(("create",), "", ("persistentvolumes",), **CLUSTER),
    *_actions(("create",), "certificates.k8s.io", ("certificatesigningrequests",), **CLUSTER),
    *_actions(("update",), "certificates.k8s.io", ("certificatesigningrequests",), subresource="approval", **CLUSTER),
    *_actions(("approve", "sign"), "certificates.k8s.io", ("signers",), **CLUSTER),
    *_actions(
        WRITES,
        "admissionregistration.k8s.io",
        (
            "validatingwebhookconfigurations",
            "mutatingwebhookconfigurations",
            "validatingadmissionpolicies",
            "validatingadmissionpolicybindings",
            "mutatingadmissionpolicies",
            "mutatingadmissionpolicybindings",
        ),
        **CLUSTER,
    ),
    *_actions(("create",), "apiextensions.k8s.io", ("customresourcedefinitions",), **CLUSTER),
)
ACCEPTED_INCOMPLETE: Mapping[Platform, frozenset[str]] = {
    "upstream": frozenset(),
    "gke": frozenset({"webhook authorizer does not support user rule resolution"}),
    "eks": frozenset(),
}


def parse_platform(value: object) -> Platform:
    if value not in PLATFORMS:
        raise ValueError(f"platform must be one of {', '.join(PLATFORMS)}")
    return value


def check_catalog(platform: Platform, operations: Iterable[CatalogOperation]) -> None:
    if platform == "upstream":
        return
    writes = sorted(item.name for item in operations if item.call.verb not in READ_VERBS)
    if writes:
        raise ValueError(f"managed platforms support read-only catalogs only; {platform} refuses {', '.join(writes)}")


def check_version(platform: Platform, version: object) -> list[str]:
    git_version = version.get("gitVersion") if isinstance(version, dict) else None
    if not isinstance(git_version, str) or not git_version:
        return [f"{VERSION_PATH} returned no gitVersion"]
    on_gke = GKE_VERSION_MARKER in git_version
    if on_gke and platform != "gke":
        return [f"the cluster runs GKE ({git_version}) but the effector platform is {platform}"]
    if platform == "gke" and not on_gke:
        return [f"the effector platform is gke but the cluster runs {git_version}"]
    return []


def accepts_incomplete(platform: Platform, status: Mapping[str, Any]) -> bool:
    error = status.get("evaluationError")
    return status.get("incomplete") is True and isinstance(error, str) and error in ACCEPTED_INCOMPLETE[platform]


def reviews_denied_actions(platform: Platform) -> bool:
    return bool(ACCEPTED_INCOMPLETE[platform])
