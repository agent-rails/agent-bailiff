from __future__ import annotations

import json
import logging
import threading
import urllib.parse
from collections.abc import Callable, Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from agent_bailiff.effector.catalog import CatalogOperation
from agent_bailiff.effector.kubernetes import USER_PREFIX, KubernetesUnavailable, Transport, read_token
from agent_bailiff.effector.rbac import EffectorIdentity, synthetic_user

CHECK_INTERVAL_SECONDS = 60
PAGE_SIZE = 500
MAX_PAGES = 200
RBAC_PATH = "/apis/rbac.authorization.k8s.io/v1"
ADMISSION_PATH = "/apis/admissionregistration.k8s.io/v1"
BASELINE_RULES = (
    {"apiGroups": ["authorization.k8s.io"], "resources": ["selfsubjectaccessreviews"], "verbs": ["create"]},
    {"apiGroups": ["authorization.k8s.io"], "resources": ["selfsubjectrulesreviews"], "verbs": ["create"]},
    {"apiGroups": ["authentication.k8s.io"], "resources": ["selfsubjectreviews"], "verbs": ["create"]},
)
BASELINE_NON_RESOURCE = (
    {"verbs": ["get"], "nonResourceURLs": ["/healthz", "/livez", "/readyz", "/version", "/version/"]},
    {
        "verbs": ["get"],
        "nonResourceURLs": [
            "/.well-known/openid-configuration",
            "/.well-known/openid-configuration/",
            "/openid/v1/jwks",
            "/openid/v1/jwks/",
        ],
    },
    {"verbs": ["get"], "nonResourceURLs": ["/api", "/api/*", "/apis", "/apis/*", "/openapi", "/openapi/*"]},
)
NON_RESOURCE = "#non-resource"
IMPLICIT_GROUPS = ["system:authenticated"]
BINDING_KINDS = ("RoleBinding", "ClusterRoleBinding")
ROLE_KINDS = ("Role", "ClusterRole")
POLICY_FIELDS = ("failurePolicy", "matchConditions", "validations")

Atom = tuple[str, str, str, str | None]
Key = tuple[str, str | None, str]

logger = logging.getLogger(__name__)


class RbacDrift(RuntimeError):
    def __init__(self, problems: Sequence[str]) -> None:
        super().__init__("; ".join(problems))
        self.problems = tuple(problems)


def atoms(rules: Iterable[Mapping[str, Any]]) -> set[Atom]:
    expanded: set[Atom] = set()
    for rule in rules:
        names: list[str | None] = list(rule.get("resourceNames") or []) or [None]
        for verb in rule.get("verbs") or []:
            for url in rule.get("nonResourceURLs") or []:
                expanded.add((verb, NON_RESOURCE, url, None))
            for group in rule.get("apiGroups") or []:
                for resource in rule.get("resources") or []:
                    for name in names:
                        expanded.add((verb, group, resource, name))
    return expanded


class RbacAudit:
    def __init__(
        self,
        transport: Transport,
        effector_token: Path,
        audit_token: Path,
        identity: EffectorIdentity,
        manifests: Mapping[str, Any],
        tenants: Mapping[str, Sequence[str]],
        operations: Sequence[CatalogOperation],
    ) -> None:
        self._transport = transport
        self._audit_token = audit_token
        self._identity = identity
        self._items = {_key(item): item for item in manifests["items"]}
        self._tenants = tenants
        self._operations = operations
        self._granted = {
            account: self._granted_to(account) for account in (identity.service_account, identity.audit_account)
        }
        self._tokens = {identity.service_account: effector_token, identity.audit_account: audit_token}

    def check(self) -> list[str]:
        problems: list[str] = []
        namespaces = [item["metadata"]["name"] for item in self._list("/api/v1/namespaces")]
        if not namespaces:
            problems.append("the audit identity listed no namespaces")
        for namespace in namespaces:
            for account in self._granted:
                problems.extend(self._check_rules(account, namespace))
        problems.extend(self._check_synthetic_users())
        problems.extend(self._check_objects(BINDING_KINDS, self._compare_binding, self._reaches_effector))
        problems.extend(self._check_objects(ROLE_KINDS, self._compare_role, lambda item: False))
        problems.extend(self._check_policies())
        return problems

    def _check_synthetic_users(self) -> list[str]:
        problems: list[str] = []
        identities = sorted({operation.identity for operation in self._operations})
        namespaces = sorted({namespace for allowed in self._tenants.values() for namespace in allowed})
        for tenant in sorted(self._tenants):
            for identity in identities:
                user = synthetic_user(tenant, identity)
                for namespace in namespaces:
                    for operation in self._operations:
                        expected = namespace in self._tenants[tenant] and operation.identity == identity
                        if self._allowed(user, namespace, operation) != expected:
                            state = "may" if not expected else "may not"
                            problems.append(f"{user} {state} {operation.name} in {namespace}")
        return problems

    def _allowed(self, user: str, namespace: str, operation: CatalogOperation) -> bool:
        call = operation.call
        attributes = {"namespace": namespace, "verb": call.verb, "group": call.group, "resource": call.resource}
        if call.subresource:
            attributes["subresource"] = call.subresource
        review = {
            "apiVersion": "authorization.k8s.io/v1",
            "kind": "SubjectAccessReview",
            "spec": {"user": user, "groups": IMPLICIT_GROUPS, "resourceAttributes": attributes},
        }
        status = self._request(
            self._audit_token, "POST", "/apis/authorization.k8s.io/v1/subjectaccessreviews", review
        ).get("status")
        if not isinstance(status, dict) or not isinstance(status.get("allowed"), bool):
            raise KubernetesUnavailable("a SubjectAccessReview returned no decision")
        return status["allowed"] is True

    def _check_rules(self, account: str, namespace: str) -> list[str]:
        review = {
            "apiVersion": "authorization.k8s.io/v1",
            "kind": "SelfSubjectRulesReview",
            "spec": {"namespace": namespace},
        }
        status = self._request(
            self._tokens[account], "POST", "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews", review
        ).get("status")
        if not isinstance(status, dict) or status.get("incomplete") is not False:
            return [f"the rules of {account} in {namespace} could not be listed completely"]
        rules = self._granted[account]
        allowed = (
            atoms(BASELINE_RULES) | atoms(BASELINE_NON_RESOURCE) | rules.get(None, set()) | rules.get(namespace, set())
        )
        granted = atoms(status.get("resourceRules") or []) | atoms(status.get("nonResourceRules") or [])
        extra = sorted((atom for atom in granted if atom not in allowed and atom[:3] + (None,) not in allowed), key=str)
        return [f"{account} holds a grant outside the generated set in {namespace}: {atom}" for atom in extra]

    def _check_objects(
        self,
        kinds: Sequence[str],
        compare: Callable[[Mapping[str, Any], Mapping[str, Any]], bool],
        foreign: Callable[[Mapping[str, Any]], bool],
    ) -> list[str]:
        problems: list[str] = []
        for kind in kinds:
            plural = kind.lower() + "s"
            live = {_key(item, kind): item for item in self._list(f"{RBAC_PATH}/{plural}")}
            for key, item in self._expected(kind).items():
                if key not in live:
                    problems.append(f"the generated {kind} {_label(key)} is missing")
                elif not compare(item, live[key]):
                    problems.append(f"the generated {kind} {_label(key)} was changed")
            for key, item in live.items():
                if key not in self._items and foreign(item):
                    problems.append(f"the {kind} {_label(key)} grants to the effector or a synthetic user")
        return problems

    def _check_policies(self) -> list[str]:
        problems: list[str] = []
        for kind, plural, compare in (
            ("ValidatingAdmissionPolicy", "validatingadmissionpolicies", _same_policy),
            ("ValidatingAdmissionPolicyBinding", "validatingadmissionpolicybindings", _same_policy_binding),
        ):
            live = {_key(item, kind): item for item in self._list(f"{ADMISSION_PATH}/{plural}")}
            for key, item in self._expected(kind).items():
                if key not in live:
                    problems.append(f"the generated {kind} {_label(key)} is missing")
                elif not compare(item, live[key]):
                    problems.append(f"the generated {kind} {_label(key)} was changed")
        return problems

    def _compare_binding(self, expected: Mapping[str, Any], live: Mapping[str, Any]) -> bool:
        return bool(live.get("roleRef") == expected["roleRef"] and live.get("subjects") == expected["subjects"])

    def _compare_role(self, expected: Mapping[str, Any], live: Mapping[str, Any]) -> bool:
        return "aggregationRule" not in live and atoms(live.get("rules") or []) == atoms(expected["rules"])

    def _reaches_effector(self, binding: Mapping[str, Any]) -> bool:
        identity = self._identity
        for subject in binding.get("subjects") or []:
            if subject.get("kind") == "User" and str(subject.get("name", "")).startswith(f"{USER_PREFIX}:"):
                return True
            if (
                subject.get("kind") == "ServiceAccount"
                and subject.get("namespace") == identity.namespace
                and subject.get("name") in (identity.service_account, identity.audit_account)
            ):
                return True
        return False

    def _granted_to(self, account: str) -> dict[str | None, set[Atom]]:
        granted: dict[str | None, set[Atom]] = {}
        for item in self._items.values():
            if item["kind"] not in BINDING_KINDS:
                continue
            if not any(subject.get("name") == account for subject in item["subjects"]):
                continue
            role = self._items[(item["roleRef"]["kind"], item["metadata"].get("namespace"), item["roleRef"]["name"])]
            granted.setdefault(item["metadata"].get("namespace"), set()).update(atoms(role["rules"]))
        return granted

    def _expected(self, kind: str) -> dict[Key, Mapping[str, Any]]:
        return {key: item for key, item in self._items.items() if key[0] == kind}

    def _list(self, path: str) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        token = ""
        for _ in range(MAX_PAGES):
            query = {"limit": str(PAGE_SIZE)} | ({"continue": token} if token else {})
            page = self._request(self._audit_token, "GET", f"{path}?{urllib.parse.urlencode(query)}", None)
            batch = page.get("items")
            if not isinstance(batch, list):
                raise KubernetesUnavailable(f"{path} returned no item list")
            items.extend(item for item in batch if isinstance(item, dict))
            token = (page.get("metadata") or {}).get("continue") or ""
            if not token:
                return items
        raise KubernetesUnavailable(f"{path} has more than {MAX_PAGES} pages")

    def _request(self, token_file: Path, method: str, path: str, body: object) -> dict[str, Any]:
        headers = {"Authorization": f"Bearer {read_token(token_file)}", "Accept": "application/json"}
        payload = None
        if body is not None:
            payload = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        status, data = self._transport.request(method, path, headers, payload)
        if status != 200 and status != 201:
            raise KubernetesUnavailable(f"{method} {path.split('?')[0]} returned {status}")
        try:
            document = json.loads(data)
        except ValueError:
            raise KubernetesUnavailable(f"{path} did not return JSON") from None
        if not isinstance(document, dict):
            raise KubernetesUnavailable(f"{path} did not return an object")
        return document


class RbacGate:
    def __init__(
        self,
        audit: RbacAudit,
        clock: Callable[[], int],
        interval: int = CHECK_INTERVAL_SECONDS,
    ) -> None:
        self._audit = audit
        self._clock = clock
        self._interval = interval
        self._verified_at: int | None = None
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def verify(self) -> None:
        now = self._clock()
        try:
            problems = self._audit.check()
        except Exception as exc:
            problems = [f"the RBAC check failed: {exc}"]
        with self._lock:
            self._verified_at = None if problems else now
        if problems:
            for problem in problems:
                logger.error("effector RBAC drift: %s", problem)
            raise RbacDrift(problems)

    def healthy(self, now: int) -> bool:
        with self._lock:
            verified = self._verified_at
        return verified is not None and 0 <= now - verified <= 2 * self._interval

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def _run(self) -> None:
        while not self._stop.wait(self._interval):
            try:
                self.verify()
            except RbacDrift:
                logger.error("the effector refuses calls until its RBAC matches the generated set")


def _key(item: Mapping[str, Any], kind: str | None = None) -> Key:
    metadata = item.get("metadata") or {}
    return (kind or item["kind"], metadata.get("namespace"), metadata.get("name", ""))


def _label(key: Key) -> str:
    return f"{key[1]}/{key[2]}" if key[1] else key[2]


def _same_policy(expected: Mapping[str, Any], live: Mapping[str, Any]) -> bool:
    spec, wanted = live.get("spec") or {}, expected["spec"]
    if any(spec.get(field) != wanted.get(field) for field in POLICY_FIELDS if field in wanted):
        return False
    constraints = spec.get("matchConstraints") or {}
    if (
        constraints.get("namespaceSelector")
        or constraints.get("objectSelector")
        or constraints.get("excludeResourceRules")
    ):
        return False
    if any(rule.get("scope", "*") != "*" for rule in constraints.get("resourceRules") or []):
        return False
    rules = [
        {key: value for key, value in rule.items() if key != "scope"} for rule in constraints.get("resourceRules") or []
    ]
    return rules == wanted["matchConstraints"]["resourceRules"] and "paramKind" not in spec


def _same_policy_binding(expected: Mapping[str, Any], live: Mapping[str, Any]) -> bool:
    spec = live.get("spec") or {}
    resources = spec.get("matchResources") or {}
    return (
        spec.get("policyName") == expected["spec"]["policyName"]
        and spec.get("validationActions") == expected["spec"]["validationActions"]
        and "paramRef" not in spec
        and not any(resources.get(field) for field in ("namespaceSelector", "objectSelector", "resourceRules"))
        and not resources.get("excludeResourceRules")
    )
