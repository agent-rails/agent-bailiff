from __future__ import annotations

import functools
import json
import logging
import random
import threading
import time
import urllib.parse
from collections.abc import Callable, Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Protocol

from agent_bailiff.effector.catalog import CatalogOperation
from agent_bailiff.effector.kubernetes import USER_PREFIX, KubernetesUnavailable, Transport, read_token
from agent_bailiff.effector.platform import VERSION_PATH, Platform, check_version
from agent_bailiff.effector.rbac import (
    DEPLOYMENT_FIELDS,
    DEPLOYMENT_SPEC_FIELDS,
    OBJECT_META_FIELDS,
    POD_TEMPLATE_FIELDS,
    EffectorIdentity,
    service_account_user,
    synthetic_user,
)
from agent_bailiff.webhook.manifests import (
    ENFORCE_SELECTOR,
    MATCH_CONDITIONS,
    REVIEW_VERSIONS,
    SERVICE_PATH,
    SERVICE_PORT,
    TIMEOUT_SECONDS,
    WEBHOOK,
)
from agent_bailiff.webhook.manifests import NAME as WEBHOOK_NAME
from agent_bailiff.webhook.manifests import RULES as WEBHOOK_RULES

CHECK_INTERVAL_SECONDS = 60
REVIEW_WORKERS = 4
THROTTLE_RETRIES = 5
RETRY_BASE_SECONDS = 0.5
RETRY_MAX_SECONDS = 8.0
PAGE_SIZE = 500
MAX_PAGES = 200
RBAC_PATH = "/apis/rbac.authorization.k8s.io/v1"
ADMISSION_PATH = "/apis/admissionregistration.k8s.io/v1"
APPS_SCHEMA_PATH = "/openapi/v3/apis/apps/v1"
SCHEMA_REF = "#/components/schemas/"
DEPLOYMENT = "io.k8s.api.apps.v1.Deployment"
DEPLOYMENT_SPEC = "io.k8s.api.apps.v1.DeploymentSpec"
POD_TEMPLATE_SPEC = "io.k8s.api.core.v1.PodTemplateSpec"
OBJECT_META = "io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta"
PINNED_SCHEMAS = {
    DEPLOYMENT: DEPLOYMENT_FIELDS,
    DEPLOYMENT_SPEC: DEPLOYMENT_SPEC_FIELDS,
    POD_TEMPLATE_SPEC: POD_TEMPLATE_FIELDS,
    OBJECT_META: OBJECT_META_FIELDS,
}
PINNED_REFERENCES = (
    (DEPLOYMENT, "metadata", OBJECT_META),
    (DEPLOYMENT, "spec", DEPLOYMENT_SPEC),
    (DEPLOYMENT_SPEC, "template", POD_TEMPLATE_SPEC),
    (POD_TEMPLATE_SPEC, "metadata", OBJECT_META),
)
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
POLICY_FIELDS = ("failurePolicy", "matchConditions", "validations", "variables")

Atom = tuple[str, str, str, str | None]
Key = tuple[str, str | None, str]

logger = logging.getLogger(__name__)


class AuditTransport(Transport, Protocol):
    def close(self) -> None: ...


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


def grants(rules: Iterable[Mapping[str, Any]], operation: CatalogOperation) -> bool:
    call = operation.call
    combined = f"{call.resource}/{call.subresource}" if call.subresource else call.resource
    for rule in rules:
        verbs, groups = rule.get("verbs") or [], rule.get("apiGroups") or []
        if not ({call.verb, "*"} & set(verbs) and {call.group, "*"} & set(groups)):
            continue
        for resource in rule.get("resources") or []:
            if resource in ("*", combined) or (call.subresource and resource == f"*/{call.subresource}"):
                return True
    return False


class RbacAudit:
    def __init__(
        self,
        transport: AuditTransport,
        effector_token: Path,
        audit_token: Path,
        identity: EffectorIdentity,
        manifests: Mapping[str, Any],
        tenants: Mapping[str, Sequence[str]],
        operations: Sequence[CatalogOperation],
        *,
        platform: Platform,
        workers: int = REVIEW_WORKERS,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._transport = transport
        self._platform = platform
        self._workers = workers
        self._sleep = sleep
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
        problems = check_version(self._platform, self._request(self._audit_token, "GET", VERSION_PATH, None))
        if problems:
            return problems
        namespaces = [item["metadata"]["name"] for item in self._list("/api/v1/namespaces")]
        if not namespaces:
            problems.append("the audit identity listed no namespaces")
        bindings = self._live(BINDING_KINDS)
        roles = self._live(ROLE_KINDS)
        reviews: list[Callable[[], list[str]]] = [
            functools.partial(self._check_rules, account, namespace)
            for namespace in namespaces
            for account in self._granted
        ]
        reviews.extend(self._synthetic_user_reviews())
        for found in self._run(reviews):
            problems.extend(found)
        problems.extend(self._check_objects(BINDING_KINDS, bindings, self._compare_binding, self._reaches_effector))
        problems.extend(self._check_objects(ROLE_KINDS, roles, self._compare_role, lambda item: False))
        problems.extend(self._check_shared_grants(bindings, roles))
        problems.extend(self._check_policies())
        return problems

    def check_release_webhook(self) -> list[str]:
        if not any(operation.call.verb == "patch" for operation in self._operations):
            return []
        namespace = self._identity.webhook_namespace
        registration = self._request(
            self._audit_token, "GET", f"{ADMISSION_PATH}/validatingwebhookconfigurations/{WEBHOOK_NAME}", None
        )
        hooks = [hook for hook in registration.get("webhooks") or [] if isinstance(hook, dict)]
        named = [hook for hook in hooks if hook.get("name") == WEBHOOK]
        if len(named) != 1:
            return [f"the ValidatingWebhookConfiguration {WEBHOOK_NAME} does not register {WEBHOOK}"]
        hook = named[0]
        client = hook.get("clientConfig") or {}
        expected = {"name": WEBHOOK_NAME, "namespace": namespace, "path": SERVICE_PATH, "port": SERVICE_PORT}
        problems: list[str] = []
        if hook.get("failurePolicy") != "Fail":
            problems.append(f"{WEBHOOK} does not fail closed")
        if hook.get("admissionReviewVersions") != REVIEW_VERSIONS or hook.get("timeoutSeconds") != TIMEOUT_SECONDS:
            problems.append(f"{WEBHOOK} does not use the generated review version and timeout")
        if hook.get("matchConditions") != MATCH_CONDITIONS or hook.get("rules") != WEBHOOK_RULES:
            problems.append(f"{WEBHOOK} does not match every write by a synthetic user")
        if hook.get("namespaceSelector") or hook.get("objectSelector"):
            problems.append(f"{WEBHOOK} is narrowed by a selector")
        if "url" in client or client.get("service") != expected:
            problems.append(f"{WEBHOOK} does not call the {namespace}/{WEBHOOK_NAME} Service")
        service = self._request(
            self._audit_token, "GET", f"/api/v1/namespaces/{namespace}/services/{WEBHOOK_NAME}", None
        )
        if (service.get("spec") or {}).get("selector") != ENFORCE_SELECTOR:
            problems.append(f"the Service {namespace}/{WEBHOOK_NAME} does not select only Enforce-mode webhook pods")
        return problems

    def close(self) -> None:
        self._transport.close()

    def check_restart_schema(self) -> list[str]:
        if not any(operation.call.restarts for operation in self._operations):
            return []
        document = self._request(self._audit_token, "GET", APPS_SCHEMA_PATH, None)
        schemas = (document.get("components") or {}).get("schemas")
        if not isinstance(schemas, dict):
            raise KubernetesUnavailable(f"{APPS_SCHEMA_PATH} returned no schemas")
        problems: list[str] = []
        for name, pinned in PINNED_SCHEMAS.items():
            properties = (schemas.get(name) or {}).get("properties")
            if not isinstance(properties, dict):
                problems.append(f"the cluster serves no {name} schema")
                continue
            added, removed = sorted(set(properties) - set(pinned)), sorted(set(pinned) - set(properties))
            if added or removed:
                problems.append(
                    f"the cluster's {name} fields differ from those the restart policy compares:"
                    f" added {added}, removed {removed}"
                )
        for owner, field, target in PINNED_REFERENCES:
            if _reference(schemas, owner, field) != SCHEMA_REF + target:
                problems.append(f"the cluster's {owner}.{field} is not a {target}")
        return problems

    def _synthetic_user_reviews(self) -> list[Callable[[], list[str]]]:
        identities = sorted({operation.identity for operation in self._operations})
        return [
            functools.partial(self._check_synthetic_user, synthetic_user(tenant, identity), namespace, operation)
            for tenant in sorted(self._tenants)
            for identity in identities
            for namespace in sorted(set(self._tenants[tenant]))
            for operation in self._operations
        ]

    def _check_synthetic_user(self, user: str, namespace: str, operation: CatalogOperation) -> list[str]:
        expected = operation.identity == user.rsplit(":", 1)[1]
        if self._allowed(user, namespace, operation) == expected:
            return []
        return [f"{user} {'may not' if expected else 'may'} {operation.name} in {namespace}"]

    def _check_shared_grants(self, bindings: Mapping[Key, Mapping[str, Any]], roles: Mapping[Key, Any]) -> list[str]:
        namespaces = {namespace for allowed in self._tenants.values() for namespace in allowed}
        problems: list[str] = []
        for key, binding in bindings.items():
            if key in self._items or (key[0] == "RoleBinding" and key[1] not in namespaces):
                continue
            subjects = binding.get("subjects") or []
            if not any(
                subject.get("kind") == "Group" and subject.get("name") in IMPLICIT_GROUPS for subject in subjects
            ):
                continue
            reference = binding.get("roleRef") or {}
            scope = key[1] if reference.get("kind") == "Role" else None
            role = roles.get((str(reference.get("kind")), scope, str(reference.get("name"))))
            rules = (role or {}).get("rules") or []
            granted = [operation.name for operation in self._operations if grants(rules, operation)]
            if granted:
                problems.append(
                    f"the {key[0]} {_label(key)} grants {', '.join(granted)} to every synthetic user"
                    f" through {IMPLICIT_GROUPS[0]}"
                )
        return problems

    def _run(self, reviews: Sequence[Callable[[], list[str]]]) -> list[list[str]]:
        with ThreadPoolExecutor(max_workers=self._workers, thread_name_prefix="rbac-audit") as executor:
            return list(executor.map(lambda review: review(), reviews))

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

    def _live(self, kinds: Sequence[str]) -> dict[Key, dict[str, Any]]:
        return {_key(item, kind): item for kind in kinds for item in self._list(f"{RBAC_PATH}/{kind.lower()}s")}

    def _check_objects(
        self,
        kinds: Sequence[str],
        live: Mapping[Key, Mapping[str, Any]],
        compare: Callable[[Mapping[str, Any], Mapping[str, Any]], bool],
        foreign: Callable[[Mapping[str, Any]], bool],
    ) -> list[str]:
        problems: list[str] = []
        for kind in kinds:
            for key, item in self._expected(kind).items():
                if key not in live:
                    problems.append(f"the generated {kind} {_label(key)} is missing")
                elif not compare(item, live[key]):
                    problems.append(f"the generated {kind} {_label(key)} was changed")
            for key, item in live.items():
                if key[0] == kind and key not in self._items and foreign(item):
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
        usernames = {
            service_account_user(identity.namespace, account)
            for account in (identity.service_account, identity.audit_account)
        }
        binding_namespace = (binding.get("metadata") or {}).get("namespace")
        for subject in binding.get("subjects") or []:
            name = str(subject.get("name", ""))
            if subject.get("kind") == "User" and (name.startswith(f"{USER_PREFIX}:") or name in usernames):
                return True
            if (
                subject.get("kind") == "ServiceAccount"
                and (subject.get("namespace") or binding_namespace) == identity.namespace
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
        for attempt in range(THROTTLE_RETRIES + 1):
            status, data = self._transport.request(method, path, headers, payload)
            if status != 429 or attempt == THROTTLE_RETRIES:
                break
            self._sleep(random.uniform(0, min(RETRY_MAX_SECONDS, RETRY_BASE_SECONDS * 2**attempt)))
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
        self._restart_verified_at: int | None = None
        self._write_verified_at: int | None = None
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def verify(self) -> None:
        now = self._clock()
        try:
            problems = self._audit.check()
        except Exception as exc:
            problems = [f"the RBAC check failed: {exc}"]
        restart_problems = [] if problems else self._extra("the Deployment schema", self._audit.check_restart_schema)
        write_problems = [] if problems else self._extra("the release webhook", self._audit.check_release_webhook)
        with self._lock:
            self._verified_at = None if problems else now
            self._restart_verified_at = None if problems or restart_problems else now
            self._write_verified_at = None if problems or write_problems else now
        for problem in restart_problems:
            logger.error("restart withdrawn: %s", problem)
        for problem in write_problems:
            logger.error("writes withdrawn: %s", problem)
        if problems:
            for problem in problems:
                logger.error("effector RBAC drift: %s", problem)
            raise RbacDrift(problems)

    def healthy(self, now: int) -> bool:
        with self._lock:
            verified = self._verified_at
        return self._fresh(verified, now)

    def restart_healthy(self, now: int) -> bool:
        with self._lock:
            verified, restart = self._verified_at, self._restart_verified_at
        return self._fresh(verified, now) and self._fresh(restart, now)

    def write_healthy(self, now: int) -> bool:
        with self._lock:
            verified, write = self._verified_at, self._write_verified_at
        return self._fresh(verified, now) and self._fresh(write, now)

    def _extra(self, subject: str, check: Callable[[], list[str]]) -> list[str]:
        try:
            return check()
        except Exception as exc:
            return [f"{subject} check failed: {exc}"]

    def _fresh(self, verified: int | None, now: int) -> bool:
        return verified is not None and 0 <= now - verified <= 2 * self._interval

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._audit.close()

    def _run(self) -> None:
        delay = self._interval
        while not self._stop.wait(delay):
            started = self._clock()
            try:
                self.verify()
            except RbacDrift:
                logger.error("the effector refuses calls until its RBAC matches the generated set")
            delay = min(self._interval, max(0, self._interval - (self._clock() - started)))


def _key(item: Mapping[str, Any], kind: str | None = None) -> Key:
    metadata = item.get("metadata") or {}
    return (kind or item["kind"], metadata.get("namespace"), metadata.get("name", ""))


def _label(key: Key) -> str:
    return f"{key[1]}/{key[2]}" if key[1] else key[2]


def _reference(schemas: Mapping[str, Any], owner: str, field: str) -> object:
    schema = ((schemas.get(owner) or {}).get("properties") or {}).get(field) or {}
    if "$ref" in schema:
        return schema["$ref"]
    parts = schema.get("allOf") or []
    return parts[0].get("$ref") if len(parts) == 1 and isinstance(parts[0], dict) else None


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
