from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent_warrant.identity import decode_public_key, is_valid_public_key
from agent_warrant.resolver import PinnedResolver
from agent_warrant.trust import IssuerAllowance, IssuerTrustPolicy, TenantAllowance
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agent_bailiff.control.suspension import suspension_directory
from agent_bailiff.custodian.files import read_owned
from agent_bailiff.decide.config import PolicyRef, TargetBinding
from agent_bailiff.decide.costs import CostTable
from agent_bailiff.docket.sink import Writers
from agent_bailiff.effector.rbac import EffectorIdentity, check_inputs
from agent_bailiff.keys import check_component, parse_pinned_keys
from agent_bailiff.strict_json import parse_strict_json

MAX_CONFIG_BYTES = 1 << 20
MAX_OS_ID = 2**32 - 2

DOCKET_CLIENT_KEYS = frozenset({"socket", "sink_uid", "state_dir"})
GATEWAY_KEYS = frozenset({"uid", "socket", "socket_group", "private_dir"})
ISSUER_KEYS = frozenset({"public_key", "max_budget", "max_depth", "tenants"})
TENANT_KEYS = frozenset({"principals", "principal_prefixes"})
BINDING_KEYS = frozenset({"tenant", "tool", "resource", "credential_id", "target", "custodian"})
DECIDE_KEYS = frozenset(
    {"name", "key", "max_proof_age", "reconcile_seconds", "custodians", "bindings", "policy", "costs", "issuers"}
    | {"ledger", "routes", "docket", "gateway"}
)
CUSTODIAN_KEYS = frozenset(
    {"name", "key", "decider", "decide_keys", "max_proof_age", "max_clearance_lifetime", "skew_seconds"}
    | {"rate_limit", "rate_window", "issuers", "bindings", "kek", "credentials", "claims", "ledger", "routes"}
    | {"docket", "gateway"}
)
DOCKET_KEYS = frozenset({"docket", "socket", "socket_group", "allowed_uids", "writers"})
EFFECTOR_KEYS = frozenset(
    {"name", "key", "catalog", "custodian", "custodian_keys", "decider", "decide_keys", "skew_seconds"}
    | {"max_clearance_lifetime", "port", "kubernetes", "rbac", "ledger", "docket"}
)
KUBERNETES_KEYS = frozenset({"host", "port", "ca", "token_file", "audit_token_file"})
RBAC_KEYS = frozenset({"namespace", "service_account", "applier", "tenants"})
CONTROL_KEYS = frozenset({"name", "key", "decide_config", "docket", "writers"})


class ConfigError(ValueError):
    pass


class Section:
    def __init__(self, document: object, label: str, keys: frozenset[str]) -> None:
        if not isinstance(document, dict):
            raise ConfigError(f"{label} must be an object")
        missing = sorted(keys - set(document))
        unknown = sorted(set(document) - keys)
        if missing or unknown:
            problems = [f"missing {', '.join(missing)}"] if missing else []
            problems += [f"unknown {', '.join(unknown)}"] if unknown else []
            raise ConfigError(f"{label}: {'; '.join(problems)}")
        self._document: dict[str, Any] = document
        self._label = label

    def raw(self, name: str) -> Any:
        return self._document[name]

    def section(self, name: str, keys: frozenset[str]) -> Section:
        return Section(self._document[name], f"{self._label}.{name}", keys)

    def text(self, name: str) -> str:
        value = self._document[name]
        if not isinstance(value, str) or not value or not all("!" <= character <= "~" for character in value):
            raise ConfigError(f"{self._label}.{name} must be a non-empty ASCII printable str without whitespace")
        return value

    def component(self, name: str) -> str:
        try:
            return check_component(self._document[name])
        except ValueError as exc:
            raise ConfigError(f"{self._label}.{name}: {exc}") from None

    def path(self, name: str) -> Path:
        value = self._document[name]
        if not isinstance(value, str) or not value.startswith("/") or "\x00" in value:
            raise ConfigError(f"{self._label}.{name} must be an absolute path")
        return Path(value)

    def integer(self, name: str, minimum: int = 0, maximum: int = 2**53 - 1) -> int:
        value = self._document[name]
        if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
            raise ConfigError(f"{self._label}.{name} must be an integer between {minimum} and {maximum}")
        return value

    def os_id(self, name: str) -> int:
        return self.integer(name, 0, MAX_OS_ID)

    def wrap(self, name: str, problem: Exception) -> ConfigError:
        return ConfigError(f"{self._label}.{name}: {problem}")


@dataclass(frozen=True)
class DocketClientSettings:
    socket: Path
    sink_uid: int
    state_dir: Path


@dataclass(frozen=True)
class GatewaySettings:
    uid: int
    socket: Path
    socket_group: int
    private_dir: Path


@dataclass(frozen=True)
class Issuers:
    resolver: PinnedResolver
    trust_policy: IssuerTrustPolicy


@dataclass(frozen=True)
class SharedLedgerSettings:
    path: Path
    group: int


@dataclass(frozen=True)
class ReadOnlyLedgerSettings:
    path: Path
    writer_uid: int
    group: int


@dataclass(frozen=True)
class DecideSettings:
    name: str
    key: Path
    max_proof_age: int
    reconcile_seconds: int
    custodians: frozenset[str]
    bindings: tuple[TargetBinding, ...]
    policy: PolicyRef
    costs: CostTable
    issuers: Issuers
    ledger: SharedLedgerSettings
    suspension_dir: Path
    routes: Path
    docket: DocketClientSettings
    gateway: GatewaySettings


@dataclass(frozen=True)
class CustodianSettings:
    name: str
    key: Path
    decider: str
    decide_keys: Mapping[str, Ed25519PublicKey]
    max_proof_age: int
    max_clearance_lifetime: int
    skew_seconds: int
    rate_limit: int
    rate_window: int
    issuers: Issuers
    bindings: Path
    kek: Path
    credentials: Path
    claims: Path
    ledger: ReadOnlyLedgerSettings
    suspension_dir: Path
    routes: Path
    docket: DocketClientSettings
    gateway: GatewaySettings


@dataclass(frozen=True)
class KubernetesSettings:
    host: str
    port: int
    ca: Path
    token_file: Path
    audit_token_file: Path


@dataclass(frozen=True)
class EffectorSettings:
    name: str
    key: Path
    catalog: Path
    custodian: str
    custodian_keys: Mapping[str, Ed25519PublicKey]
    decider: str
    decide_keys: Mapping[str, Ed25519PublicKey]
    skew_seconds: int
    max_clearance_lifetime: int
    port: int
    kubernetes: KubernetesSettings
    rbac: EffectorIdentity
    tenants: Mapping[str, tuple[str, ...]]
    ledger: ReadOnlyLedgerSettings
    suspension_dir: Path
    docket: DocketClientSettings


@dataclass(frozen=True)
class DocketSettings:
    docket: Path
    socket: Path
    socket_group: int
    allowed_uids: frozenset[int]
    writers: Writers


@dataclass(frozen=True)
class ControlSettings:
    name: str
    key: Path
    decide_config: Path
    docket: DocketClientSettings
    writers: Writers


def read_config(path: Path, label: str) -> Any:
    try:
        return parse_strict_json(read_owned(path, label, MAX_CONFIG_BYTES))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ConfigError(f"the {label} is not valid JSON: {exc}") from None


def load_decide(path: Path) -> DecideSettings:
    return parse_decide(read_config(path, "decide config"))


def load_custodian(path: Path) -> CustodianSettings:
    return parse_custodian(read_config(path, "custodian config"))


def load_docket(path: Path) -> DocketSettings:
    return parse_docket(read_config(path, "docket config"))


def load_effector(path: Path) -> EffectorSettings:
    return parse_effector(read_config(path, "effector config"))


def parse_effector(document: object) -> EffectorSettings:
    config = Section(document, "effector", EFFECTOR_KEYS)
    custodian = config.component("custodian")
    decider = config.component("decider")
    keys = {}
    for field, owner in (("custodian_keys", custodian), ("decide_keys", decider)):
        try:
            keys[field] = parse_pinned_keys(owner, config.raw(field))
        except ValueError as exc:
            raise config.wrap(field, exc) from None
    kubernetes = config.section("kubernetes", KUBERNETES_KEYS)
    host = kubernetes.text("host")
    if host not in ("127.0.0.1", "localhost") and not all(part.isalnum() or part in ".-" for part in host):
        raise ConfigError("effector.kubernetes.host must be a host name or address")
    ledger = config.section("ledger", frozenset({"path", "writer_uid", "group"}))
    rbac = config.section("rbac", RBAC_KEYS)
    tenants = rbac.raw("tenants")
    if not isinstance(tenants, dict) or not all(
        isinstance(namespaces, list) and all(isinstance(namespace, str) for namespace in namespaces)
        for namespaces in tenants.values()
    ):
        raise ConfigError("effector.rbac.tenants must map tenants to lists of namespaces")
    identity = EffectorIdentity(rbac.text("namespace"), rbac.text("service_account"), rbac.text("applier"))
    try:
        check_inputs(identity, tenants)
    except ValueError as exc:
        raise rbac.wrap("tenants", exc) from None
    return EffectorSettings(
        name=config.component("name"),
        key=config.path("key"),
        catalog=config.path("catalog"),
        custodian=custodian,
        custodian_keys=keys["custodian_keys"],
        decider=decider,
        decide_keys=keys["decide_keys"],
        skew_seconds=config.integer("skew_seconds", 0, 300),
        max_clearance_lifetime=config.integer("max_clearance_lifetime", 1),
        port=config.integer("port", 1, 65535),
        kubernetes=KubernetesSettings(
            host,
            kubernetes.integer("port", 1, 65535),
            kubernetes.path("ca"),
            kubernetes.path("token_file"),
            kubernetes.path("audit_token_file"),
        ),
        rbac=identity,
        tenants={tenant: tuple(namespaces) for tenant, namespaces in tenants.items()},
        ledger=ReadOnlyLedgerSettings(ledger.path("path"), ledger.os_id("writer_uid"), ledger.os_id("group")),
        suspension_dir=suspension_directory(ledger.path("path")),
        docket=_docket_client(config),
    )


def load_control(path: Path) -> ControlSettings:
    return parse_control(read_config(path, "control config"))


def parse_decide(document: object) -> DecideSettings:
    config = Section(document, "decide", DECIDE_KEYS)
    name = config.component("name")
    custodian_names = frozenset(_non_empty_list(config, "custodians", check_component))
    ledger = config.section("ledger", frozenset({"path", "group"}))
    return DecideSettings(
        name=name,
        key=config.path("key"),
        max_proof_age=config.integer("max_proof_age", 1),
        reconcile_seconds=config.integer("reconcile_seconds", 1, 3600),
        custodians=custodian_names,
        bindings=_target_bindings(config, custodian_names),
        policy=_policy(config.section("policy", frozenset({"id", "version", "document"}))),
        costs=_costs(config),
        issuers=_issuers(config),
        ledger=SharedLedgerSettings(ledger.path("path"), ledger.os_id("group")),
        suspension_dir=suspension_directory(ledger.path("path")),
        routes=config.path("routes"),
        docket=_docket_client(config),
        gateway=_gateway(config),
    )


def parse_custodian(document: object) -> CustodianSettings:
    config = Section(document, "custodian", CUSTODIAN_KEYS)
    decider = config.component("decider")
    try:
        decide_keys = parse_pinned_keys(decider, config.raw("decide_keys"))
    except ValueError as exc:
        raise config.wrap("decide_keys", exc) from None
    ledger = config.section("ledger", frozenset({"path", "writer_uid", "group"}))
    return CustodianSettings(
        name=config.component("name"),
        key=config.path("key"),
        decider=decider,
        decide_keys=decide_keys,
        max_proof_age=config.integer("max_proof_age", 1),
        max_clearance_lifetime=config.integer("max_clearance_lifetime", 1),
        skew_seconds=config.integer("skew_seconds", 0, 300),
        rate_limit=config.integer("rate_limit", 1),
        rate_window=config.integer("rate_window", 1),
        issuers=_issuers(config),
        bindings=config.path("bindings"),
        kek=config.path("kek"),
        credentials=config.path("credentials"),
        claims=config.path("claims"),
        ledger=ReadOnlyLedgerSettings(ledger.path("path"), ledger.os_id("writer_uid"), ledger.os_id("group")),
        suspension_dir=suspension_directory(ledger.path("path")),
        routes=config.path("routes"),
        docket=_docket_client(config),
        gateway=_gateway(config),
    )


def parse_docket(document: object) -> DocketSettings:
    config = Section(document, "docket", DOCKET_KEYS)
    allowed = frozenset(_non_empty_list(config, "allowed_uids", _os_id))
    return DocketSettings(
        docket=config.path("docket"),
        socket=config.path("socket"),
        socket_group=config.os_id("socket_group"),
        allowed_uids=allowed,
        writers=_writers(config),
    )


def parse_control(document: object) -> ControlSettings:
    config = Section(document, "control", CONTROL_KEYS)
    name = config.component("name")
    writers = _writers(config)
    if name in writers:
        raise ConfigError("control.writers must not pin control's own writer")
    return ControlSettings(
        name=name,
        key=config.path("key"),
        decide_config=config.path("decide_config"),
        docket=_docket_client(config),
        writers=writers,
    )


def _docket_client(config: Section) -> DocketClientSettings:
    docket = config.section("docket", DOCKET_CLIENT_KEYS)
    return DocketClientSettings(docket.path("socket"), docket.os_id("sink_uid"), docket.path("state_dir"))


def _gateway(config: Section) -> GatewaySettings:
    gateway = config.section("gateway", GATEWAY_KEYS)
    return GatewaySettings(
        gateway.os_id("uid"), gateway.path("socket"), gateway.os_id("socket_group"), gateway.path("private_dir")
    )


def _writers(config: Section) -> dict[str, dict[str, Ed25519PublicKey]]:
    document = config.raw("writers")
    if not isinstance(document, dict) or not document:
        raise ConfigError("writers must be a non-empty object of writer names to pinned keys")
    writers = {}
    for writer, keys in document.items():
        try:
            writers[check_component(writer)] = parse_pinned_keys(writer, keys)
        except ValueError as exc:
            raise config.wrap(f"writers.{writer}", exc) from None
    return writers


def _issuers(config: Section) -> Issuers:
    document = config.raw("issuers")
    if not isinstance(document, dict):
        raise ConfigError("issuers must be an object of issuer ids")
    keys = {}
    allowances = {}
    for issuer, item in document.items():
        entry = Section(item, f"issuers.{issuer}", ISSUER_KEYS)
        try:
            keys[issuer] = _issuer_key(entry.raw("public_key"))
            allowances[issuer] = IssuerAllowance(
                tenants=_tenants(entry),
                max_budget=entry.integer("max_budget"),
                max_depth=entry.integer("max_depth"),
            )
        except (TypeError, ValueError) as exc:
            raise config.wrap(f"issuers.{issuer}", exc) from None
    try:
        return Issuers(PinnedResolver(keys), IssuerTrustPolicy(allowances))
    except (TypeError, ValueError) as exc:
        raise config.wrap("issuers", exc) from None


def _issuer_key(encoded: object) -> Ed25519PublicKey:
    if not isinstance(encoded, str) or not is_valid_public_key(encoded):
        raise ValueError("public_key must be an unpadded base64url Ed25519 key")
    key: Ed25519PublicKey = decode_public_key(encoded)
    return key


def _non_empty_list[T](config: Section, name: str, check: Callable[[object], T]) -> list[T]:
    items = config.raw(name)
    if not isinstance(items, list) or not items:
        raise ConfigError(f"{name} must be a non-empty list")
    try:
        return [check(item) for item in items]
    except ValueError as exc:
        raise config.wrap(name, exc) from None


def _os_id(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_OS_ID:
        raise ValueError(f"ids must be integers between 0 and {MAX_OS_ID}")
    return value


def _tenants(entry: Section) -> dict[str, TenantAllowance]:
    document = entry.raw("tenants")
    if not isinstance(document, dict):
        raise ValueError("tenants must be an object of tenant ids")
    tenants = {}
    for tenant, item in document.items():
        allowance = Section(item, f"tenants.{tenant}", TENANT_KEYS)
        principals = allowance.raw("principals")
        prefixes = allowance.raw("principal_prefixes")
        if not isinstance(principals, list) or not isinstance(prefixes, list):
            raise ValueError("principals and principal_prefixes must be lists")
        tenants[tenant] = TenantAllowance(principals=principals, principal_prefixes=prefixes)
    return tenants


def _target_bindings(config: Section, custodians: frozenset[str]) -> tuple[TargetBinding, ...]:
    document = config.raw("bindings")
    if not isinstance(document, list):
        raise ConfigError("decide.bindings must be a list")
    bindings = []
    for index, item in enumerate(document):
        entry = Section(item, f"decide.bindings[{index}]", BINDING_KEYS)
        try:
            binding = TargetBinding(**{name: entry.raw(name) for name in sorted(BINDING_KEYS)})
        except (TypeError, ValueError) as exc:
            raise config.wrap(f"bindings[{index}]", exc) from None
        if binding.custodian not in custodians:
            raise ConfigError(f"decide.bindings[{index}] names a custodian outside decide.custodians")
        bindings.append(binding)
    return tuple(bindings)


def _policy(section: Section) -> PolicyRef:
    try:
        return PolicyRef.from_dict(section.text("id"), section.text("version"), section.raw("document"))
    except (TypeError, ValueError, KeyError) as exc:
        raise section.wrap("document", exc) from None


def _costs(config: Section) -> CostTable:
    costs = config.section("costs", frozenset({"version", "tools"}))
    tools = costs.raw("tools")
    if not isinstance(tools, dict):
        raise ConfigError("decide.costs.tools must be an object")
    try:
        return CostTable(costs.integer("version"), tools)
    except ValueError as exc:
        raise costs.wrap("tools", exc) from None
