from __future__ import annotations

import json
import os
import stat
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from agent_warrant.identity import encode_public_key

from agent_bailiff.control.suspension import create_suspension_directory, suspension_directory
from agent_bailiff.custodian.backend import LocalBackend
from agent_bailiff.custodian.claims import ClaimsStore
from agent_bailiff.custodian.files import create_owned
from agent_bailiff.custodian.store import CredentialStore
from agent_bailiff.effector.catalog import shipped_catalog
from agent_bailiff.keys import PublicKeyRecord, check_component, generate_signing_key
from agent_bailiff.service.ledger import create_writer
from agent_bailiff.service.settings import (
    parse_control,
    parse_custodian,
    parse_decide,
    parse_docket,
    parse_effector,
)
from agent_bailiff.strict_json import parse_strict_json

PRIVATE_MODE = 0o700
FORBIDDEN_DIRECTORY_BITS = 0o077
MAX_PIN_BYTES = 4096
CONFIG = "config.json"
KEY = "signing.key"
ROUTES = "routes.json"
BINDINGS = "bindings.json"
DOCKET_STATE = "docket-state"
GRPC = "grpc"
DENY_ALL_POLICY = {"default": "deny", "rules": []}
DEFAULT_MAX_PROOF_AGE = 60
DEFAULT_RECONCILE_SECONDS = 10
DEFAULT_SKEW_SECONDS = 5
DEFAULT_RATE_LIMIT = 60
DEFAULT_RATE_WINDOW = 60
DEFAULT_CATALOG = shipped_catalog("kubernetes")


class InitError(Exception):
    pass


def read_pin(path: Path) -> PublicKeyRecord:
    with open(path, "rb") as source:
        raw = source.read(MAX_PIN_BYTES + 1)
    if len(raw) > MAX_PIN_BYTES:
        raise InitError(f"{path} is larger than {MAX_PIN_BYTES} bytes")
    try:
        return PublicKeyRecord.from_document(parse_strict_json(raw))
    except (ValueError, UnicodeDecodeError) as exc:
        raise InitError(f"{path} is not a public key record: {exc}") from None


def init_decide(
    directory: Path,
    *,
    name: str,
    custodians: Iterable[str],
    ledger: Path,
    ledger_group: int,
    docket: Mapping[str, Any],
    gateway: Mapping[str, Any],
) -> PublicKeyRecord:
    check_component(name)
    _check_new(directory, (CONFIG, KEY, ROUTES, DOCKET_STATE, GRPC))
    suspension = suspension_directory(ledger)
    for path in (ledger, suspension):
        if os.path.lexists(path):
            raise InitError(f"{path} already exists")
    document = {
        "name": name,
        "key": str(directory / KEY),
        "max_proof_age": DEFAULT_MAX_PROOF_AGE,
        "reconcile_seconds": DEFAULT_RECONCILE_SECONDS,
        "custodians": sorted(custodians),
        "bindings": [],
        "policy": {"id": "default", "version": "1", "document": DENY_ALL_POLICY},
        "costs": {"version": 1, "tools": {}},
        "issuers": {},
        "ledger": {"path": str(ledger), "group": ledger_group},
        "routes": str(directory / ROUTES),
        "docket": _docket_client(directory, docket),
        "gateway": _gateway(directory, gateway),
    }
    parse_decide(document)
    create_writer(ledger, ledger_group).close()
    create_suspension_directory(suspension, ledger_group)
    _make_private_dirs(directory, (DOCKET_STATE, GRPC))
    _write(directory / ROUTES, {"routes": []})
    record = generate_signing_key(directory / KEY, name)
    _write(directory / CONFIG, document)
    return record


def init_custodian(
    directory: Path,
    *,
    name: str,
    decide: PublicKeyRecord,
    ledger: Path,
    ledger_uid: int,
    ledger_group: int,
    docket: Mapping[str, Any],
    gateway: Mapping[str, Any],
) -> PublicKeyRecord:
    check_component(name)
    files = (CONFIG, KEY, ROUTES, BINDINGS, "kek", "credentials.db", "claims.db", DOCKET_STATE, GRPC)
    _check_new(directory, files)
    document = {
        "name": name,
        "key": str(directory / KEY),
        "decider": decide.component,
        "decide_keys": {decide.kid: encode_public_key(decide.public_key)},
        "max_proof_age": DEFAULT_MAX_PROOF_AGE,
        "max_clearance_lifetime": DEFAULT_MAX_PROOF_AGE,
        "skew_seconds": DEFAULT_SKEW_SECONDS,
        "rate_limit": DEFAULT_RATE_LIMIT,
        "rate_window": DEFAULT_RATE_WINDOW,
        "issuers": {},
        "bindings": str(directory / BINDINGS),
        "kek": str(directory / "kek"),
        "credentials": str(directory / "credentials.db"),
        "claims": str(directory / "claims.db"),
        "ledger": {"path": str(ledger), "writer_uid": ledger_uid, "group": ledger_group},
        "routes": str(directory / ROUTES),
        "docket": _docket_client(directory, docket),
        "gateway": _gateway(directory, gateway),
    }
    parse_custodian(document)
    _make_private_dirs(directory, (DOCKET_STATE, GRPC))
    _write(directory / ROUTES, {"routes": []})
    _write(directory / BINDINGS, {"bindings": []})
    record = generate_signing_key(directory / KEY, name)
    CredentialStore.create(directory / "credentials.db", LocalBackend.generate(directory / "kek")).close()
    ClaimsStore.create(directory / "claims.db").close()
    _write(directory / CONFIG, document)
    return record


def init_control(
    directory: Path,
    *,
    name: str,
    decide_config: Path,
    pins: Iterable[PublicKeyRecord],
    docket: Mapping[str, Any],
) -> PublicKeyRecord:
    check_component(name)
    _check_new(directory, (CONFIG, KEY, DOCKET_STATE))
    document = {
        "name": name,
        "key": str(directory / KEY),
        "decide_config": str(decide_config),
        "docket": _docket_client(directory, docket),
        "writers": _writers(pins),
    }
    parse_control(document)
    _make_private_dirs(directory, (DOCKET_STATE,))
    record = generate_signing_key(directory / KEY, name)
    _write(directory / CONFIG, document)
    return record


def init_effector(
    directory: Path,
    *,
    name: str,
    custodian: PublicKeyRecord,
    decide: PublicKeyRecord,
    ledger: Path,
    ledger_uid: int,
    ledger_group: int,
    port: int,
    kubernetes: Mapping[str, Any],
    rbac: Mapping[str, Any],
    docket: Mapping[str, Any],
) -> PublicKeyRecord:
    check_component(name)
    _check_new(directory, (CONFIG, KEY, DOCKET_STATE))
    document = {
        "name": name,
        "key": str(directory / KEY),
        "catalog": str(DEFAULT_CATALOG),
        "custodian": custodian.component,
        "custodian_keys": {custodian.kid: encode_public_key(custodian.public_key)},
        "decider": decide.component,
        "decide_keys": {decide.kid: encode_public_key(decide.public_key)},
        "skew_seconds": DEFAULT_SKEW_SECONDS,
        "max_clearance_lifetime": DEFAULT_MAX_PROOF_AGE,
        "port": port,
        "kubernetes": {
            "host": kubernetes["host"],
            "port": kubernetes["port"],
            "ca": str(kubernetes["ca"]),
            "token_file": str(kubernetes["token_file"]),
            "audit_token_file": str(kubernetes["audit_token_file"]),
        },
        "rbac": {
            "namespace": rbac["namespace"],
            "service_account": rbac["service_account"],
            "applier": rbac["applier"],
            "tenants": {tenant: list(namespaces) for tenant, namespaces in rbac["tenants"].items()},
        },
        "ledger": {"path": str(ledger), "writer_uid": ledger_uid, "group": ledger_group},
        "docket": _docket_client(directory, docket),
    }
    parse_effector(document)
    _make_private_dirs(directory, (DOCKET_STATE,))
    record = generate_signing_key(directory / KEY, name)
    _write(directory / CONFIG, document)
    return record


def init_docket(
    directory: Path,
    *,
    socket: Path,
    socket_group: int,
    allowed_uids: Iterable[int],
    pins: Iterable[PublicKeyRecord],
) -> Path:
    _check_new(directory, (CONFIG, "docket.log"))
    document = {
        "docket": str(directory / "docket.log"),
        "socket": str(socket),
        "socket_group": socket_group,
        "allowed_uids": sorted(set(allowed_uids)),
        "writers": _writers(pins),
    }
    parse_docket(document)
    _write(directory / CONFIG, document)
    return directory / CONFIG


def _writers(pins: Iterable[PublicKeyRecord]) -> dict[str, dict[str, str]]:
    writers: dict[str, dict[str, str]] = {}
    for pin in pins:
        writers.setdefault(pin.component, {})[pin.kid] = encode_public_key(pin.public_key)
    return writers


def _docket_client(directory: Path, docket: Mapping[str, Any]) -> dict[str, Any]:
    return {"socket": docket["socket"], "sink_uid": docket["sink_uid"], "state_dir": str(directory / DOCKET_STATE)}


def _gateway(directory: Path, gateway: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "uid": gateway["uid"],
        "socket": gateway["socket"],
        "socket_group": gateway["socket_group"],
        "private_dir": str(directory / GRPC),
    }


def _check_new(directory: Path, names: Iterable[str]) -> None:
    if not directory.is_absolute():
        raise InitError(f"{directory} must be an absolute path")
    try:
        info = os.lstat(directory)
    except OSError as exc:
        raise InitError(f"cannot inspect {directory}: {exc.strerror}") from None
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & FORBIDDEN_DIRECTORY_BITS
    ):
        raise InitError(f"{directory} must be a directory owned by uid {os.geteuid()} with mode 0700")
    existing = sorted(name for name in names if os.path.lexists(directory / name))
    if existing:
        raise InitError(f"{directory} already holds {', '.join(existing)}; init never overwrites")


def _make_private_dirs(directory: Path, names: Iterable[str]) -> None:
    for name in names:
        path = directory / name
        os.mkdir(path, PRIVATE_MODE)
        os.chmod(path, PRIVATE_MODE)


def _write(path: Path, document: Mapping[str, Any]) -> None:
    create_owned(path, path.name, json.dumps(document, indent=2, sort_keys=True).encode() + b"\n")
