from __future__ import annotations

import threading
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agent_bailiff.custodian.release import Release, verify_release
from agent_bailiff.decide.clearance import Clearance, verify_clearance
from agent_bailiff.decide.identity import ArgsError, snapshot_args
from agent_bailiff.effector.catalog import CatalogOperation, OperationCatalog
from agent_bailiff.signing import Refused

MAX_TRACKED_RELEASES = 65536


@dataclass(frozen=True)
class ReleaseCheckConfig:
    effector_id: str
    custodian_id: str
    decider_id: str
    custodian_keys: Mapping[str, Ed25519PublicKey]
    decide_keys: Mapping[str, Ed25519PublicKey]
    skew_seconds: int
    max_clearance_lifetime: int


@dataclass(frozen=True)
class CheckedCall:
    operation: CatalogOperation
    arguments: Mapping[str, Any]
    release: Release
    clearance: Clearance


class ReleaseRefused(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class ReleaseCheck:
    def __init__(self, config: ReleaseCheckConfig, catalog: OperationCatalog, started_at: int) -> None:
        self._config = config
        self._catalog = catalog
        self._started_at = started_at
        self._seen: dict[str, int] = {}
        self._lock = threading.Lock()

    def verify(self, name: object, arguments: object, token: object, now: int) -> CheckedCall:
        return verify_operation(self._config, self._catalog, name, arguments, token, now)

    def claim(self, checked: CheckedCall, now: int) -> None:
        if checked.release.iat <= self._started_at:
            raise ReleaseRefused("release_predates_start")
        self._claim(checked.release, now)

    def _claim(self, release: Release, now: int) -> None:
        with self._lock:
            for op_id in [key for key, expiry in self._seen.items() if expiry <= now]:
                del self._seen[op_id]
            if release.op_id in self._seen:
                raise ReleaseRefused("release_replayed")
            if len(self._seen) >= MAX_TRACKED_RELEASES:
                raise ReleaseRefused("effector_busy")
            self._seen[release.op_id] = release.exp


def verify_operation(
    config: ReleaseCheckConfig,
    catalog: OperationCatalog,
    name: object,
    arguments: object,
    token: object,
    now: int,
) -> CheckedCall:
    """Verify a released catalog operation without claiming it or reading mutable state."""
    release = verify_release(
        token,
        config.custodian_keys,
        now=now,
        expected_aud=config.effector_id,
        expected_iss=config.custodian_id,
        skew_seconds=config.skew_seconds,
    )
    if isinstance(release, Refused):
        raise ReleaseRefused(f"release_{release.reason}")
    if release.catalog != catalog.digest:
        raise ReleaseRefused("catalog_mismatch")
    clearance = verify_clearance(
        release.clearance,
        config.decide_keys,
        now=now,
        expected_aud=config.custodian_id,
        expected_iss=config.decider_id,
        skew_seconds=config.skew_seconds,
        max_lifetime=config.max_clearance_lifetime,
    )
    if isinstance(clearance, Refused):
        raise ReleaseRefused(f"clearance_{clearance.reason}")
    bound = ("op_id", "tenant", "task", "tool", "resource", "args_digest")
    if any(getattr(clearance, field) != getattr(release, field) for field in bound):
        raise ReleaseRefused("clearance_mismatch")
    operation = catalog.operation(name) if isinstance(name, str) else None
    if operation is None or operation.tool != release.tool:
        raise ReleaseRefused("unknown_operation")
    if not isinstance(arguments, dict) or not operation.accepts(arguments):
        raise ReleaseRefused("malformed_arguments")
    resource = operation.resource.format(**{key: arguments[key] for key in ("namespace", "name") if key in arguments})
    if resource != release.resource:
        raise ReleaseRefused("resource_mismatch")
    try:
        digest = snapshot_args(arguments).digest
    except ArgsError:
        raise ReleaseRefused("malformed_arguments") from None
    if digest != release.args_digest:
        raise ReleaseRefused("arguments_mismatch")
    return CheckedCall(operation, dict(arguments), release, clearance)
