from __future__ import annotations

import asyncio
import logging
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_bailiff.adapters.agentgateway.calls import ToolRoutes
from agent_bailiff.adapters.agentgateway.processors import CustodianProcessor, DecideProcessor
from agent_bailiff.adapters.agentgateway.server import ExtMcpProcessor, ProcessorServer
from agent_bailiff.control.control import Control
from agent_bailiff.control.suspension import Suspension, SuspensionView
from agent_bailiff.custodian.backend import LocalBackend
from agent_bailiff.custodian.bindings import BindingTable
from agent_bailiff.custodian.claims import ClaimsStore
from agent_bailiff.custodian.config import CustodianConfig
from agent_bailiff.custodian.custodian import Custodian
from agent_bailiff.custodian.release import ReleaseSigner
from agent_bailiff.custodian.store import CredentialStore
from agent_bailiff.decide.config import DeciderConfig
from agent_bailiff.decide.decider import Decider
from agent_bailiff.docket.client import DocketClient
from agent_bailiff.docket.sink import DocketSink
from agent_bailiff.effector.catalog import OperationCatalog
from agent_bailiff.effector.drift import RbacAudit, RbacGate
from agent_bailiff.effector.kubernetes import HttpsTransport, KubernetesClient
from agent_bailiff.effector.rbac import generate_manifests
from agent_bailiff.effector.release import ReleaseCheck, ReleaseCheckConfig
from agent_bailiff.effector.server import Effector, EffectorConfig, EffectorServer
from agent_bailiff.keys import key_id, load_signing_key
from agent_bailiff.service.ledger import open_reader, open_writer
from agent_bailiff.service.settings import (
    ControlSettings,
    CustodianSettings,
    DecideSettings,
    DocketClientSettings,
    DocketSettings,
    EffectorSettings,
    GatewaySettings,
    read_config,
)

logger = logging.getLogger(__name__)


class Closeable(Protocol):
    def close(self) -> None: ...


@dataclass
class RunningDecide:
    decider: Decider
    server: ProcessorServer
    reconcile_seconds: int
    _close: tuple[Closeable, ...]

    def serve(self, stop: threading.Event) -> None:
        while not stop.wait(self.reconcile_seconds):
            reconcile(self.decider, int(time.time()))

    def close(self) -> None:
        self.server.close()
        _close_all(self._close)


@dataclass
class RunningCustodian:
    custodian: Custodian
    server: ProcessorServer
    _close: tuple[Closeable, ...]

    def close(self) -> None:
        self.server.close()
        _close_all(self._close)


def load_routes(path: Path) -> ToolRoutes:
    try:
        return ToolRoutes.from_document(read_config(path, "route table"))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"the route table is invalid: {exc}") from None


def docket_client(settings: DocketClientSettings, writer: str, key: Ed25519PrivateKey) -> DocketClient:
    return DocketClient(
        settings.socket,
        writer,
        key_id(writer, key.public_key()),
        key,
        sink_uid=settings.sink_uid,
        state_dir=settings.state_dir,
    )


def processor_server(processor: ExtMcpProcessor, settings: GatewaySettings) -> ProcessorServer:
    return ProcessorServer(
        processor,
        settings.socket,
        settings.private_dir,
        gateway_uid=settings.uid,
        socket_gid=settings.socket_group,
    )


def start_decide(settings: DecideSettings) -> RunningDecide:
    key = load_signing_key(settings.key)
    routes = load_routes(settings.routes)
    ledger = open_writer(settings.ledger.path, settings.ledger.group)
    try:
        decider = Decider(
            config=DeciderConfig(
                settings.name,
                key_id(settings.name, key.public_key()),
                settings.custodians,
                settings.max_proof_age,
                settings.bindings,
                settings.name,
            ),
            ledger=ledger,
            resolver=settings.issuers.resolver,
            trust_policy=settings.issuers.trust_policy,
            policy=settings.policy,
            suspension=Suspension(settings.suspension_dir, settings.ledger.group),
            docket=docket_client(settings.docket, settings.name, key),
            signing_key=key,
            costs=settings.costs,
        )
        server = processor_server(DecideProcessor(decider, routes), settings.gateway)
        server.start()
    except BaseException:
        ledger.close()
        raise
    return RunningDecide(decider, server, settings.reconcile_seconds, (ledger,))


def start_custodian(settings: CustodianSettings) -> RunningCustodian:
    key = load_signing_key(settings.key)
    routes = load_routes(settings.routes)
    bindings = BindingTable.load(settings.bindings)
    opened: list[Closeable] = []
    try:
        store = CredentialStore.open(settings.credentials, LocalBackend.load(settings.kek))
        opened.append(store)
        claims = ClaimsStore.open(settings.claims)
        opened.append(claims)
        ledger = open_reader(settings.ledger.path, settings.ledger.writer_uid, settings.ledger.group)
        opened.append(ledger)
        custodian = Custodian(
            config=CustodianConfig(
                custodian_id=settings.name,
                decider_id=settings.decider,
                decide_keys=settings.decide_keys,
                docket_writer=settings.name,
                max_proof_age=settings.max_proof_age,
                max_clearance_lifetime=settings.max_clearance_lifetime,
                skew_seconds=settings.skew_seconds,
                rate_limit=settings.rate_limit,
                rate_window=settings.rate_window,
            ),
            bindings=bindings,
            store=store,
            claims=claims,
            ledger=ledger,
            resolver=settings.issuers.resolver,
            trust_policy=settings.issuers.trust_policy,
            docket=docket_client(settings.docket, settings.name, key),
            suspension=SuspensionView(settings.suspension_dir, settings.ledger.writer_uid, settings.ledger.group),
            release_signer=ReleaseSigner(settings.name, key, key_id(settings.name, key.public_key())),
        )
        headers = frozenset(binding.header_name for binding in bindings.credential_bindings)
        server = processor_server(CustodianProcessor(custodian, routes, headers), settings.gateway)
        server.start()
    except BaseException:
        _close_all(tuple(opened))
        raise
    return RunningCustodian(custodian, server, tuple(opened))


def put_credential(settings: CustodianSettings, tenant: str, credential_id: str, target: str, secret: bytes) -> None:
    store = CredentialStore.open(settings.credentials, LocalBackend.load(settings.kek))
    try:
        store.put(tenant, credential_id, target, secret)
    finally:
        store.close()


async def serve_docket(settings: DocketSettings, stop: asyncio.Event) -> None:
    sink = DocketSink(
        settings.docket,
        settings.socket,
        settings.writers,
        settings.allowed_uids,
        socket_gid=settings.socket_group,
    )
    await sink.start()
    try:
        await stop.wait()
    finally:
        await sink.close()


@dataclass
class ControlSession:
    control: Control
    _ledger: Closeable

    def close(self) -> None:
        _close_all((self._ledger,))


def open_control(settings: ControlSettings, decide: DecideSettings) -> ControlSession:
    key = load_signing_key(settings.key)
    ledger = open_writer(decide.ledger.path, decide.ledger.group)
    try:
        control = Control(
            component=settings.name,
            writers=settings.writers,
            ledger=ledger,
            suspension=Suspension(decide.suspension_dir, decide.ledger.group),
            docket=docket_client(settings.docket, settings.name, key),
            docket_writer=settings.name,
        )
    except BaseException:
        ledger.close()
        raise
    return ControlSession(control, ledger)


def reconcile(decider: Decider, now: int) -> None:
    try:
        reconciled = decider.reconcile(now)
    except Exception:
        logger.exception("reconcile failed; it runs again at the next interval")
        return
    if reconciled:
        logger.info("reconciled %d expired clearances to outcome_unknown", len(reconciled))


def _close_all(resources: tuple[Closeable, ...]) -> None:
    for resource in reversed(resources):
        resource.close()


@dataclass
class RunningEffector:
    server: EffectorServer
    rbac: RbacGate

    def close(self) -> None:
        self.server.close()
        self.rbac.close()


def start_effector(settings: EffectorSettings) -> RunningEffector:
    key = load_signing_key(settings.key)
    catalog = OperationCatalog.load(settings.catalog)
    check = ReleaseCheck(
        ReleaseCheckConfig(
            effector_id=settings.name,
            custodian_id=settings.custodian,
            decider_id=settings.decider,
            custodian_keys=settings.custodian_keys,
            decide_keys=settings.decide_keys,
            skew_seconds=settings.skew_seconds,
            max_clearance_lifetime=settings.max_clearance_lifetime,
        ),
        catalog,
    )
    kubernetes = settings.kubernetes
    transport = HttpsTransport(kubernetes.host, kubernetes.port, kubernetes.ca)
    client = KubernetesClient(transport, kubernetes.token_file)
    manifests = generate_manifests(catalog, settings.rbac, settings.tenants)
    audit = RbacAudit(
        transport,
        kubernetes.token_file,
        kubernetes.audit_token_file,
        settings.rbac,
        manifests,
        settings.tenants,
        catalog.operations,
    )
    rbac = RbacGate(audit, lambda: int(time.time()))
    rbac.verify()
    suspension = SuspensionView(settings.suspension_dir, settings.ledger.writer_uid, settings.ledger.group)
    effector = Effector(
        EffectorConfig(settings.name, settings.name),
        catalog,
        check,
        client,
        suspension,
        docket_client(settings.docket, settings.name, key),
        rbac,
    )
    server = EffectorServer(effector, settings.port)
    server.start()
    rbac.start()
    return RunningEffector(server, rbac)
