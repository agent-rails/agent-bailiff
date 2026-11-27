import asyncio
import copy
import io
import json
import logging
import os
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import grpc
import pytest
from agent_warrant.identity import encode_public_key
from agent_warrant.task_root import issue_task_root
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from google.protobuf import struct_pb2
from test_agentgateway_calls import message
from test_decide import AGENT_KEY, ISSUER_ID, ISSUER_KEY, NOW, POLICY, PRINCIPAL, SCOPE, TENANT, make_request

from agent_bailiff import cli
from agent_bailiff.adapters.agentgateway._proto import ext_mcp_pb2
from agent_bailiff.control.suspension import create_suspension_directory, suspension_directory
from agent_bailiff.custodian import ClaimsStore, CredentialStore, CredentialUnavailable, LocalBackend
from agent_bailiff.custodian.echo import MARKER
from agent_bailiff.custodian.files import OwnedFileError
from agent_bailiff.custodian.store import StoredCredential
from agent_bailiff.docket import DocketClient, Grant, decode_record, encode_record
from agent_bailiff.docket.entry import Entry
from agent_bailiff.docket.manifest import MAX_MANIFEST_BYTES, entry_bytes_bound
from agent_bailiff.docket.protocol import MAX_FRAME_BYTES
from agent_bailiff.docket.retention import Retention
from agent_bailiff.docket.sink import build_kid_index
from agent_bailiff.keys import generate_signing_key, key_id
from agent_bailiff.service import run
from agent_bailiff.service.ledger import create_writer
from agent_bailiff.service.settings import (
    ConfigError,
    load_control,
    load_custodian,
    load_decide,
    load_docket,
    parse_control,
    parse_custodian,
    parse_decide,
    parse_docket,
)

UID = os.geteuid()
GID = os.getegid()
ROOT = Path(__file__).resolve().parent.parent
SECRET = b"Bearer deploy-secret"
CHECK_REQUEST = "/agentgateway.dev.ext_mcp.ExtMcp/CheckRequest"
CHECK_RESPONSE = "/agentgateway.dev.ext_mcp.ExtMcp/CheckResponse"
ROUTES = {
    "routes": [{"service": "deploy", "name": "deploy_service", "tool": "deploy.service", "resource": "env/staging/api"}]
}
ISSUERS = {
    ISSUER_ID: {
        "public_key": encode_public_key(ISSUER_KEY.public_key()),
        "max_budget": 100,
        "max_depth": 4,
        "tenants": {TENANT: {"principals": [PRINCIPAL], "principal_prefixes": []}},
    }
}


def private(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def write_owned(path, document):
    path.write_text(json.dumps(document))
    os.chmod(path, 0o600)
    return path


class Deployment:
    def __init__(self, root):
        self.root = root
        self.decide = private(root / "decide")
        self.custodian = private(root / "custodian")
        self.control = private(root / "control")
        self.docket = private(root / "docket")
        self.receipts = root / "receipts"
        self.receipts.mkdir(mode=0o750)
        os.chown(self.receipts, -1, GID)
        os.chmod(self.receipts, 0o750)
        self.ledger_dir = root / "ledger"
        self.ledger_dir.mkdir(mode=0o750)
        os.chown(self.ledger_dir, -1, GID)
        os.chmod(self.ledger_dir, 0o750)
        self.ledger = self.ledger_dir / "ledger.db"
        self.sockets = {"docket": root / "s" / "docket.sock", "decide": root / "d" / "decide.sock"}
        self.sockets["custodian"] = root / "c" / "custodian.sock"
        self.sockets["redactor"] = root / "c" / "redactor.sock"
        self.keys = {
            "decide.example": generate_signing_key(self.decide / "signing.key", "decide.example"),
            "custodian.example": generate_signing_key(self.custodian / "signing.key", "custodian.example"),
            "control": generate_signing_key(self.control / "signing.key", "control"),
        }
        for directory in (self.decide, self.custodian, self.control):
            private(directory / "docket-state")
            private(directory / "grpc")
        self.suspension = suspension_directory(self.ledger)
        create_suspension_directory(self.suspension, GID)
        write_owned(self.decide / "routes.json", ROUTES)
        write_owned(self.custodian / "routes.json", ROUTES)
        write_owned(
            self.custodian / "bindings.json",
            {
                "bindings": [
                    {
                        "tenant": TENANT,
                        "tool": "deploy.service",
                        "resource": "env/staging/*",
                        "credential_id": "deploy-api",
                        "target": "deploy.example",
                        "header_name": "Authorization",
                        "canary": False,
                    }
                ]
            },
        )
        self.documents = {
            "decide": self.decide_document(),
            "custodian": self.custodian_document(),
            "docket": self.docket_document(),
            "control": self.control_document(),
        }
        self.paths = {
            "decide": self.decide / "config.json",
            "custodian": self.custodian / "config.json",
            "docket": self.docket / "config.json",
            "control": self.control / "config.json",
        }
        for name, document in self.documents.items():
            write_owned(self.paths[name], document)

    def pins(self, name):
        record = self.keys[name]
        return {record.kid: encode_public_key(record.public_key)}

    def docket_client(self, directory):
        return {"socket": str(self.sockets["docket"]), "sink_uid": UID, "state_dir": str(directory / "docket-state")}

    def gateway(self, name, directory):
        return {
            "uid": UID,
            "socket": str(self.sockets[name]),
            "socket_group": GID,
            "private_dir": str(directory / "grpc"),
        }

    def decide_document(self):
        return {
            "name": "decide.example",
            "key": str(self.decide / "signing.key"),
            "max_proof_age": 60,
            "scope_v1_cutoff": 1_700_000_000,
            "reconcile_seconds": 1,
            "custodians": ["custodian.example"],
            "bindings": [
                {
                    "tenant": TENANT,
                    "tool": "deploy.service",
                    "resource": "env/staging/*",
                    "credential_id": "deploy-api",
                    "target": "deploy.example",
                    "custodian": "custodian.example",
                }
            ],
            "policy": {"id": "default", "version": "1", "document": POLICY},
            "costs": {"version": 1, "tools": {"deploy.service": 1}},
            "issuers": ISSUERS,
            "ledger": {"path": str(self.ledger), "group": GID},
            "routes": str(self.decide / "routes.json"),
            "docket": self.docket_client(self.decide),
            "gateway": self.gateway("decide", self.decide),
        }

    def custodian_document(self):
        return {
            "name": "custodian.example",
            "key": str(self.custodian / "signing.key"),
            "decider": "decide.example",
            "decide_keys": self.pins("decide.example"),
            "max_proof_age": 60,
            "scope_v1_cutoff": 1_700_000_000,
            "max_clearance_lifetime": 60,
            "skew_seconds": 5,
            "rate_limit": 10,
            "rate_window": 60,
            "inflight_ttl": 150,
            "inflight_max": 64,
            "inflight_max_bytes": 65536,
            "inflight_per_tenant": 16,
            "response_socket": str(self.sockets["redactor"]),
            "response_workers": 2,
            "issuers": ISSUERS,
            "bindings": str(self.custodian / "bindings.json"),
            "kek": str(self.custodian / "kek"),
            "credentials": str(self.custodian / "credentials.db"),
            "claims": str(self.custodian / "claims.db"),
            "ledger": {"path": str(self.ledger), "writer_uid": UID, "group": GID},
            "routes": str(self.custodian / "routes.json"),
            "docket": self.docket_client(self.custodian),
            "gateway": self.gateway("custodian", self.custodian),
        }

    def docket_document(self):
        return {
            "docket": str(self.docket / "docket.log"),
            "socket": str(self.sockets["docket"]),
            "socket_group": GID,
            "reader_group": GID,
            "allowed_uids": [UID],
            "writers": {name: self.pins(name) for name in self.keys},
            "grant_writers": [],
            "snapshot_every": 10_000,
            "free_space_floor": 256 << 20,
            "segment_bytes": 256 << 20,
            "retained_bytes": 1 << 30,
            "receipt_dir": str(self.receipts),
            "archiver_uid": UID,
            "max_receipt_age": 86400,
        }

    def control_document(self):
        return {
            "name": "control",
            "key": str(self.control / "signing.key"),
            "decide_config": str(self.decide / "config.json"),
            "docket": self.docket_client(self.control),
            "writers": {name: self.pins(name) for name in ("decide.example", "custodian.example")},
            "grant_writers": [],
            "issuers": ISSUERS,
        }

    def records(self):
        index = build_kid_index(load_docket(self.paths["docket"]).writers)
        lines = (self.docket / "docket.log").read_text().splitlines()
        return [(line, decode_record(line, index)) for line in lines]

    def record_line(self, hop, decision):
        for line, record in self.records():
            if (record.entry.hop, record.entry.decision) == (hop, decision):
                return line
        raise AssertionError(f"no {hop} {decision} record")


class DocketThread:
    def __init__(self, settings):
        self.loop = asyncio.new_event_loop()
        self.stop_event = None
        self.started = threading.Event()
        self.error = None
        self.thread = threading.Thread(target=self._run, args=(settings,), daemon=True)
        self.thread.start()
        deadline = time.monotonic() + 5
        while not settings.socket.exists() and self.thread.is_alive() and time.monotonic() < deadline:
            time.sleep(0.01)

    def _run(self, settings):
        asyncio.set_event_loop(self.loop)

        async def main():
            self.stop_event = asyncio.Event()
            await run.serve_docket(settings, self.stop_event)

        try:
            self.loop.run_until_complete(main())
        except BaseException as exc:
            self.error = exc

    def stop(self):
        if self.loop.is_closed():
            return
        if self.stop_event is not None:
            self.loop.call_soon_threadsafe(self.stop_event.set)
        self.thread.join(5)
        self.loop.close()


@pytest.fixture(autouse=True)
def separate_archiver(monkeypatch):
    monkeypatch.setattr(run, "sink_euid", lambda: -1)


@pytest.fixture
def deployment():
    root = Path(tempfile.mkdtemp(prefix="bv-", dir="/tmp"))
    os.chmod(root, 0o700)
    yield Deployment(root)
    shutil.rmtree(root)


@pytest.fixture
def docket(deployment):
    running = DocketThread(load_docket(deployment.paths["docket"]))
    yield running
    running.stop()


def test_the_example_documents_parse(deployment):
    decide = load_decide(deployment.paths["decide"])
    custodian = load_custodian(deployment.paths["custodian"])
    docket = load_docket(deployment.paths["docket"])
    control = load_control(deployment.paths["control"])
    assert decide.name == "decide.example" and decide.custodians == {"custodian.example"}
    assert list(custodian.decide_keys) == [deployment.keys["decide.example"].kid]
    assert (decide.scope_v1_cutoff, custodian.scope_v1_cutoff) == (1_700_000_000, 1_700_000_000)
    assert (custodian.inflight_ttl, custodian.inflight_max) == (150, 64)
    assert (custodian.inflight_max_bytes, custodian.inflight_per_tenant) == (65536, 16)
    assert (custodian.response_socket, custodian.response_workers) == (deployment.sockets["redactor"], 2)
    assert docket.allowed_uids == {UID} and set(docket.writers) == set(deployment.keys)
    assert docket.grant_writers == frozenset()
    assert control.name == "control" and set(control.writers) == {"decide.example", "custodian.example"}
    assert control.grant_writers == frozenset()
    assert control.issuers.trust_policy.check_issuer(ISSUER_ID) is None


def mutate(document, change):
    copied = copy.deepcopy(document)
    change(copied)
    return copied


def other_key():
    return Ed25519PrivateKey.generate().public_key()


BAD_DECIDE = {
    "unknown_key": lambda doc: doc.update(extra=1),
    "missing_key": lambda doc: doc.pop("routes"),
    "relative_path": lambda doc: doc.update(key="signing.key"),
    "bad_name": lambda doc: doc.update(name="decide example"),
    "zero_proof_age": lambda doc: doc.update(max_proof_age=0),
    "bool_proof_age": lambda doc: doc.update(max_proof_age=True),
    "negative_scope_v1_cutoff": lambda doc: doc.update(scope_v1_cutoff=-1),
    "bool_scope_v1_cutoff": lambda doc: doc.update(scope_v1_cutoff=True),
    "missing_scope_v1_cutoff": lambda doc: doc.pop("scope_v1_cutoff"),
    "negative_group": lambda doc: doc["ledger"].update(group=-1),
    "huge_uid": lambda doc: doc["gateway"].update(uid=2**32),
    "no_custodians": lambda doc: doc.update(custodians=[]),
    "binding_for_unknown_custodian": lambda doc: doc["bindings"][0].update(custodian="other"),
    "binding_with_extra_field": lambda doc: doc["bindings"][0].update(header_name="x"),
    "bad_policy": lambda doc: doc["policy"].update(document={"default": "maybe"}),
    "bad_cost": lambda doc: doc["costs"].update(tools={"deploy.service": 0}),
    "small_order_issuer_key": lambda doc: doc["issuers"][ISSUER_ID].update(public_key="A" * 43),
    "issuer_with_extra_field": lambda doc: doc["issuers"][ISSUER_ID].update(note="x"),
    "tenant_principals_not_a_list": lambda doc: doc["issuers"][ISSUER_ID]["tenants"][TENANT].update(principals="x"),
    "docket_section_with_extra_field": lambda doc: doc["docket"].update(writer="decide"),
    "reconcile_too_slow": lambda doc: doc.update(reconcile_seconds=3601),
}


@pytest.mark.parametrize("name", sorted(BAD_DECIDE))
def test_a_bad_decide_config_is_refused(deployment, name):
    with pytest.raises(ConfigError):
        parse_decide(mutate(deployment.documents["decide"], BAD_DECIDE[name]))


BAD_CUSTODIAN = {
    "float_scope_v1_cutoff": lambda doc: doc.update(scope_v1_cutoff=1.5),
    "missing_scope_v1_cutoff": lambda doc: doc.pop("scope_v1_cutoff"),
    "unpinned_kid_for_the_key": lambda doc: doc.update(
        decide_keys={"decide.example-1": doc["decide_keys"].popitem()[1]}
    ),
    "key_of_another_component": lambda doc: doc.update(decider="custodian.example"),
    "no_decide_keys": lambda doc: doc.update(decide_keys={}),
    "excess_skew": lambda doc: doc.update(skew_seconds=301),
    "zero_rate_limit": lambda doc: doc.update(rate_limit=0),
    "zero_inflight_max": lambda doc: doc.update(inflight_max=0),
    "bool_inflight_max_bytes": lambda doc: doc.update(inflight_max_bytes=True),
    "zero_inflight_per_tenant": lambda doc: doc.update(inflight_per_tenant=0),
    "inflight_ttl_over_an_hour": lambda doc: doc.update(inflight_ttl=3601),
    "inflight_ttl_inside_the_upstream_timeout_margin": lambda doc: doc.update(inflight_ttl=149),
    "missing_inflight_ttl": lambda doc: doc.pop("inflight_ttl"),
    "missing_response_socket": lambda doc: doc.pop("response_socket"),
    "relative_response_socket": lambda doc: doc.update(response_socket="c/redactor.sock"),
    "response_socket_is_the_custodian_socket": lambda doc: doc.update(response_socket=doc["gateway"]["socket"]),
    "zero_response_workers": lambda doc: doc.update(response_workers=0),
    "three_response_workers": lambda doc: doc.update(response_workers=3),
    "missing_response_workers": lambda doc: doc.pop("response_workers"),
    "ledger_without_writer": lambda doc: doc["ledger"].pop("writer_uid"),
    "decide_keys_not_an_object": lambda doc: doc.update(decide_keys=["x"]),
}


@pytest.mark.parametrize("name", sorted(BAD_CUSTODIAN))
def test_a_bad_custodian_config_is_refused(deployment, name):
    with pytest.raises(ConfigError):
        parse_custodian(mutate(deployment.documents["custodian"], BAD_CUSTODIAN[name]))


def test_a_writer_pinned_under_another_writers_key_id_is_refused(deployment):
    document = deployment.documents["docket"]
    decide_pins = document["writers"]["decide.example"]
    with pytest.raises(ConfigError):
        parse_docket(mutate(document, lambda doc: doc["writers"].update({"control": decide_pins})))
    with pytest.raises(ConfigError):
        parse_docket(mutate(document, lambda doc: doc["writers"].update({"control": {"control-1": "x"}})))
    key = other_key()
    unknown = {key_id("control", key): encode_public_key(key)}
    assert parse_docket(mutate(document, lambda doc: doc["writers"].update({"control": unknown})))


def test_a_docket_config_marks_a_pinned_writer_as_a_grant_writer(deployment):
    document = mutate(deployment.documents["docket"], lambda doc: doc.update(grant_writers=["custodian.example"]))
    assert parse_docket(document).grant_writers == frozenset({"custodian.example"})


@pytest.mark.parametrize(
    "change",
    [
        lambda doc: doc.update(allowed_uids=[]),
        lambda doc: doc.update(allowed_uids=["0"]),
        lambda doc: doc.update(allowed_uids=[True]),
        lambda doc: doc.update(writers={}),
        lambda doc: doc.update(socket_group=None),
        lambda doc: doc.update(reader_group="0"),
        lambda doc: doc.update(reader_group=True),
        lambda doc: doc.update(reader_group=-1),
        lambda doc: doc.update(reader_group=None),
        lambda doc: doc.update(snapshot_every=0),
        lambda doc: doc.update(snapshot_every=True),
        lambda doc: doc.update(snapshot_every="10"),
        lambda doc: doc.update(snapshot_every=1.5),
        lambda doc: doc.update(snapshot_every=None),
        lambda doc: doc.pop("snapshot_every"),
        lambda doc: doc.update(free_space_floor=2 * MAX_FRAME_BYTES - 1),
        lambda doc: doc.update(free_space_floor=True),
        lambda doc: doc.update(free_space_floor="268435456"),
        lambda doc: doc.update(free_space_floor=None),
        lambda doc: doc.update(segment_bytes=(64 << 20) - 1),
        lambda doc: doc.update(segment_bytes=True),
        lambda doc: doc.update(segment_bytes="268435456"),
        lambda doc: doc.update(segment_bytes=None),
        lambda doc: doc.update(retained_bytes=(512 << 20) - 1),
        lambda doc: doc.update(retained_bytes=True),
        lambda doc: doc.update(retained_bytes=None),
        lambda doc: doc.update(receipt_dir="receipts"),
        lambda doc: doc.update(receipt_dir=None),
        lambda doc: doc.update(archiver_uid=-1),
        lambda doc: doc.update(archiver_uid=None),
        lambda doc: doc.update(max_receipt_age=3599),
        lambda doc: doc.update(max_receipt_age=7 * 86400 + 1),
        lambda doc: doc.update(max_receipt_age=True),
        lambda doc: doc.pop("max_receipt_age"),
        lambda doc: doc.pop("grant_writers"),
        lambda doc: doc.update(grant_writers=None),
        lambda doc: doc.update(grant_writers="decide.example"),
        lambda doc: doc.update(grant_writers=["issuer"]),
        lambda doc: doc.update(grant_writers=["decide.example", "decide.example"]),
        lambda doc: doc.update(grant_writers=[""]),
        lambda doc: doc.update(grant_writers=[1]),
    ],
)
def test_a_bad_docket_config_is_refused(deployment, change):
    with pytest.raises(ConfigError):
        parse_docket(mutate(deployment.documents["docket"], change))


def test_a_docket_config_carries_its_retention(deployment):
    settings = parse_docket(deployment.documents["docket"])
    assert settings.retention == Retention(deployment.receipts, UID, 1 << 30, 86400)


def test_a_docket_config_whose_manifest_could_outgrow_its_limit_is_refused(deployment):
    segments = MAX_MANIFEST_BYTES // entry_bytes_bound(parse_docket(deployment.documents["docket"]).writers)
    retained = (segments - 1) * (64 << 20)
    fits = mutate(deployment.documents["docket"], lambda doc: doc.update(segment_bytes=64 << 20))
    assert parse_docket(mutate(fits, lambda doc: doc.update(retained_bytes=retained - (64 << 20))))
    with pytest.raises(ConfigError, match="raise segment_bytes or lower retained_bytes"):
        parse_docket(mutate(fits, lambda doc: doc.update(retained_bytes=retained)))


def test_control_must_not_pin_its_own_writer(deployment):
    document = mutate(
        deployment.documents["control"], lambda doc: doc["writers"].update(control=deployment.pins("control"))
    )
    with pytest.raises(ConfigError):
        parse_control(document)


def test_a_control_config_marks_a_pinned_writer_as_a_grant_writer(deployment):
    document = mutate(deployment.documents["control"], lambda doc: doc.update(grant_writers=["custodian.example"]))
    assert parse_control(document).grant_writers == frozenset({"custodian.example"})


@pytest.mark.parametrize(
    "change",
    [
        lambda doc: doc.pop("grant_writers"),
        lambda doc: doc.update(grant_writers=None),
        lambda doc: doc.update(grant_writers=["issuer"]),
        lambda doc: doc.update(grant_writers=["decide.example", "decide.example"]),
        lambda doc: doc.pop("issuers"),
        lambda doc: doc.update(issuers=[]),
        lambda doc: doc["issuers"][ISSUER_ID].update(public_key="not-a-key"),
        lambda doc: doc["issuers"][ISSUER_ID].pop("tenants"),
    ],
)
def test_a_bad_control_config_is_refused(deployment, change):
    with pytest.raises(ConfigError):
        parse_control(mutate(deployment.documents["control"], change))


@pytest.mark.parametrize("mode", [0o640, 0o644, 0o400])
def test_a_config_file_with_the_wrong_mode_is_refused(deployment, mode):
    os.chmod(deployment.paths["decide"], mode)
    with pytest.raises(OwnedFileError):
        load_decide(deployment.paths["decide"])


def test_a_config_file_of_another_uid_is_refused(deployment, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: UID + 1)
    with pytest.raises(OwnedFileError):
        load_docket(deployment.paths["docket"])


def test_a_config_with_duplicate_keys_is_refused(deployment):
    path = deployment.paths["docket"]
    text = path.read_text()
    path.write_text(text[:-1] + ', "socket_group": 0}')
    with pytest.raises(ConfigError):
        load_docket(path)


def test_the_docket_service_accepts_pinned_writers_and_removes_its_socket(deployment, docket):
    key = run.load_signing_key(deployment.decide / "signing.key")
    client = DocketClient(
        deployment.sockets["docket"],
        "decide.example",
        deployment.keys["decide.example"].kid,
        key,
        sink_uid=UID,
        state_dir=deployment.decide / "docket-state",
    )
    record = client.append(
        Entry(entry_id="e-1", trace_id="t-1", hop="decide", component="decide.example", decision="refuse", at=NOW)
    )
    assert record.seq == 1
    docket.stop()
    assert docket.error is None
    assert not deployment.sockets["docket"].exists()
    assert len(deployment.records()) == 1


def check(socket_path, request):
    with grpc.insecure_channel(f"unix:{socket_path}") as channel:
        stub = channel.unary_unary(
            CHECK_REQUEST,
            request_serializer=ext_mcp_pb2.McpRequest.SerializeToString,
            response_deserializer=ext_mcp_pb2.McpRequestResult.FromString,
        )
        return stub(request, timeout=10)


def call_message(request, metadata=None):
    headers = {
        "x-bailiff-task-root": request.task_root,
        "x-bailiff-leaf-proof": request.leaf_proof,
        "x-bailiff-nonce": request.nonce,
        "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
    }
    call = message(params={"name": "deploy_service", "arguments": request.args}, headers=headers)
    if metadata is not None:
        call.metadata_context.CopyFrom(metadata)
    return call


class Stack:
    def __init__(self, deployment):
        self.deployment = deployment
        create_writer(deployment.ledger, GID).close()
        self.decide = run.start_decide(load_decide(deployment.paths["decide"]))
        stdin = io.TextIOWrapper(io.BytesIO(SECRET + b"\n"))
        self.put(stdin)
        self.custodian = run.start_custodian(load_custodian(deployment.paths["custodian"]))

    def put(self, stdin):
        directory = self.deployment.custodian
        CredentialStore.create(directory / "credentials.db", LocalBackend.generate(directory / "kek")).close()
        ClaimsStore.create(directory / "claims.db").close()
        original = sys.stdin
        sys.stdin = stdin
        try:
            arguments = ["custodian", "put-credential", "--config", str(self.deployment.paths["custodian"])]
            arguments += ["--tenant", TENANT, "--credential-id", "deploy-api", "--target", "deploy.example"]
            assert cli.main(arguments) == 0
        finally:
            sys.stdin = original

    def call(self, request):
        decided = check(self.deployment.sockets["decide"], call_message(request))
        if decided.WhichOneof("result") != "pass":
            return decided, None
        metadata = struct_pb2.Struct()
        metadata.CopyFrom(decided.metadata)
        return decided, check(self.deployment.sockets["custodian"], call_message(request, metadata))

    def close(self):
        self.custodian.close()
        self.decide.close()


@pytest.fixture
def live():
    now = int(time.time())
    root = issue_task_root(
        ISSUER_KEY,
        issuer=ISSUER_ID,
        task_id="task-1",
        tenant_id=TENANT,
        principal=PRINCIPAL,
        purpose="release-bot",
        budget=100,
        max_depth=4,
        issued_at=now - 5,
        expires_at=now + 3600,
        scope=SCOPE,
        subject=encode_public_key(AGENT_KEY.public_key()),
    )

    def request(nonce="n-1"):
        return make_request(root, at=int(time.time()), nonce=nonce, trace_id="")

    return request


@pytest.fixture
def stack(deployment, docket):
    running = Stack(deployment)
    yield running
    running.close()


def control(deployment, *arguments, stdin=None):
    original = sys.stdin
    if stdin is not None:
        sys.stdin = io.TextIOWrapper(io.BytesIO(stdin.encode()))
    try:
        return cli.main(["control", *arguments, "--config", str(deployment.paths["control"]), "--actor", "ops"])
    finally:
        sys.stdin = original


def test_the_services_release_a_credential_once_through_both_sockets(stack, live):
    request = live()
    decided, released = stack.call(request)
    assert released.WhichOneof("result") == "pass", released
    [header] = released.header_mutation.set
    assert (header.key, header.value) == ("Authorization", SECRET)
    replay, _ = stack.call(request)
    assert replay.error.reason == "already_issued"


def check_response(socket_path, response):
    with grpc.insecure_channel(f"unix:{socket_path}") as channel:
        stub = channel.unary_unary(
            CHECK_RESPONSE,
            request_serializer=ext_mcp_pb2.McpResponse.SerializeToString,
            response_deserializer=ext_mcp_pb2.McpResponseResult.FromString,
        )
        return stub(response, timeout=10)


def test_the_custodian_redacts_an_echo_on_its_response_socket(stack, live, deployment):
    decided, released = stack.call(live())
    assert released.WhichOneof("result") == "pass", released
    echo = json.dumps({"content": [{"type": "text", "text": f"echo {SECRET.decode()}"}]}).encode()
    response = ext_mcp_pb2.McpResponse(method="tools/call", mcp_response=echo)
    response.metadata_context.CopyFrom(decided.metadata)
    result = check_response(deployment.sockets["redactor"], response)
    assert result.WhichOneof("result") == "mutated", result
    assert b"deploy-secret" not in result.mutated and MARKER in json.loads(result.mutated)["content"][0]["text"]
    again = check_response(deployment.sockets["redactor"], response)
    assert (again.WhichOneof("result"), again.error.reason) == ("error", "response_unmatched")
    with pytest.raises(grpc.RpcError) as caught:
        check_response(deployment.sockets["custodian"], response)
    assert caught.value.code() == grpc.StatusCode.UNIMPLEMENTED


def test_closing_the_custodian_removes_its_response_socket(stack, deployment):
    assert deployment.sockets["redactor"].exists()
    stack.custodian.close()
    assert not deployment.sockets["redactor"].exists()
    assert not deployment.sockets["custodian"].exists()
    stack.custodian = run.start_custodian(load_custodian(deployment.paths["custodian"]))
    assert deployment.sockets["redactor"].exists()


@pytest.mark.parametrize("level", ["task", "tenant", "root"])
def test_control_revoke_from_a_docket_line_stops_the_next_call(stack, live, deployment, level, capsys):
    stack.call(live())
    line = deployment.record_line("decide", "allow")
    record_path = deployment.control / "record.txt"
    record_path.write_text(line + "\n")
    assert control(deployment, "revoke", "--level", level, "--record", str(record_path)) == 0
    outcome = json.loads(capsys.readouterr().out)
    assert (outcome["action"], outcome["reason"]) == ("revoke", level)
    decided, released = stack.call(live("n-2"))
    assert (decided.error.reason, released) == ("chain_invalid", None)
    [entry] = [record.entry for _, record in deployment.records() if record.entry.hop == "control"]
    assert entry.trace_id == "4bf92f3577b34da6a3ce929d0e0e4736" and entry.entry_id == outcome["entry_id"]


def test_control_revoke_from_a_grant_stops_a_task_before_its_first_call(stack, live, deployment, capsys):
    granter = Ed25519PrivateKey.generate()
    kid = key_id("grants.example", granter.public_key())
    document = mutate(
        deployment.documents["control"],
        lambda doc: doc.update(
            writers={**doc["writers"], "grants.example": {kid: encode_public_key(granter.public_key())}},
            grant_writers=["grants.example"],
        ),
    )
    write_owned(deployment.paths["control"], document)
    now = int(time.time())
    root = issue_task_root(
        ISSUER_KEY,
        issuer=ISSUER_ID,
        task_id="task-1",
        tenant_id=TENANT,
        principal=PRINCIPAL,
        purpose="release-bot",
        budget=100,
        max_depth=4,
        issued_at=now - 5,
        expires_at=now + 3600,
        scope=SCOPE,
        subject=encode_public_key(AGENT_KEY.public_key()),
    )
    grant = Grant(grant_id="grant-1", at=now, root_token=root.encode())
    token = encode_record(granter, kid, "grants.example", 1, None, grant).token
    assert control(deployment, "revoke", "--level", "task", "--record", "-", stdin=token + "\n") == 0
    outcome = json.loads(capsys.readouterr().out)
    assert outcome["trace_id"] == "grant-1"
    decided, released = stack.call(live())
    assert (decided.error.reason, released) == ("chain_invalid", None)
    [entry] = [record.entry for _, record in deployment.records() if record.entry.hop == "control"]
    assert (entry.trace_id, entry.parent_entry, entry.op_id) == ("grant-1", "grant-1", None)


def test_control_suspend_and_resume_through_the_cli(stack, live, deployment, capsys):
    stack.call(live())
    line = deployment.record_line("decide", "allow")
    assert control(deployment, "suspend", "--record", "-", stdin=line + "\n") == 0
    decided, _ = stack.call(live("n-2"))
    assert decided.error.reason == "suspended"
    assert control(deployment, "resume") == 0
    decided, released = stack.call(live("n-3"))
    assert released.WhichOneof("result") == "pass", (decided, released)


def test_control_refuses_a_tampered_record(stack, live, deployment, capsys):
    stack.call(live())
    line = deployment.record_line("decide", "allow")
    payload, signature = line.split(".")
    tampered = f"{payload[:-2]}{'A' if payload[-2] != 'A' else 'B'}{payload[-1]}.{signature}"
    assert control(deployment, "revoke", "--level", "task", "--record", "-", stdin=tampered) == cli.EXIT_REFUSED
    assert "control refused: record_" in capsys.readouterr().err
    _, released = stack.call(live("n-2"))
    assert released.WhichOneof("result") == "pass"


def test_control_reports_an_applied_but_unrecorded_revoke(stack, live, deployment, docket, capsys):
    stack.call(live())
    line = deployment.record_line("decide", "allow")
    docket.stop()
    assert control(deployment, "revoke", "--level", "task", "--record", "-", stdin=line) == cli.EXIT_UNRECORDED
    captured = capsys.readouterr()
    assert json.loads(captured.out)["action"] == "revoke"
    assert "was applied but its docket entry was not acknowledged" in captured.err


def test_control_refuses_an_oversized_record(deployment, capsys):
    assert control(deployment, "suspend", "--record", "-", stdin="x" * (70000)) == cli.EXIT_REFUSED
    assert "larger than" in capsys.readouterr().err


@pytest.mark.parametrize("stdin", [b"", b"\n", b"x" * 65537])
def test_put_credential_refuses_an_empty_or_oversized_secret(deployment, stdin, capsys):
    original = sys.stdin
    sys.stdin = io.TextIOWrapper(io.BytesIO(stdin))
    try:
        arguments = ["custodian", "put-credential", "--config", str(deployment.paths["custodian"])]
        result = cli.main(arguments + ["--tenant", TENANT, "--credential-id", "c", "--target", "t"])
    finally:
        sys.stdin = original
    assert result == cli.EXIT_REFUSED


def put_credential(deployment, stdin, *extra):
    directory = deployment.custodian
    CredentialStore.create(directory / "credentials.db", LocalBackend.generate(directory / "kek")).close()
    original = sys.stdin
    sys.stdin = io.TextIOWrapper(io.BytesIO(stdin))
    try:
        arguments = ["custodian", "put-credential", "--config", str(deployment.paths["custodian"])]
        return cli.main(arguments + ["--tenant", TENANT, "--credential-id", "c", "--target", "t", *extra])
    finally:
        sys.stdin = original


def stored(deployment):
    directory = deployment.custodian
    store = CredentialStore.open(directory / "credentials.db", LocalBackend.load(directory / "kek"))
    try:
        return store.get(TENANT, "c", "t")
    finally:
        store.close()


def test_put_credential_refuses_a_short_credential_and_names_the_exception_flag(deployment, capsys):
    assert put_credential(deployment, b"Bearer short-key\n") == cli.EXIT_REFUSED
    captured = capsys.readouterr()
    assert "stored" not in captured.out
    assert "put-credential refused: credential cannot be redacted from results" in captured.err
    assert "--accept-unredactable" in captured.err and "short-key" not in captured.err
    with pytest.raises(CredentialUnavailable):
        stored(deployment)


def test_put_credential_records_an_accepted_exception(deployment, capsys, caplog):
    with caplog.at_level(logging.WARNING, logger="agent_bailiff.custodian.store"):
        assert put_credential(deployment, b"Bearer short-key\n", "--accept-unredactable") == 0
    assert capsys.readouterr().out == "stored\n"
    assert "accepted unredactable exception" in caplog.text
    assert stored(deployment) == StoredCredential(b"Bearer short-key", frozenset({"unredactable"}))


def test_put_credential_refuses_an_exception_a_credential_does_not_need(deployment, capsys):
    assert put_credential(deployment, SECRET + b"\n", "--accept-unredactable") == cli.EXIT_REFUSED
    assert "can be redacted" in capsys.readouterr().err
    with pytest.raises(CredentialUnavailable):
        stored(deployment)


def check_credentials(deployment):
    return cli.main(["custodian", "check-credentials", "--config", str(deployment.paths["custodian"])])


def store_bound(deployment, secret, **options):
    directory = deployment.custodian
    store = CredentialStore.create(directory / "credentials.db", LocalBackend.generate(directory / "kek"))
    try:
        store.put(TENANT, "deploy-api", "deploy.example", secret, **options)
    finally:
        store.close()


def test_check_credentials_passes_a_store_release_accepts(deployment, capsys):
    store_bound(deployment, b"Bearer short-key", accept_unredactable=True)
    assert check_credentials(deployment) == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "check-credentials: none would be refused at release; 1 stored" in captured.err


def test_check_credentials_lists_a_credential_release_would_refuse(deployment, capsys):
    store_bound(deployment, SECRET)
    connection = sqlite3.connect(deployment.custodian / "credentials.db")
    connection.execute("UPDATE credentials SET exception = 'unredactable'")
    connection.commit()
    connection.close()
    assert check_credentials(deployment) == cli.EXIT_REFUSED
    captured = capsys.readouterr()
    assert [json.loads(line) for line in captured.out.splitlines()] == [
        {
            "credential_id": "deploy-api",
            "problem": "credential does not decrypt under its binding",
            "target": "deploy.example",
            "tenant": TENANT,
        }
    ]
    assert "1 would be refused at release; 1 stored" in captured.err
    assert SECRET.decode() not in captured.out + captured.err


def test_check_credentials_lists_a_binding_with_no_stored_credential(deployment, capsys):
    directory = deployment.custodian
    CredentialStore.create(directory / "credentials.db", LocalBackend.generate(directory / "kek")).close()
    assert check_credentials(deployment) == cli.EXIT_REFUSED
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {
        "credential_id": "deploy-api",
        "problem": "no credential is stored for this binding",
        "target": "deploy.example",
        "tenant": TENANT,
    }
    assert "1 would be refused at release; 0 stored" in captured.err


def test_check_credentials_prints_a_malformed_row(deployment, capsys):
    store_bound(deployment, SECRET)
    connection = sqlite3.connect(deployment.custodian / "credentials.db")
    connection.execute("UPDATE credentials SET tenant = ?", (b"tenant-a",))
    connection.commit()
    connection.close()
    assert check_credentials(deployment) == cli.EXIT_REFUSED
    problems = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [(found["tenant"], found["problem"]) for found in problems] == [
        ("b'tenant-a'", "credential row is malformed"),
        (TENANT, "no credential is stored for this binding"),
    ]


def test_check_credentials_refuses_a_missing_store(deployment, capsys):
    assert check_credentials(deployment) == cli.EXIT_REFUSED
    assert "check-credentials refused" in capsys.readouterr().err


def test_check_config_runs_the_adapter_check_unchanged(tmp_path, capsys):
    arguments = ["check-config", "--gateway-config", str(tmp_path / "missing.json"), "--routes", "r", "--bindings", "b"]
    arguments += ["--decide-socket", "/d.sock", "--custodian-socket", "/c.sock", "--redactor-socket", "/r.sock"]
    assert cli.main(arguments) == 1
    assert "check-config refused" in capsys.readouterr().err


def wait_for(path, process, seconds=10):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if path.exists():
            return
        assert process.poll() is None, process.communicate()
        time.sleep(0.02)
    raise AssertionError(f"{path} did not appear")


SEPARATE_ARCHIVER = (
    "import sys\n"
    "from agent_bailiff.service import run\n"
    "run.sink_euid = lambda: -1\n"
    "from agent_bailiff import cli\n"
    "sys.exit(cli.main())\n"
)


def service_process(*arguments):
    return subprocess.Popen(
        [sys.executable, "-c", SEPARATE_ARCHIVER, *arguments],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def test_the_docket_command_runs_until_sigterm(deployment):
    process = service_process("docket", "run", "--config", str(deployment.paths["docket"]))
    try:
        wait_for(deployment.sockets["docket"], process)
        process.send_signal(signal.SIGTERM)
        assert process.wait(10) == 0, process.communicate()
    finally:
        if process.poll() is None:
            process.kill()
    assert not deployment.sockets["docket"].exists()


def test_the_decide_and_custodian_commands_run_until_sigterm(deployment, docket):
    create_writer(deployment.ledger, GID).close()
    CredentialStore.create(
        deployment.custodian / "credentials.db", LocalBackend.generate(deployment.custodian / "kek")
    ).close()
    ClaimsStore.create(deployment.custodian / "claims.db").close()
    decide = service_process("decide", "run", "--config", str(deployment.paths["decide"]))
    try:
        wait_for(deployment.sockets["decide"], decide)
        custodian = service_process("custodian", "run", "--config", str(deployment.paths["custodian"]))
        try:
            wait_for(deployment.sockets["custodian"], custodian)
            custodian.send_signal(signal.SIGINT)
            assert custodian.wait(10) == 0, custodian.communicate()
        finally:
            if custodian.poll() is None:
                custodian.kill()
        decide.send_signal(signal.SIGTERM)
        assert decide.wait(10) == 0, decide.communicate()
    finally:
        if decide.poll() is None:
            decide.kill()
    assert not deployment.sockets["decide"].exists() and not deployment.sockets["custodian"].exists()


def test_a_service_with_a_bad_config_exits_refused(deployment, capsys):
    os.chmod(deployment.paths["docket"], 0o644)
    assert cli.main(["docket", "run", "--config", str(deployment.paths["docket"])]) == cli.EXIT_REFUSED
    assert "docket refused" in capsys.readouterr().err


def test_a_suspend_after_decide_passed_stops_the_running_custodian(stack, live, deployment, capsys):
    stack.call(live())
    line = deployment.record_line("decide", "allow")
    request = live("n-2")
    decided = check(deployment.sockets["decide"], call_message(request))
    assert decided.WhichOneof("result") == "pass"
    assert control(deployment, "suspend", "--record", "-", stdin=line + "\n") == 0
    metadata = struct_pb2.Struct()
    metadata.CopyFrom(decided.metadata)
    released = check(deployment.sockets["custodian"], call_message(request, metadata))
    assert released.error.reason == "release_refused", released
    refusals = [record.entry for _, record in deployment.records() if record.entry.hop == "custodian"]
    assert [(entry.decision, entry.reason) for entry in refusals] == [("release", "ok"), ("refuse", "suspended")]


def test_snapshot_every_is_required(deployment):
    with pytest.raises(ConfigError, match="missing snapshot_every"):
        parse_docket(mutate(deployment.documents["docket"], lambda doc: doc.pop("snapshot_every")))


def test_free_space_floor_is_required(deployment):
    with pytest.raises(ConfigError, match="missing free_space_floor"):
        parse_docket(mutate(deployment.documents["docket"], lambda doc: doc.pop("free_space_floor")))


def test_segment_bytes_is_required(deployment):
    with pytest.raises(ConfigError, match="missing segment_bytes"):
        parse_docket(mutate(deployment.documents["docket"], lambda doc: doc.pop("segment_bytes")))


def test_segment_bytes_admits_64_mib(deployment):
    settings = parse_docket(mutate(deployment.documents["docket"], lambda doc: doc.update(segment_bytes=64 << 20)))
    assert settings.segment_bytes == 64 << 20


def test_the_docket_command_refuses_an_archiver_uid_equal_to_its_own(deployment):
    process = subprocess.run(
        [sys.executable, "-m", "agent_bailiff.cli", "docket", "run", "--config", str(deployment.paths["docket"])],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert process.returncode == 1
    assert f"docket.archiver_uid {UID} is the sink's own uid" in process.stderr
    assert not deployment.sockets["docket"].exists()


def test_the_docket_command_refuses_to_run_as_root(deployment):
    process = subprocess.run(
        [
            sys.executable,
            "-c",
            SEPARATE_ARCHIVER.replace("lambda: -1", "lambda: 0"),
            "docket",
            "run",
            "--config",
            str(deployment.paths["docket"]),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert process.returncode == 1
    assert "the docket sink is running as root" in process.stderr
    assert not deployment.sockets["docket"].exists()


def test_serve_docket_refuses_to_run_the_sink_as_root(deployment, monkeypatch):
    constructed = []

    class RecordingSink:
        def __init__(self, *args, **options):
            constructed.append(options)

        async def start(self):
            raise RuntimeError("sink started")

        async def close(self):
            pass

    monkeypatch.setattr(run, "DocketSink", RecordingSink)
    monkeypatch.setattr(run, "sink_euid", lambda: 0)
    settings = load_docket(deployment.paths["docket"])
    assert settings.retention.archiver_uid != 0
    with pytest.raises(ValueError, match="running as root"):
        asyncio.run(run.serve_docket(settings, asyncio.Event()))
    assert constructed == []


def test_serve_docket_passes_snapshot_every_to_the_sink(deployment, monkeypatch):
    seen = {}

    class RecordingSink:
        def __init__(self, *args, **options):
            seen.update(options)

        async def start(self):
            raise RuntimeError("stop after construction")

        async def close(self):
            pass

    monkeypatch.setattr(run, "DocketSink", RecordingSink)
    settings = parse_docket(
        mutate(
            deployment.documents["docket"],
            lambda doc: doc.update(snapshot_every=7, free_space_floor=1 << 30, segment_bytes=1 << 27),
        )
    )
    with pytest.raises(RuntimeError, match="stop after construction"):
        asyncio.run(run.serve_docket(settings, asyncio.Event()))
    assert seen["snapshot_every"] == 7
    assert seen["free_space_floor"] == 1 << 30
    assert seen["segment_bytes"] == 1 << 27
