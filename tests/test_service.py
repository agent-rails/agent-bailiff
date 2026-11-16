import asyncio
import copy
import io
import json
import os
import shutil
import signal
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
from agent_bailiff.custodian import ClaimsStore, CredentialStore, LocalBackend
from agent_bailiff.custodian.files import OwnedFileError
from agent_bailiff.docket import DocketClient, decode_record
from agent_bailiff.docket.entry import Entry
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
        self.ledger_dir = root / "ledger"
        self.ledger_dir.mkdir(mode=0o750)
        os.chown(self.ledger_dir, -1, GID)
        os.chmod(self.ledger_dir, 0o750)
        self.ledger = self.ledger_dir / "ledger.db"
        self.sockets = {"docket": root / "s" / "docket.sock", "decide": root / "d" / "decide.sock"}
        self.sockets["custodian"] = root / "c" / "custodian.sock"
        self.keys = {
            "decide.example": generate_signing_key(self.decide / "signing.key", "decide.example"),
            "custodian.example": generate_signing_key(self.custodian / "signing.key", "custodian.example"),
            "control": generate_signing_key(self.control / "signing.key", "control"),
        }
        for directory in (self.decide, self.custodian, self.control):
            private(directory / "docket-state")
            private(directory / "grpc")
        private(self.decide / "suspension")
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
            "suspension_dir": str(self.decide / "suspension"),
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
            "max_clearance_lifetime": 60,
            "skew_seconds": 5,
            "rate_limit": 10,
            "rate_window": 60,
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
            "allowed_uids": [UID],
            "writers": {name: self.pins(name) for name in self.keys},
        }

    def control_document(self):
        return {
            "name": "control",
            "key": str(self.control / "signing.key"),
            "decide_config": str(self.decide / "config.json"),
            "docket": self.docket_client(self.control),
            "writers": {name: self.pins(name) for name in ("decide.example", "custodian.example")},
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
    assert docket.allowed_uids == {UID} and set(docket.writers) == set(deployment.keys)
    assert control.name == "control" and set(control.writers) == {"decide.example", "custodian.example"}


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
    "unpinned_kid_for_the_key": lambda doc: doc.update(
        decide_keys={"decide.example-1": doc["decide_keys"].popitem()[1]}
    ),
    "key_of_another_component": lambda doc: doc.update(decider="custodian.example"),
    "no_decide_keys": lambda doc: doc.update(decide_keys={}),
    "excess_skew": lambda doc: doc.update(skew_seconds=301),
    "zero_rate_limit": lambda doc: doc.update(rate_limit=0),
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


@pytest.mark.parametrize(
    "change",
    [
        lambda doc: doc.update(allowed_uids=[]),
        lambda doc: doc.update(allowed_uids=["0"]),
        lambda doc: doc.update(allowed_uids=[True]),
        lambda doc: doc.update(writers={}),
        lambda doc: doc.update(socket_group=None),
    ],
)
def test_a_bad_docket_config_is_refused(deployment, change):
    with pytest.raises(ConfigError):
        parse_docket(mutate(deployment.documents["docket"], change))


def test_control_must_not_pin_its_own_writer(deployment):
    document = mutate(
        deployment.documents["control"], lambda doc: doc["writers"].update(control=deployment.pins("control"))
    )
    with pytest.raises(ConfigError):
        parse_control(document)


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


def test_check_config_runs_the_adapter_check_unchanged(tmp_path, capsys):
    arguments = ["check-config", "--gateway-config", str(tmp_path / "missing.json"), "--routes", "r", "--bindings", "b"]
    arguments += ["--decide-socket", "/d.sock", "--custodian-socket", "/c.sock"]
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


def service_process(*arguments):
    return subprocess.Popen(
        [sys.executable, "-m", "agent_bailiff.cli", *arguments],
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
