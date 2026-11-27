import contextlib
import copy
import importlib.util
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

import pytest
from test_issue_certs import certs_module

QUICKSTART = Path(__file__).resolve().parents[1] / "examples" / "quickstart"
COMPOSE_FILE = QUICKSTART / "compose.yaml"
CERT_WATCH_NOW = Path(__file__).resolve().parent / "fixtures" / "quickstart-cert-watch.compose.yaml"
IMAGE = "agent-bailiff-quickstart:dev"
UP_TIMEOUT_SECONDS = 900
RUN_TIMEOUT_SECONDS = 180
pytestmark = [
    pytest.mark.skipif(
        os.environ.get("AGENT_BAILIFF_TEST_QUICKSTART") != "1",
        reason="set AGENT_BAILIFF_TEST_QUICKSTART=1 to run the quickstart compose stack",
    ),
    pytest.mark.skipif(shutil.which("docker") is None, reason="docker is not installed"),
]

PROFILES = ("gitea",)

_spec = importlib.util.spec_from_file_location("quickstart_bootstrap", QUICKSTART / "bootstrap.py")
assert _spec is not None and _spec.loader is not None
b = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = b
_spec.loader.exec_module(b)

VOLUMES = {
    "pins": "/pins",
    "issuer-data": "/var/lib/bailiff/issuer",
    "issuer-docket": "/var/lib/bailiff/issuer-docket",
    "decide-data": "/var/lib/bailiff/decide",
    "custodian-data": "/var/lib/bailiff/custodian",
    "control-data": "/var/lib/bailiff/control",
    "rule-data": "/var/lib/bailiff/rule",
    "reader-data": "/var/lib/bailiff/reader",
    "docket-data": "/var/lib/bailiff/docket",
    "ledger": "/var/lib/bailiff/ledger",
    "gitea-admin": "/var/lib/bailiff/gitea-admin",
    "docket-run": "/run/bailiff/docket",
    "decide-run": "/run/bailiff/decide",
    "custodian-run": "/run/bailiff/custodian",
    "agent-data": "/var/lib/bailiff/agent",
    "agent-public": "/var/lib/bailiff/agent-public",
    "tasks": "/var/lib/bailiff/tasks",
    "docket-receipts": "/var/lib/bailiff/receipts",
    "gateway-config": "/var/lib/bailiff/gateway",
    "certs-public": "/var/lib/bailiff/certs/public",
    **{f"certs-{name}": f"/var/lib/bailiff/certs/{name}" for name in certs_module.SERVICES},
}
PROFILE_VOLUMES = {"trace": {"exporter-data": "/var/lib/bailiff/exporter"}}
PRIVATE_VOLUMES = (
    "issuer-data",
    "issuer-docket",
    "decide-data",
    "custodian-data",
    "control-data",
    "rule-data",
    "reader-data",
    "docket-data",
    "ledger",
    "gitea-admin",
    "docket-run",
    "decide-run",
    "custodian-run",
    "docket-receipts",
    *(f"certs-{name}" for name in certs_module.SERVICES),
)

DECIDE = (b.DECIDE_UID, b.LEDGER_GID)
CUSTODIAN = (b.CUSTODIAN_UID, b.CUSTODIAN_UID)
CERTS_UID = 10012
CERT_WATCH_UID = 10015
STUB_UID = 10011
CERTS = (CERTS_UID, CERTS_UID)
FIRST = "gen-0001"
DIRECTORY, FILE, SOCKET = "directory", "file", "socket"
CERT_ENTRIES = {
    "certs-public": (*CERTS, 0o755, DIRECTORY),
    f"certs-public/{FIRST}": (*CERTS, 0o755, DIRECTORY),
    f"certs-public/{FIRST}/ca.pem": (*CERTS, 0o444, FILE),
    **{f"certs-public/{FIRST}/{name}.pem": (*CERTS, 0o444, FILE) for name in certs_module.SERVICES},
    **{
        entry: values
        for name, settings in certs_module.SERVICES.items()
        for entry, values in {
            f"certs-{name}": (CERTS_UID, settings.gid, 0o750, DIRECTORY),
            f"certs-{name}/{FIRST}": (*CERTS, 0o755, DIRECTORY),
            f"certs-{name}/{FIRST}/{name}.pem": (*CERTS, 0o444, FILE),
            f"certs-{name}/{FIRST}/{name}.key": (CERTS_UID, settings.gid, 0o440, FILE),
        }.items()
    },
}
EXPECTED_ENTRIES = {
    "pins": (0, 0, 0o755, DIRECTORY),
    "pins/issuer": (b.ISSUER_UID, b.ISSUER_UID, 0o755, DIRECTORY),
    "pins/issuer/issuer.json": (b.ISSUER_UID, b.ISSUER_UID, 0o644, FILE),
    "pins/issuer/issuer-docket.json": (b.ISSUER_UID, b.ISSUER_UID, 0o644, FILE),
    "pins/decide": (b.DECIDE_UID, b.DECIDE_UID, 0o755, DIRECTORY),
    "pins/decide/decide.json": (*DECIDE, 0o644, FILE),
    "pins/custodian": (*CUSTODIAN, 0o755, DIRECTORY),
    "pins/custodian/custodian.json": (*CUSTODIAN, 0o644, FILE),
    "pins/control": (b.DECIDE_UID, b.DECIDE_UID, 0o755, DIRECTORY),
    "pins/control/control.json": (*DECIDE, 0o644, FILE),
    "pins/rule": (b.DECIDE_UID, b.DECIDE_UID, 0o755, DIRECTORY),
    "pins/rule/rule.json": (*DECIDE, 0o644, FILE),
    "issuer-data": (b.ISSUER_UID, b.ISSUER_UID, 0o700, DIRECTORY),
    "issuer-data/issuer.key": (b.ISSUER_UID, b.ISSUER_UID, 0o600, FILE),
    "issuer-docket": (b.ISSUER_UID, b.ISSUER_UID, 0o700, DIRECTORY),
    "issuer-docket/signing.key": (b.ISSUER_UID, b.ISSUER_UID, 0o600, FILE),
    "issuer-docket/docket-state": (b.ISSUER_UID, b.ISSUER_UID, 0o700, DIRECTORY),
    "decide-data": (*DECIDE, 0o700, DIRECTORY),
    "decide-data/config.json": (*DECIDE, 0o600, FILE),
    "decide-data/routes.json": (*DECIDE, 0o600, FILE),
    "decide-data/signing.key": (*DECIDE, 0o600, FILE),
    "decide-data/docket-state": (*DECIDE, 0o700, DIRECTORY),
    "decide-data/grpc": (*DECIDE, 0o700, DIRECTORY),
    "custodian-data": (*CUSTODIAN, 0o700, DIRECTORY),
    "custodian-data/config.json": (*CUSTODIAN, 0o600, FILE),
    "custodian-data/routes.json": (*CUSTODIAN, 0o600, FILE),
    "custodian-data/bindings.json": (*CUSTODIAN, 0o600, FILE),
    "custodian-data/signing.key": (*CUSTODIAN, 0o600, FILE),
    "custodian-data/kek": (*CUSTODIAN, 0o600, FILE),
    "custodian-data/credentials.db": (*CUSTODIAN, 0o600, FILE),
    "custodian-data/claims.db": (*CUSTODIAN, 0o600, FILE),
    "custodian-data/docket-state": (*CUSTODIAN, 0o700, DIRECTORY),
    "custodian-data/grpc": (*CUSTODIAN, 0o700, DIRECTORY),
    "control-data": (*DECIDE, 0o700, DIRECTORY),
    "control-data/config.json": (*DECIDE, 0o600, FILE),
    "control-data/signing.key": (*DECIDE, 0o600, FILE),
    "control-data/docket-state": (*DECIDE, 0o700, DIRECTORY),
    "rule-data": (*DECIDE, 0o700, DIRECTORY),
    "rule-data/config.json": (*DECIDE, 0o600, FILE),
    "rule-data/signing.key": (*DECIDE, 0o600, FILE),
    "rule-data/docket-state": (*DECIDE, 0o700, DIRECTORY),
    "reader-data": (b.READER_UID, b.READER_UID, 0o700, DIRECTORY),
    "reader-data/issuers.json": (b.READER_UID, b.READER_UID, 0o600, FILE),
    "docket-data": (b.DOCKET_UID, b.DOCKET_READERS_GID, 0o750, DIRECTORY),
    "docket-data/config.json": (b.DOCKET_UID, b.DOCKET_UID, 0o600, FILE),
    "docket-data/docket.log": (b.DOCKET_UID, b.DOCKET_READERS_GID, 0o640, FILE),
    "docket-data/docket.log.snapshot": (b.DOCKET_UID, b.DOCKET_READERS_GID, 0o640, FILE),
    "docket-data/docket.log.lock": (b.DOCKET_UID, b.DOCKET_UID, 0o600, FILE),
    "ledger": (*DECIDE, 0o750, DIRECTORY),
    "ledger/ledger.db": (*DECIDE, 0o640, FILE),
    "ledger/ledger.db.suspension": (*DECIDE, 0o750, DIRECTORY),
    "gitea-admin": (b.CUSTODIAN_UID, b.GITEA_ADMIN_GID, 0o750, DIRECTORY),
    "gitea-admin/password": (b.CUSTODIAN_UID, b.GITEA_ADMIN_GID, 0o640, FILE),
    "docket-run": (b.DOCKET_UID, b.DOCKET_WRITERS_GID, 0o750, DIRECTORY),
    "docket-run/docket.sock": (b.DOCKET_UID, b.DOCKET_WRITERS_GID, 0o660, SOCKET),
    "docket-run/docket.sock.lock": (b.DOCKET_UID, b.DOCKET_UID, 0o600, FILE),
    "decide-run": (b.DECIDE_UID, b.GATEWAY_SOCKETS_GID, 0o750, DIRECTORY),
    "decide-run/decide.sock": (b.DECIDE_UID, b.GATEWAY_SOCKETS_GID, 0o660, SOCKET),
    "decide-run/decide.sock.lock": (*DECIDE, 0o600, FILE),
    "custodian-run": (b.CUSTODIAN_UID, b.GATEWAY_SOCKETS_GID, 0o750, DIRECTORY),
    "custodian-run/custodian.sock": (b.CUSTODIAN_UID, b.GATEWAY_SOCKETS_GID, 0o660, SOCKET),
    "custodian-run/custodian.sock.lock": (*CUSTODIAN, 0o600, FILE),
    "custodian-run/redactor.sock": (b.CUSTODIAN_UID, b.GATEWAY_SOCKETS_GID, 0o660, SOCKET),
    "custodian-run/redactor.sock.lock": (*CUSTODIAN, 0o600, FILE),
    "agent-data": (b.AGENT_UID, b.AGENT_UID, 0o700, DIRECTORY),
    "agent-data/agent.key": (b.AGENT_UID, b.AGENT_UID, 0o600, FILE),
    "agent-public": (b.AGENT_UID, b.AGENT_UID, 0o755, DIRECTORY),
    "agent-public/agent.pub": (b.AGENT_UID, b.AGENT_UID, 0o644, FILE),
    "tasks": (b.ISSUER_UID, b.ISSUER_UID, 0o755, DIRECTORY),
    "tasks/task.json": (b.ISSUER_UID, b.ISSUER_UID, 0o644, FILE),
    "docket-receipts": (b.ARCHIVER_UID, b.DOCKET_READERS_GID, 0o750, DIRECTORY),
    "gateway-config": (*CUSTODIAN, 0o755, DIRECTORY),
    "gateway-config/gateway.json": (*CUSTODIAN, 0o644, FILE),
    **CERT_ENTRIES,
}
TRANSIENT_ENTRIES = {
    re.compile(r"ledger/ledger\.db-(shm|wal)"): (*DECIDE, 0o640, FILE),
}
EXPECTED_IDENTITIES = {
    "docket": (b.DOCKET_UID, b.DOCKET_UID, {b.DOCKET_UID, b.DOCKET_WRITERS_GID, b.DOCKET_READERS_GID}),
    "decide": (b.DECIDE_UID, b.LEDGER_GID, {b.LEDGER_GID, b.DOCKET_WRITERS_GID, b.GATEWAY_SOCKETS_GID}),
    "custodian": (
        b.CUSTODIAN_UID,
        b.CUSTODIAN_UID,
        {b.CUSTODIAN_UID, b.DOCKET_WRITERS_GID, b.LEDGER_GID, b.GATEWAY_SOCKETS_GID},
    ),
    "gateway": (b.GATEWAY_UID, b.GATEWAY_UID, {b.GATEWAY_UID, b.GATEWAY_SOCKETS_GID}),
    "cert-watch": (CERT_WATCH_UID, CERT_WATCH_UID, {CERT_WATCH_UID}),
    "stub-upstream": (STUB_UID, STUB_UID, {STUB_UID, certs_module.SERVICES["stub-upstream"].gid}),
}
ONE_SHOTS = (
    "issuer-init",
    "decide-init",
    "custodian-init",
    "control-init",
    "rule-init",
    "reader-init",
    "docket-init",
    "gateway-init",
    "gitea-secret",
    "gitea-admin",
    "bootstrap",
    "agent-key",
    "certs",
)
STAT_SCRIPT = """
import json, os, stat, sys
kinds = {stat.S_IFDIR: "directory", stat.S_IFREG: "file", stat.S_IFSOCK: "socket"}
entries = {}
def record(path):
    info = os.lstat(path)
    kind = kinds.get(stat.S_IFMT(info.st_mode), "other")
    entries[path[3:]] = [info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), kind]
for top in sorted(os.listdir("/v")):
    for root, dirs, files in os.walk(f"/v/{top}"):
        record(root)
        if os.path.basename(root) in ("docket-state", "grpc"):
            dirs.clear()
            continue
        for name in files:
            record(os.path.join(root, name))
json.dump(entries, sys.stdout)
"""
SNAPSHOT_SCRIPT = """
import hashlib, json, os, stat, sys
snapshot = {}
for top in sorted(os.listdir("/v")):
    for root, dirs, files in os.walk(f"/v/{top}"):
        dirs[:] = [name for name in dirs if name not in ("docket-state", "grpc")]
        for name in files:
            path = os.path.join(root, name)
            info = os.lstat(path)
            if not stat.S_ISREG(info.st_mode) or name.endswith((".db", ".db-shm", ".db-wal", ".lock", "docket.log")):
                continue
            with open(path, "rb") as handle:
                digest = hashlib.sha256(handle.read()).hexdigest()
            snapshot[path[3:]] = [digest, info.st_mtime_ns, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)]
json.dump(snapshot, sys.stdout)
"""
CA_SCRIPT = """
import json
print(json.dumps(open("/v/certs-public/current/ca.pem").read()))
"""
READ_PROBE = """
import json, os, sys
denied = {}
for top in sorted(os.listdir("/v")):
    try:
        os.listdir(f"/v/{top}")
        denied[top] = False
    except PermissionError:
        denied[top] = True
json.dump(denied, sys.stdout)
"""


def free_ports(count):
    probes = [socket.socket() for _ in range(count)]
    try:
        for probe in probes:
            probe.bind(("127.0.0.1", 0))
        return [probe.getsockname()[1] for probe in probes]
    finally:
        for probe in probes:
            probe.close()


class Stack:
    def __init__(self, project, profiles=(), files=(), env=None):
        self.project = project
        self.profiles = tuple(profiles)
        self.files = (COMPOSE_FILE, *files)
        self.jaeger_port, gitea_mcp_port, self.gateway_port = free_ports(3)
        self.env = {
            **os.environ,
            "COMPOSE_PROJECT_NAME": project,
            "GITEA_MCP_PORT": str(gitea_mcp_port),
            "JAEGER_PORT": str(self.jaeger_port),
            "GATEWAY_PORT": str(self.gateway_port),
            "UPSTREAM": "gitea" if "gitea" in self.profiles else "stub",
            **(env or {}),
        }
        self.volumes = {
            **VOLUMES,
            **{name: path for p in self.profiles for name, path in PROFILE_VOLUMES.get(p, {}).items()},
        }

    def compose(self, *arguments, timeout=RUN_TIMEOUT_SECONDS, stdin=None, expect=0):
        selected = [arg for profile in self.profiles for arg in ("--profile", profile)]
        command = ["docker", "compose", *self.file_arguments(), *selected, *arguments]
        result = subprocess.run(
            command, env=self.env, input=stdin, capture_output=True, text=True, timeout=timeout, check=False
        )
        assert result.returncode == expect, f"{' '.join(arguments)} failed:\n{result.stdout}\n{result.stderr}"
        return result.stdout

    def file_arguments(self):
        return [arg for path in self.files for arg in ("--file", str(path))]

    def container(self, service):
        return self.compose("ps", "--all", "--quiet", service).strip()

    def probe(self, script, user="0:0", arguments=()):
        mounts = [arg for name in self.volumes for arg in ("--volume", f"{self.project}_{name}:/v/{name}:ro")]
        capabilities = ["--cap-add", "DAC_READ_SEARCH"] if user == "0:0" else []
        command = [
            "docker", "run", "--rm", "--network", "none", "--user", user, "--read-only",
            "--cap-drop", "ALL", *capabilities, *mounts, IMAGE, "-c", script, *arguments,
        ]  # fmt: skip
        result = subprocess.run(command, capture_output=True, text=True, timeout=RUN_TIMEOUT_SECONDS, check=False)
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)


@contextlib.contextmanager
def started(stack):
    try:
        stack.compose("up", "--build", "--detach", "--wait", timeout=UP_TIMEOUT_SECONDS)
        yield stack
    finally:
        subprocess.run(
            ["docker", "compose", *stack.file_arguments(), "--profile", "*", "down", "--volumes", "--remove-orphans"],
            env=stack.env,
            capture_output=True,
            timeout=RUN_TIMEOUT_SECONDS,
            check=False,
        )


@pytest.fixture(scope="module")
def stack(request):
    with started(Stack(f"bailiff-qs-{uuid.uuid4().hex[:8]}", getattr(request.module, "PROFILES", ()))) as running:
        yield running


def identity(container):
    output = subprocess.run(
        ["docker", "top", container, "-eo", "pid,uid,gid,supgid"],
        capture_output=True,
        text=True,
        timeout=RUN_TIMEOUT_SECONDS,
        check=True,
    ).stdout
    rows = [line.split() for line in output.splitlines()[1:]]
    assert rows, output
    return {(int(uid), int(gid), frozenset(int(group) for group in groups.split(","))) for _, uid, gid, groups in rows}


def test_uid_matrix(stack):
    for service, (uid, gid, groups) in EXPECTED_IDENTITIES.items():
        assert identity(stack.container(service)) == {(uid, gid, frozenset(groups))}, service
    entries = {path: tuple(values) for path, values in stack.probe(STAT_SCRIPT).items()}
    for path, actual in entries.items():
        if path in EXPECTED_ENTRIES:
            assert actual == EXPECTED_ENTRIES[path], path
            continue
        transient = [expected for pattern, expected in TRANSIENT_ENTRIES.items() if pattern.fullmatch(path)]
        assert transient == [actual], f"unexpected entry {path} {actual}"
    assert set(EXPECTED_ENTRIES) <= set(entries)


def test_the_agent_uid_reads_no_bailiff_state(stack):
    denied = stack.probe(READ_PROBE, user=f"{b.AGENT_UID}:{b.AGENT_UID}")
    assert {name for name, refused in denied.items() if refused} == set(PRIVATE_VOLUMES)
    assert {name for name, refused in denied.items() if not refused} == {
        "pins",
        "agent-data",
        "agent-public",
        "tasks",
        "gateway-config",
        "certs-public",
    }


def test_the_agent_mounts_no_bailiff_state(stack):
    services = json.loads(stack.compose("--profile", "agent", "config", "--format", "json"))["services"]
    agent = services["agent"]
    assert sorted((volume["source"], volume.get("read_only", False)) for volume in agent["volumes"]) == [
        ("agent-data", True),
        ("agent-public", True),
        ("tasks", True),
    ]
    assert list(agent["networks"]) == ["edge"]
    assert "network_mode" not in agent


def pip_absent(stack, service, *arguments):
    probe = (
        "import glob, importlib.util, sys; "
        "print(all(importlib.util.find_spec(name) is None for name in ('pip', 'ensurepip')) "
        "and not glob.glob(f'{sys.prefix}/lib/**/*.whl', recursive=True))"
    )
    run = [*arguments, "run", "--rm", "--no-deps", "--entrypoint", "python", service, "-c", probe]
    return stack.compose(*run).strip() == "True"


def test_the_image_ships_without_pip(stack):
    assert pip_absent(stack, "agent", "--profile", "agent")


def test_bootstrap_rerun_idempotent(stack):
    before = stack.probe(SNAPSHOT_SCRIPT)
    outputs = {service: stack.compose("run", "--rm", "--no-deps", service) for service in ONE_SHOTS}
    after = stack.probe(SNAPSHOT_SCRIPT)
    assert after == before
    for service, step in [
        ("issuer-init", "issuer"),
        ("decide-init", "decide"),
        ("custodian-init", "custodian"),
        ("control-init", "control"),
        ("rule-init", "rule"),
        ("reader-init", "reader"),
        ("docket-init", "docket"),
        ("gateway-init", "gateway"),
        ("gitea-secret", "admin-secret"),
        ("agent-key", "key"),
    ]:
        assert outputs[service].strip().splitlines()[-1] == f"{step}: kept", outputs[service]
    assert outputs["certs"].strip().splitlines()[-1] == f"kept {FIRST}", outputs["certs"]
    lines = outputs["bootstrap"].strip().splitlines()
    assert lines[-2:] == ["credential: kept", "gitea: kept"], outputs["bootstrap"]
    assert not any(line.startswith("gitea: created") for line in lines)
    reach = json.loads("\n".join(line for line in lines if not line.startswith(("credential:", "gitea:"))))
    assert reach["what this token can reach"]["probes"][f"read issues in {b.ORG}/demo"] == "allowed"


def health(stack, service):
    output = subprocess.run(
        ["docker", "inspect", "--format", "{{json .State.Health}}", stack.container(service)],
        capture_output=True,
        text=True,
        timeout=RUN_TIMEOUT_SECONDS,
        check=True,
    ).stdout
    return json.loads(output)


def test_cert_watch_is_healthy_on_a_fresh_set(stack):
    state = health(stack, "cert-watch")
    assert state["Status"] == "healthy", state
    assert state["Log"][-1]["Output"].strip() == "certificates ok", state


def test_the_install_ca_is_copied_out_with_compose_cp(stack):
    with tempfile.TemporaryDirectory() as directory:
        target = Path(directory) / "ca.pem"
        stack.compose("cp", "cert-watch:/var/lib/bailiff/certs/public/current/ca.pem", str(target))
        copied = target.read_text()
    assert copied == stack.probe(CA_SCRIPT)
    assert copied.startswith("-----BEGIN CERTIFICATE-----")


def cert_snapshot(stack):
    return {path: values for path, values in stack.probe(SNAPSHOT_SCRIPT).items() if path.startswith("certs-")}


def test_a_second_up_keeps_the_certs(stack):
    before = cert_snapshot(stack)
    stack.compose("up", "--detach", "--wait", timeout=UP_TIMEOUT_SECONDS)
    assert cert_snapshot(stack) == before
    assert len(before) == len(certs_module.SERVICES) * 3 + 1
    assert stack.compose("logs", "--no-log-prefix", "certs").strip().splitlines()[-1] == f"kept {FIRST}"


def test_cert_watch_turns_unhealthy_on_a_leaf_within_the_margin(stack):
    stack.compose("stop")
    issued = stack.compose("run", "--rm", "--no-deps", "certs", "issue", "--reissue", "--days", "20")
    assert issued.strip().splitlines()[-1] == "issued gen-0002", issued
    watch = copy.copy(stack)
    watch.files = (*stack.files, CERT_WATCH_NOW)
    watch.compose("up", "--detach", "--no-deps", "--wait", "--wait-timeout", "60", "cert-watch", expect=1)
    state = health(stack, "cert-watch")
    assert state["Status"] == "unhealthy", state
    assert state["Log"][-1]["ExitCode"] == 1, state
    output = state["Log"][-1]["Output"]
    assert all(f"{name}.pem expires at" in output for name in certs_module.SERVICES), output
