import json
import os
import secrets
import time
from dataclasses import replace

import pytest
import test_service
from agent_warrant.encoding import b64u
from agent_warrant.identity import encode_public_key
from agent_warrant.task_root import TaskRoot
from google.protobuf import struct_pb2
from test_agentgateway_calls import message
from test_decide import AGENT_KEY, CHILD_KEY, ISSUER_ID, ISSUER_KEY, PERMISSION, POLICY, PRINCIPAL, TENANT
from test_service import Stack, check, write_owned

from agent_bailiff import cli
from agent_bailiff.client import Holder
from agent_bailiff.client.contract import prepare_call
from agent_bailiff.custodian.files import create_owned
from agent_bailiff.keys import KEY_LABEL
from agent_bailiff.proxy.agent_key import generate_agent_key
from agent_bailiff.proxy.task_state import TaskState
from agent_bailiff.routes import ToolRoutes

deployment = test_service.deployment
docket = test_service.docket
separate_archiver = test_service.separate_archiver

DECIDER = "decide.example"
ARGS = {"service": "api", "replicas": 2}
DEPLOY = {"tools": ["deploy.service"], "resources": ["env/staging/*"], "max_cost_per_call": 5}
CANARY = {"tools": ["deploy.canary"], "resources": ["env/prod/*"], "max_cost_per_call": 5}
RESTART = {"tools": ["deploy.restart"], "resources": ["env/staging/*"], "max_cost_per_call": 1}
PAIRED = {"permissions": [DEPLOY, CANARY, RESTART]}
CALLS = {
    "deploy_staging": ("deploy.service", "env/staging/api"),
    "deploy_prod": ("deploy.service", "env/prod/api"),
    "canary_prod": ("deploy.canary", "env/prod/api"),
    "canary_staging": ("deploy.canary", "env/staging/api"),
    "restart_staging": ("deploy.restart", "env/staging/api"),
}
ROUTES_DOCUMENT = {
    "routes": [
        {"service": "deploy", "name": name, "tool": tool, "resource": resource}
        for name, (tool, resource) in CALLS.items()
    ]
}
ROUTES = ToolRoutes.from_document(ROUTES_DOCUMENT)
COSTS = {"version": 1, "tools": {"deploy.service": 1, "deploy.canary": 1, "deploy.restart": 3}}
BINDINGS = [
    {
        "tenant": TENANT,
        "tool": tool,
        "resource": resource.rsplit("/", 1)[0] + "/*",
        "credential_id": "deploy-api",
        "target": "deploy.example",
    }
    for tool, resource in CALLS.values()
]


def configure(deployment, *, decide_cutoff, custodian_cutoff):
    documents = deployment.documents
    documents["decide"].update(
        scope_v1_cutoff=decide_cutoff,
        bindings=[{**binding, "custodian": "custodian.example"} for binding in BINDINGS],
        policy={"id": "default", "version": "1", "document": POLICY},
        costs=COSTS,
    )
    documents["custodian"].update(scope_v1_cutoff=custodian_cutoff)
    for name in ("decide", "custodian"):
        write_owned(deployment.paths[name], documents[name])
        write_owned(getattr(deployment, name) / "routes.json", ROUTES_DOCUMENT)
    custodian_bindings = [{**binding, "header_name": "Authorization", "canary": False} for binding in BINDINGS]
    write_owned(deployment.custodian / "bindings.json", {"bindings": custodian_bindings})


@pytest.fixture
def running(deployment, docket):
    stacks = []

    def start(*, decide_cutoff, custodian_cutoff=None):
        configure(
            deployment,
            decide_cutoff=decide_cutoff,
            custodian_cutoff=decide_cutoff if custodian_cutoff is None else custodian_cutoff,
        )
        stacks.append(Stack(deployment))
        return stacks[-1]

    yield start
    for stack in stacks:
        stack.close()


def issue_task(deployment, scope, *, max_depth=0):
    issuer = test_service.private(deployment.root / "issuer")
    create_owned(issuer / "issuer.key", KEY_LABEL, ISSUER_KEY.private_bytes_raw())
    keys = test_service.private(deployment.root / "agent-keys")
    subject = generate_agent_key(keys)
    tasks = deployment.root / "tasks"
    tasks.mkdir(mode=0o755)
    os.chmod(tasks, 0o755)
    arguments = [
        "task", "issue", "--issuer-key", str(issuer / "issuer.key"), "--issuer", ISSUER_ID,
        "--decider-id", DECIDER, "--tenant", TENANT, "--principal", PRINCIPAL, "--purpose", "release-bot",
        "--scope", json.dumps(scope), "--budget", "50", "--ttl", "600", "--max-depth", str(max_depth),
        f"--subject={subject}", "--out-dir", str(tasks),
    ]  # fmt: skip
    assert cli.main(arguments) == 0
    return TaskState.load(tasks / "task.json", keys).holder


def v1_holder(issued_at):
    unsigned = TaskRoot(
        task_id="task-v1",
        tenant_id=TENANT,
        principal=PRINCIPAL,
        purpose="release-bot",
        budget=50,
        max_depth=0,
        issued_at=issued_at,
        expires_at=issued_at + 600,
        scope=PERMISSION,
        subject=encode_public_key(AGENT_KEY.public_key()),
        issuer=ISSUER_ID,
        proof="",
    )
    root = replace(unsigned, proof=b64u(ISSUER_KEY.sign(unsigned.signing_bytes())))
    return Holder(root.encode(), (), AGENT_KEY, DECIDER)


def call(deployment, holder, name):
    prepared = prepare_call(
        holder, ROUTES, "deploy", name, ARGS, request_id=1, now=int(time.time()), token_bytes=secrets.token_bytes
    )
    request = message(params={"name": name, "arguments": ARGS}, headers=dict(prepared.headers))
    decided = check(deployment.sockets["decide"], request)
    if decided.WhichOneof("result") != "pass":
        return decided.error.reason
    metadata = struct_pb2.Struct()
    metadata.CopyFrom(decided.metadata)
    request.metadata_context.CopyFrom(metadata)
    released = check(deployment.sockets["custodian"], request)
    if released.WhichOneof("result") != "pass":
        return f"custodian {released.error.reason}"
    [header] = released.header_mutation.set
    return "released" if (header.key, header.value) == ("Authorization", test_service.SECRET) else header


def verified_docket(deployment, docket, capsys):
    docket.stop()
    pins = []
    for name in ("decide.example", "custodian.example"):
        path = deployment.root / f"{name}.pub.json"
        path.write_text(json.dumps(deployment.keys[name].to_document()))
        os.chmod(path, 0o644)
        pins += ["--pin", str(path)]
    capsys.readouterr()
    code = cli.main(["docket", "verify", "--docket", str(deployment.docket / "docket.log"), *pins, "--json"])
    captured = capsys.readouterr()
    assert code == 0, captured.err
    entries = [(row["writer"], row["entry"]) for row in map(json.loads, captured.out.splitlines())]
    return [(writer, entry["decision"], entry["tool"], entry["resource"], entry["reason"]) for writer, entry in entries]


def test_an_issued_paired_task_releases_only_the_calls_one_permission_covers(running, deployment, docket, capsys):
    running(decide_cutoff=int(time.time()) - 60)
    holder = issue_task(deployment, PAIRED)
    outcomes = {name: call(deployment, holder, name) for name in CALLS}
    assert outcomes == {
        "deploy_staging": "released",
        "deploy_prod": "out_of_scope",
        "canary_prod": "released",
        "canary_staging": "out_of_scope",
        "restart_staging": "cost_over_call_cap",
    }
    rows = verified_docket(deployment, docket, capsys)
    released = [(tool, resource) for _, decision, tool, resource, _ in rows if decision == "release"]
    assert released == [CALLS["deploy_staging"], CALLS["canary_prod"]]
    assert sorted(row[4] for row in rows if row[1] == "refuse") == [
        "cost_over_call_cap",
        "out_of_scope",
        "out_of_scope",
    ]


def test_a_narrowing_child_is_accepted_and_a_widening_one_is_refused_at_both_ends(running, deployment, docket, capsys):
    running(decide_cutoff=0)
    holder = issue_task(deployment, PAIRED, max_depth=1)
    links = holder.delegate(
        CHILD_KEY.public_key(), scope={"permissions": [DEPLOY]}, budget=10, ttl=300, now=int(time.time())
    )
    child = Holder(holder.task_root, links, CHILD_KEY, DECIDER)
    assert call(deployment, child, "deploy_staging") == "released"
    assert call(deployment, child, "canary_prod") == "out_of_scope"
    widening = {"permissions": [{**DEPLOY, "resources": ["env/prod/*"]}]}
    with pytest.raises(ValueError, match="does not narrow"):
        holder.delegate(CHILD_KEY.public_key(), scope=widening, budget=10, ttl=300, now=int(time.time()))
    narrowed = child.leaf
    forged = replace(narrowed, scope=widening, proof="")
    forged = replace(forged, proof=b64u(holder.key.sign(forged.signing_bytes())))
    assert call(deployment, Holder(holder.task_root, (forged.encode(),), CHILD_KEY, DECIDER), "deploy_prod") == (
        "chain_invalid"
    )
    verified_docket(deployment, docket, capsys)


def test_a_v1_root_issued_before_a_shared_cutoff_is_released(running, deployment, docket, capsys):
    now = int(time.time())
    running(decide_cutoff=now + 3600)
    assert call(deployment, v1_holder(now - 5), "deploy_staging") == "released"
    assert [row[:2] for row in verified_docket(deployment, docket, capsys)] == [
        ("decide.example", "allow"),
        ("custodian.example", "release"),
    ]


def test_a_v1_root_issued_after_a_shared_cutoff_is_refused_before_the_custodian(running, deployment, docket, capsys):
    now = int(time.time())
    running(decide_cutoff=now - 60)
    assert call(deployment, v1_holder(now - 5), "deploy_staging") == "chain_invalid"
    assert all(row[0] != "custodian.example" for row in verified_docket(deployment, docket, capsys))


def test_a_custodian_cutoff_ahead_of_decide_dockets_the_chain_refusal(running, deployment, docket, capsys):
    now = int(time.time())
    running(decide_cutoff=now + 3600, custodian_cutoff=now - 60)
    assert call(deployment, v1_holder(now - 5), "deploy_staging") == "custodian release_refused"
    rows = verified_docket(deployment, docket, capsys)
    assert ("custodian.example", "refuse", *CALLS["deploy_staging"], "chain_refused") in rows
