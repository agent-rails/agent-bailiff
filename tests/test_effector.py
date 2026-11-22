import base64
import json
import os
import threading
import urllib.error
import urllib.request
from dataclasses import asdict, replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_bailiff.custodian.release import ReleaseSigner
from agent_bailiff.decide.clearance import Clearance, encode_clearance
from agent_bailiff.decide.identity import snapshot_args
from agent_bailiff.docket.entry import Record
from agent_bailiff.docket.sink import VerifiedLine
from agent_bailiff.docket.tasks import TaskList
from agent_bailiff.effector.catalog import OperationCatalog
from agent_bailiff.effector.kubernetes import KubernetesClient, KubernetesUnavailable, project, request_path
from agent_bailiff.effector.release import ReleaseCheck, ReleaseCheckConfig, ReleaseRefused
from agent_bailiff.effector.server import Effector, EffectorConfig, EffectorServer

NOW = 1_800_000_000
CATALOG = OperationCatalog.load(
    Path(__file__).resolve().parent.parent / "agent_bailiff" / "effector" / "catalogs" / "kubernetes.json"
)
DECIDE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(20, 52)))
CUSTODIAN_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(21, 53)))
CONFIG = ReleaseCheckConfig(
    effector_id="effector.homelab",
    custodian_id="custodian.example",
    decider_id="decide.example",
    custodian_keys={"custodian-1": CUSTODIAN_KEY.public_key()},
    decide_keys={"decide-1": DECIDE_KEY.public_key()},
    skew_seconds=5,
    max_clearance_lifetime=60,
)
SCALE_ARGS = {"namespace": "staging", "name": "api", "replicas": 3}


def service_account_token(name, lifetime=600, issued_at=NOW):
    def part(document):
        return base64.urlsafe_b64encode(json.dumps(document).encode()).rstrip(b"=").decode()

    claims = {"sub": f"system:serviceaccount:bailiff-system:{name}", "iat": issued_at, "exp": issued_at + lifetime}
    return f"{part({'alg': 'RS256'})}.{part(claims)}.c2ln"


EFFECTOR_TOKEN = service_account_token("effector")
AUDIT_TOKEN = service_account_token("effector-audit")


def clearance_for(name="scale_deployment", arguments=None, **overrides):
    arguments = SCALE_ARGS if arguments is None else arguments
    operation = CATALOG.operation(name)
    fields = {
        "iss": "decide.example",
        "aud": "custodian.example",
        "iat": NOW,
        "exp": NOW + 60,
        "op_id": f"op-{name}-{arguments.get('replicas', 0)}",
        "tenant": "tenant-a",
        "task": "task-1",
        "root_binding": "r" * 43,
        "leaf_binding": "l" * 43,
        "request_digest": "q" * 43,
        "tool": operation.tool,
        "resource": operation.resource.format(**{k: arguments[k] for k in ("namespace", "name") if k in arguments}),
        "args_digest": snapshot_args(arguments).digest,
        "cost": 1,
        "credential_id": "effector.homelab",
        "target": "cluster.homelab",
        "trace_id": "t" * 32,
        "entry_id": "e" * 32,
    }
    fields.update(overrides)
    return Clearance(**fields)


def release_for(clearance=None, catalog=CATALOG.digest, audience="effector.homelab", now=NOW + 1):
    clearance = clearance or clearance_for()
    token = encode_clearance(clearance, DECIDE_KEY, "decide-1")
    signer = ReleaseSigner("custodian.example", CUSTODIAN_KEY, "custodian-1")
    return signer.sign(clearance, token, audience, catalog, "f" * 32, now)


class FakeTransport:
    def __init__(self, status=200, body=b'{"spec": {"replicas": 3}, "status": {"replicas": 1}}', error=None):
        self.status, self.body, self.error = status, body, error
        self.requests = []

    def request(self, method, path, headers, body):
        self.requests.append((method, path, dict(headers), body))
        if self.error:
            raise self.error
        return self.status, self.body


class RecordingDocket:
    def __init__(self, fail_on=()):
        self.entries = []
        self.fail_on = fail_on

    def append(self, entry):
        if entry.decision in self.fail_on:
            raise ConnectionError("docket down")
        self.entries.append(entry)
        return Record(writer="effector.homelab", seq=len(self.entries), prev=None, entry=entry, kid="k", token="t")


class Verified:
    def __init__(self, value=True):
        self.value = value

    def healthy(self, now):
        return self.value

    def restart_healthy(self, now):
        return self.value and self.restart

    def write_healthy(self, now):
        return self.value and self.write

    restart = True
    write = True


class Suspended:
    def __init__(self, value=False):
        self.suspended = value


@pytest.fixture
def token_file(tmp_path):
    path = tmp_path / "token"
    path.write_text(EFFECTOR_TOKEN + "\n")
    os.chmod(path, 0o600)
    return path


def effector(token_file, transport=None, docket=None, suspended=False, rbac_healthy=True, started_at=NOW - 1):
    transport = transport or FakeTransport()
    docket = docket or RecordingDocket()
    instance = Effector(
        EffectorConfig("effector.homelab", "effector.homelab"),
        CATALOG,
        ReleaseCheck(CONFIG, CATALOG, started_at),
        KubernetesClient(transport, token_file),
        Suspended(suspended),
        docket,
        Verified(rbac_healthy),
    )
    return instance, transport, docket


def scale_params(arguments=None):
    return {"name": "scale_deployment", "arguments": SCALE_ARGS if arguments is None else arguments}


def test_a_released_scale_call_patches_the_scale_subresource_as_the_synthetic_user(token_file):
    instance, transport, docket = effector(token_file)
    result = instance.call(scale_params(), release_for(), NOW + 2)
    assert result["isError"] is False
    assert json.loads(result["content"][0]["text"]) == {"spec.replicas": 3, "status.replicas": 1}
    [(method, path, headers, body)] = transport.requests
    assert (method, path) == ("PATCH", "/apis/apps/v1/namespaces/staging/deployments/api/scale")
    assert json.loads(body) == {"spec": {"replicas": 3}}
    assert headers["Impersonate-User"] == "bailiff:tenant-a:scale"
    assert headers["Impersonate-Extra-bailiff.dev%2Fop-id"] == "op-scale_deployment-3"
    assert headers["Authorization"] == f"Bearer {EFFECTOR_TOKEN}"
    assert headers["Content-Type"] == "application/merge-patch+json"
    assert [(entry.decision, entry.outcome) for entry in docket.entries] == [("attempt", None), ("outcome", "done")]
    assert docket.entries[1].parent_entry == docket.entries[0].entry_id
    assert docket.entries[1].performed is True


def test_reads_are_built_from_pinned_fields_and_projected(token_file):
    pod = {
        "metadata": {"name": "p1", "labels": {"a": "b"}},
        "status": {"phase": "Running"},
        "spec": {"nodeName": "n1", "containers": [{"env": [{"value": "secret"}]}]},
    }
    body = json.dumps({"items": [pod]}).encode()
    instance, transport, _ = effector(token_file, FakeTransport(body=body))
    arguments = {"namespace": "staging", "limit": 5}
    clearance = clearance_for("list_pods", arguments)
    result = instance.call({"name": "list_pods", "arguments": arguments}, release_for(clearance), NOW + 2)
    assert json.loads(result["content"][0]["text"]) == [
        {"metadata.name": "p1", "status.phase": "Running", "spec.nodeName": "n1"}
    ]
    assert transport.requests[0][:2] == ("GET", "/api/v1/namespaces/staging/pods?limit=5")
    assert "secret" not in result["content"][0]["text"]


def test_a_log_read_is_truncated_text(token_file):
    instance, transport, _ = effector(token_file, FakeTransport(body=b"x" * 70000))
    arguments = {"namespace": "staging", "name": "p1", "tailLines": 10}
    clearance = clearance_for("read_pod_log", arguments)
    result = instance.call({"name": "read_pod_log", "arguments": arguments}, release_for(clearance), NOW + 2)
    assert len(result["content"][0]["text"]) == 65536
    assert transport.requests[0][1] == "/api/v1/namespaces/staging/pods/p1/log?tailLines=10"


@pytest.mark.parametrize(
    ("params", "release", "reason"),
    [
        (scale_params(), None, "release_malformed"),
        (scale_params(), "garbage", "release_malformed"),
        (scale_params(), release_for(audience="other"), "release_wrong_audience"),
        (scale_params(), release_for(catalog="z" * 43), "catalog_mismatch"),
        (scale_params(), release_for(now=NOW - 100), "release_expired"),
        (scale_params({**SCALE_ARGS, "replicas": 4}), release_for(), "arguments_mismatch"),
        (scale_params({**SCALE_ARGS, "namespace": "prod"}), release_for(), "resource_mismatch"),
        (scale_params({**SCALE_ARGS, "replicas": 11}), release_for(), "malformed_arguments"),
        (scale_params({**SCALE_ARGS, "kind": "StatefulSet"}), release_for(), "malformed_arguments"),
        (
            {"name": "get_deployment", "arguments": {"namespace": "staging", "name": "api"}},
            release_for(),
            "unknown_operation",
        ),
        ({"name": "scale_deployment", "arguments": SCALE_ARGS, "extra": 1}, release_for(), "malformed_request"),
    ],
)
def test_calls_that_do_not_match_their_release_are_refused_before_kubernetes(token_file, params, release, reason):
    instance, transport, docket = effector(token_file)
    result = instance.call(params, release, NOW + 2)
    assert result == {"content": [{"type": "text", "text": reason}], "isError": True}
    assert transport.requests == [] and docket.entries == []


def test_a_clearance_that_disagrees_with_its_release_is_refused(token_file):
    clearance = clearance_for()
    token = encode_clearance(replace(clearance, resource="k8s/prod/deployments/api"), DECIDE_KEY, "decide-1")
    release = ReleaseSigner("custodian.example", CUSTODIAN_KEY, "custodian-1").sign(
        clearance, token, "effector.homelab", CATALOG.digest, "f" * 32, NOW + 1
    )
    instance, transport, _ = effector(token_file)
    assert instance.call(scale_params(), release, NOW + 2)["content"][0]["text"] == "clearance_mismatch"
    assert transport.requests == []


def test_a_release_signed_by_an_unpinned_key_is_refused(token_file):
    clearance = clearance_for()
    token = encode_clearance(clearance, DECIDE_KEY, "decide-1")
    forged = ReleaseSigner("custodian.example", Ed25519PrivateKey.generate(), "custodian-1").sign(
        clearance, token, "effector.homelab", CATALOG.digest, "f" * 32, NOW + 1
    )
    instance, transport, _ = effector(token_file)
    assert instance.call(scale_params(), forged, NOW + 2)["content"][0]["text"] == "release_bad_signature"


def test_a_release_is_used_once(token_file):
    instance, transport, _ = effector(token_file)
    release = release_for()
    assert instance.call(scale_params(), release, NOW + 2)["isError"] is False
    assert instance.call(scale_params(), release, NOW + 3)["content"][0]["text"] == "release_replayed"
    assert len(transport.requests) == 1


def test_verifying_a_release_claims_nothing():
    check = ReleaseCheck(CONFIG, CATALOG, NOW - 1)
    release = release_for()
    checked = check.verify("scale_deployment", SCALE_ARGS, release, NOW + 2)
    assert check.verify("scale_deployment", SCALE_ARGS, release, NOW + 2) == checked
    check.claim(checked, NOW + 2)
    assert check.verify("scale_deployment", SCALE_ARGS, release, NOW + 3) == checked
    with pytest.raises(ReleaseRefused, match="release_replayed"):
        check.claim(checked, NOW + 3)


def test_a_verified_release_from_before_the_start_is_refused_at_claim():
    check = ReleaseCheck(CONFIG, CATALOG, NOW + 1)
    checked = check.verify("scale_deployment", SCALE_ARGS, release_for(now=NOW + 1), NOW + 3)
    with pytest.raises(ReleaseRefused, match="release_predates_start"):
        check.claim(checked, NOW + 3)


def test_a_suspended_or_unreadable_suspension_refuses_before_any_check(token_file):
    instance, transport, docket = effector(token_file, suspended=True)
    assert instance.call(scale_params(), release_for(), NOW + 2)["content"][0]["text"] == "suspended"
    instance, transport, docket = effector(token_file, suspended=None)
    assert instance.call(scale_params(), release_for(), NOW + 2)["content"][0]["text"] == "suspended"
    assert transport.requests == [] and docket.entries == []


def test_no_call_is_made_without_an_acknowledged_attempt_entry(token_file):
    instance, transport, _ = effector(token_file, docket=RecordingDocket(fail_on=("attempt",)))
    assert instance.call(scale_params(), release_for(), NOW + 2)["content"][0]["text"] == "docket_unavailable"
    assert transport.requests == []


def test_a_timeout_or_missing_outcome_entry_is_outcome_unknown_never_success(token_file):
    instance, _, docket = effector(token_file, FakeTransport(error=KubernetesUnavailable("timed out")))
    assert instance.call(scale_params(), release_for(), NOW + 2)["content"][0]["text"] == "outcome_unknown"
    assert docket.entries[-1].outcome == "outcome_unknown"
    instance, transport, _ = effector(token_file, docket=RecordingDocket(fail_on=("outcome",)))
    assert instance.call(scale_params(), release_for(), NOW + 2)["content"][0]["text"] == "outcome_unknown"
    assert len(transport.requests) == 1


def test_kubernetes_refusals_and_server_errors_are_recorded(token_file):
    instance, _, docket = effector(token_file, FakeTransport(status=403, body=b"{}"))
    assert instance.call(scale_params(), release_for(), NOW + 2)["content"][0]["text"] == "kubernetes_403"
    assert (docket.entries[-1].outcome, docket.entries[-1].performed) == ("refused", False)
    instance, _, docket = effector(token_file, FakeTransport(status=503, body=b"{}"))
    assert instance.call(scale_params(), release_for(), NOW + 2)["content"][0]["text"] == "outcome_unknown"


def test_tools_list_publishes_strict_schemas(token_file):
    instance, _, _ = effector(token_file)
    tools = {tool["name"]: tool for tool in instance.tools()}
    schema = tools["scale_deployment"]["inputSchema"]
    assert schema["additionalProperties"] is False
    assert schema["required"] == ["name", "namespace", "replicas"]
    assert schema["properties"]["replicas"] == {"type": "integer", "minimum": 1, "maximum": 10}


def test_request_paths_and_projection_use_only_catalog_fields():
    operation = CATALOG.operation("get_deployment")
    assert request_path(operation, {"namespace": "a", "name": "b"}) == "/apis/apps/v1/namespaces/a/deployments/b"
    assert project(operation, {"metadata": {"name": "b", "annotations": {"x": "y"}}, "spec": {"replicas": 2}}) == {
        "metadata.name": "b",
        "spec.replicas": 2,
        "status.replicas": None,
        "status.readyReplicas": None,
        "status.updatedReplicas": None,
    }


def post(port, message, headers=None):
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/mcp",
        json.dumps(message).encode(),
        {"Content-Type": "application/json", **(headers or {})},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            data = response.read()
            return response.status, json.loads(data) if data else None
    except urllib.error.HTTPError as error:
        return error.code, None


def test_the_mcp_server_serves_session_methods_and_calls_on_localhost(token_file):
    instance, transport, _ = effector(token_file)
    server = EffectorServer(instance, 0, clock=lambda: NOW + 2)
    server.start()
    port = server.server_address[1]
    try:
        assert server.server_address[0] == "127.0.0.1"
        status, body = post(port, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        assert status == 200 and body["result"]["serverInfo"]["name"] == "agent-bailiff-effector"
        assert post(port, {"jsonrpc": "2.0", "method": "notifications/initialized"})[0] == 202
        status, body = post(port, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        assert len(body["result"]["tools"]) == 5
        status, body = post(
            port,
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": scale_params()},
            {"bailiff-release": release_for()},
        )
        assert body["result"]["isError"] is False and len(transport.requests) == 1
        status, body = post(port, {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": scale_params()})
        assert body["result"]["content"][0]["text"] == "release_malformed"
        assert post(port, {"jsonrpc": "2.0", "id": 5, "method": "initialize"}, {"Origin": "http://evil"})[0] == 403
        assert post(port, [{"jsonrpc": "2.0", "id": 6, "method": "ping"}])[0] == 400
    finally:
        server.close()


def test_the_checked_fields_cover_the_release(token_file):
    assert {"op_id", "tenant", "task", "tool", "resource", "args_digest"} <= set(asdict(clearance_for()))


class SuspendAfterChecks:
    def __init__(self):
        self.reads = 0

    @property
    def suspended(self):
        self.reads += 1
        return self.reads > 1


def test_a_suspension_set_after_the_checks_stops_the_call(token_file):
    instance, transport, docket = effector(token_file)
    instance._suspension = SuspendAfterChecks()
    assert instance.call(scale_params(), release_for(), NOW + 2)["content"][0]["text"] == "suspended"
    assert transport.requests == []
    assert [(entry.decision, entry.outcome, entry.reason) for entry in docket.entries] == [
        ("attempt", None, None),
        ("outcome", "refused", "suspended"),
    ]


def test_an_unreadable_token_file_is_recorded_as_outcome_unknown(token_file):
    os.chmod(token_file, 0o644)
    instance, transport, docket = effector(token_file)
    assert instance.call(scale_params(), release_for(), NOW + 2)["content"][0]["text"] == "outcome_unknown"
    assert transport.requests == []
    assert docket.entries[-1].outcome == "outcome_unknown"


def test_an_unexpected_client_failure_is_recorded_as_outcome_unknown(token_file):
    instance, _, docket = effector(token_file, FakeTransport(error=RuntimeError("bug")))
    assert instance.call(scale_params(), release_for(), NOW + 2)["content"][0]["text"] == "outcome_unknown"
    assert docket.entries[-1].outcome == "outcome_unknown"


def test_a_json_response_over_the_catalog_limit_is_not_returned(token_file):
    pods = [{"metadata": {"name": "p" * 60}, "status": {"phase": "Running"}} for _ in range(2000)]
    instance, _, docket = effector(token_file, FakeTransport(body=json.dumps({"items": pods}).encode()))
    arguments = {"namespace": "staging", "limit": 5}
    result = instance.call(
        {"name": "list_pods", "arguments": arguments}, release_for(clearance_for("list_pods", arguments)), NOW + 2
    )
    assert result["content"][0]["text"] == "response_too_large"
    assert docket.entries[-1].outcome == "done"


TASK_HANDLES = {"tenant": "tenant-a", "task": "task-1"}


def refusals(docket):
    return [
        (entry.decision, entry.outcome, entry.reason, entry.parent_entry, dict(entry.handles))
        for entry in docket.entries
    ]


def test_no_call_is_made_while_rbac_is_unverified(token_file):
    instance, transport, docket = effector(token_file, rbac_healthy=False)
    assert instance.call(scale_params(), release_for(), NOW + 2)["content"][0]["text"] == "rbac_unverified"
    assert transport.requests == []
    assert refusals(docket) == [("refuse", None, "rbac_unverified", "f" * 32, TASK_HANDLES)]


def test_an_effector_refusal_counts_against_its_task(token_file):
    instance, _, docket = effector(token_file, rbac_healthy=False)
    instance.call(scale_params(), release_for(), NOW + 2)
    [entry] = docket.entries
    verified = VerifiedLine(1, Record("effector.homelab", 1, None, entry, "k", "t"), 0, 2)
    tasks = TaskList(frozenset({"control.example"}))
    tasks.add(verified)
    [row] = tasks.rows()
    assert (row.tenant, row.task, row.refusals, row.allows) == ("tenant-a", "task-1", 1, 0)


def test_a_release_refused_after_its_claim_is_consumed(token_file):
    instance, transport, docket = effector(token_file, rbac_healthy=False)
    release = release_for()
    assert instance.call(scale_params(), release, NOW + 2)["content"][0]["text"] == "rbac_unverified"
    instance._rbac.value = True
    assert instance.call(scale_params(), release, NOW + 3)["content"][0]["text"] == "release_replayed"
    assert transport.requests == [] and len(docket.entries) == 1


def test_a_release_that_fails_verification_is_refused_before_rbac_health_and_not_recorded(token_file):
    instance, transport, docket = effector(token_file, rbac_healthy=False)
    release = release_for(audience="effector.other")
    assert instance.call(scale_params(), release, NOW + 2)["content"][0]["text"] == "release_wrong_audience"
    assert transport.requests == [] and docket.entries == []


def test_replaying_a_refused_release_records_one_refusal(token_file):
    instance, transport, docket = effector(token_file, rbac_healthy=False)
    release = release_for()
    reasons = [instance.call(scale_params(), release, NOW + 2)["content"][0]["text"] for _ in range(1000)]
    assert reasons[0] == "rbac_unverified" and set(reasons[1:]) == {"release_replayed"}
    assert transport.requests == [] and len(docket.entries) == 1


def test_a_busy_or_early_claim_is_logged_and_not_recorded(token_file, monkeypatch):
    monkeypatch.setattr("agent_bailiff.effector.release.MAX_TRACKED_RELEASES", 1)
    instance, transport, docket = effector(token_file)
    assert instance.call(scale_params(), release_for(), NOW + 2)["isError"] is False
    busy = release_for(clearance_for(op_id="op-busy"))
    assert instance.call(scale_params(), busy, NOW + 2)["content"][0]["text"] == "effector_busy"
    early, _, early_docket = effector(token_file, started_at=NOW + 1)
    assert early.call(scale_params(), release_for(), NOW + 2)["content"][0]["text"] == "release_predates_start"
    assert [entry.decision for entry in docket.entries] == ["attempt", "outcome"] and early_docket.entries == []


def test_concurrent_calls_with_one_release_perform_it_once(token_file):
    instance, transport, docket = effector(token_file)
    release = release_for()
    barrier = threading.Barrier(16)
    results = []

    def call():
        barrier.wait()
        results.append(instance.call(scale_params(), release, NOW + 2))

    threads = [threading.Thread(target=call) for _ in range(16)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sum(result["isError"] is False for result in results) == 1
    assert {result["content"][0]["text"] for result in results if result["isError"]} == {"release_replayed"}
    assert len(transport.requests) == 1


@pytest.mark.parametrize("started_at", [NOW + 1, NOW + 2])
def test_a_release_issued_before_or_in_the_second_the_effector_started_is_refused(token_file, started_at):
    instance, transport, _ = effector(token_file, started_at=started_at)
    assert (
        instance.call(scale_params(), release_for(now=NOW + 1), NOW + 3)["content"][0]["text"]
        == "release_predates_start"
    )
    assert transport.requests == []


@pytest.mark.parametrize("status", [302, 304])
def test_a_redirect_is_never_reported_as_success(token_file, status):
    instance, _, docket = effector(token_file, FakeTransport(status=status, body=b'{"spec": {"replicas": 3}}'))
    assert instance.call(scale_params(), release_for(), NOW + 2)["content"][0]["text"] == "outcome_unknown"
    assert (docket.entries[-1].outcome, docket.entries[-1].performed) == ("outcome_unknown", False)


class FakeResponse:
    def __init__(self, status, size):
        self.status, self.size = status, size

    def read(self, limit):
        return b"x" * min(self.size, limit)


class FakeConnection:
    response = None

    def __init__(self, *args, **kwargs):
        pass

    def request(self, *args, **kwargs):
        pass

    def getresponse(self):
        return FakeConnection.response

    def close(self):
        pass


@pytest.mark.parametrize(("status", "expected"), [(403, (403, b"")), (500, (500, b""))])
def test_the_transport_returns_a_non_2xx_status_without_reading_its_body(monkeypatch, tmp_path, status, expected):
    from agent_bailiff.effector import kubernetes

    monkeypatch.setattr(kubernetes.ssl, "create_default_context", lambda cafile: None)
    monkeypatch.setattr(kubernetes.http.client, "HTTPSConnection", FakeConnection)
    FakeConnection.response = FakeResponse(status, 4 << 20)
    transport = kubernetes.HttpsTransport("127.0.0.1", 6443, tmp_path / "ca.crt")
    assert transport.request("GET", "/api", {}, None) == expected


def test_the_transport_refuses_an_oversized_2xx_body(monkeypatch, tmp_path):
    from agent_bailiff.effector import kubernetes

    monkeypatch.setattr(kubernetes.ssl, "create_default_context", lambda cafile: None)
    monkeypatch.setattr(kubernetes.http.client, "HTTPSConnection", FakeConnection)
    FakeConnection.response = FakeResponse(200, 4 << 20)
    with pytest.raises(KubernetesUnavailable, match="larger than the limit"):
        kubernetes.HttpsTransport("127.0.0.1", 6443, tmp_path / "ca.crt").request("GET", "/api", {}, None)


class PooledResponse:
    def __init__(self, status=200, body=b"{}", will_close=False):
        self.status, self.body, self.will_close = status, body, will_close

    def read(self, limit):
        return self.body[:limit]

    def isclosed(self):
        return True


class PooledConnection:
    opened = []

    def __init__(self, *args, **kwargs):
        self.responses, self.closed, self.sent = [], False, 0
        PooledConnection.opened.append(self)

    def request(self, *args, **kwargs):
        self.sent += 1
        if not self.responses:
            raise ConnectionResetError("stale")

    def getresponse(self):
        return self.responses.pop(0)

    def close(self):
        self.closed = True


@pytest.fixture
def pooled(monkeypatch, tmp_path):
    from agent_bailiff.effector import kubernetes

    monkeypatch.setattr(kubernetes.ssl, "create_default_context", lambda cafile: None)
    PooledConnection.opened = []

    def connect(*args, **kwargs):
        connection = PooledConnection()
        connection.responses = [PooledResponse() for _ in range(3)]
        return connection

    monkeypatch.setattr(kubernetes.http.client, "HTTPSConnection", connect)
    return kubernetes.PooledTransport("127.0.0.1", 6443, tmp_path / "ca.crt", 2)


def test_the_pooled_transport_reuses_an_idle_connection(pooled):
    assert pooled.request("GET", "/api", {}, None) == (200, b"{}")
    assert pooled.request("GET", "/api", {}, None) == (200, b"{}")
    assert len(PooledConnection.opened) == 1 and PooledConnection.opened[0].sent == 2


def test_the_pooled_transport_retries_a_stale_connection_once_on_a_new_one(pooled):
    pooled.request("GET", "/api", {}, None)
    PooledConnection.opened[0].responses.clear()
    assert pooled.request("GET", "/api", {}, None) == (200, b"{}")
    assert PooledConnection.opened[0].closed and len(PooledConnection.opened) == 2


def test_the_pooled_transport_never_resends_after_a_timeout(pooled, monkeypatch):
    pooled.request("GET", "/api", {}, None)

    def timeout(*args, **kwargs):
        raise TimeoutError("timed out")

    monkeypatch.setattr(PooledConnection.opened[0], "getresponse", timeout)
    with pytest.raises(KubernetesUnavailable, match="timed out"):
        pooled.request("GET", "/api", {}, None)
    assert len(PooledConnection.opened) == 1 and PooledConnection.opened[0].closed


def test_the_pooled_transport_drops_a_connection_the_server_closes_or_that_overflows(pooled):
    pooled.request("GET", "/api", {}, None)
    PooledConnection.opened[0].responses = [PooledResponse(will_close=True)]
    pooled.request("GET", "/api", {}, None)
    assert PooledConnection.opened[0].closed
    pooled.request("GET", "/api", {}, None)
    PooledConnection.opened[1].responses = [PooledResponse(body=b"x" * ((1 << 20) + 1))]
    with pytest.raises(KubernetesUnavailable, match="larger than the limit"):
        pooled.request("GET", "/api", {}, None)
    assert PooledConnection.opened[1].closed


def test_closing_the_pooled_transport_closes_idle_connections(pooled):
    pooled.request("GET", "/api", {}, None)
    pooled.close()
    assert PooledConnection.opened[0].closed


def test_a_restart_patches_the_deployment_as_its_own_field_manager_at_the_release_time(token_file):
    from test_effector_catalog import with_restart

    operation = OperationCatalog(with_restart()).operation("restart_deployment")
    transport = FakeTransport(
        body=b'{"metadata": {"name": "api", "generation": 4}, "status": {"observedGeneration": 3}}'
    )
    result = KubernetesClient(transport, token_file).call(
        operation, {"namespace": "staging", "name": "api"}, "tenant-a", "op-1", "t" * 32, NOW, "release"
    )
    [(method, path, headers, body)] = transport.requests
    assert (method, path) == (
        "PATCH",
        "/apis/apps/v1/namespaces/staging/deployments/api?fieldManager=bailiff-effector&force=true",
    )
    assert json.loads(body) == {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "api"},
        "spec": {
            "template": {
                "metadata": {
                    "annotations": {
                        "kubectl.kubernetes.io/restartedAt": "2027-01-15T08:00:00Z",
                        "bailiff.dev/restart-op": "op-1",
                    }
                }
            }
        },
    }
    assert headers["Impersonate-User"] == "bailiff:tenant-a:restart"
    assert headers["Impersonate-Extra-bailiff.dev%2Frelease"] == "release"
    assert headers["Content-Type"] == "application/apply-patch+yaml"
    assert result.payload == {"metadata.name": "api", "metadata.generation": 4, "status.observedGeneration": 3}


def test_a_restart_is_refused_without_a_fresh_schema_check_while_other_calls_run(token_file):
    instance, transport, docket = effector(token_file)
    instance._rbac.restart = False
    arguments = {"namespace": "staging", "name": "api"}
    clearance = clearance_for("restart_deployment", arguments, op_id="op-restart-1")
    result = instance.call({"name": "restart_deployment", "arguments": arguments}, release_for(clearance), NOW + 2)
    assert result["content"][0]["text"] == "restart_unverified"
    assert transport.requests == []
    assert refusals(docket) == [("refuse", None, "restart_unverified", "f" * 32, TASK_HANDLES)]
    assert instance.call(scale_params(), release_for(), NOW + 2)["isError"] is False


def test_a_write_is_refused_without_a_verified_release_webhook_while_reads_run(token_file):
    instance, transport, docket = effector(token_file)
    instance._rbac.write = False
    assert instance.call(scale_params(), release_for(), NOW + 2)["content"][0]["text"] == "webhook_unverified"
    assert transport.requests == []
    assert refusals(docket) == [("refuse", None, "webhook_unverified", "f" * 32, TASK_HANDLES)]
    arguments = {"namespace": "staging", "limit": 5}
    clearance = clearance_for("list_pods", arguments, op_id="op-list-1")
    assert (
        instance.call({"name": "list_pods", "arguments": arguments}, release_for(clearance), NOW + 2)["isError"]
        is False
    )


@pytest.mark.parametrize(
    "token",
    [
        service_account_token("effector", lifetime=601),
        service_account_token("effector", lifetime=31_536_000),
        service_account_token("effector", lifetime=0),
        "effector-token",
        "a.b.c",
        "e30.e30.c2ln",
    ],
)
def test_a_token_that_is_not_short_lived_is_refused_before_any_request(tmp_path, token):
    path = tmp_path / "token"
    path.write_text(token)
    os.chmod(path, 0o600)
    transport = FakeTransport()
    with pytest.raises(KubernetesUnavailable, match="at most 600 seconds"):
        KubernetesClient(transport, path).call(
            CATALOG.operation("list_pods"),
            {"namespace": "staging", "limit": 5},
            "tenant-a",
            "op-1",
            "t" * 32,
            NOW,
        )
    assert transport.requests == []
