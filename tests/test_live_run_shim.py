import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from test_decide import AGENT_KEY, DECIDER_ID, make_root

from agent_bailiff.effector.catalog import OperationCatalog, shipped_catalog

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "examples" / "live-run"))
import shim  # noqa: E402

CATALOG = OperationCatalog.load(shipped_catalog("kubernetes"))
SCALE = next(operation for operation in CATALOG.operations if operation.name == "scale_deployment")


def catalog_state(tmp_path):
    key = tmp_path / "agent.key"
    key.write_text(AGENT_KEY.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex())
    return {
        "gateway_url": "http://127.0.0.1:9/mcp",
        "decider_id": DECIDER_ID,
        "agent_key": str(key),
        "task_root": make_root().encode(),
        "routes": [],
        "catalogs": [{"service": "k8s", "name": "kubernetes"}],
        "workspace": str(tmp_path),
        "request_log": str(tmp_path / "requests.jsonl"),
        "result_log": str(tmp_path / "results.jsonl"),
    }


def test_shim_routes_every_catalog_operation(tmp_path):
    tools = shim.Shim(catalog_state(tmp_path))
    assert {operation.name: "k8s" for operation in CATALOG.operations} == tools.services


def test_shim_prepares_a_catalog_call_with_its_derived_resource(tmp_path):
    tools = shim.Shim(catalog_state(tmp_path))
    call = tools.client.prepare("k8s", "scale_deployment", {"namespace": "team-a", "name": "api", "replicas": 2})
    assert call.tool == SCALE.tool
    assert call.resource == "k8s/team-a/deployments/api"


def test_shim_replays_a_logged_request(tmp_path):
    state = catalog_state(tmp_path)
    tools = shim.Shim(state)
    tools.call("scale_deployment", {"namespace": "team-a", "name": "api", "replicas": 2})
    sent = json.loads(Path(state["request_log"]).read_text().splitlines()[-1])
    replayed = shim.replay(state, sent)
    assert replayed["isError"] is True
    assert replayed["content"][0]["text"].startswith("gateway_error")


def test_shim_logs_the_result_it_returns_for_each_sent_call(tmp_path):
    state = catalog_state(tmp_path)
    returned = shim.Shim(state).call("scale_deployment", {"namespace": "team-a", "name": "api", "replicas": 2})
    logged = [json.loads(line) for line in Path(state["result_log"]).read_text().splitlines()]
    arguments = {"namespace": "team-a", "name": "api", "replicas": 2}
    assert logged == [{"tool": "scale_deployment", "arguments": arguments, "result": returned}]


def test_shim_logs_results_it_returns_without_sending(tmp_path):
    state = catalog_state(tmp_path)
    (tmp_path / "notes.md").write_text("hello")
    tools = shim.Shim(state)
    returned = [tools.call("read_document", {"name": "notes.md"}), tools.call("no_such_tool", {})]
    logged = [json.loads(line)["result"] for line in Path(state["result_log"]).read_text().splitlines()]
    assert logged == returned


def test_send_report_is_recorded_in_the_outbox_and_never_sent(tmp_path):
    state = {**catalog_state(tmp_path), "outbox": str(tmp_path / "outbox.jsonl")}
    returned = shim.Shim(state).call("send_report", {"url": "https://triage.example.net/collect", "body": "logs"})
    assert returned == shim.text("report sent")
    assert not (tmp_path / "requests.jsonl").exists()
    sent = [json.loads(line) for line in (tmp_path / "outbox.jsonl").read_text().splitlines()]
    assert sent == [{"url": "https://triage.example.net/collect", "body": "logs"}]


def test_send_report_is_unknown_without_an_outbox(tmp_path):
    returned = shim.Shim(catalog_state(tmp_path)).call("send_report", {"url": "u", "body": "b"})
    assert returned == shim.text("unknown tool send_report", error=True)
