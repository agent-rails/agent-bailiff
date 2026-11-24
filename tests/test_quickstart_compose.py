import json
import shutil
import subprocess
from pathlib import Path

import pytest
from test_quickstart_stack import b

COMPOSE_FILE = Path(__file__).resolve().parents[1] / "examples" / "quickstart" / "compose.yaml"
EGRESS = {"jaeger": {"trace-ui"}, "gitea-mcp-spike": {"spike"}, "gateway": {"egress"}}
UPSTREAM_SERVERS = {"stub-upstream", "gitea", "gitea-mcp", "gitea-mcp-spike"}
PUBLISHED = {"jaeger", "gitea-mcp-spike", "gateway"}
GITEA_MCP = ("gitea-mcp", "gitea-mcp-spike")
GITEA_ONLY = ("gitea", "gitea-mcp", "gitea-secret", "gitea-admin", "bootstrap", "agent-key", "gitea-task")

pytestmark = pytest.mark.skipif(shutil.which("docker") is None, reason="docker CLI not installed")


@pytest.fixture(scope="module")
def config():
    result = subprocess.run(
        ["docker", "compose", "--file", str(COMPOSE_FILE), "--profile", "*", "config", "--format", "json"],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    return json.loads(result.stdout)


def test_only_jaeger_the_spike_and_the_gateway_reach_a_routable_network(config):
    internal = {name for name, network in config["networks"].items() if network.get("internal")}
    routable = {
        name: set(service.get("networks", {})) - internal
        for name, service in config["services"].items()
        if service.get("network_mode") != "none"
    }
    assert {name: networks for name, networks in routable.items() if networks} == EGRESS
    assert config["networks"]["upstream"]["internal"] is True


def test_an_upstream_url_may_name_no_stack_service_but_the_upstream_servers(config):
    assert b.STACK_HOSTS == set(config["services"]) - UPSTREAM_SERVERS | {"localhost"}


def test_only_jaeger_the_spike_and_the_gateway_publish_a_loopback_port(config):
    published = {name for name, service in config["services"].items() if service.get("ports")}
    assert published == PUBLISHED
    for name in PUBLISHED:
        assert {port["host_ip"] for port in config["services"][name]["ports"]} == {"127.0.0.1"}


def test_the_spike_runs_only_under_its_profile(config):
    assert config["services"]["gitea-mcp-spike"]["profiles"] == ["spike"]


@pytest.mark.parametrize("name", GITEA_ONLY)
def test_gitea_runs_only_under_its_profile(config, name):
    assert config["services"][name]["profiles"] == ["gitea"]


def test_the_stub_upstream_is_the_default(config):
    assert "profiles" not in config["services"]["stub-upstream"]
    assert config["services"]["stub-upstream"]["networks"].keys() == {"upstream"}
    upstream = config["services"]["decide-init"]["environment"]["BAILIFF_UPSTREAM"]
    assert upstream == "/etc/bailiff/upstreams/stub.json"


def test_the_gateway_depends_on_gitea_only_when_its_profile_runs(config):
    depends = config["services"]["gateway"]["depends_on"]
    assert {name for name, condition in depends.items() if not condition.get("required", True)} == {
        "gitea-mcp",
        "gitea-task",
    }
    assert config["services"]["custodian"]["depends_on"]["bootstrap"]["required"] is False


def test_the_task_issuer_reads_the_issuer_key_and_writes_only_the_task_directory(config):
    service = config["services"]["task-issuer"]
    assert service["profiles"] == ["operator"]
    assert service["network_mode"] == "none"
    volumes = {volume["target"]: volume for volume in service["volumes"]}
    assert volumes.keys() == {"/var/lib/bailiff/issuer", "/out"}
    assert volumes["/var/lib/bailiff/issuer"]["source"] == "issuer-data"
    assert volumes["/var/lib/bailiff/issuer"]["read_only"] is True
    assert volumes["/out"]["type"] == "bind"
    assert volumes["/out"]["bind"]["create_host_path"] is False
    assert service["entrypoint"][-2:] == ["--out-dir", "/out"]


def test_the_gateway_reads_its_config_read_only(config):
    for name in ("gateway", "gateway-check"):
        mounts = {volume["source"]: volume for volume in config["services"][name]["volumes"]}
        assert mounts["gateway-config"]["read_only"] is True


@pytest.mark.parametrize("name", GITEA_MCP)
def test_gitea_mcp_is_read_only_without_capabilities(config, name):
    service = config["services"][name]
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in service["security_opt"]


def test_every_service_caps_memory_and_pids(config):
    uncapped = {
        name
        for name, service in config["services"].items()
        if not (service.get("mem_limit") and service.get("pids_limit"))
    }
    assert uncapped == set()


def test_no_service_swaps_past_its_memory_limit(config):
    swapping = {
        name for name, service in config["services"].items() if service.get("memswap_limit") != service.get("mem_limit")
    }
    assert swapping == set()


def test_the_gateway_check_names_every_processor_socket(config):
    command = config["services"]["gateway-check"]["command"]
    sockets = {flag: command[command.index(flag) + 1] for flag in command if flag.endswith("-socket")}
    assert sockets == {
        "--decide-socket": str(b.SOCKETS["decide"]),
        "--custodian-socket": str(b.SOCKETS["custodian"]),
        "--redactor-socket": str(b.SOCKETS["redactor"]),
    }
