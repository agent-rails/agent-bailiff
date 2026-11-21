import json
import shutil
import subprocess
from pathlib import Path

import pytest

COMPOSE_FILE = Path(__file__).resolve().parents[1] / "examples" / "quickstart" / "compose.yaml"
EGRESS = {"jaeger": {"trace-ui"}, "gitea-mcp-spike": {"spike"}}
PUBLISHED = {"jaeger", "gitea-mcp-spike"}
GITEA_MCP = ("gitea-mcp", "gitea-mcp-spike")

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


def test_only_jaeger_and_the_spike_reach_a_routable_network(config):
    internal = {name for name, network in config["networks"].items() if network.get("internal")}
    routable = {
        name: set(service.get("networks", {})) - internal
        for name, service in config["services"].items()
        if service.get("network_mode") != "none"
    }
    assert {name: networks for name, networks in routable.items() if networks} == EGRESS
    assert config["networks"]["upstream"]["internal"] is True


def test_only_jaeger_and_the_spike_publish_a_port(config):
    published = {name for name, service in config["services"].items() if service.get("ports")}
    assert published == PUBLISHED
    for name in PUBLISHED:
        assert {port["host_ip"] for port in config["services"][name]["ports"]} == {"127.0.0.1"}


def test_the_spike_runs_only_under_its_profile(config):
    assert config["services"]["gitea-mcp-spike"]["profiles"] == ["spike"]
    assert "profiles" not in config["services"]["gitea-mcp"]


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
