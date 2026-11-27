import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from test_issue_certs import certs_module
from test_quickstart_rule import rule_module
from test_quickstart_stack import b

COMPOSE_FILE = Path(__file__).resolve().parents[1] / "examples" / "quickstart" / "compose.yaml"
SIDECAR_CONFIG = COMPOSE_FILE.parent / "gitea-mcp-tls.json"
EGRESS = {"jaeger": {"trace-ui"}, "gitea-mcp-spike": {"spike"}, "gateway": {"egress"}}
PUBLISHED = {"jaeger", "gitea-mcp-spike", "gateway"}
GITEA_MCP = ("gitea-mcp", "gitea-mcp-spike")
GITEA_ONLY = (
    "gitea", "gitea-mcp-tls", "gitea-mcp", "gitea-secret", "gitea-admin", "bootstrap", "agent-key", "gitea-task",
)  # fmt: skip
DOCKET_READERS = ("reader", "archiver", "exporter")
ISSUERS = ("task-issuer", "gitea-task")
CERTS = "/var/lib/bailiff/certs"
CERT_VOLUMES = {
    "certs-public": f"{CERTS}/public",
    **{f"certs-{name}": f"{CERTS}/{name}" for name in certs_module.SERVICES},
}
CERT_MOUNTS = {
    "certs": {(volume, False) for volume in CERT_VOLUMES},
    "cert-watch": {("certs-public", True)},
    "gateway-init": {("certs-public", True)},
    "gateway": {("certs-gateway", True)},
    "agent": {("certs-public", True)},
    "stub-upstream": {("certs-stub-upstream", True)},
    "gitea-mcp-tls": {("certs-gitea-mcp-tls", True)},
    "baseline": {("certs-public", True)},
}
OWN_UIDS = ("certs", "cert-watch", "gitea-mcp-tls", "gitea-mcp")
KEY_GIDS = {f"certs-{leaf}": str(settings.gid) for leaf, settings in certs_module.SERVICES.items()}
STUB_LEAF = f"{CERTS}/stub-upstream/current/stub-upstream"
SIDECAR_LEAF = f"{CERTS}/gitea-mcp-tls/current/gitea-mcp-tls"

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
    assert b.STACK_HOSTS | b.UPSTREAM_HOSTS == set(config["services"]) | {"localhost"}
    assert not b.STACK_HOSTS & b.UPSTREAM_HOSTS


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
        "gitea-mcp-tls",
        "gitea-mcp",
        "gitea-task",
    }
    assert config["services"]["custodian"]["depends_on"]["bootstrap"]["required"] is False


def arguments_of(service):
    return [*(service.get("entrypoint") or []), *(service.get("command") or [])]


def flag_values(arguments, flag):
    return {arguments[index + 1] for index, argument in enumerate(arguments) if argument == flag}


def test_the_task_issuer_reads_the_issuer_key_and_writes_only_the_task_directory(config):
    service = config["services"]["task-issuer"]
    assert service["profiles"] == ["operator"]
    assert service["network_mode"] == "none"
    volumes = {volume["target"]: volume for volume in service["volumes"]}
    assert volumes.keys() == {"/var/lib/bailiff/issuer", str(b.DIRS["issuer-docket"]), "/run/bailiff/docket", "/out"}
    assert volumes["/var/lib/bailiff/issuer"]["source"] == "issuer-data"
    assert volumes["/var/lib/bailiff/issuer"]["read_only"] is True
    assert volumes["/out"]["type"] == "bind"
    assert volumes["/out"]["bind"]["create_host_path"] is False
    entrypoint = service["entrypoint"]
    assert entrypoint[-2:] == ["--out-dir", "/out"]
    assert flag_values(entrypoint, "--docket-writer") == {b.NAMES["issuer-docket"]}
    assert flag_values(entrypoint, "--docket-key") == {str(b.ISSUER_DOCKET_KEY)}
    assert flag_values(entrypoint, "--docket-state-dir") == {str(b.ISSUER_DOCKET_STATE)}
    assert flag_values(entrypoint, "--docket-key") != flag_values(entrypoint, "--issuer-key")


@pytest.mark.parametrize("name", ISSUERS)
def test_an_issuer_reaches_the_docket_socket_only_once_the_docket_is_healthy(config, name):
    service = config["services"][name]
    assert service["user"] == f"{b.ISSUER_UID}:{b.ISSUER_UID}"
    assert service["group_add"] == [str(b.DOCKET_WRITERS_GID)]
    mounts = {volume["source"]: volume for volume in service["volumes"]}
    assert not mounts["issuer-docket"].get("read_only", False)
    assert mounts["docket-run"]["target"] == str(b.SOCKETS["docket"].parent)
    assert service["depends_on"]["docket"]["condition"] == "service_healthy"


@pytest.mark.parametrize("name", DOCKET_READERS)
def test_every_docket_reader_pins_the_same_writers_and_the_grant_writer(config, name):
    arguments = arguments_of(config["services"][name])
    assert flag_values(arguments, "--pin") == {str(b.pin_path(component)) for component in b.WRITERS}
    assert flag_values(arguments, "--grant-pin") == {str(b.GRANT_PIN)}


def test_the_reader_reads_the_issuers_file_its_own_init_writes(config):
    init, reader = config["services"]["reader-init"], config["services"]["reader"]
    assert init["user"] == reader["user"] == f"{b.READER_UID}:{b.READER_UID}"
    assert "profiles" not in init
    init_mounts = {volume["source"]: volume for volume in init["volumes"]}
    reader_mounts = {volume["source"]: volume for volume in reader["volumes"]}
    assert init_mounts["reader-data"]["target"] == reader_mounts["reader-data"]["target"] == str(b.DIRS["reader"])
    assert not init_mounts["reader-data"].get("read_only", False)
    assert reader_mounts["reader-data"]["read_only"] is True
    assert init_mounts["pins"]["read_only"] is True
    assert reader["depends_on"]["reader-init"]["condition"] == "service_completed_successfully"
    assert config["services"]["docket-init"]["depends_on"]["reader-init"]["condition"] == (
        "service_completed_successfully"
    )


def test_the_rule_pins_the_same_writers_as_the_docket_readers():
    assert {str(path) for path in rule_module.PINS} == {str(b.pin_path(component)) for component in b.WRITERS}
    assert rule_module.GRANT_PIN == b.GRANT_PIN


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


def cert_mounts(config):
    mounts = {}
    for name, service in config["services"].items():
        for volume in service.get("volumes", []):
            if volume.get("source") in CERT_VOLUMES:
                assert volume["target"] == CERT_VOLUMES[volume["source"]], name
                mounts.setdefault(name, set()).add((volume["source"], volume.get("read_only", False)))
    return mounts


def test_only_the_certs_init_writes_the_certificates_and_each_reader_mounts_read_only(config):
    assert cert_mounts(config) == CERT_MOUNTS


def test_a_key_volume_reader_is_in_that_keys_group_and_starts_after_the_certs_init(config):
    for name, mounts in cert_mounts(config).items():
        if name == "certs":
            continue
        service = config["services"][name]
        assert service["depends_on"]["certs"]["condition"] == "service_completed_successfully", name
        groups = {KEY_GIDS[volume] for volume, _ in mounts if volume in KEY_GIDS}
        assert set(service.get("group_add", [])) & set(KEY_GIDS.values()) == groups, name


def test_the_stub_upstream_serves_its_leaf_on_the_port_the_stub_config_names(config):
    arguments = arguments_of(config["services"]["stub-upstream"])
    url = b.load_upstream(b.QUICKSTART_UPSTREAMS / "stub.json").url
    assert url == f"https://stub-upstream:{flag_values(arguments, '--port').pop()}/mcp"
    assert flag_values(arguments, "--certificate") == {f"{STUB_LEAF}.pem"}
    assert flag_values(arguments, "--private-key") == {f"{STUB_LEAF}.key"}


def test_the_certs_init_runs_offline_without_capabilities_in_every_key_group(config):
    service = config["services"]["certs"]
    assert service["cap_drop"] == ["ALL"]
    assert "cap_add" not in service
    assert service["read_only"] is True
    assert service["network_mode"] == "none"
    assert service["group_add"] == [str(settings.gid) for settings in certs_module.SERVICES.values()]
    assert service["entrypoint"] == ["python", "/app/quickstart/issue_certs.py"]
    assert service["command"] == ["issue"]


@pytest.mark.parametrize("name", OWN_UIDS)
def test_a_certificate_service_runs_as_a_uid_no_other_service_uses(config, name):
    uid, gid = config["services"][name]["user"].split(":")
    assert uid == gid
    sharing = {
        other
        for other, service in config["services"].items()
        if other != name and service.get("user", "").split(":")[0] == uid
    }
    assert sharing == set()


def test_cert_watch_checks_the_public_certificates_every_six_hours(config):
    service = config["services"]["cert-watch"]
    health = service["healthcheck"]
    assert health["test"][:6] == ["CMD", "python", "/app/quickstart/issue_certs.py", "check", "--margin-days", "30"]
    assert health["interval"] == "6h0m0s"
    assert health["start_period"] and health["start_interval"]
    assert service["depends_on"]["certs"]["condition"] == "service_completed_successfully"


def test_cert_watch_finishes_its_check_before_the_healthcheck_times_out(config):
    timeout = config["services"]["cert-watch"]["healthcheck"]["timeout"]
    assert re.fullmatch(r"\d+s", timeout), timeout
    assert certs_module.CHECK_DEADLINE_SECONDS < int(timeout[:-1])


def test_the_gateway_serves_its_install_leaf_on_the_published_port(config):
    listener = json.loads(b.GATEWAY_TEMPLATE.read_text())["gateways"]["default"]
    leaf = f"{CERTS}/gateway/current/gateway"
    assert listener["tls"] == {"cert": f"{leaf}.pem", "key": f"{leaf}.key"}
    assert {port["target"] for port in config["services"]["gateway"]["ports"]} == {listener["port"]}


def test_cert_watch_probes_the_stub_upstream_and_the_gateway_with_the_install_ca(config):
    service = config["services"]["cert-watch"]
    port = flag_values(arguments_of(config["services"]["stub-upstream"]), "--port").pop()
    gateway_port = json.loads(b.GATEWAY_TEMPLATE.read_text())["gateways"]["default"]["port"]
    assert flag_values(service["healthcheck"]["test"], "--probe") == {
        f"stub-upstream=stub-upstream:{port}",
        f"gateway=gateway:{gateway_port}",
    }
    assert service["networks"].keys() == {"upstream"}
    assert set(service["networks"]) <= set(config["services"]["gateway"]["networks"])
    assert service["depends_on"]["stub-upstream"]["condition"] == "service_started"
    assert service["depends_on"]["gateway"]["condition"] == "service_started"


def test_cert_watch_also_probes_the_configured_upstream_when_its_profile_runs(config):
    service = config["services"]["cert-watch"]
    assert flag_values(service["healthcheck"]["test"], "--probe-upstream") == {
        config["services"]["decide-init"]["environment"]["BAILIFF_UPSTREAM"]
    }
    assert {volume["target"] for volume in service["volumes"]} == {"/etc/bailiff/upstreams", f"{CERTS}/public"}
    assert service["depends_on"]["gitea-mcp-tls"] == {
        "condition": "service_started",
        "required": False,
    }


def test_gitea_serves_http_only_on_a_unix_socket_with_no_network(config):
    gitea = config["services"]["gitea"]
    settings = gitea["environment"]
    assert settings["GITEA__server__PROTOCOL"] == "http+unix"
    assert settings["GITEA__server__HTTP_ADDR"] == str(b.GITEA_SOCKET)
    assert gitea["network_mode"] == "none"
    assert "networks" not in gitea
    assert gitea["healthcheck"]["test"][:5] == ["CMD", "curl", "-fsS", "--unix-socket", str(b.GITEA_SOCKET)]


def test_the_gitea_socket_volume_is_mounted_only_by_gitea_and_its_clients(config):
    mounts = {
        name: (volume["target"], volume.get("read_only", False))
        for name, service in config["services"].items()
        for volume in service.get("volumes", [])
        if volume.get("source") == "gitea-run"
    }
    socket_dir = str(b.GITEA_SOCKET.parent)
    assert mounts == {
        "gitea": (socket_dir, False),
        "gitea-mcp": (socket_dir, True),
        "gitea-mcp-spike": (socket_dir, True),
        "bootstrap": (socket_dir, True),
    }
    assert config["volumes"]["gitea-run"]["driver_opts"]["type"] == "tmpfs"


@pytest.mark.parametrize("name", GITEA_MCP)
def test_gitea_mcp_reaches_gitea_over_the_socket_at_the_root_url_host(config, name):
    arguments = arguments_of(config["services"][name])
    root_url = config["services"]["gitea"]["environment"]["GITEA__server__ROOT_URL"]
    assert flag_values(arguments, "-gitea-unix-socket") == {str(b.GITEA_SOCKET)}
    assert flag_values(arguments, "-host") == {root_url.rstrip("/")} == {f"http://{b.GITEA_HOST}"}


def test_the_sidecar_proxies_plain_https_to_gitea_mcp_on_loopback_with_its_own_leaf():
    assert json.loads(SIDECAR_CONFIG.read_text()) == {
        "config": {
            "adminAddr": "127.0.0.1:15000",
            "statsAddr": "127.0.0.1:15020",
            "readinessAddr": "127.0.0.1:15021",
        },
        "binds": [
            {
                "port": 8443,
                "listeners": [
                    {
                        "protocol": "HTTPS",
                        "tls": {"cert": f"{SIDECAR_LEAF}.pem", "key": f"{SIDECAR_LEAF}.key"},
                        "routes": [
                            {
                                "policies": {"urlRewrite": {"authority": {"full": "127.0.0.1:8080"}}},
                                "backends": [{"host": "127.0.0.1:8080"}],
                            }
                        ],
                    }
                ],
            }
        ],
    }
    assert certs_module.SERVICES["gitea-mcp-tls"].names == ("gitea-mcp-tls",)


def test_the_sidecar_runs_the_pinned_gateway_image_with_its_config_and_key_read_only(config):
    sidecar = config["services"]["gitea-mcp-tls"]
    assert sidecar["image"] == config["services"]["gateway"]["image"]
    assert "@sha256:" in sidecar["image"]
    assert sidecar["command"] == ["-f", "/etc/agentgateway/gitea-mcp-tls.json"]
    mounts = {volume["target"]: volume for volume in sidecar["volumes"]}
    assert mounts.keys() == {"/etc/agentgateway/gitea-mcp-tls.json", f"{CERTS}/gitea-mcp-tls"}
    assert mounts["/etc/agentgateway/gitea-mcp-tls.json"]["source"] == str(SIDECAR_CONFIG)
    assert all(volume["read_only"] for volume in mounts.values())
    assert sidecar["group_add"] == [str(certs_module.SERVICES["gitea-mcp-tls"].gid)]
    assert sidecar["read_only"] is True
    assert sidecar["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in sidecar["security_opt"]
    assert sidecar["networks"].keys() == {"upstream"}
    assert "ports" not in sidecar


def test_gitea_mcp_listens_on_loopback_inside_the_sidecars_network_namespace(config):
    gitea_mcp = config["services"]["gitea-mcp"]
    arguments = arguments_of(gitea_mcp)
    route = json.loads(SIDECAR_CONFIG.read_text())["binds"][0]["listeners"][0]["routes"][0]
    backend = route["backends"][0]
    assert gitea_mcp["network_mode"] == "service:gitea-mcp-tls"
    assert "networks" not in gitea_mcp
    assert f"{flag_values(arguments, '-bind').pop()}:{flag_values(arguments, '-port').pop()}" == backend["host"]
    assert route["policies"]["urlRewrite"]["authority"]["full"] == backend["host"]
    assert gitea_mcp["depends_on"]["gitea-mcp-tls"]["restart"] is True


def test_the_gitea_upstream_names_the_sidecar_on_its_bound_port():
    url = b.load_upstream(b.QUICKSTART_UPSTREAMS / "gitea.json").url
    assert url == f"https://gitea-mcp-tls:{json.loads(SIDECAR_CONFIG.read_text())['binds'][0]['port']}/mcp"


def test_the_spike_stays_off_the_upstream_network(config):
    assert config["services"]["gitea-mcp-spike"]["networks"].keys() == {"spike"}


def test_the_baseline_reaches_the_upstream_network_with_the_install_ca_under_its_own_profile(config):
    service = config["services"]["baseline"]
    assert service["profiles"] == ["load"]
    assert service["networks"].keys() == {"upstream"}
    assert service["user"] == config["services"]["bootstrap"]["user"]


def test_bootstrap_reaches_gitea_only_over_the_socket(config):
    assert config["services"]["bootstrap"]["network_mode"] == "none"
    assert "networks" not in config["services"]["bootstrap"]
