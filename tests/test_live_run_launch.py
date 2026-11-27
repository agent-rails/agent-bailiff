import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "examples" / "live-run"))
import launch  # noqa: E402

DIGEST = "agent-bailiff-live-run@sha256:" + "a" * 64
WEBHOOK = "agent-bailiff-webhook@sha256:" + "b" * 64
IMAGE_ID = "sha256:" + "c" * 64
OTHER_ID = "sha256:" + "d" * 64
PRODUCTION = ("do-fra1-core-infra-prod", "gke_onstack-infra_europe-west1-b_onstack-infra")
CERT_USER = {"client-certificate-data": "Y2VydA==", "client-key-data": "a2V5"}


def view(context="orbstack", server="https://127.0.0.1:26443", user=None, contexts=1, cluster=None):
    entry = {"server": server, "certificate-authority-data": "Y2E="} if cluster is None else cluster
    return {
        "contexts": [{"name": context, "context": {"cluster": context, "user": context}}] * contexts,
        "clusters": [{"name": context, "cluster": entry}],
        "users": [{"name": context, "user": CERT_USER if user is None else user}],
    }


@pytest.fixture
def kubectl_view(monkeypatch):
    calls = []

    def answer(document):
        def run(command, **options):
            calls.append(command)
            return subprocess.CompletedProcess(command, 0, stdout=json.dumps(document), stderr="")

        monkeypatch.setattr(launch.subprocess, "run", run)
        return calls

    return answer


def test_the_kubeconfig_is_minified_and_pointed_at_the_orbstack_host(kubectl_view):
    calls = kubectl_view(view())
    config = launch.minify_kubeconfig("orbstack")
    assert config["clusters"][0]["cluster"]["server"] == "https://k8s.orb.local:26443"
    assert config["contexts"][0]["name"] == "orbstack"
    assert calls == [["kubectl", "config", "view", "--minify", "--flatten", "--context", "orbstack", "-o", "json"]]


def test_a_server_other_than_loopback_is_unchanged(kubectl_view):
    kubectl_view(view(server="https://k8s.orb.local:26443"))
    assert launch.minify_kubeconfig("orbstack")["clusters"][0]["cluster"]["server"] == "https://k8s.orb.local:26443"


CA = {"certificate-authority-data": "Y2E="}
ORBSTACK_SERVER = {"server": "https://127.0.0.1:26443"}


@pytest.mark.parametrize(
    ("cluster", "message"),
    [
        ({**ORBSTACK_SERVER, **CA, "proxy-url": "http://proxy:3128"}, r"sets \['proxy-url'\]"),
        ({**ORBSTACK_SERVER, **CA, "insecure-skip-tls-verify": True}, r"sets \['insecure-skip-tls-verify'\]"),
        ({**ORBSTACK_SERVER, **CA, "tls-server-name": "k8s.orb.local"}, r"sets \['tls-server-name'\]"),
        (ORBSTACK_SERVER, "no certificate-authority-data"),
        ({**ORBSTACK_SERVER, "certificate-authority-data": ""}, "no certificate-authority-data"),
        ({"server": "http://127.0.0.1:26443", **CA}, "is not https"),
        ({"server": "https://user:pw@127.0.0.1:26443", **CA}, "is not https"),
        ({"server": "https://127.0.0.1:26443/proxy", **CA}, "is not https"),
        ({"server": "https://127.0.0.1:26443?x=1", **CA}, "is not https"),
        ({"server": "https://127.0.0.1:26443#x", **CA}, "is not https"),
        ({"server": "https://127.0.0.1:99999", **CA}, "invalid port"),
        (CA, "not a printable string"),
        ({"server": 123, **CA}, "not a printable string"),
        ({"server": ["https://127.0.0.1:26443"], **CA}, "not a printable string"),
        ({"server": " https://127.0.0.1:26443", **CA}, "not a printable string"),
        ({"server": "https://127.0.0.1:26443\n", **CA}, "not a printable string"),
        ({"server": "https://127.0.\t0.1:26443", **CA}, "not a printable string"),
        ({**ORBSTACK_SERVER, "certificate-authority-data": True}, "no certificate-authority-data"),
        ({**ORBSTACK_SERVER, "certificate-authority-data": "not base64!"}, "is not base64"),
        ({"server": "https://evil.example:26443", **CA}, "host evil.example is not one of"),
        ({"server": "https://[::1]:26443", **CA}, "is not https://"),
        ({"server": "https://[::ffff:127.0.0.1]:26443", **CA}, "is not https://"),
        ({"server": "https://k8s.orb.local.:26443", **CA}, "is not one of"),
        ({"server": "https://2130706433:26443", **CA}, "is not one of"),
        ({"server": "https://127.0.0.1", **CA}, "with a port"),
    ],
    ids=[
        "proxy-url", "insecure", "tls-server-name", "no-ca", "empty-ca", "http", "userinfo", "path", "query",
        "fragment", "bad-port", "no-server", "int-server", "list-server", "leading-space", "newline", "tab",
        "bool-ca", "ca-not-base64", "other-host", "ipv6", "mapped-ipv6", "trailing-dot", "decimal-ip", "no-port",
    ],
)  # fmt: skip
def test_a_cluster_entry_outside_the_allowlist_is_refused(kubectl_view, cluster, message):
    kubectl_view(view(cluster=cluster))
    with pytest.raises(RuntimeError, match=message):
        launch.minify_kubeconfig("orbstack")


@pytest.mark.parametrize(
    "server", ["https://user:hunter2@127.0.0.1:26443", "https://127.0.0.1:26443?token=hunter2", "https://h:hunter2"]
)
def test_a_refused_server_is_not_echoed(kubectl_view, server):
    kubectl_view(view(server=server))
    with pytest.raises(RuntimeError) as refusal:
        launch.minify_kubeconfig("orbstack")
    assert "hunter2" not in str(refusal.value)


@pytest.mark.parametrize(
    ("user", "message"),
    [
        ({"tokenFile": "/var/run/token"}, r"sets \['tokenFile'\]"),
        ({"username": "admin", "password": "pw"}, r"sets \['password', 'username'\]"),
        ({"token": "t", "as": "system:admin"}, r"sets \['as'\]"),
        ({"token": "t", "as-groups": ["system:masters"]}, r"sets \['as-groups'\]"),
        ({"token": "t", "as-uid": "0"}, r"sets \['as-uid'\]"),
        ({"token": "t", "as-user-extra": {"k": ["v"]}}, r"sets \['as-user-extra'\]"),
        ({"token": "t", "extensions": []}, r"sets \['extensions'\]"),
        ({"client-certificate": "/c", "client-key": "/k"}, r"sets \['client-certificate', 'client-key'\]"),
        ({"token": ""}, "non-empty printable strings"),
        ({"token": 1}, "non-empty printable strings"),
        ({"token": "a\r\nX: y"}, "non-empty printable strings"),
        ({}, "a token alone or a client certificate and key"),
        ({"client-key-data": "a2V5"}, "a token alone or a client certificate and key"),
        ({"token": "t", **CERT_USER}, "a token alone"),
        ({**CERT_USER, "client-certificate-data": "not base64!"}, "client-certificate-data is not base64"),
        ({**CERT_USER, "client-key-data": "%%%"}, "client-key-data is not base64"),
    ],
    ids=[
        "token-file", "basic", "as", "as-groups", "as-uid", "as-user-extra", "extensions", "cert-files", "empty", "int",
        "crlf-token", "no-credential", "key-only", "token-and-cert", "cert-not-base64", "key-not-base64",
    ],
)  # fmt: skip
def test_a_user_entry_outside_the_allowlist_is_refused(kubectl_view, user, message):
    kubectl_view(view(user=user))
    with pytest.raises(RuntimeError, match=message):
        launch.minify_kubeconfig("orbstack")


@pytest.mark.parametrize(
    "user", [{"token": "t"}, {"client-certificate-data": "Y2VydA==", "client-key-data": "a2V5"}], ids=["token", "cert"]
)
def test_a_static_user_credential_is_kept(kubectl_view, user):
    kubectl_view(view(user=user))
    assert launch.minify_kubeconfig("orbstack")["users"][0]["user"] == user


def test_the_orbstack_server_is_rebuilt_from_its_port(kubectl_view):
    kubectl_view(view(server="https://127.0.0.1:26443/"))
    assert launch.minify_kubeconfig("orbstack")["clusters"][0]["cluster"] == {
        "server": "https://k8s.orb.local:26443",
        **CA,
    }


@pytest.mark.parametrize("context", [*PRODUCTION, "kind-dev"])
def test_a_context_other_than_orbstack_is_refused_before_kubectl(monkeypatch, context):
    monkeypatch.setattr(launch.subprocess, "run", lambda *args, **options: pytest.fail("kubectl called"))
    with pytest.raises(RuntimeError, match="not a disposable cluster"):
        launch.minify_kubeconfig(context)


GKE_PROBE = "gke_engineering-scratch-pad_europe-west1-b_bailiff-probe"


@pytest.mark.parametrize("context", [GKE_PROBE, "gke_onstack-infra_europe-west1-b_bailiff-probe-x"])
def test_only_a_gke_bailiff_probe_context_is_a_gke_platform(context):
    assert launch.platform_of(context) == ("gke" if context == GKE_PROBE else "upstream")


GKE_SERVER = "https://34.1.2.3"
GKE_CLUSTER = {"endpoint": "34.1.2.3", "resourceLabels": {"purpose": "bailiff-probe"}}


@pytest.fixture
def gke_probe(monkeypatch):
    calls = []

    def answer(cluster=GKE_CLUSTER, server=GKE_SERVER, context=GKE_PROBE):
        documents = {
            "kubectl": view(context, server, user={"exec": {"command": "gke-gcloud-auth-plugin"}}),
            "gcloud": cluster,
        }

        def run(command, **options):
            calls.append(command)
            return subprocess.CompletedProcess(command, 0, stdout=json.dumps(documents[command[0]]), stderr="")

        monkeypatch.setattr(launch.subprocess, "run", run)
        return calls

    return answer


def test_the_applier_token_replaces_the_gke_credential_plugin(gke_probe):
    calls = gke_probe()
    config = launch.minify_kubeconfig(GKE_PROBE, applier_token="applier", gke_project="engineering-scratch-pad")
    assert config["users"][0]["user"] == {"token": "applier"}
    assert config["clusters"][0]["cluster"]["server"] == GKE_SERVER
    assert calls[1] == [
        "gcloud", "container", "clusters", "describe", "bailiff-probe", "--project", "engineering-scratch-pad",
        "--location", "europe-west1-b", "--format", "json",
    ]  # fmt: skip


def test_a_gke_context_without_an_applier_token_is_refused(gke_probe):
    gke_probe()
    with pytest.raises(RuntimeError, match="credential plugin"):
        launch.minify_kubeconfig(GKE_PROBE, gke_project="engineering-scratch-pad")


@pytest.mark.parametrize("project", [None, "onstack-infra"])
def test_a_gke_context_outside_the_given_project_is_refused_before_kubectl(monkeypatch, project):
    monkeypatch.setattr(launch.subprocess, "run", lambda *args, **options: pytest.fail("kubectl called"))
    with pytest.raises(RuntimeError, match="not in the probe project"):
        launch.minify_kubeconfig(GKE_PROBE, applier_token="applier", gke_project=project)


@pytest.mark.parametrize(
    ("cluster", "message"),
    [
        ({"endpoint": "34.1.2.3"}, "has no label purpose=bailiff-probe"),
        ({"endpoint": "34.1.2.3", "resourceLabels": {"purpose": "prod"}}, "has no label purpose=bailiff-probe"),
        ({"endpoint": "35.9.9.9", "resourceLabels": {"purpose": "bailiff-probe"}}, "is not the endpoint"),
    ],
    ids=["unlabelled", "other-label", "other-endpoint"],
)
def test_a_gke_context_that_is_not_the_labelled_probe_cluster_is_refused(gke_probe, cluster, message):
    gke_probe(cluster)
    with pytest.raises(RuntimeError, match=message):
        launch.minify_kubeconfig(GKE_PROBE, applier_token="applier", gke_project="engineering-scratch-pad")


@pytest.mark.parametrize("server", ["https://34.1.2.3:443", "https://34.1.2.3/", "HTTPS://34.1.2.3"])
def test_the_gke_server_is_rebuilt_from_the_endpoint(gke_probe, server):
    gke_probe(server=server)
    config = launch.minify_kubeconfig(GKE_PROBE, applier_token="applier", gke_project="engineering-scratch-pad")
    assert config["clusters"][0]["cluster"]["server"] == GKE_SERVER


@pytest.mark.parametrize(
    ("server", "message"),
    [
        ("https://34.1.2.3:8443", "is not the endpoint"),
        ("http://34.1.2.3", "is not https"),
        ("https://34.1.2.3/api", "is not https"),
        ("https://34.1.\t2.3", "not a printable string"),
    ],
    ids=["other-port", "http", "path", "tab"],
)
def test_a_gke_server_on_another_port_or_scheme_is_refused(gke_probe, server, message):
    gke_probe(server=server)
    with pytest.raises(RuntimeError, match=message):
        launch.minify_kubeconfig(GKE_PROBE, applier_token="applier", gke_project="engineering-scratch-pad")


@pytest.mark.parametrize(
    ("document", "message"),
    [
        (view(contexts=0), "exactly one of contexts"),
        (view(contexts=2), "exactly one of contexts"),
        (view(context="other"), "names context 'other'"),
        (view(user={"exec": {"command": "gke-gcloud-auth-plugin"}}), "credential plugin"),
        (view(user={"auth-provider": {"name": "oidc"}}), "credential plugin"),
    ],
    ids=["no-context", "two-contexts", "renamed", "exec", "auth-provider"],
)
def test_a_kubeconfig_the_container_cannot_use_is_refused(kubectl_view, document, message):
    kubectl_view(document)
    with pytest.raises(RuntimeError, match=message):
        launch.minify_kubeconfig("orbstack")


@pytest.fixture
def token_environment(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv(launch.TOKEN_VARIABLE, " oauth-token\n")


def test_the_token_is_taken_out_of_the_environment_children_inherit(token_environment):
    assert launch.read_token() == "oauth-token"
    assert launch.TOKEN_VARIABLE not in launch.os.environ


def test_an_api_key_in_the_environment_is_refused(token_environment, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-x")
    with pytest.raises(RuntimeError, match="unset ANTHROPIC_API_KEY"):
        launch.read_token()


@pytest.mark.parametrize("value", [None, "", "  "])
def test_a_missing_or_empty_token_is_refused(token_environment, monkeypatch, value):
    if value is None:
        monkeypatch.delenv(launch.TOKEN_VARIABLE)
    else:
        monkeypatch.setenv(launch.TOKEN_VARIABLE, value)
    with pytest.raises(RuntimeError, match="set CLAUDE_CODE_OAUTH_TOKEN"):
        launch.read_token()


def inspect_returns(monkeypatch, digests):
    def run(command, **options):
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps(digests), stderr="")

    monkeypatch.setattr(launch.subprocess, "run", run)


def test_the_webhook_image_is_resolved_to_its_repo_digest_by_image_id(monkeypatch):
    calls = []

    def run(command, **options):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps([WEBHOOK]), stderr="")

    monkeypatch.setattr(launch.subprocess, "run", run)
    assert launch.resolve_digest("orbstack", IMAGE_ID) == WEBHOOK
    assert calls[0][:5] == ["docker", "--context", "orbstack", "image", "inspect"]
    assert calls[0][5] == IMAGE_ID


@pytest.mark.parametrize("digests", [[], None, ["agent-bailiff-live-run:local"], ["agent-bailiff-live-run@sha256:abc"]])
def test_an_image_without_a_repo_digest_is_refused(monkeypatch, digests):
    inspect_returns(monkeypatch, digests)
    with pytest.raises(RuntimeError, match="no sha256 repo digest"):
        launch.resolve_digest("orbstack", IMAGE_ID)


def parse_bundle(data):
    header, body = data.split(b"\n", 1)
    token_length, kubeconfig_length = map(int, header.split())
    assert len(body) == token_length + kubeconfig_length
    return body[:token_length].decode(), body[token_length:]


def test_the_stdin_bundle_carries_the_token_and_kubeconfig():
    token, config = parse_bundle(launch.stdin_bundle("oauth-token", view()))
    assert token == "oauth-token"
    assert json.loads(config) == view()


def test_the_run_bundle_has_no_kubeconfig():
    assert launch.stdin_bundle("oauth-token", None) == b"11 0\noauth-token"


def spec(script="run", **changes):
    values = {
        "script": script,
        "context": "orbstack" if script == "kubernetes" else None,
        "model": "m",
        "out": Path("out.json"),
        "run_id": "r1",
        "archiver_uid": 10009,
        "docker_context": "orbstack",
        "webhook_image": WEBHOOK if script == "kubernetes" else None,
    }
    return launch.RunSpec(**{**values, **changes})


def test_the_container_command_is_confined_and_carries_no_secret(token_environment):
    command = launch.container_command(spec(), DIGEST)
    assert command == [
        "docker", "--context", "orbstack", "run", "--rm", "-i", "--init",
        "--name", "bl-r1", "--label", "agent-bailiff/run=r1", "--stop-timeout", "300", "--platform", "linux/amd64",
        "--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "SETUID", "--cap-add", "SETGID", "--cap-add", "KILL",
        "--tmpfs", "/live:size=512m", "-e", "ROOT=/live", "-e", "ARCHIVER_UID=10009", "-e", "SCRIPT=run.py",
        DIGEST, "--run-id", "r1", "--model", "m",
    ]  # fmt: skip
    assert "-v" not in command and "--volume" not in command and "--mount" not in command
    assert not any("oauth-token" in part for part in command)


def test_the_kubernetes_command_passes_the_context_and_webhook_digest():
    command = launch.container_command(spec("kubernetes"), DIGEST)
    assert command[-4:] == ["--context", "orbstack", "--webhook-image", WEBHOOK]
    assert "SCRIPT=kubernetes.py" in command


def test_the_kubernetes_command_needs_a_webhook_image():
    with pytest.raises(RuntimeError, match="needs a webhook image"):
        launch.container_command(spec("kubernetes", webhook_image=None), DIGEST)


def test_the_read_catalog_command_passes_the_catalog_and_no_webhook():
    command = launch.container_command(spec("kubernetes", webhook_image=None, catalog="kubernetes-read"), DIGEST)
    assert command[-6:] == ["--context", "orbstack", "--catalog", "kubernetes-read", "--platform", "upstream"]
    assert "--webhook-image" not in command


def test_the_gke_read_command_passes_the_platform():
    command = launch.container_command(
        spec("kubernetes", context=GKE_PROBE, webhook_image=None, catalog="kubernetes-read", platform="gke"), DIGEST
    )
    assert command[-6:] == ["--context", GKE_PROBE, "--catalog", "kubernetes-read", "--platform", "gke"]


def test_a_write_catalog_on_gke_is_refused():
    with pytest.raises(RuntimeError, match="kubernetes-read catalog only"):
        launch.container_command(spec("kubernetes", context=GKE_PROBE, platform="gke"), DIGEST)


def test_the_kubernetes_command_needs_a_context():
    with pytest.raises(RuntimeError, match="needs a context"):
        launch.container_command(spec("kubernetes", context=None), DIGEST)


@pytest.mark.parametrize("status", ["ok", "failed"])
def test_the_result_is_the_last_compact_line(status):
    stdout = f'progress\n{{"run_id":"r1","status":"{status}","final":{{}}}}\n'
    assert launch.read_result(stdout, "r1")["status"] == status


@pytest.mark.parametrize(
    ("stdout", "message"),
    [
        ("", "printed no result"),
        ('{\n  "run_id": "r1",\n  "status": "ok"\n}\n', "not compact result JSON"),
        ('{"run_id":"r2","status":"ok"}', "not a result for run r1"),
        ('{"run_id":"r1"}', "not a result for run r1"),
        ('["r1"]', "not a result for run r1"),
    ],
    ids=["empty", "pretty", "wrong-run", "no-status", "not-object"],
)
def test_a_result_other_than_an_ok_line_for_this_run_is_refused(stdout, message):
    with pytest.raises(RuntimeError, match=message):
        launch.read_result(stdout, "r1")


def lock_state(monkeypatch, owner, running):
    def run(command, **options):
        stdout = owner if command[0] == "kubectl" else running
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

    monkeypatch.setattr(launch.subprocess, "run", run)


def test_a_lock_held_by_a_running_container_says_wait(monkeypatch):
    lock_state(monkeypatch, "r0", "bl-r0\n")
    assert "container bl-r0 is running; wait" in launch.report_lock("orbstack", "orbstack")


def test_a_stale_lock_names_what_to_delete(monkeypatch):
    lock_state(monkeypatch, "r0", "")
    report = launch.report_lock("orbstack", "orbstack")
    assert "bl-r0 is not running" in report
    assert "agent-bailiff/run=r0" in report


def test_an_absent_lock_is_reported(monkeypatch):
    lock_state(monkeypatch, "", "")
    assert "absent" in launch.report_lock("orbstack", "orbstack")


def test_the_result_file_is_private_and_never_overwritten(tmp_path):
    path = tmp_path / "result.json"
    launch.write_result(path, {"run_id": "r1"})
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        launch.write_result(path, {"run_id": "r2"})


def fake_docker(monkeypatch, tags, built, after_build=None):
    calls = []

    def run(command, **options):
        calls.append(command)
        if "build" in command:
            Path(command[command.index("--iidfile") + 1]).write_text(built)
            tags[command[command.index("-t") + 1]] = built
            if after_build:
                after_build()
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(launch.subprocess, "run", run)
    return calls


@pytest.mark.parametrize(("platform", "expected"), [(None, []), ("linux/amd64", ["--platform", "linux/amd64"])])
def test_an_image_is_built_for_the_platform_asked_or_natively(monkeypatch, platform, expected):
    calls = fake_docker(monkeypatch, {}, IMAGE_ID)
    assert launch.build_image("orbstack", "Dockerfile", "t:1", platform) == IMAGE_ID
    [command] = calls
    iidfile = command[command.index("--iidfile") + 1]
    head = ["docker", "--context", "orbstack", "build", *expected]
    assert command == [*head, "--iidfile", iidfile, "-f", "Dockerfile", "-t", "t:1", "."]


def test_a_launch_runs_the_image_it_built_when_another_launch_retags_the_tag(monkeypatch):
    tags = {}
    fake_docker(monkeypatch, tags, IMAGE_ID, after_build=lambda: tags.update({"t:1": OTHER_ID}))
    assert launch.build_image("orbstack", "Dockerfile", "t:1") == IMAGE_ID
    assert tags["t:1"] == OTHER_ID


@pytest.mark.parametrize("written", ["", "\n", "latest", "sha256:abc"])
def test_a_build_without_an_image_id_is_refused(monkeypatch, written):
    fake_docker(monkeypatch, {}, written)
    with pytest.raises(RuntimeError, match="image ID"):
        launch.build_image("orbstack", "Dockerfile", "t:1")


def test_a_build_that_writes_no_iidfile_is_refused(monkeypatch):
    monkeypatch.setattr(launch.subprocess, "run", lambda command, **options: None)
    with pytest.raises(RuntimeError, match="image ID"):
        launch.build_image("orbstack", "Dockerfile", "t:1")
