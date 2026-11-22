import json
import os
import secrets
import subprocess
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
TAG = "agent-bailiff-live-run:test"
ARCHIVER_UID = 10009
KUBE_CONTEXT = os.environ.get("AGENT_BAILIFF_TEST_KUBE_CONTEXT")
WEBHOOK_IMAGE = os.environ.get("AGENT_BAILIFF_TEST_WEBHOOK_IMAGE")
pytestmark = pytest.mark.skipif(
    os.environ.get("AGENT_BAILIFF_TEST_LIVE_RUN_IMAGE") != "1", reason="set AGENT_BAILIFF_TEST_LIVE_RUN_IMAGE=1"
)


@pytest.fixture(scope="module")
def image():
    subprocess.run(
        ["docker", "build", "--platform", "linux/amd64", "-f", "examples/live-run/Dockerfile", "-t", TAG, "."],
        cwd=ROOT,
        check=True,
        capture_output=True,
        timeout=1800,
    )
    return TAG


def bundle(token=b"t" * 20, kubeconfig=b"", declared=None):
    lengths = declared or (len(token), len(kubeconfig))
    return f"{lengths[0]} {lengths[1]}\n".encode() + token + kubeconfig


def container(image, script="run.py", *arguments, name=None, tmpfs=True, archiver_uid=ARCHIVER_UID, network=()):
    return [
        "docker", "run", "--rm", "-i", "--init", "--platform", "linux/amd64",
        *(["--name", name] if name else []),
        "--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "SETUID", "--cap-add", "SETGID", "--cap-add", "KILL",
        *(["--tmpfs", "/live:size=512m"] if tmpfs else []),
        *network,
        "-e", "ROOT=/live", "-e", f"ARCHIVER_UID={archiver_uid}", "-e", f"SCRIPT={script}",
        image, *arguments,
    ]  # fmt: skip


def run(command, stdin=b"", timeout=120):
    return subprocess.run(command, input=stdin, capture_output=True, timeout=timeout, check=False)


@pytest.mark.parametrize("script", ["run.py", "kubernetes.py"])
def test_both_scripts_import_in_the_image(image, script):
    result = run(
        ["docker", "run", "--rm", "--entrypoint", "python", image, "-E", "-s", f"examples/live-run/{script}", "--help"]
    )
    assert result.returncode == 0, result.stderr
    assert b"--archiver-uid" in result.stdout


@pytest.mark.parametrize(
    ("options", "stdin", "message"),
    [
        ({"tmpfs": False}, bundle(), b"must be a tmpfs mount"),
        ({"archiver_uid": 1000}, bundle(), b"is the harness uid"),
        ({}, bundle(declared=(40, 0)), b"token is truncated"),
        ({}, bundle(kubeconfig=b"{}"), b"run.py takes no kubeconfig"),
        ({"script": "kubernetes.py"}, bundle(), b"needs a kubeconfig"),
        ({"script": "../run.py"}, bundle(), b"SCRIPT must be run.py or kubernetes.py"),
    ],
    ids=["no-tmpfs", "archiver-is-harness", "truncated", "stray-kubeconfig", "missing-kubeconfig", "script"],
)
def test_the_entrypoint_refuses_a_bad_start(image, options, stdin, message):
    result = run(container(image, options.pop("script", "run.py"), "--run-id", "r1", **options), stdin)
    assert result.returncode == 1
    assert message in result.stderr


def test_the_harness_starts_confined_in_the_entrypoint_layout(image):
    result = run(container(image, "run.py", "--run-id", "r1", "--archiver-uid", "1000"), bundle())
    assert result.returncode == 1
    assert b"harness's own uid" in result.stderr, result.stderr


def kubeconfig(context):
    view = json.loads(
        subprocess.run(
            ["kubectl", "config", "view", "--minify", "--flatten", "--context", context, "-o", "json"],
            capture_output=True,
            check=True,
            timeout=30,
        ).stdout
    )
    for cluster in view["clusters"]:
        cluster["cluster"]["server"] = cluster["cluster"]["server"].replace("127.0.0.1", "k8s.orb.local")
    return json.dumps(view).encode()


def kubectl(*arguments):
    return subprocess.run(
        ["kubectl", "--context", KUBE_CONTEXT, *arguments], capture_output=True, text=True, timeout=60, check=True
    ).stdout


needs_cluster = pytest.mark.skipif(
    not KUBE_CONTEXT or not WEBHOOK_IMAGE,
    reason="set AGENT_BAILIFF_TEST_KUBE_CONTEXT and AGENT_BAILIFF_TEST_WEBHOOK_IMAGE",
)


@needs_cluster
def test_kubectl_reads_the_mounted_kubeconfig(image):
    command = ["docker", "run", "--rm", "-i", "--entrypoint", "kubectl", image, "--kubeconfig", "/dev/stdin"]
    result = run([*command, "auth", "whoami", "-o", "name"], kubeconfig(KUBE_CONTEXT), timeout=60)
    assert result.returncode == 0, result.stderr


@needs_cluster
def test_docker_stop_runs_teardown(image):
    run_id = secrets.token_hex(4)
    name = f"bl-{run_id}"
    arguments = ["--run-id", run_id, "--context", KUBE_CONTEXT, "--webhook-image", WEBHOOK_IMAGE]
    stdin = bundle(kubeconfig=kubeconfig(KUBE_CONTEXT))
    process = subprocess.Popen(
        container(image, "kubernetes.py", *arguments, name=name), stdin=subprocess.PIPE, stderr=subprocess.PIPE
    )
    process.stdin.write(stdin)
    process.stdin.close()
    try:
        deadline = time.monotonic() + 180
        while "-prod" not in kubectl("get", "namespaces", "-l", f"agent-bailiff/run={run_id}", "-o", "name"):
            assert process.poll() is None, process.stderr.read()
            assert time.monotonic() < deadline, "the run never created its namespaces"
            time.sleep(1)
        subprocess.run(["docker", "stop", "--time", "300", name], check=True, capture_output=True, timeout=330)
        assert process.wait(30) == 143
    finally:
        if process.poll() is None:
            subprocess.run(["docker", "stop", name], capture_output=True, timeout=330)
    assert kubectl("get", "namespace", "agent-bailiff-lock", "--ignore-not-found", "-o", "name") == ""
    left = kubectl(
        "get", "namespaces,validatingwebhookconfigurations", "-l", f"agent-bailiff/run={run_id}", "-o", "name"
    )
    assert left == ""
