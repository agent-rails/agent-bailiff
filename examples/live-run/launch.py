"""Host launcher for the live run: builds the image, passes the token and a minified kubeconfig on stdin, runs the
harness in one container and writes its result JSON. See README.md."""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent.parent
IMAGE_TAG = "agent-bailiff-live-run:local"
WEBHOOK_TAG = "agent-bailiff-webhook:live"
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
DIGEST_REF = re.compile(r"[^@\s]+@sha256:[0-9a-f]{64}")
ALLOWED_CONTEXTS = frozenset({"orbstack"})
GKE_PROBE = re.compile(r"gke_(?P<project>[a-z0-9-]+)_(?P<location>[a-z0-9-]+)_bailiff-probe")
PROBE_CLUSTER = "bailiff-probe"
PROBE_LABEL = "purpose"
ORBSTACK_HOST = "k8s.orb.local"
ORBSTACK_HOSTS = frozenset({"127.0.0.1", ORBSTACK_HOST})
CLUSTER_KEYS = frozenset({"server", "certificate-authority-data"})
USER_KEYS = frozenset({"client-certificate-data", "client-key-data", "token"})
TOKEN_FORM = frozenset({"token"})
CERTIFICATE_FORM = frozenset({"client-certificate-data", "client-key-data"})
GKE_PORTS = (None, 443)
READ_CATALOG = "kubernetes-read"
ROOT = "/live"
TOKEN_VARIABLE = "CLAUDE_CODE_OAUTH_TOKEN"
LOCK = "agent-bailiff-lock"
RUN_SECONDS = 3600
STOP_SECONDS = 300


@dataclass(frozen=True)
class RunSpec:
    script: str
    context: str | None
    model: str
    out: Path
    run_id: str
    archiver_uid: int
    docker_context: str
    webhook_image: str | None = None
    catalog: str = "kubernetes"
    platform: str = "upstream"


def build_image(docker_context: str, dockerfile: str, tag: str, platform: str | None = None) -> str:
    target = ["--platform", platform] if platform else []
    with tempfile.TemporaryDirectory() as scratch:
        iidfile = Path(scratch) / "iid"
        subprocess.run(
            ["docker", "--context", docker_context, "build", *target, "--iidfile", str(iidfile), "-f", dockerfile,
             "-t", tag, "."],
            cwd=REPO,
            check=True,
            timeout=1800,
        )  # fmt: skip
        image_id = iidfile.read_text().strip() if iidfile.is_file() else ""
    if IMAGE_ID.fullmatch(image_id) is None:
        raise RuntimeError(f"the build of {tag} reported no image ID ({image_id!r})")
    return image_id


def resolve_digest(docker_context: str, image_id: str) -> str:
    output = subprocess.run(
        ["docker", "--context", docker_context, "image", "inspect", image_id, "--format", "{{json .RepoDigests}}"],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    ).stdout
    digests = json.loads(output) or []
    if not digests or DIGEST_REF.fullmatch(digests[0]) is None:
        raise RuntimeError(
            f"{image_id} has no sha256 repo digest ({digests}); the live run needs OrbStack's image store"
        )
    return str(digests[0])


def platform_of(context: str) -> str:
    return "gke" if GKE_PROBE.fullmatch(context) else "upstream"


def check_user(user: dict[str, Any]) -> None:
    if "exec" in user or "auth-provider" in user:
        raise RuntimeError("the kubeconfig user runs a credential plugin; the container needs a static credential")
    extra = sorted(set(user) - USER_KEYS)
    if extra:
        raise RuntimeError(f"the kubeconfig user sets {extra}; only {sorted(USER_KEYS)} are allowed")
    if not all(isinstance(value, str) and value and value.isprintable() for value in user.values()):
        raise RuntimeError("the kubeconfig user values must be non-empty printable strings")
    if set(user) not in (TOKEN_FORM, CERTIFICATE_FORM):
        raise RuntimeError("the kubeconfig user must hold a token alone or a client certificate and key")
    for key in CERTIFICATE_FORM & set(user):
        try:
            base64.b64decode(user[key], validate=True)
        except binascii.Error as error:
            raise RuntimeError(f"the kubeconfig {key} is not base64") from error


def check_cluster(cluster: dict[str, Any]) -> tuple[str, int | None]:
    extra = sorted(set(cluster) - CLUSTER_KEYS)
    if extra:
        raise RuntimeError(f"the kubeconfig cluster sets {extra}; only {sorted(CLUSTER_KEYS)} are allowed")
    authority = cluster.get("certificate-authority-data")
    if not isinstance(authority, str) or not authority:
        raise RuntimeError("the kubeconfig cluster has no certificate-authority-data")
    try:
        base64.b64decode(authority, validate=True)
    except binascii.Error as error:
        raise RuntimeError("the kubeconfig certificate-authority-data is not base64") from error
    text = cluster.get("server")
    if not isinstance(text, str) or not text.isprintable() or text != text.strip():
        raise RuntimeError("the kubeconfig server is not a printable string without surrounding whitespace")
    server = urllib.parse.urlsplit(text)
    if (
        server.scheme != "https"
        or not server.hostname
        or ":" in server.hostname
        or server.username is not None
        or server.path not in ("", "/")
        or server.query
        or server.fragment
    ):
        raise RuntimeError("the kubeconfig server is not https://<host>[:<port>] with no user info, path or query")
    try:
        return server.hostname, server.port
    except ValueError as error:
        raise RuntimeError("the kubeconfig server has an invalid port") from error


def check_gke_probe(project: str, location: str, host: str, port: int | None) -> None:
    output = subprocess.run(
        ["gcloud", "container", "clusters", "describe", PROBE_CLUSTER, "--project", project, "--location", location,
         "--format", "json"],
        capture_output=True, text=True, check=True, timeout=60,
    ).stdout  # fmt: skip
    cluster = json.loads(output)
    if (cluster.get("resourceLabels") or {}).get(PROBE_LABEL) != PROBE_CLUSTER:
        raise RuntimeError(f"cluster {PROBE_CLUSTER} in {project} has no label {PROBE_LABEL}={PROBE_CLUSTER}")
    if host != cluster.get("endpoint") or port not in GKE_PORTS:
        raise RuntimeError(f"the kubeconfig server {host}:{port} is not the endpoint of {PROBE_CLUSTER} in {project}")


def minify_kubeconfig(
    context: str,
    allowed: frozenset[str] = ALLOWED_CONTEXTS,
    applier_token: str | None = None,
    gke_project: str | None = None,
) -> dict[str, Any]:
    probe = GKE_PROBE.fullmatch(context)
    if context not in allowed and probe is None:
        raise RuntimeError(
            f"context {context!r} is not a disposable cluster; allowed: {sorted(allowed)} or a GKE bailiff-probe"
        )
    if probe is not None and probe["project"] != gke_project:
        raise RuntimeError(f"context {context!r} is not in the probe project given by --gke-project ({gke_project})")
    output = subprocess.run(
        ["kubectl", "config", "view", "--minify", "--flatten", "--context", context, "-o", "json"],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    ).stdout
    view: dict[str, Any] = json.loads(output)
    for key in ("contexts", "clusters", "users"):
        if len(view.get(key) or []) != 1:
            raise RuntimeError(f"the minified kubeconfig must hold exactly one of {key}")
    if view["contexts"][0]["name"] != context:
        raise RuntimeError(f"the minified kubeconfig names context {view['contexts'][0]['name']!r}, not {context!r}")
    if applier_token is not None:
        view["users"][0]["user"] = {"token": applier_token}
    check_user(view["users"][0].get("user") or {})
    cluster = view["clusters"][0]["cluster"]
    host, port = check_cluster(cluster)
    if probe is not None:
        check_gke_probe(probe["project"], probe["location"], host, port)
        cluster["server"] = f"https://{host}"
        return view
    if host not in ORBSTACK_HOSTS or port is None:
        raise RuntimeError(f"the kubeconfig server host {host} is not one of {sorted(ORBSTACK_HOSTS)} with a port")
    cluster["server"] = f"https://{ORBSTACK_HOST}:{port}"
    return view


def read_token() -> str:
    if "ANTHROPIC_API_KEY" in os.environ:
        raise RuntimeError("unset ANTHROPIC_API_KEY; the live run authenticates only with CLAUDE_CODE_OAUTH_TOKEN")
    token = os.environ.pop(TOKEN_VARIABLE, "").strip()
    if not token:
        raise RuntimeError(f"set {TOKEN_VARIABLE} (claude setup-token)")
    return token


def stdin_bundle(token: str, kubeconfig: dict[str, Any] | None) -> bytes:
    secret = token.encode()
    config = json.dumps(kubeconfig).encode() if kubeconfig is not None else b""
    return f"{len(secret)} {len(config)}\n".encode() + secret + config


def container_command(spec: RunSpec, image: str) -> list[str]:
    command = [
        "docker", "--context", spec.docker_context, "run", "--rm", "-i", "--init",
        "--name", f"bl-{spec.run_id}", "--label", f"agent-bailiff/run={spec.run_id}",
        "--stop-timeout", str(STOP_SECONDS), "--platform", "linux/amd64",
        "--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "SETUID", "--cap-add", "SETGID", "--cap-add", "KILL",
        "--tmpfs", f"{ROOT}:size=512m",
        "-e", f"ROOT={ROOT}", "-e", f"ARCHIVER_UID={spec.archiver_uid}", "-e", f"SCRIPT={spec.script}.py",
        image, "--run-id", spec.run_id, "--model", spec.model,
    ]  # fmt: skip
    if spec.script != "kubernetes":
        return command
    if spec.context is None:
        raise RuntimeError("the kubernetes run needs a context")
    if spec.catalog == READ_CATALOG:
        return [*command, "--context", spec.context, "--catalog", READ_CATALOG, "--platform", spec.platform]
    if spec.platform != "upstream":
        raise RuntimeError(f"platform {spec.platform} supports the {READ_CATALOG} catalog only")
    if spec.webhook_image is None:
        raise RuntimeError("the kubernetes catalog needs a webhook image")
    return [*command, "--context", spec.context, "--webhook-image", spec.webhook_image]


def read_result(stdout: str, run_id: str) -> dict[str, Any]:
    lines = stdout.strip().splitlines()
    if not lines:
        raise RuntimeError("the harness printed no result")
    try:
        result = json.loads(lines[-1])
    except json.JSONDecodeError as error:
        raise RuntimeError(f"the last stdout line is not compact result JSON: {lines[-1][:200]!r}") from error
    if not isinstance(result, dict) or result.get("run_id") != run_id or result.get("status") not in ("ok", "failed"):
        raise RuntimeError(f"the result is not a result for run {run_id}")
    return result


def report_lock(context: str, docker_context: str) -> str:
    owner = subprocess.run(
        ["kubectl", "--context", context, "get", "namespace", LOCK, "--ignore-not-found", "-o",
         "jsonpath={.metadata.annotations.agent-bailiff/owner}"],
        capture_output=True, text=True, check=True, timeout=30,
    ).stdout.strip()  # fmt: skip
    if not owner:
        return f"namespace {LOCK} is absent or has no owner"
    running = subprocess.run(
        ["docker", "--context", docker_context, "ps", "--filter", f"name=^bl-{owner}$", "--format", "{{.Names}}"],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    ).stdout.split()
    if running:
        return f"namespace {LOCK} is held by run {owner}, and container bl-{owner} is running; wait for it"
    return (
        f"namespace {LOCK} is held by run {owner}, and container bl-{owner} is not running; delete the namespaces "
        f"labelled agent-bailiff/run={owner}, then namespace {LOCK}"
    )


def write_result(path: Path, result: dict[str, Any]) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as file:
        json.dump(result, file, indent=2)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--script", choices=("run", "kubernetes"), required=True)
    parser.add_argument("--context", default="orbstack", help="disposable cluster context for the kubernetes run")
    parser.add_argument("--docker-context", default="orbstack")
    parser.add_argument("--model", default="claude-sonnet-5-5")
    parser.add_argument("--archiver-uid", type=int, default=10009)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--catalog", choices=("kubernetes", READ_CATALOG), default="kubernetes")
    parser.add_argument("--applier-token-file", type=Path, help="static applier token for a context that uses exec")
    parser.add_argument("--gke-project", help="project of the GKE bailiff-probe cluster the context must name")
    args = parser.parse_args()
    if args.out.exists():
        raise SystemExit(f"{args.out} already exists")
    if args.out.resolve().is_relative_to(REPO):
        raise SystemExit(f"{args.out} is inside the repo, which is the image build context; write it elsewhere")
    token = read_token()
    kubernetes = args.script == "kubernetes"
    applier_token = args.applier_token_file.read_text().strip() if args.applier_token_file else None
    kubeconfig = (
        minify_kubeconfig(args.context, applier_token=applier_token, gke_project=args.gke_project)
        if kubernetes
        else None
    )
    webhook = None
    if kubernetes and args.catalog != READ_CATALOG:
        webhook = resolve_digest(
            args.docker_context, build_image(args.docker_context, "deploy/kubernetes/Dockerfile.webhook", WEBHOOK_TAG)
        )
    image = build_image(args.docker_context, "examples/live-run/Dockerfile", IMAGE_TAG, "linux/amd64")
    spec = RunSpec(
        script=args.script,
        context=args.context if kubernetes else None,
        model=args.model,
        out=args.out,
        run_id=secrets.token_hex(4),
        archiver_uid=args.archiver_uid,
        docker_context=args.docker_context,
        webhook_image=webhook,
        catalog=args.catalog,
        platform=platform_of(args.context),
    )
    process = subprocess.Popen(container_command(spec, image), stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        stdout, _ = process.communicate(stdin_bundle(token, kubeconfig), timeout=RUN_SECONDS)
    except subprocess.TimeoutExpired:
        subprocess.run(
            ["docker", "--context", spec.docker_context, "stop", "--time", str(STOP_SECONDS), f"bl-{spec.run_id}"],
            timeout=STOP_SECONDS + 30,
            check=False,
        )
        process.wait(30)
        raise SystemExit(f"run {spec.run_id} passed {RUN_SECONDS} s and was stopped") from None
    if process.returncode != 0:
        if kubernetes:
            print(report_lock(args.context, args.docker_context), file=sys.stderr)
        raise SystemExit(process.returncode)
    result = read_result(stdout.decode(), spec.run_id)
    write_result(spec.out, result)
    print(f"run {spec.run_id}: wrote {spec.out}")
    if result["status"] != "ok":
        raise SystemExit(f"run {spec.run_id} failed its checks: {', '.join(result['failures'])}")


if __name__ == "__main__":
    main()
