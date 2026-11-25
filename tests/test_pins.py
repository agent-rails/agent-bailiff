import json
import re
import tomllib
from pathlib import Path

import test_install_smoke
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parent.parent
PINS = {
    "agent-warrant==0.4.0",
    "toolcall-authz==0.3.0",
    "cryptography==50.0.2",
    "grpcio==1.85.3",
    "protobuf==7.36.2",
}
PINNED_NAMES = ("agent-warrant", "toolcall-authz", "cryptography", "grpcio", "protobuf")
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


def test_runtime_dependencies_are_exactly_the_pins():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    assert sorted(project["dependencies"]) == sorted(PINS)


def test_installed_versions_match_the_pins():
    from importlib.metadata import version

    assert {f"{name}=={version(name)}" for name in PINNED_NAMES} == PINS


def test_workflow_actions_are_pinned_to_commit_shas():
    uses = re.findall(r"uses:\s*(\S+)", WORKFLOW.read_text())
    assert uses
    for reference in uses:
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", reference), reference


def test_workflow_token_is_read_only_and_credentials_are_not_persisted():
    workflow = WORKFLOW.read_text()
    assert re.search(r"^permissions:\n  contents: read$", workflow, re.MULTILINE)
    assert "persist-credentials: false" in workflow


def test_type_check_is_strict_and_runs_in_ci():
    config = tomllib.loads((ROOT / "pyproject.toml").read_text())["tool"]["mypy"]
    assert config["strict"] is True
    assert "agent_bailiff" in config["files"]
    assert "- run: mypy" in WORKFLOW.read_text()


def locked_versions():
    versions = {}
    for line in (ROOT / "requirements-ci.txt").read_text().splitlines():
        if not line or line[0] in " #-":
            continue
        name, version = line.split(";")[0].split()[0].split("==")
        versions[canonicalize_name(name)] = version
    return versions


def test_lock_pins_every_requirement_with_hashes():
    text = (ROOT / "requirements-ci.txt").read_text()
    entries = re.split(r"\n(?=\S)", text.strip())
    assert entries
    for entry in entries:
        assert re.match(r"[\w.-]+==[\w.]+", entry), entry
        hash_lines = [line for line in entry.splitlines()[1:] if not line.lstrip().startswith("#")]
        assert any(re.fullmatch(r"\s+--hash=sha256:[0-9a-f]{64}( \\)?", line) for line in hash_lines), entry


def test_lock_satisfies_pyproject_and_build_requirements():
    data = tomllib.loads((ROOT / "pyproject.toml").read_text())
    required = [
        *data["project"]["dependencies"],
        *data["project"]["optional-dependencies"]["dev"],
        *data["build-system"]["requires"],
    ]
    versions = locked_versions()
    for text in required:
        requirement = Requirement(text)
        name = canonicalize_name(requirement.name)
        assert name in versions, text
        assert requirement.specifier.contains(versions[name], prereleases=True), (text, versions[name])
    assert {f"{name}=={versions[name]}" for name in PINNED_NAMES} == PINS


INSTALLER = re.compile(r"\b(pip3?|uv|pipx|poetry|conda|easy_install)\b")


JOB = re.compile(r"^  [a-z][a-z0-9-]*:$")


def test_every_ci_job_installs_from_the_hash_lock_and_the_smoke_job_only_adds_uv():
    jobs: dict[str, list[str]] = {}
    current = None
    for line in WORKFLOW.read_text().split("\njobs:\n", 1)[1].splitlines():
        if JOB.match(line):
            current = jobs.setdefault(line.strip().removesuffix(":"), [])
        elif INSTALLER.search(line):
            assert current is not None, line
            current.append(line.strip().removeprefix("- run:").strip())
    assert set(jobs) == {"test", "install-smoke", "quickstart-integration", "live-run-image"}
    assert jobs.pop("install-smoke") == [
        "- uses: astral-sh/setup-uv@68559e99cc807c1eb7e9238fd43a15bba460eec2 # v10.3.3",
        "python -m pip install --require-hashes -r requirements-ci.txt",
    ]
    locked = [
        "python -m pip install --require-hashes -r requirements-ci.txt",
        "python -m pip install --no-deps --no-build-isolation -e .",
        "python -m pip check",
    ]
    assert jobs.pop("quickstart-integration") == [
        *locked,
        "/opt/bailiff-agent/bin/python -m pip install --require-hashes -r requirements-ci.txt",
        "/opt/bailiff-agent/bin/python -m pip install --no-deps --no-build-isolation .",
        "/opt/bailiff-agent/bin/python -m pip check",
    ]
    assert jobs.pop("test") == [
        *locked,
        '"$RUNNER_TEMP/aw030/bin/python" -m pip install --require-hashes -r requirements-aw030.txt',
    ]
    for name, installs in jobs.items():
        assert installs == locked, name


def test_the_install_smoke_resolves_runtime_and_build_deps_within_the_ci_lock():
    command = test_install_smoke.install_command("HEAD")
    assert command[command.index("--constraints") + 1] == str(test_install_smoke.LOCK)
    assert command[command.index("--build-constraints") + 1] == str(test_install_smoke.LOCK)
    assert "--no-python-downloads" in command
    assert test_install_smoke.LOCK == ROOT / "requirements-ci.txt"


def test_package_imports():
    import agent_bailiff  # noqa: F401


CLAUDE_CLI = "@anthropic-ai/claude-code"
CLAUDE_CLI_VERSION = "2.1.301"
CLAUDE_CLI_INTEGRITY = "sha512-sEqs0D9IIc6GwbdMvss5GHOjLjhaoqbrZWdickLRlG6v4kT946t4pq3zFAmQdUpRgdv1CvtSLyRrrdp+hDS9ww=="


def test_the_live_run_claude_cli_is_pinned_by_lockfile():
    live_run = ROOT / "examples" / "live-run"
    assert json.loads((live_run / "package.json").read_text())["dependencies"] == {CLAUDE_CLI: CLAUDE_CLI_VERSION}
    packages = json.loads((live_run / "package-lock.json").read_text())["packages"]
    cli = packages[f"node_modules/{CLAUDE_CLI}"]
    assert (cli["version"], cli["integrity"]) == (CLAUDE_CLI_VERSION, CLAUDE_CLI_INTEGRITY)
    assert f"node_modules/{CLAUDE_CLI}-linux-x64" in packages
    for path, package in packages.items():
        if not path:
            continue
        assert package["version"] == CLAUDE_CLI_VERSION, path
        assert package["resolved"].startswith("https://registry.npmjs.org/@anthropic-ai/"), path
        assert re.fullmatch(r"sha512-[A-Za-z0-9+/]{86}==", package["integrity"]), path


def test_the_live_run_image_pins_every_input_by_digest():
    dockerfile = (ROOT / "examples" / "live-run" / "Dockerfile").read_text()
    stages = re.findall(r"^FROM .*$", dockerfile, re.MULTILINE)
    images = re.findall(r"^FROM --platform=linux/amd64 (\S+)", dockerfile, re.MULTILINE)
    assert len(stages) == len(images) == 2
    for image in images:
        assert re.fullmatch(r"[\w.-]+:[\w.-]+@sha256:[0-9a-f]{64}", image), image
    added = dict(re.findall(r"ADD --checksum=sha256:([0-9a-f]{64}) --chmod=0755 \\\n\s+(\S+)", dockerfile))
    assert len(added) == 2
    pins = (ROOT / "adapters" / "agentgateway" / "agentgateway-v1.7.0.sha256").read_text()
    gateway = re.search(r"^([0-9a-f]{64})  agentgateway-linux-amd64$", pins, re.MULTILINE).group(1)
    assert added[gateway].endswith("/v1.7.0/agentgateway-linux-amd64")
    assert "npm ci" in dockerfile and "npm install" not in dockerfile
    assert "--require-hashes -r /tmp/requirements-ci.txt" in dockerfile
