import re
import tomllib
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parent.parent
PINS = {
    "agent-warrant==0.1.0",
    "toolcall-authz==0.3.0",
    "cryptography==50.0.2",
    "grpcio==1.85.1",
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


def test_ci_installs_only_from_the_hash_lock():
    lines = WORKFLOW.read_text().splitlines()
    installs = [line.strip().removeprefix("- run:").strip() for line in lines if INSTALLER.search(line)]
    assert installs == [
        "python -m pip install --require-hashes -r requirements-ci.txt",
        "python -m pip install --no-deps --no-build-isolation -e .",
        "python -m pip check",
    ]


def test_package_imports():
    import agent_bailiff  # noqa: F401
