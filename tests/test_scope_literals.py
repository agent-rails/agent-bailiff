import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCOPE_IMPORT = re.compile(r"from\s+agent_warrant\.scope\s+import\s+(\([^)]*\)|[^\n]*)")
V1_SCOPE = re.compile(r"""scope\W{0,6}\{\s*\\?["']tools\\?["']""", re.IGNORECASE)


def scope_literal_problems(path, text):
    problems = [
        f"{path}: imports covers from agent_warrant.scope; use Permission.covers"
        for match in SCOPE_IMPORT.finditer(text)
        if re.search(r"\bcovers\b", match.group(1))
    ]
    for match in V1_SCOPE.finditer(text):
        line = text.count("\n", 0, match.start()) + 1
        problems.append(f'{path}:{line}: v1 scope literal; wrap it as {{"permissions": [...]}}')
    return problems


def tracked_files():
    listing = subprocess.run(["git", "ls-files", "-z", ":!tests"], cwd=ROOT, capture_output=True, check=True)
    for name in listing.stdout.decode().split("\0"):
        path = ROOT / name
        if name and path.is_file():
            yield name, path


def test_the_tree_has_no_covers_import_and_no_v1_scope_literal():
    problems = []
    for name, path in tracked_files():
        try:
            text = path.read_text()
        except UnicodeDecodeError:
            continue
        problems += scope_literal_problems(name, text)
    assert problems == []


@pytest.mark.parametrize(
    "text",
    [
        "from agent_warrant.scope import covers\n",
        "from agent_warrant.scope import Permission, covers\n",
        "from agent_warrant.scope import (\n    Permission,\n    covers,\n)\n",
        'SCOPE = {"tools": ["deploy.*"], "resources": ["env/*"], "max_cost_per_call": 5}\n',
        'scope={\n    "tools": ["k8s.*"],\n',
        '"scope": {"tools": ["a"], "resources": ["b"], "max_cost_per_call": 1}\n',
        """--scope '{"tools": ["notes.read_note"], "resources": ["notes/todo"], "max_cost_per_call": 1}'\n""",
        'TASK_SCOPE = {\\"tools\\": []}\n',
    ],
)
def test_a_seeded_covers_import_or_v1_scope_is_found(text):
    assert scope_literal_problems("seeded.py", text)


@pytest.mark.parametrize(
    "text",
    [
        "from agent_warrant.scope import Permission, check_call\n",
        "Permission(tools, resources, 0).covers(tool, resource)\n",
        'SCOPE = {"permissions": [{"tools": ["deploy.*"], "resources": ["env/*"], "max_cost_per_call": 5}]}\n',
        'costs = {"version": 1, "tools": {"deploy.service": 1}}\n',
        '--scope \'{"permissions": [{"tools": ["a"], "resources": ["b"], "max_cost_per_call": 1}]}\'\n',
    ],
)
def test_a_v2_scope_and_permission_covers_pass(text):
    assert scope_literal_problems("seeded.py", text) == []
