import subprocess
import sys

import pytest

from agent_bailiff.effector.catalog import Argument

PROBE = """
import sys
from importlib.abc import MetaPathFinder


class Block(MetaPathFinder):
    def find_spec(self, name, path=None, target=None):
        if name == "google.protobuf" or name.startswith(("google.protobuf.", "agent_bailiff.adapters")):
            raise ImportError(f"blocked {name}")
        return None


sys.meta_path.insert(0, Block())
from agent_bailiff.routes import ToolRoute, ToolRoutes

routes = ToolRoutes([ToolRoute("gitea", "get_me", "gitea.user.read", "gitea/user/self")])
print(routes.route("gitea", "get_me").resource_for({}))
"""


def test_routes_import_without_the_gateway_adapter_or_protobuf():
    result = subprocess.run([sys.executable, "-c", PROBE], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "gitea/user/self"


IDENTIFIER = Argument("repo", "identifier")


@pytest.mark.parametrize("value", ["My_Repo.v2", "a-b", "a", "_x", "9", "a" * 100, "a..b"])
def test_an_identifier_accepts_real_repository_names(value):
    assert IDENTIFIER.accepts(value)


@pytest.mark.parametrize("value", [".hidden", "..", ".", "a" * 101, "a/b", "a b", "a\n", "", 1, None, True, "é"])
def test_an_identifier_refuses_anything_that_is_not_one_segment(value):
    assert not IDENTIFIER.accepts(value)
