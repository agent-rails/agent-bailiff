import subprocess
import sys

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
