import re
import subprocess
import sys

import pytest

from agent_bailiff.effector.catalog import Argument
from agent_bailiff.routes import ToolRoute, ToolRoutes

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


OWNER_REPO = [{"name": "owner", "kind": "identifier"}, {"name": "repo", "kind": "identifier"}]
ROUTE = {
    "service": "gitea",
    "name": "list_issues",
    "tool": "gitea.issues.read",
    "resource": "gitea/repos/{owner}/{repo}/issues",
    "schema": OWNER_REPO,
}


def document_route(**changes):
    return ToolRoutes.from_document({"routes": [{**ROUTE, **changes}]}).route("gitea", "list_issues")


@pytest.mark.parametrize(
    ("second", "expected"),
    [
        ({**ROUTE, "name": "close_issue", "resource": ""}, "route 1 ('close_issue'): resource must be"),
        ({**ROUTE, "name": "close_issue", "tool": "gitea.*"}, "route 1 ('close_issue'): tool must be"),
        ({"service": "gitea"}, "route 1 (None): each route must have exactly the fields"),
        ("not a route", "route 1 (None): each route must have exactly the fields"),
        ({**ROUTE, "name": "x" * 1000, "resource": ""}, f"route 1 ('{'x' * 79}): resource must be"),
    ],
)
def test_a_bad_document_route_is_named_by_index_and_name(second, expected):
    with pytest.raises(ValueError, match=re.escape(expected)):
        ToolRoutes.from_document({"routes": [ROUTE, second]})


def test_a_document_route_checks_its_schema_arguments_and_leaves_the_others():
    route = document_route()
    assert route.resource_for({"owner": "o", "repo": "r", "page": 2}) == "gitea/repos/o/r/issues"
    assert route.resource_for({"owner": "Acme_Co", "repo": "My.Repo"}) == "gitea/repos/Acme_Co/My.Repo/issues"


@pytest.mark.parametrize(
    "arguments",
    [
        {"owner": "o"},
        {"repo": "r", "page": 2},
        {"owner": "o", "repo": "../x"},
        {"owner": "o", "repo": ".."},
        {"owner": "o", "repo": 1},
        {"owner": "o" * 100, "repo": "r" * 100},
    ],
)
def test_a_document_route_without_a_valid_resource_resolves_to_nothing(arguments):
    assert document_route().resource_for(arguments) is None


def test_a_missing_schema_argument_is_never_accepted_even_with_extras():
    route = document_route()
    assert route.resource_for({"owner": "o", "page": 2, "reponame": "r"}) is None


def test_a_fixed_document_route_may_carry_an_empty_schema():
    route = document_route(resource="gitea/user/self", schema=[])
    assert route.resource_for({"anything": "goes"}) == "gitea/user/self"


@pytest.mark.parametrize(
    ("changes", "match"),
    [
        ({"schema": {}}, "must be a list"),
        ({"schema": [{"name": "owner"}]}, "exactly the fields"),
        ({"schema": [{"name": "owner", "kind": "identifier", "extra": 1}]}, "exactly the fields"),
        ({"schema": [{"name": 1, "kind": "identifier"}]}, "strings"),
        ({"schema": [{"name": "owner", "kind": "label"}, OWNER_REPO[1]]}, "identifier arguments only"),
        ({"schema": [{"name": "owner", "kind": "integer"}, OWNER_REPO[1]]}, "identifier arguments only"),
        ({"schema": [*OWNER_REPO, OWNER_REPO[1]]}, "each argument once"),
        ({"schema": [*OWNER_REPO, {"name": "page", "kind": "identifier"}]}, "exactly the resource placeholders"),
        ({"schema": OWNER_REPO[:1]}, "exactly the resource placeholders"),
        ({"schema": OWNER_REPO, "tool": "k8s.pods.list"}, "routed only from their catalog"),
        ({"extra": 1}, "exactly the fields"),
        ({"resource": "gitea/repos/{owner}{repo}/issues"}, "whole resource segment"),
        ({"resource": "gitea/repos/{owner}/{repo}-x/issues"}, "whole resource segment"),
        ({"resource": "gitea/repos/{owner}.{repo}"}, "whole resource segment"),
    ],
)
def test_a_route_document_schema_outside_the_format_is_refused(changes, match):
    with pytest.raises(ValueError, match=match):
        document_route(**changes)


def test_a_catalog_route_still_refuses_extra_arguments():
    route = ToolRoute("k8s", "x", "k8s.x", "k8s/{namespace}/x", (Argument("namespace", "label"),))
    assert route.resource_for({"namespace": "staging"}) == "k8s/staging/x"
    assert route.resource_for({"namespace": "staging", "extra": 1}) is None


@pytest.mark.parametrize("resource", ["k8s/{namespace}{name}", "k8s/a{namespace}", "k8s/{namespace}-x/pods"])
def test_a_catalog_route_placeholder_must_be_a_whole_segment(resource):
    schema = (Argument("namespace", "label"), Argument("name", "label"))
    with pytest.raises(ValueError, match="whole resource segment"):
        ToolRoute("k8s", "x", "k8s.x", resource, schema)


def test_a_duplicate_route_error_caps_the_echoed_names():
    route = {**ROUTE, "name": "n" * 1000}
    with pytest.raises(ValueError) as raised:
        ToolRoutes.from_document({"routes": [route, route]})
    assert len(str(raised.value)) < 300
