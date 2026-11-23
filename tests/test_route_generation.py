import json
import stat

import pytest

from agent_bailiff.cli import main
from agent_bailiff.route_generation import DUPLICATE, Rejected, generate_routes
from agent_bailiff.routes import ToolRoutes


def tools(*names):
    return {"tools": [{"name": name, "inputSchema": {"type": "object"}} for name in names]}


def test_routes_are_sorted_with_empty_resources():
    document, rejected = generate_routes(tools("search", "fetch"), "docs")
    assert rejected == []
    assert document == {
        "routes": [
            {"service": "docs", "name": "fetch", "tool": "docs.fetch", "resource": ""},
            {"service": "docs", "name": "search", "tool": "docs.search", "resource": ""},
        ]
    }


@pytest.mark.parametrize(
    ("name", "reason"),
    [
        ("list*", "wildcard"),
        ("list issues", "ASCII printable"),
        ("lïst", "ASCII printable"),
        ("", "ASCII printable"),
        ("x" * 200, "not a scope id"),
    ],
)
def test_a_name_that_is_not_a_concrete_scope_id_is_rejected(name, reason):
    document, rejected = generate_routes(tools("fetch", name), "docs")
    assert [route["name"] for route in document["routes"]] == ["fetch"]
    assert len(rejected) == 1
    assert reason in rejected[0].reason


def test_a_tool_without_a_string_name_is_rejected():
    document, rejected = generate_routes({"tools": [{"name": 7}, "fetch"]}, "docs")
    assert document == {"routes": []}
    assert [item.reason for item in rejected] == ["the tool has no string name"] * 2


def test_a_duplicated_name_is_rejected_and_not_routed():
    document, rejected = generate_routes(tools("fetch", "search", "fetch"), "docs")
    assert [route["name"] for route in document["routes"]] == ["search"]
    assert rejected == [Rejected("fetch", DUPLICATE)]


@pytest.mark.parametrize("service", ["k8s", "", "do cs", "docs*"])
def test_a_reserved_or_invalid_service_is_refused(service):
    with pytest.raises(ValueError):
        generate_routes(tools("fetch"), service)


@pytest.mark.parametrize("document", [[], {"tools": {}}, {"tools": [], "nextCursor": "x"}])
def test_a_document_that_is_not_a_tools_list_is_refused(document):
    with pytest.raises(ValueError, match='"tools" list'):
        generate_routes(document, "docs")


def test_a_generated_table_does_not_load_until_resources_are_filled():
    document, _ = generate_routes(tools("fetch"), "docs")
    with pytest.raises(ValueError, match=r"route 0 \('fetch'\)"):
        ToolRoutes.from_document(document)
    document["routes"][0]["resource"] = "docs/pages"
    assert ToolRoutes.from_document(document).route("docs", "fetch") is not None


def run_cli(tmp_path, document, out_name="routes.json"):
    source = tmp_path / "tools.json"
    source.write_text(json.dumps(document))
    out = tmp_path / out_name
    return main(["routes", "generate", "--tools", str(source), "--service", "docs", "--out", str(out)]), out


def test_the_cli_writes_a_new_table_and_exits_zero(tmp_path, capsys):
    code, out = run_cli(tmp_path, tools("fetch"))
    assert code == 0
    assert json.loads(out.read_text())["routes"][0]["tool"] == "docs.fetch"
    assert stat.S_IMODE(out.stat().st_mode) == 0o644
    assert "fill each resource" in capsys.readouterr().err


def test_the_cli_exits_one_when_any_name_is_rejected(tmp_path, capsys):
    code, out = run_cli(tmp_path, tools("fetch", "bad name"))
    assert code == 1
    assert [route["name"] for route in json.loads(out.read_text())["routes"]] == ["fetch"]
    assert "rejected 'bad name'" in capsys.readouterr().err


def test_the_cli_never_overwrites_the_out_file(tmp_path, capsys):
    (tmp_path / "routes.json").write_text("owner edits")
    code, out = run_cli(tmp_path, tools("fetch"))
    assert code == 1
    assert out.read_text() == "owner edits"
    assert "routes generate refused" in capsys.readouterr().err


def test_the_cli_refuses_a_symlinked_out_path(tmp_path):
    (tmp_path / "target.json").write_text("kept")
    (tmp_path / "routes.json").symlink_to(tmp_path / "target.json")
    code, _ = run_cli(tmp_path, tools("fetch"))
    assert code == 1
    assert (tmp_path / "target.json").read_text() == "kept"


@pytest.mark.parametrize("raw", ["not json", '{"tools": [], "tools": []}'])
def test_the_cli_refuses_a_tools_file_that_is_not_strict_json(tmp_path, raw):
    source = tmp_path / "tools.json"
    source.write_text(raw)
    out = tmp_path / "routes.json"
    assert main(["routes", "generate", "--tools", str(source), "--service", "docs", "--out", str(out)]) == 1
    assert not out.exists()
