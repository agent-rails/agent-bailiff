import pytest
from agent_warrant.scope import covers, validate_entry

from agent_bailiff.scope_pattern import is_bounded_resource, is_bounded_tool


@pytest.mark.parametrize("entry", ["gitea/repos/a/b", "gitea/repos/a/*", "env/*", "deploy.service"])
def test_exact_ids_and_segment_patterns_are_bounded(entry):
    assert is_bounded_resource(entry)


@pytest.mark.parametrize("entry", ["gitea/repos/acme-*", "deploy.*", "a_*", "x:*", "env/a.*"])
def test_patterns_that_stop_inside_a_segment_are_unbounded(entry):
    assert not is_bounded_resource(entry)


@pytest.mark.parametrize("entry", ["notes.read_note", "notes.*", "gitea.issues.*", "gitea/a"])
def test_exact_tools_and_dot_patterns_are_bounded_tools(entry):
    assert is_bounded_tool(entry)


@pytest.mark.parametrize("entry", ["gitea.issues_*", "gitea.issues-*", "gitea:*", "gitea/*"])
def test_tool_patterns_that_stop_inside_a_name_are_unbounded(entry):
    assert not is_bounded_tool(entry)


@pytest.mark.parametrize("tool", ["notes.x_y", "notes.x/y", "notes.x-y", "notes.x:y", "notes.x.y"])
def test_a_dot_tool_grant_covers_every_valid_suffix_across_separators(tool):
    scope = {"tools": ["notes.*"], "resources": ["r"], "max_cost_per_call": 1}
    assert is_bounded_tool("notes.*")
    assert covers(scope, tool, "r")


@pytest.mark.parametrize("tool", ["notes", "notesx", "notes_x"])
def test_a_dot_tool_grant_does_not_cover_the_stem_or_a_longer_name(tool):
    scope = {"tools": ["notes.*"], "resources": ["r"], "max_cost_per_call": 1}
    assert not covers(scope, tool, "r")


@pytest.mark.parametrize("entry", [".*", "a.*.*", "", "a*b.*"])
def test_is_bounded_tool_checks_only_the_suffix_and_leaves_invalid_entries_to_validate_entry(entry):
    assert is_bounded_tool(entry)
    assert validate_entry(entry) is not None
