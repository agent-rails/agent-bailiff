from types import SimpleNamespace

import pytest
from agent_warrant.scope import check_call, permissions_of, validate_entry

from agent_bailiff.scope_pattern import is_bounded_resource, is_bounded_scope, is_bounded_tool, scope_refusal

NOTES = {"tools": ["notes.read_note", "notes.write_note"], "resources": ["todo"], "max_cost_per_call": 5}
PAYROLL = {"tools": ["notes.read_note"], "resources": ["payroll"], "max_cost_per_call": 1}


def _records(*scopes):
    return tuple(SimpleNamespace(permissions=permissions_of(scope)) for scope in scopes)


def _scope(*permissions):
    return {"permissions": list(permissions)}


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
    scope = _scope({"tools": ["notes.*"], "resources": ["r"], "max_cost_per_call": 1})
    assert is_bounded_tool("notes.*")
    assert check_call(permissions_of(scope), tool, "r", 1) is None


@pytest.mark.parametrize("tool", ["notes", "notesx", "notes_x"])
def test_a_dot_tool_grant_does_not_cover_the_stem_or_a_longer_name(tool):
    scope = _scope({"tools": ["notes.*"], "resources": ["r"], "max_cost_per_call": 1})
    assert check_call(permissions_of(scope), tool, "r", 1) is not None


@pytest.mark.parametrize("entry", [".*", "a.*.*", "", "a*b.*"])
def test_is_bounded_tool_checks_only_the_suffix_and_leaves_invalid_entries_to_validate_entry(entry):
    assert is_bounded_tool(entry)
    assert validate_entry(entry) is not None


def test_is_bounded_scope_checks_every_permission():
    bounded = _scope(NOTES, PAYROLL)
    unbounded = _scope(NOTES, {"tools": ["notes.read_note"], "resources": ["pay-*"], "max_cost_per_call": 1})
    assert is_bounded_scope(permissions_of(bounded))
    assert not is_bounded_scope(permissions_of(unbounded))


def test_a_call_paired_inside_one_permission_is_allowed():
    records = _records(_scope(NOTES, PAYROLL))
    assert scope_refusal(records, "notes.write_note", "todo", 5) is None
    assert scope_refusal(records, "notes.read_note", "payroll", 1) is None


def test_a_tool_and_resource_from_different_permissions_do_not_pair():
    records = _records(_scope(NOTES, PAYROLL))
    assert scope_refusal(records, "notes.write_note", "payroll", 1) == "out_of_scope"


def test_cost_is_checked_against_the_permission_that_covers_the_pair():
    records = _records(_scope(NOTES, PAYROLL))
    assert scope_refusal(records, "notes.read_note", "payroll", 2) == "cost_over_call_cap"
    assert scope_refusal(records, "notes.read_note", "todo", 5) is None


def test_any_unbounded_record_in_the_chain_refuses_before_scope():
    wide = _scope({"tools": ["notes.*"], "resources": ["to-*"], "max_cost_per_call": 5})
    records = _records(wide, _scope(NOTES))
    assert scope_refusal(records, "notes.read_note", "todo", 1) == "unbounded_scope"


def test_only_the_leaf_record_decides_the_call():
    records = _records(_scope(NOTES, PAYROLL), _scope(NOTES))
    assert scope_refusal(records, "notes.read_note", "payroll", 1) == "out_of_scope"


def test_a_v1_record_is_one_permission():
    records = _records(NOTES)
    assert scope_refusal(records, "notes.write_note", "todo", 5) is None
    assert scope_refusal(records, "notes.write_note", "todo", 6) == "cost_over_call_cap"


@pytest.mark.parametrize("tool, resource", [("notes.*", "todo"), ("notes.read_note", "notes/../todo"), ("", "todo")])
def test_a_value_that_is_not_concrete_is_out_of_scope(tool, resource):
    assert scope_refusal(_records(_scope(NOTES)), tool, resource, 1) == "out_of_scope"


def test_no_records_is_a_caller_error():
    with pytest.raises(ValueError):
        scope_refusal((), "notes.read_note", "todo", 1)
