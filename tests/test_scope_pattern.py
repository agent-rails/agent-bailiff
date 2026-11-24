import pytest

from agent_bailiff.scope_pattern import is_bounded_resource


@pytest.mark.parametrize("entry", ["gitea/repos/a/b", "gitea/repos/a/*", "env/*", "deploy.service"])
def test_exact_ids_and_segment_patterns_are_bounded(entry):
    assert is_bounded_resource(entry)


@pytest.mark.parametrize("entry", ["gitea/repos/acme-*", "deploy.*", "a_*", "x:*", "env/a.*"])
def test_patterns_that_stop_inside_a_segment_are_unbounded(entry):
    assert not is_bounded_resource(entry)
