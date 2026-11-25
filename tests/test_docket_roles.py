import pytest

from agent_bailiff.docket.roles import WriterRoles


def roles() -> WriterRoles:
    return WriterRoles({"decide": frozenset({"decide-a", "decide-b"}), "custodian": frozenset({"custodian"})})


def test_a_writer_holds_only_the_hops_it_is_pinned_for():
    assert roles().holds("decide-b", "decide")
    assert not roles().holds("custodian", "decide")
    assert not roles().holds("effector", "decide")


def test_a_hop_the_report_does_not_read_is_ignored():
    assert roles().reads("custodian")
    assert not roles().reads("effector")
    assert not roles().holds("effector", "effector")


def test_an_empty_writer_set_is_refused():
    with pytest.raises(ValueError, match="no writer is pinned for hop control"):
        WriterRoles({"decide": frozenset({"decide"}), "control": frozenset()})


def test_a_writer_pinned_for_two_hops_is_refused():
    with pytest.raises(ValueError, match="writer decide is pinned for both hops custodian and decide"):
        WriterRoles({"decide": frozenset({"decide"}), "custodian": frozenset({"decide"})})
