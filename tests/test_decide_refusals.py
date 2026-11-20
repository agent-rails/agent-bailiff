import time

import pytest

from agent_bailiff.decide.refusals import RefusalBudget


class FakeClock:
    def __init__(self, now=1000.0):
        self.now = now

    def __call__(self):
        return self.now


def make_budget(clock, **options):
    return RefusalBudget(**{"limit": 2, "window_seconds": 10, "clock": clock, **options})


def admit(budget, tenant="t", task="task", reason="out_of_scope", tool="tool.read"):
    return budget.admit(tenant, task, reason, tool)


def test_admits_up_to_the_limit_per_window():
    clock = FakeClock()
    budget = make_budget(clock)
    assert [admit(budget) is not None for _ in range(3)] == [True, True, False]
    clock.now += 10
    assert admit(budget) is not None


def test_tenants_tasks_reasons_and_tools_have_separate_budgets():
    budget = make_budget(FakeClock(), limit=1)
    assert admit(budget) is not None
    assert admit(budget, tenant="t2") is not None
    assert admit(budget, task="other") is not None
    assert admit(budget, reason="unknown_cost") is not None
    assert admit(budget, tool="tool.write") is not None
    assert admit(budget) is None


def test_padding_one_kind_does_not_hide_the_first_refusal_of_another():
    budget = make_budget(FakeClock(), limit=16)
    for _ in range(64):
        admit(budget, reason="unknown_cost", tool="deploy.delete")
    assert admit(budget, reason="out_of_scope", tool="gitea.contents.read") is not None


def test_a_refund_returns_one_admission():
    budget = make_budget(FakeClock(), limit=1)
    window = admit(budget)
    budget.refund("t", "task", "out_of_scope", "tool.read", window)
    assert admit(budget) is not None
    assert admit(budget) is None


def test_a_refund_never_goes_below_zero():
    budget = make_budget(FakeClock(), limit=1)
    window = admit(budget)
    budget.refund("t", "task", "out_of_scope", "tool.read", window)
    budget.refund("t", "task", "out_of_scope", "tool.read", window)
    assert admit(budget) is not None
    assert admit(budget) is None


def test_a_refund_from_an_expired_window_does_not_lift_the_new_one():
    clock = FakeClock()
    budget = make_budget(clock, limit=1)
    old = admit(budget)
    clock.now += 10
    assert admit(budget) is not None
    budget.refund("t", "task", "out_of_scope", "tool.read", old)
    assert admit(budget) is None


def test_a_full_budget_refuses_new_kinds_and_keeps_active_counts():
    clock = FakeClock()
    budget = make_budget(clock, max_kinds=1)
    assert [admit(budget, task="a") is not None for _ in range(3)] == [True, True, False]
    assert admit(budget, task="b") is None
    assert admit(budget, task="a") is None
    clock.now += 10
    assert admit(budget, task="b") is not None


def test_one_tenant_cannot_fill_the_budget_for_another():
    budget = make_budget(FakeClock(), max_kinds=8, max_kinds_per_tenant=2)
    assert [admit(budget, tenant="a", task=f"task-{n}") is not None for n in range(3)] == [True, True, False]
    assert admit(budget, tenant="b") is not None


def test_expired_kinds_free_the_tenant_share():
    clock = FakeClock()
    budget = make_budget(clock, max_kinds_per_tenant=1)
    assert admit(budget, task="a") is not None
    assert admit(budget, task="b") is None
    clock.now += 10
    assert admit(budget, task="b") is not None


def test_uses_its_own_clock_not_the_request_time():
    clock = FakeClock()
    budget = make_budget(clock, limit=1)
    assert admit(budget) is not None
    clock.now -= 1
    assert admit(budget) is None


def test_defaults_to_a_monotonic_clock():
    assert RefusalBudget()._clock is time.monotonic


@pytest.mark.parametrize("name", ["limit", "window_seconds", "max_kinds", "max_kinds_per_tenant"])
@pytest.mark.parametrize("value", [0, -1, True, 1.5])
def test_rejects_a_non_positive_integer(name, value):
    with pytest.raises(ValueError, match=name):
        RefusalBudget(**{name: value})
