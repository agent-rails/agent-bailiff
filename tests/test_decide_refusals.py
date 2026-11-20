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


def test_admits_up_to_the_limit_per_window():
    clock = FakeClock()
    budget = make_budget(clock)
    assert [budget.admit("t", "task") for _ in range(3)] == [True, True, False]
    clock.now += 10
    assert budget.admit("t", "task")


def test_tasks_and_tenants_have_separate_budgets():
    budget = make_budget(FakeClock(), limit=1)
    assert budget.admit("t1", "task")
    assert budget.admit("t2", "task")
    assert budget.admit("t1", "other")
    assert not budget.admit("t1", "task")


def test_a_refund_returns_one_admission():
    budget = make_budget(FakeClock(), limit=1)
    assert budget.admit("t", "task")
    budget.refund("t", "task")
    assert budget.admit("t", "task")
    assert not budget.admit("t", "task")


def test_a_refund_never_goes_below_zero():
    budget = make_budget(FakeClock(), limit=1)
    budget.refund("t", "task")
    assert budget.admit("t", "task")
    budget.refund("t", "task")
    budget.refund("t", "task")
    assert budget.admit("t", "task")
    assert not budget.admit("t", "task")


def test_a_full_budget_refuses_new_tasks_and_keeps_active_counts():
    clock = FakeClock()
    budget = make_budget(clock, max_tasks=1)
    assert [budget.admit("t", "a") for _ in range(3)] == [True, True, False]
    assert not budget.admit("t", "b")
    assert not budget.admit("t", "a")
    clock.now += 10
    assert budget.admit("t", "b")


def test_uses_its_own_clock_not_the_request_time():
    clock = FakeClock()
    budget = make_budget(clock, limit=1)
    assert budget.admit("t", "task")
    clock.now -= 1
    assert not budget.admit("t", "task")


def test_defaults_to_a_monotonic_clock():
    assert RefusalBudget()._clock is time.monotonic


@pytest.mark.parametrize("name", ["limit", "window_seconds", "max_tasks"])
@pytest.mark.parametrize("value", [0, -1, True, 1.5])
def test_rejects_a_non_positive_integer(name, value):
    with pytest.raises(ValueError, match=name):
        RefusalBudget(**{name: value})
