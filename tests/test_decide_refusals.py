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


def verdicts(budget, count, tenant="t", task="task"):
    return [budget.admit(tenant, task).verdict for _ in range(count)]


def test_records_up_to_the_limit_then_one_capped_marker_per_window():
    clock = FakeClock()
    budget = make_budget(clock)
    assert verdicts(budget, 5) == ["record", "record", "capped", "drop", "drop"]
    clock.now += 10
    assert verdicts(budget, 3) == ["record", "record", "capped"]


def test_tenants_and_tasks_have_separate_budgets():
    budget = make_budget(FakeClock(), limit=1)
    assert verdicts(budget, 2) == ["record", "capped"]
    assert verdicts(budget, 1, tenant="t2") == ["record"]
    assert verdicts(budget, 1, task="other") == ["record"]


def test_a_refund_returns_one_record():
    budget = make_budget(FakeClock(), limit=1)
    budget.refund("t", "task", budget.admit("t", "task"))
    assert verdicts(budget, 2) == ["record", "capped"]


def test_a_refund_never_goes_below_zero():
    budget = make_budget(FakeClock(), limit=1)
    admission = budget.admit("t", "task")
    budget.refund("t", "task", admission)
    budget.refund("t", "task", admission)
    assert verdicts(budget, 2) == ["record", "capped"]


def test_a_refunded_capped_marker_is_offered_again():
    budget = make_budget(FakeClock(), limit=1)
    budget.admit("t", "task")
    budget.refund("t", "task", budget.admit("t", "task"))
    assert verdicts(budget, 2) == ["capped", "drop"]


def test_a_refund_from_an_expired_window_does_not_lift_the_new_one():
    clock = FakeClock()
    budget = make_budget(clock, limit=1)
    old = budget.admit("t", "task")
    clock.now += 10
    assert budget.admit("t", "task").verdict == "record"
    budget.refund("t", "task", old)
    assert budget.admit("t", "task").verdict == "capped"


def test_a_tenant_at_its_share_gets_one_capped_marker_per_window():
    clock = FakeClock()
    budget = make_budget(clock, max_tasks_per_tenant=2)
    assert [budget.admit("a", f"task-{n}").verdict for n in range(2)] == ["record", "record"]
    overflow = budget.admit("a", "task-2")
    assert (overflow.verdict, overflow.tenant_overflow) == ("capped", True)
    assert budget.admit("a", "task-3").verdict == "drop"
    assert budget.admit("a", "task-0").verdict == "record"
    assert budget.admit("b", "task-0").verdict == "record"
    clock.now += 10
    assert budget.admit("a", "task-2").verdict == "record"


def test_a_refunded_tenant_marker_is_offered_again():
    budget = make_budget(FakeClock(), max_tasks_per_tenant=1)
    budget.admit("a", "task-0")
    budget.refund("a", "task-1", budget.admit("a", "task-1"))
    assert budget.admit("a", "task-1").verdict == "capped"


def test_a_full_table_caps_every_tenant_and_keeps_active_counts():
    clock = FakeClock()
    budget = make_budget(clock, max_tasks=1)
    assert verdicts(budget, 1, task="a") == ["record"]
    assert budget.admit("t", "b").verdict == "capped"
    assert verdicts(budget, 2, task="a") == ["record", "capped"]
    clock.now += 10
    assert budget.admit("t", "b").verdict == "record"


def test_tracked_tenant_markers_are_bounded():
    budget = make_budget(FakeClock(), max_tasks=1)
    budget.admit("t", "a")
    assert budget.admit("u", "b").verdict == "capped"
    assert budget.admit("v", "b").verdict == "drop"


def test_uses_its_own_clock_not_the_request_time():
    clock = FakeClock()
    budget = make_budget(clock, limit=1)
    budget.admit("t", "task")
    clock.now -= 1
    assert budget.admit("t", "task").verdict == "capped"


def test_a_window_is_expired_on_use_even_behind_a_newer_head():
    clock = FakeClock()
    budget = make_budget(clock, limit=1)
    budget.admit("t", "a")
    clock.now -= 50
    budget.admit("t", "b")
    clock.now += 55
    assert budget.admit("t", "b").verdict == "record"


def test_defaults_to_a_monotonic_clock():
    assert RefusalBudget()._clock is time.monotonic


@pytest.mark.parametrize("name", ["limit", "window_seconds", "max_tasks", "max_tasks_per_tenant"])
@pytest.mark.parametrize("value", [0, -1, True, 1.5])
def test_rejects_a_non_positive_integer(name, value):
    with pytest.raises(ValueError, match=name):
        RefusalBudget(**{name: value})
