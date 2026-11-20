import time

import pytest

from agent_bailiff.decide.refusals import Admission, RefusalBudget, capped_reason


class FakeClock:
    def __init__(self, now=1000.0):
        self.now = now

    def __call__(self):
        return self.now


def make_budget(clock, **options):
    return RefusalBudget(**{"limit": 2, "window_seconds": 10, "clock": clock, **options})


def admit(budget, tenant="t", task="task", root="root", reason="out_of_scope"):
    return budget.admit(tenant, task, root, reason)


def verdicts(budget, count, **fields):
    return [admit(budget, **fields).verdict for _ in range(count)]


def test_records_up_to_the_limit_then_one_capped_marker_per_window():
    clock = FakeClock()
    budget = make_budget(clock)
    assert verdicts(budget, 5) == ["record", "record", "capped", "drop", "drop"]
    clock.now += 10
    assert verdicts(budget, 3) == ["record", "record", "capped"]


def test_tenants_tasks_and_roots_have_separate_budgets():
    budget = make_budget(FakeClock(), limit=1)
    assert verdicts(budget, 2) == ["record", "capped"]
    assert verdicts(budget, 1, tenant="t2") == ["record"]
    assert verdicts(budget, 1, task="other") == ["record"]
    assert verdicts(budget, 1, root="other") == ["record"]


def test_operational_refusals_do_not_use_the_agent_budget():
    budget = make_budget(FakeClock(), limit=1)
    assert verdicts(budget, 3, reason="suspended") == ["record", "capped", "drop"]
    assert verdicts(budget, 1, reason="already_issued") == ["drop"]
    assert verdicts(budget, 2) == ["record", "capped"]


def test_agent_reasons_share_one_budget():
    budget = make_budget(FakeClock(), limit=1)
    assert verdicts(budget, 1, reason="policy_denied") == ["record"]
    assert verdicts(budget, 1) == ["capped"]


@pytest.mark.parametrize(
    ("reason", "admission", "expected"),
    [
        ("out_of_scope", Admission("capped", 0), "refusals_capped"),
        ("needs_approval", Admission("capped", 0), "refusals_capped"),
        ("suspended", Admission("capped", 0), "operational_refusals_capped"),
        ("already_issued", Admission("capped", 0), "operational_refusals_capped"),
        ("internal_error", Admission("capped", 0), "operational_refusals_capped"),
        ("out_of_scope", Admission("capped", 0, tenant_overflow=True), "tenant_refusals_capped"),
    ],
)
def test_capped_reason_names_the_class(reason, admission, expected):
    assert capped_reason(reason, admission) == expected


def test_a_refund_returns_one_record():
    budget = make_budget(FakeClock(), limit=1)
    budget.refund("t", "task", "root", "out_of_scope", admit(budget))
    assert verdicts(budget, 2) == ["record", "capped"]


def test_a_refund_never_goes_below_zero():
    budget = make_budget(FakeClock(), limit=1)
    admission = admit(budget)
    budget.refund("t", "task", "root", "out_of_scope", admission)
    budget.refund("t", "task", "root", "out_of_scope", admission)
    assert verdicts(budget, 2) == ["record", "capped"]


def test_a_refunded_capped_marker_is_offered_again():
    budget = make_budget(FakeClock(), limit=1)
    admit(budget)
    budget.refund("t", "task", "root", "out_of_scope", admit(budget))
    assert verdicts(budget, 2) == ["capped", "drop"]


def test_a_refund_from_an_expired_window_does_not_lift_the_new_one():
    clock = FakeClock()
    budget = make_budget(clock, limit=1)
    old = admit(budget)
    clock.now += 10
    assert admit(budget).verdict == "record"
    budget.refund("t", "task", "root", "out_of_scope", old)
    assert admit(budget).verdict == "capped"


def test_a_tenant_at_its_share_gets_one_capped_marker_per_window():
    clock = FakeClock()
    budget = make_budget(clock, max_windows_per_tenant=2)
    assert [admit(budget, tenant="a", task=f"task-{n}").verdict for n in range(2)] == ["record", "record"]
    overflow = admit(budget, tenant="a", task="task-2")
    assert (overflow.verdict, overflow.tenant_overflow) == ("capped", True)
    assert admit(budget, tenant="a", task="task-3").verdict == "drop"
    assert admit(budget, tenant="a", task="task-0").verdict == "record"
    assert admit(budget, tenant="b", task="task-0").verdict == "record"
    clock.now += 10
    assert admit(budget, tenant="a", task="task-2").verdict == "record"


def test_a_refunded_tenant_marker_is_offered_again():
    budget = make_budget(FakeClock(), max_windows_per_tenant=1)
    admit(budget, tenant="a", task="task-0")
    budget.refund("a", "task-1", "root", "out_of_scope", admit(budget, tenant="a", task="task-1"))
    assert admit(budget, tenant="a", task="task-1").verdict == "capped"


def test_a_full_table_caps_every_tenant_and_keeps_active_counts():
    clock = FakeClock()
    budget = make_budget(clock, max_windows=1)
    assert verdicts(budget, 1, task="a") == ["record"]
    assert admit(budget, task="b").verdict == "capped"
    assert verdicts(budget, 2, task="a") == ["record", "capped"]
    clock.now += 10
    assert admit(budget, task="b").verdict == "record"


def test_tracked_tenant_markers_are_bounded():
    budget = make_budget(FakeClock(), max_windows=1)
    admit(budget, tenant="t", task="a")
    assert admit(budget, tenant="u", task="b").verdict == "capped"
    assert admit(budget, tenant="v", task="b").verdict == "drop"


def test_uses_its_own_clock_not_the_request_time():
    clock = FakeClock()
    budget = make_budget(clock, limit=1)
    admit(budget)
    clock.now -= 1
    assert admit(budget).verdict == "capped"


def test_a_window_is_expired_on_use_even_behind_a_newer_head():
    clock = FakeClock()
    budget = make_budget(clock, limit=1)
    admit(budget, task="a")
    clock.now -= 50
    admit(budget, task="b")
    clock.now += 55
    assert admit(budget, task="b").verdict == "record"


def test_defaults_to_a_monotonic_clock():
    assert RefusalBudget()._clock is time.monotonic


@pytest.mark.parametrize("name", ["limit", "window_seconds", "max_windows", "max_windows_per_tenant"])
@pytest.mark.parametrize("value", [0, -1, True, 1.5])
def test_rejects_a_non_positive_integer(name, value):
    with pytest.raises(ValueError, match=name):
        RefusalBudget(**{name: value})
