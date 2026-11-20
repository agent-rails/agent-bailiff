import pytest

from agent_bailiff.decide.refusals import RefusalBudget


def test_admits_up_to_the_limit_per_window():
    budget = RefusalBudget(limit=2, window_seconds=10)
    assert [budget.admit("t", "task", 100) for _ in range(3)] == [True, True, False]
    assert budget.admit("t", "task", 110)


def test_tasks_and_tenants_have_separate_budgets():
    budget = RefusalBudget(limit=1, window_seconds=10)
    assert budget.admit("t1", "task", 100)
    assert budget.admit("t2", "task", 100)
    assert budget.admit("t1", "other", 100)
    assert not budget.admit("t1", "task", 100)


def test_a_clock_moving_back_starts_a_new_window():
    budget = RefusalBudget(limit=1, window_seconds=10)
    assert budget.admit("t", "task", 100)
    assert budget.admit("t", "task", 50)


def test_tracked_tasks_stay_bounded():
    budget = RefusalBudget(limit=1, window_seconds=10, max_tasks=4)
    for n in range(100):
        assert budget.admit("t", f"task-{n}", 100)
    assert len(budget._windows) <= 4


@pytest.mark.parametrize("name", ["limit", "window_seconds", "max_tasks"])
@pytest.mark.parametrize("value", [0, -1, True, 1.5])
def test_rejects_a_non_positive_integer(name, value):
    with pytest.raises(ValueError, match=name):
        RefusalBudget(**{name: value})
