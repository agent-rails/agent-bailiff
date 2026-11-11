import pytest

from agent_bailiff.decide.costs import CostError, CostTable


@pytest.mark.parametrize("rule", [0, -1])
def test_fixed_cost_below_one_is_refused_at_load(rule):
    with pytest.raises(ValueError, match="between 1 and"):
        CostTable(1, {"deploy.service": rule})


@pytest.mark.parametrize("amount", [0, -1])
def test_argument_cost_below_one_is_refused_at_evaluation(amount):
    table = CostTable(1, {"signer.withdraw": "amount"})
    with pytest.raises(CostError, match="between 1 and"):
        table.cost("signer.withdraw", {"amount": amount})


def test_costs_of_one_and_more_are_accepted():
    table = CostTable(1, {"deploy.service": 1, "signer.withdraw": "amount"})
    assert table.cost("deploy.service", {}) == 1
    assert table.cost("signer.withdraw", {"amount": 7}) == 7
