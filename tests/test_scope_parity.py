import pytest
import test_custodian
from agent_warrant.chain import delegate
from agent_warrant.identity import encode_public_key
from test_custodian import Refused, Released, clearance_for, sign_clearance
from test_decide import AGENT_KEY, CHILD_KEY, NOW, TENANT, make_request, make_root, make_v1_root

from agent_bailiff.decide import derive_op_id

ledger_path = test_custodian.ledger_path
make_custodian = test_custodian.make_custodian
make_decider = test_custodian.make_decider
open_docket = test_custodian.open_docket
private = test_custodian.private
reader = test_custodian.reader
sink = test_custodian.sink
state = test_custodian.state
workdir = test_custodian.workdir
writer = test_custodian.writer

DEPLOY = {"tools": ["deploy.service"], "resources": ["env/staging/*"], "max_cost_per_call": 5}
CANARY = {"tools": ["deploy.canary"], "resources": ["env/prod/*"], "max_cost_per_call": 5}
PAIRED = {"permissions": [DEPLOY, CANARY]}


def root_case(scope=None, v1=False):
    def build():
        return (make_v1_root() if v1 else make_root(scope=scope)), ()

    return build


def delegated_case(child_scope):
    def build():
        root = make_root(scope=PAIRED)
        link = delegate(
            root,
            root,
            AGENT_KEY,
            child_subject=encode_public_key(CHILD_KEY.public_key()),
            scope=child_scope,
            budget=10,
            ttl=600,
            now=NOW,
        )
        return root, (link,)

    return build


CASES = {
    "paired_call": (root_case(PAIRED), "deploy.service", "env/staging/api", 0, "ok"),
    "cross_pair": (root_case(PAIRED), "deploy.service", "env/prod/api", 0, "out_of_scope"),
    "over_cap": (
        root_case({"permissions": [{**DEPLOY, "max_cost_per_call": 0}, CANARY]}),
        "deploy.service",
        "env/staging/api",
        0,
        "cost_over_call_cap",
    ),
    "unbounded": (
        root_case({"permissions": [{**DEPLOY, "resources": ["env/staging-*"]}]}),
        "deploy.service",
        "env/staging-x/api",
        0,
        "unbounded_scope",
    ),
    "v1_before_cutoff": (root_case(v1=True), "deploy.service", "env/staging/api", NOW + 1, "ok"),
    "v1_at_cutoff": (root_case(v1=True), "deploy.service", "env/staging/api", NOW, "chain_invalid"),
    "v2_after_cutoff": (root_case(PAIRED), "deploy.service", "env/staging/api", NOW, "ok"),
    "delegated_narrow": (
        delegated_case({"permissions": [{**DEPLOY, "max_cost_per_call": 2}]}),
        "deploy.service",
        "env/staging/api",
        0,
        "ok",
    ),
    "delegated_dropped_permission": (
        delegated_case({"permissions": [{**DEPLOY, "max_cost_per_call": 2}]}),
        "deploy.canary",
        "env/prod/api",
        0,
        "out_of_scope",
    ),
}


def custodian_verdict(result):
    if isinstance(result, Released):
        return "ok"
    assert isinstance(result, Refused)
    return result.reason


@pytest.mark.parametrize("case", sorted(CASES))
def test_decide_and_custodian_agree_on_scope(make_decider, make_custodian, case):
    build, tool, resource, cutoff, expected = CASES[case]
    root, links = build()
    holder = CHILD_KEY if links else AGENT_KEY
    request = make_request(root, links, holder, tool=tool, resource=resource)
    decision = make_decider(scope_v1_cutoff=cutoff).check(request, NOW)
    if decision.allowed:
        token = decision.clearance
    else:
        leaf_binding = links[-1].binding() if links else root.binding()
        token = sign_clearance(
            clearance_for(
                request,
                root,
                op_id=derive_op_id(TENANT, root.task_id, leaf_binding, request.digest()),
                leaf_binding=leaf_binding,
            )
        )
    released = make_custodian(scope_v1_cutoff=cutoff).release(token, request, NOW + 1)
    assert ("ok" if decision.allowed else decision.reason, custodian_verdict(released)) == (expected, expected)
