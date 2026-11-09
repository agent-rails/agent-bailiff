from agent_bailiff.decide.identity import args_digest, derive_op_id, request_digest

ARGS = {"service": "api", "replicas": 3, "tags": ["a", "b"], "meta": {"z": 1, "a": "x"}}
LEAF = "A" * 43


def test_request_digest_matches_the_reference_vector():
    assert request_digest("deploy.service", "env/staging/api", ARGS, "n-1") == (
        "w5NobNsfMQOVMTMM7bnEUuagVEBb5OBaLwLr_1i_MLE"
    )
    assert request_digest("t", "r", {}, "n") == "E83xwalBQf9nB-5SK_dIWhs30XXBk_Mh611F92B2dWo"


def test_derive_op_id_matches_the_reference_vector():
    digest = request_digest("deploy.service", "env/staging/api", ARGS, "n-1")
    assert derive_op_id("tenant-a", "task-1", LEAF, digest) == "IZYT9xMwqFw3Kx8x4p05q8CMKKF4hEY_2P0U9qv0oDI"


def test_args_digest_matches_the_reference_vector():
    assert args_digest(ARGS) == "Poq-hYmn4g8gI_-xiMaXU2egqv6nq-Eh_kr0zgvcs7c"
    assert args_digest({}) == "RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o"


def test_request_digest_ignores_key_order_and_changes_with_each_field():
    base = request_digest("deploy.service", "env/staging/api", ARGS, "n-1")
    assert request_digest("deploy.service", "env/staging/api", dict(reversed(ARGS.items())), "n-1") == base
    assert request_digest("deploy.rollback", "env/staging/api", ARGS, "n-1") != base
    assert request_digest("deploy.service", "env/staging/web", ARGS, "n-1") != base
    assert request_digest("deploy.service", "env/staging/api", {**ARGS, "replicas": 4}, "n-1") != base
    assert request_digest("deploy.service", "env/staging/api", ARGS, "n-2") != base


def test_derive_op_id_changes_with_each_input_and_resists_field_shifting():
    base = ("t1", "task", LEAF, "d")
    assert derive_op_id(*base) == derive_op_id(*base)
    for position in range(4):
        changed = list(base)
        changed[position] = changed[position] + "x"
        assert derive_op_id(*changed) != derive_op_id(*base)
    assert derive_op_id("t1", "a|b", "l", "d") != derive_op_id("t1", "a", "b|l", "d")
