from test_quickstart_load import added_latency


def test_the_added_latency_is_the_bailiff_percentile_minus_the_direct_one():
    level = {"p50_ms": 12.4, "p99_ms": 40.0}
    direct = {"p50_ms": 3.1, "p99_ms": 9.5}
    assert added_latency(level, direct) == {
        "baseline_p50_ms": 3.1,
        "baseline_p99_ms": 9.5,
        "added_p50_ms": 9.3,
        "added_p99_ms": 30.5,
    }


def test_the_added_latency_is_negative_when_the_direct_call_was_slower():
    assert added_latency({"p50_ms": 2.0, "p99_ms": 5.0}, {"p50_ms": 3.0, "p99_ms": 4.0})["added_p50_ms"] == -1.0
