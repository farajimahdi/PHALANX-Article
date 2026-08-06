"""Tests for the synthetic generator and scalability benchmark.

These keep sizes tiny so the suite stays fast; the heavy benchmark is a
separate runnable script. The focus here is determinism (reproducibility of
the synthetic policies) and correctness of the exponent fit.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.anomaly import detect_all  # noqa: E402
from scalability import (  # noqa: E402
    benchmark,
    fit_exponent,
    generate_policy,
)


def test_generate_policy_size_and_seq():
    rules = generate_policy(120, seed=1)
    assert len(rules) == 120
    assert [r.seq for r in rules] == list(range(1, 121))


def test_generate_policy_is_deterministic():
    a = generate_policy(80, seed=7)
    b = generate_policy(80, seed=7)
    assert [r.raw for r in a] == [r.raw for r in b]


def test_generate_policy_seed_changes_output():
    a = generate_policy(80, seed=1)
    b = generate_policy(80, seed=2)
    assert [r.raw for r in a] != [r.raw for r in b]


def test_generated_policy_is_labelled_synthetic():
    rules = generate_policy(20, seed=3)
    assert all(r.raw["notes"] == "synthetic, scalability only" for r in rules)
    assert all(r.vendor == "synthetic" for r in rules)


def test_detection_runs_on_synthetic_policy():
    rules = [r for r in generate_policy(150, seed=5) if r.enabled]
    findings = detect_all(rules)
    assert isinstance(findings, list)
    valid = {r.rule_id for r in rules}
    for f in findings:
        for ref in f.rules:
            assert ref["rule_id"] in valid


def test_fit_exponent_recovers_quadratic():
    # time = c * n^2 exactly → log-log slope must be 2.0
    synthetic = [{"n": n, "time_s": 0.5 * n * n} for n in (10, 20, 40, 80, 160)]
    assert fit_exponent(synthetic) == pytest.approx(2.0, abs=1e-9)


def test_fit_exponent_recovers_linear():
    synthetic = [{"n": n, "time_s": 3.0 * n} for n in (10, 20, 40, 80)]
    assert fit_exponent(synthetic) == pytest.approx(1.0, abs=1e-9)


def test_benchmark_small_sizes_structure():
    results = benchmark(sizes=[50, 100], seed=42)
    assert [r["n"] for r in results] == [50, 100]
    for r in results:
        assert r["time_s"] >= 0.0
        assert 0 <= r["enabled"] <= r["n"]
        assert r["findings"] >= 0
