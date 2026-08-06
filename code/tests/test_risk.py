"""Tests for the risk-scoring metric and the sensitivity analysis.

Unit tests cover each contextual factor (blast radius, exposure,
permissiveness), the class-severity table, and the boundedness of the score.
Property tests over the real CSVs assert the metric stays in range, and a
determinism test guards the reproducibility claim of the sensitivity analysis.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.anomaly import (  # noqa: E402
    detect_all,
    detect_over_permissive,
    detect_pairwise,
    load_policy,
    rule_from_row,
)
from scoring.risk import (  # noqa: E402
    DEFAULT_ZONE_TRUST,
    blast_log,
    exposure,
    permissiveness,
    score_policy,
    severity,
    severity_key,
)
from scoring import sensitivity as sens  # noqa: E402

DATASET = Path(__file__).resolve().parents[2] / "Real-Dataset" / "unified"
VENDORS = ["fortigate", "paloalto", "pfsense", "opnsense", "ipimen"]

_DEFAULTS = {
    "vendor": "test", "rule_id": "0", "rule_name": "r", "seq": "1",
    "enabled": "True", "action": "allow", "ip_version": "4",
    "src_zone": "any", "dst_zone": "any", "src_iface": "any", "dst_iface": "any",
    "src_addr": "any", "src_addr_negated": "False",
    "src_port": "any", "src_port_negated": "False",
    "dst_addr": "any", "dst_addr_negated": "False",
    "dst_port": "any", "dst_port_negated": "False",
    "protocol": "any", "service": "N/A", "schedule": "always", "log": "True",
    "nat_related": "N/A", "app_id": "any", "user_id": "any",
    "icmp_type": "N/A", "notes": "",
}


def mkrule(seq, **over):
    row = dict(_DEFAULTS)
    row["seq"] = str(seq)
    row["rule_id"] = over.pop("rule_id", f"R{seq}")
    row.update({k: str(v) for k, v in over.items()})
    return rule_from_row(row)


def score_one(rules):
    return score_policy(detect_all(rules), rules)


# =============================================================================
# Factor: exposure
# =============================================================================
def test_exposure_upward_crossing_is_max():
    r = mkrule(1, src_zone="WAN", dst_zone="MGMT")
    assert exposure(r) == pytest.approx(1.0)


def test_exposure_downward_crossing_is_zero():
    r = mkrule(1, src_zone="MGMT", dst_zone="WAN")
    assert exposure(r) == 0.0


def test_exposure_intra_zone_is_zero():
    r = mkrule(1, src_zone="LAN", dst_zone="LAN")
    assert exposure(r) == 0.0


def test_exposure_pf_na_dst_uses_source_only():
    # pf-based: dst_zone N/A → exposure from how untrusted the source is.
    untrusted = mkrule(1, vendor="pfsense", src_zone="wan", dst_zone="N/A")
    trusted = mkrule(2, vendor="pfsense", src_zone="mgmt", dst_zone="N/A")
    assert untrusted == untrusted  # smoke
    assert exposure(untrusted) == pytest.approx(1.0)
    assert exposure(trusted) == pytest.approx(0.0)


def test_exposure_na_is_not_open():
    # A rule with both zones N/A must yield zero exposure, never "max".
    r = mkrule(1, src_zone="N/A", dst_zone="N/A")
    assert exposure(r) == 0.0


# =============================================================================
# Factor: permissiveness
# =============================================================================
def test_permissiveness_full_any():
    r = mkrule(1, src_addr="any", dst_addr="any", dst_port="any", protocol="any")
    assert permissiveness(r) == 1.0


def test_permissiveness_fully_specific():
    r = mkrule(1, src_addr="10.0.0.0/24", dst_addr="10.0.1.0/24",
               dst_port="443", protocol="tcp",
               app_id="N/A", user_id="N/A")
    assert permissiveness(r) == 0.0


def test_permissiveness_partial():
    r = mkrule(1, src_addr="any", dst_addr="10.0.1.0/24",
               dst_port="443", protocol="tcp",
               app_id="N/A", user_id="N/A")
    assert permissiveness(r) == pytest.approx(0.25)


def test_permissiveness_ngfw_counts_identity_dimensions():
    # When app_id/user_id are supported (not N/A), they enter the fraction.
    r = mkrule(1, src_addr="any", dst_addr="any", dst_port="any",
               protocol="any", app_id="proxy", user_id="web.admin")
    assert permissiveness(r) == pytest.approx(4.0 / 6.0)


# =============================================================================
# Factor: blast radius (log volume)
# =============================================================================
def test_blast_log_monotonic_in_scope():
    broad = mkrule(1, src_addr="any", dst_addr="any", dst_port="any", protocol="any")
    narrow = mkrule(1, src_addr="10.0.0.1/32", dst_addr="10.0.0.2/32",
                    dst_port="443", protocol="tcp")
    assert blast_log([broad]) > blast_log([narrow])


def test_blast_log_intersection_smaller_than_whole():
    a = mkrule(1, src_addr="10.0.0.0/16", dst_addr="any", protocol="tcp", dst_port="443")
    b = mkrule(2, src_addr="10.0.0.0/24", dst_addr="any", protocol="tcp", dst_port="443")
    # intersection (the /24) is smaller than the broader rule alone
    assert blast_log([a, b]) <= blast_log([a])


# =============================================================================
# Severity (Table 5)
# =============================================================================
def test_severity_over_permissive_critical():
    r = mkrule(1, action="allow", src_addr="any", dst_addr="any",
               protocol="any", dst_port="any")
    f = detect_over_permissive([r])[0]
    assert severity(f) == 1.00


def test_severity_shadowed_deny_is_critical():
    broad = mkrule(1, action="allow", protocol="tcp", dst_port="443",
                   src_addr="10.0.0.0/16")
    narrow = mkrule(2, action="deny", protocol="tcp", dst_port="443",
                    src_addr="10.0.0.0/24")
    f = detect_pairwise([broad, narrow])[0]
    assert f.anomaly_type == "shadowing"
    assert severity_key(f) == "shadowing_deny"
    assert severity(f) == 1.00


def test_severity_shadowed_allow_is_moderate():
    broad = mkrule(1, action="deny", protocol="tcp", dst_port="443",
                   src_addr="10.0.0.0/16")
    narrow = mkrule(2, action="allow", protocol="tcp", dst_port="443",
                    src_addr="10.0.0.0/24")
    f = detect_pairwise([broad, narrow])[0]
    assert severity_key(f) == "shadowing_allow"
    assert severity(f) == 0.50


def test_severity_conflict_high():
    a = mkrule(1, action="allow", protocol="tcp", dst_port="1000-2000")
    b = mkrule(2, action="deny", protocol="tcp", dst_port="1500-2500")
    f = detect_pairwise([a, b])[0]
    assert f.anomaly_type == "conflict"
    assert severity(f) == 0.75


def test_severity_redundancy_low():
    broad = mkrule(1, action="allow", protocol="tcp", dst_port="80",
                   src_addr="198.51.100.0/24")
    narrow = mkrule(2, action="allow", protocol="tcp", dst_port="80",
                    src_addr="198.51.100.0/26")
    f = detect_pairwise([broad, narrow])[0]
    assert f.anomaly_type == "redundancy"
    assert severity(f) == 0.25


# =============================================================================
# Composite score
# =============================================================================
def test_risk_is_bounded_unit_interval():
    rules = [
        mkrule(1, action="allow", src_addr="any", dst_addr="any",
               protocol="any", dst_port="any", src_zone="WAN", dst_zone="MGMT"),
        mkrule(2, action="deny", protocol="tcp", dst_port="443",
               src_addr="10.0.0.0/24", src_zone="WAN", dst_zone="MGMT"),
    ]
    for s in score_one(rules):
        assert 0.0 <= s.risk <= 1.0
        assert 0.0 <= s.phi <= 1.0
        for v in (s.rho, s.epsilon, s.pi):
            assert 0.0 <= v <= 1.0


def test_blast_radius_normalised_to_one_in_policy():
    rules = [
        mkrule(1, action="allow", src_addr="any", dst_addr="any",
               protocol="any", dst_port="any"),
        mkrule(2, action="allow", src_addr="10.0.0.0/24", dst_addr="10.0.1.0/24",
               protocol="tcp", dst_port="443"),
    ]
    scored = score_one(rules)
    assert max(s.rho for s in scored) == pytest.approx(1.0)


# =============================================================================
# Real-data property tests
# =============================================================================
@pytest.fixture(scope="module", params=VENDORS)
def vendor_scored(request):
    rules = load_policy(DATASET / f"{request.param}.csv", enabled_only=True)
    return score_policy(detect_all(rules), rules)


def test_real_scores_in_range(vendor_scored):
    assert len(vendor_scored) > 0
    for s in vendor_scored:
        assert 0.0 <= s.risk <= 1.0
        assert 0.0 <= s.rho <= 1.0
        assert 0.0 <= s.epsilon <= 1.0
        assert 0.0 <= s.pi <= 1.0


# =============================================================================
# Sensitivity primitives + determinism
# =============================================================================
def test_topk_overlap_identical_and_disjoint():
    a = [1, 2, 3, 4, 5]
    assert sens._topk_overlap(a, a, 3) == 1.0
    assert sens._topk_overlap(a, [9, 8, 7, 6, 0], 3) == 0.0


def test_spearman_identical_and_reversed():
    a = {i: float(i) for i in range(10)}
    rev = {i: float(-i) for i in range(10)}
    assert sens._spearman(a, a) == pytest.approx(1.0)
    assert sens._spearman(a, rev) == pytest.approx(-1.0)


def test_average_ranks_handles_ties():
    ranks = sens._average_ranks({"a": 1.0, "b": 1.0, "c": 0.0})
    assert ranks["a"] == ranks["b"] == pytest.approx(1.5)
    assert ranks["c"] == pytest.approx(3.0)


def test_beta_bounded_seed_is_deterministic():
    import random
    s1 = sens._beta_bounded(random.Random(1), 20)
    s2 = sens._beta_bounded(random.Random(1), 20)
    assert s1 == s2
    # bounded samples stay near the neutral centre
    for b in s1:
        assert all(0.15 < w < 0.55 for w in b)


def test_sensitivity_run_is_reproducible():
    rules = load_policy(DATASET / "fortigate.csv", enabled_only=True)
    scored = score_policy(detect_all(rules), rules)
    items = sens._items_from_scored(scored)
    r1 = sens._stability_for_items(items, "combined", seed=7, n_random=30)
    r2 = sens._stability_for_items(items, "combined", seed=7, n_random=30)
    assert r1 == r2
    assert -1.0 <= r1["spearman_mean"] <= 1.0
