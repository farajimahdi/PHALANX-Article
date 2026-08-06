"""
Unit and property-based tests for anomaly detection algorithms.

Validates interval relation logic, set operations, and policy anomaly identification rules.
"""

import csv
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.anomaly import (  # noqa: E402
    PORT_MAX,
    V4_MAX,
    DISJOINT,
    EQUAL,
    I_SUPERSET_J,
    J_SUPERSET_I,
    PARTIAL,
    IntervalSet,
    IPSet,
    ProtoSet,
    ZoneDim,
    detect_all,
    detect_over_permissive,
    detect_pairwise,
    load_policy,
    match_overlap,
    match_subset,
    parse_ports,
    relate,
    rule_from_row,
)

DATASET = Path(__file__).resolve().parents[2] / "Real-Dataset" / "unified"
VENDORS = ["fortigate", "paloalto", "pfsense", "opnsense", "ipimen"]

# Canonical column order; helper builds rows with sane defaults.
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


# =============================================================================
# Interval algebra
# =============================================================================
def test_interval_merge_adjacent():
    s = IntervalSet([(1, 5), (6, 10), (3, 4)])
    assert s.intervals == [(1, 10)]


def test_interval_intersection():
    a = IntervalSet([(1, 10)])
    b = IntervalSet([(5, 20)])
    assert a.intersection(b).intervals == [(5, 10)]


def test_interval_disjoint_intersection_empty():
    a = IntervalSet([(1, 4)])
    b = IntervalSet([(5, 9)])
    assert a.intersection(b).is_empty()


def test_interval_subset():
    assert IntervalSet([(5, 8)]).issubset(IntervalSet([(1, 10)]))
    assert not IntervalSet([(1, 10)]).issubset(IntervalSet([(5, 8)]))


def test_interval_complement():
    s = IntervalSet([(10, 20)])
    comp = s.complement(0, 100)
    assert comp.intervals == [(0, 9), (21, 100)]


def test_empty_is_subset_of_anything():
    assert IntervalSet([]).issubset(IntervalSet([(1, 5)]))


# =============================================================================
# IP sets
# =============================================================================
def test_ipset_cidr_subset():
    a = IPSet.parse("10.0.0.0/24", "4", False)
    b = IPSet.parse("10.0.0.0/16", "4", False)
    assert a.issubset(b)
    assert not b.issubset(a)


def test_ipset_any_universal():
    s = IPSet.parse("any", "4", False)
    assert s.is_universal("4")
    assert s.fam(4).intervals == [(0, V4_MAX)]
    assert s.fam(6).is_empty()


def test_ipset_range_parsing():
    s = IPSet.parse("192.168.1.10-192.168.1.20", "4", False)
    lo = int(__import__("ipaddress").ip_address("192.168.1.10"))
    hi = int(__import__("ipaddress").ip_address("192.168.1.20"))
    assert s.fam(4).intervals == [(lo, hi)]


def test_ipset_negation_complement():
    s = IPSet.parse("10.0.0.0/24", "4", True)
    # The negated /24 must not contain the /24 itself.
    plain = IPSet.parse("10.0.0.0/24", "4", False)
    assert not plain.fam(4).intersects(s.fam(4))
    # but must contain an outside address
    outside = IPSet.parse("8.8.8.8", "4", False)
    assert outside.fam(4).issubset(s.fam(4))


def test_ipset_v6_isolated_from_v4():
    v4 = IPSet.parse("10.0.0.0/24", "4", False)
    v6 = IPSet.parse("fd00::/64", "6", False)
    assert not v4.fam(4).intersects(v6.fam(4))
    assert v6.fam(6).is_empty() is False


def test_ipset_any_plus_specific_is_any():
    # bugs-5 fidelity form: "any" beside a specific address still means any.
    s = IPSet.parse("191.247.126.126/32,any", "4", False)
    assert s.is_universal("4")


def test_ipset_both_family_any():
    s = IPSet.parse("any", "both", False)
    assert s.fam(4).intervals == [(0, V4_MAX)]
    assert not s.fam(6).is_empty()


# =============================================================================
# Ports / protocols / zones
# =============================================================================
def test_ports_any():
    assert parse_ports("any", False).intervals == [(0, PORT_MAX)]


def test_ports_single_and_subset():
    assert parse_ports("443", False).issubset(parse_ports("any", False))


def test_ports_negation():
    neg = parse_ports("443", True)
    assert not parse_ports("443", False).intersects(neg)
    assert parse_ports("80", False).issubset(neg)


def test_proto_tcp_udp_split():
    p = ProtoSet.parse("tcp/udp")
    assert ProtoSet.parse("tcp").issubset(p)
    assert ProtoSet.parse("udp").issubset(p)
    assert not ProtoSet.parse("icmp").issubset(p)


def test_proto_any_universal():
    assert ProtoSet.parse("tcp").issubset(ProtoSet.parse("any"))
    assert not ProtoSet.parse("any").issubset(ProtoSet.parse("tcp"))


def test_proto_ip_is_literal_not_universal():
    # "ip" must not be assumed to subsume tcp (conservative semantics).
    assert not ProtoSet.parse("tcp").issubset(ProtoSet.parse("ip"))
    assert not ProtoSet.parse("ip").intersects(ProtoSet.parse("tcp"))


def test_zone_na_is_non_discriminating():
    na = ZoneDim.parse("N/A")
    lan = ZoneDim.parse("LAN")
    # N/A never forces disjointness nor blocks containment.
    from core.anomaly import _zone_intersects, _zone_subset
    assert _zone_intersects(na, lan)
    assert _zone_subset(na, lan)
    assert _zone_subset(lan, na)


def test_zone_distinct_zones_disjoint():
    from core.anomaly import _zone_intersects
    assert not _zone_intersects(ZoneDim.parse("LAN"), ZoneDim.parse("DMZ"))


# =============================================================================
# Relation classification — paper Definitions 4-8
# =============================================================================
def test_shadowing_definition_4():
    # Broad allow first, narrow deny later, narrow ⊆ broad ⇒ shadowing.
    broad = mkrule(1, rule_id="R3", action="allow", protocol="tcp",
                   dst_port="443", src_addr="192.0.2.0/24", dst_addr="any")
    narrow = mkrule(2, rule_id="R7", action="deny", protocol="tcp",
                    dst_port="443", src_addr="192.0.2.64/26",
                    dst_addr="198.51.100.5/32")
    assert relate(broad.match, narrow.match) == I_SUPERSET_J
    findings = detect_pairwise([broad, narrow])
    assert [f.anomaly_type for f in findings] == ["shadowing"]
    shadowed = findings[0].rules[-1]
    assert shadowed["rule_id"] == "R7" and shadowed["role"] == "shadowed"


def test_redundancy_definition_5():
    broad = mkrule(1, rule_id="A", action="allow", protocol="tcp",
                   dst_port="80", src_addr="198.51.100.0/24")
    narrow = mkrule(2, rule_id="B", action="allow", protocol="tcp",
                    dst_port="80", src_addr="198.51.100.0/26")
    assert relate(broad.match, narrow.match) == I_SUPERSET_J
    findings = detect_pairwise([broad, narrow])
    assert [f.anomaly_type for f in findings] == ["redundancy"]


def test_generalization_definition_7():
    # Specific rule first, general rule later, same action ⇒ generalization.
    specific = mkrule(1, rule_id="S", action="allow", protocol="tcp",
                      dst_port="443", src_addr="10.0.0.0/24")
    general = mkrule(2, rule_id="G", action="allow", protocol="tcp",
                     dst_port="443", src_addr="10.0.0.0/16")
    assert relate(specific.match, general.match) == J_SUPERSET_I
    findings = detect_pairwise([specific, general])
    assert [f.anomaly_type for f in findings] == ["generalization"]
    # the removable special case is the earlier specific rule
    special = [r for r in findings[0].rules if r.get("role") == "special"][0]
    assert special["rule_id"] == "S"


def test_conflict_definition_6():
    # Genuine partial overlap (neither subset) with opposite actions.
    a = mkrule(1, rule_id="A", action="allow", protocol="tcp",
               dst_port="1000-2000", src_addr="any", dst_addr="any")
    b = mkrule(2, rule_id="B", action="deny", protocol="tcp",
               dst_port="1500-2500", src_addr="any", dst_addr="any")
    assert relate(a.match, b.match) == PARTIAL
    findings = detect_pairwise([a, b])
    assert [f.anomaly_type for f in findings] == ["conflict"]


def test_conflict_suppressed_for_near_universal_rule():
    # A near-universal deny (open in 4+ core dims) partially overlapping a
    # more specific allow should not generate a conflict.
    broad_deny = mkrule(1, rule_id="BD", action="deny",
                        src_addr="any", dst_addr="any",
                        src_port="any", dst_port="any",
                        protocol="tcp")
    specific_allow = mkrule(2, rule_id="SA", action="allow",
                            src_addr="10.0.0.0/24", dst_addr="any",
                            src_port="any", dst_port="any",
                            protocol="tcp/udp")
    assert relate(broad_deny.match, specific_allow.match) == PARTIAL
    findings = detect_pairwise([broad_deny, specific_allow])
    assert [f.anomaly_type for f in findings] == []


def test_disjoint_zones_no_anomaly():
    # Identical match but different zone pairs ⇒ no interaction.
    a = mkrule(1, action="allow", src_zone="LAN", dst_zone="DMZ",
               protocol="tcp", dst_port="22")
    b = mkrule(2, action="deny", src_zone="VPN", dst_zone="MGMT",
               protocol="tcp", dst_port="22")
    assert relate(a.match, b.match) == DISJOINT
    assert detect_pairwise([a, b]) == []


def test_specific_exception_before_general_not_flagged():
    # Earlier subset with *different* action is a legitimate exception and is
    # intentionally not one of the five formal classes.
    specific = mkrule(1, action="deny", protocol="tcp", dst_port="22",
                      src_addr="10.0.0.5/32")
    general = mkrule(2, action="allow", protocol="tcp", dst_port="22",
                     src_addr="10.0.0.0/24")
    assert relate(specific.match, general.match) == J_SUPERSET_I
    assert detect_pairwise([specific, general]) == []


# =============================================================================
# Over-permissive — Definition 8
# =============================================================================
def test_over_permissive_5a():
    r = mkrule(1, action="allow", src_addr="any", dst_addr="any",
               protocol="tcp", dst_port="443")
    findings = detect_over_permissive([r])
    assert len(findings) == 1
    assert "5a:any-src∧any-dst" in findings[0].details["conditions"]


def test_over_permissive_5b():
    r = mkrule(1, action="allow", src_addr="10.0.0.0/24", dst_addr="10.0.1.0/24",
               protocol="any", dst_port="any")
    findings = detect_over_permissive([r])
    assert len(findings) == 1
    assert "5b:any-dport∧any-proto" in findings[0].details["conditions"]


def test_over_permissive_full_any_any():
    r = mkrule(1, action="allow", src_addr="any", dst_addr="any",
               protocol="any", dst_port="any")
    findings = detect_over_permissive([r])
    assert findings[0].details["full_any_any"] is True


def test_deny_any_any_is_not_over_permissive():
    r = mkrule(1, action="deny", src_addr="any", dst_addr="any",
               protocol="any", dst_port="any")
    assert detect_over_permissive([r]) == []


def test_na_is_not_treated_as_any_for_over_permissive():
    # A pf-style rule whose dst_zone is N/A must not be flagged just for N/A;
    # only literal any-any addresses (5a) or any-proto/port (5b) trigger it.
    r = mkrule(1, action="allow", dst_zone="N/A", src_addr="192.168.0.0/24",
               dst_addr="192.168.1.0/24", protocol="tcp", dst_port="443")
    assert detect_over_permissive([r]) == []


def test_over_permissive_respects_user_id():
    # A rule with any-src/any-dst but a specific user is not over-permissive.
    r = mkrule(1, action="allow", src_addr="any", dst_addr="any",
               protocol="tcp", dst_port="443", user_id="web.admin")
    assert detect_over_permissive([r]) == []


def test_over_permissive_respects_app_id():
    # A rule with any-dport/any-proto but a specific app is not over-permissive.
    r = mkrule(1, action="allow", src_addr="10.0.0.0/24", dst_addr="10.0.1.0/24",
               protocol="any", dst_port="any", app_id="proxy")
    assert detect_over_permissive([r]) == []


def test_different_user_id_prevents_conflict():
    # Identical network dimensions but different users ⇒ no common flow.
    a = mkrule(1, rule_id="A", action="allow", src_addr="any", dst_addr="any",
               protocol="tcp", dst_port="443", user_id="alice")
    b = mkrule(2, rule_id="B", action="deny", src_addr="any", dst_addr="any",
               protocol="tcp", dst_port="443", user_id="bob")
    assert relate(a.match, b.match) == DISJOINT
    assert detect_pairwise([a, b]) == []


def test_different_app_id_prevents_generalization():
    # Identical network dimensions but different apps ⇒ no generalization.
    specific = mkrule(1, rule_id="S", action="allow", src_addr="10.0.0.0/24",
                      protocol="tcp", dst_port="443", app_id="web")
    general = mkrule(2, rule_id="G", action="allow", src_addr="10.0.0.0/16",
                     protocol="tcp", dst_port="443", app_id="mail")
    assert relate(specific.match, general.match) == DISJOINT
    assert detect_pairwise([specific, general]) == []


def test_default_deny_not_last_remains_in_pairwise():
    # A wide-open deny before the last position is a normal blocking rule:
    # it shadows everything after it and must stay in detection.
    catch_all = mkrule(1, rule_id="999999", rule_name="DEFAULT-DENY",
                       action="deny", src_addr="any", dst_addr="any",
                       protocol="any", dst_port="any")
    specific = mkrule(2, rule_id="S", action="allow", src_addr="10.0.0.0/24",
                      protocol="tcp", dst_port="443")
    findings = detect_pairwise([catch_all, specific])
    assert len(findings) == 1
    assert findings[0].anomaly_type == "shadowing"


def test_default_deny_last_only_excluded_from_over_permissive():
    # A wide-open deny is excluded from over-permissive only when it sits at
    # the last sequence position; otherwise it is a normal rule (still not an
    # allow, so not flagged either way here).
    catch_all = mkrule(2, rule_id="999999", rule_name="DEFAULT-DENY",
                       action="deny", src_addr="any", dst_addr="any",
                       protocol="any", dst_port="any")
    specific = mkrule(1, rule_id="S", action="allow", src_addr="10.0.0.0/24",
                      protocol="tcp", dst_port="443")
    assert detect_over_permissive([specific, catch_all]) == []


def test_last_catch_all_deny_excluded_from_pairwise():
    # An unnamed any-any-any deny at the end of the chain is the implicit deny.
    specific = mkrule(1, rule_id="S", action="allow", src_addr="10.0.0.0/24",
                      protocol="tcp", dst_port="443")
    catch_all = mkrule(2, rule_id="501", rule_name="Block-ANY2ANY",
                       action="deny", src_addr="any", dst_addr="any",
                       protocol="any", dst_port="any")
    assert detect_pairwise([specific, catch_all]) == []


def test_near_universal_allow_generalization_inverts_recommendation():
    # A near-universal allow catch-all makes earlier specific allow rules
    # functionally redundant, but the specific rules encode least-privilege.
    # The row must keep anomaly_type='generalization' and recommend restricting
    # the broad anchor, not removing the specific rule.
    anchor = mkrule(3, rule_id="ANCHOR", rule_name="any to any",
                    action="allow", src_addr="any", dst_addr="any",
                    protocol="any", dst_port="any")
    specific = mkrule(1, rule_id="SPEC", rule_name="web to db",
                      action="allow", src_addr="10.1.0.0/24", dst_addr="10.2.0.0/24",
                      protocol="tcp", dst_port="443")
    findings = detect_pairwise([specific, anchor])
    assert len(findings) == 1
    assert findings[0].anomaly_type == "generalization"
    assert findings[0].rules[0]["rule_id"] == "ANCHOR"
    assert findings[0].rules[1]["rule_id"] == "SPEC"
    assert "restrict or remove" in findings[0].explanation.lower()
    assert "do NOT remove" in findings[0].explanation


def test_real_pfsense_1735331401_1719520568_inverted_generalization():
    # Regression guard: the pfsense pair that originally exposed the
    # backwards-recommendation bug must keep the inverted text forever.
    from core.anomaly import load_policy, detect_all
    rules = load_policy(Path("Real-Dataset/unified/pfsense.csv"))
    max_seq = max(r.seq for r in rules)
    for f in detect_all(rules, max_seq):
        if f.anomaly_type == "generalization":
            rids = {str(r["rule_id"]) for r in f.rules}
            if "1735331401" in rids and "1719520568" in rids:
                assert f.rules[0]["role"] == "general"
                assert f.rules[1]["role"] == "specific"
                assert "do NOT remove rule" in f.explanation
                assert "restrict or remove the over-permissive rule 1719520568" in f.explanation
                return
    raise AssertionError("expected generalization finding for 1735331401/1719520568")


def test_generalization_near_universal_anchor_has_correct_roles():
    # In the inverted-recommendation branch, _pair_finding is called with
    # (rj, ri, winner_role='general', loser_role='specific'). The rules list
    # therefore has the broad anchor first, as role 'general'.
    anchor = mkrule(2, rule_id="ANCHOR", action="allow",
                    src_addr="any", dst_addr="any",
                    protocol="any", dst_port="any")
    specific = mkrule(1, rule_id="SPEC", action="allow",
                      src_addr="10.0.0.0/24", dst_addr="10.0.1.0/24",
                      protocol="tcp", dst_port="443")
    f = detect_pairwise([specific, anchor])[0]
    assert f.rules[0]["rule_id"] == "ANCHOR"
    assert f.rules[0]["role"] == "general"
    assert f.rules[1]["rule_id"] == "SPEC"
    assert f.rules[1]["role"] == "specific"


# =============================================================================
# Real-data property tests (no fabricated counts)
# =============================================================================
@pytest.fixture(scope="module", params=VENDORS)
def vendor_rules(request):
    path = DATASET / f"{request.param}.csv"
    assert path.exists(), f"missing dataset {path}"
    return request.param, load_policy(path, enabled_only=True)


def test_real_data_loads(vendor_rules):
    vendor, rules = vendor_rules
    assert len(rules) > 0
    assert all(r.enabled for r in rules)
    assert all(r.vendor == vendor for r in rules)


def test_detection_runs_on_real_data(vendor_rules):
    _, rules = vendor_rules
    findings = detect_all(rules)
    assert isinstance(findings, list)
    valid_ids = {r.rule_id for r in rules}
    for f in findings:
        assert f.anomaly_type in {
            "shadowing", "redundancy", "conflict",
            "generalization", "over_permissive",
        }
        for ref in f.rules:
            assert ref["rule_id"] in valid_ids
        assert f.explanation


def test_shadowing_findings_have_diff_action_and_containment(vendor_rules):
    _, rules = vendor_rules
    by_seq = {r.seq: r for r in rules}
    for f in detect_pairwise(rules):
        if f.anomaly_type != "shadowing":
            continue
        winner, loser = f.rules[0], f.rules[1]
        ri, rj = by_seq[winner["seq"]], by_seq[loser["seq"]]
        assert ri.seq < rj.seq
        assert ri.action != rj.action
        assert match_subset(rj.match, ri.match)  # M(Rj) ⊆ M(Ri)


def test_redundancy_findings_have_same_action_and_containment(vendor_rules):
    _, rules = vendor_rules
    by_seq = {r.seq: r for r in rules}
    for f in detect_pairwise(rules):
        if f.anomaly_type != "redundancy":
            continue
        ri, rj = by_seq[f.rules[0]["seq"]], by_seq[f.rules[1]["seq"]]
        assert ri.seq < rj.seq
        assert ri.action == rj.action
        assert match_subset(rj.match, ri.match)


def test_conflict_findings_are_partial_and_opposite(vendor_rules):
    _, rules = vendor_rules
    by_seq = {r.seq: r for r in rules}
    for f in detect_pairwise(rules):
        if f.anomaly_type != "conflict":
            continue
        ri, rj = by_seq[f.rules[0]["seq"]], by_seq[f.rules[1]["seq"]]
        assert ri.action != rj.action
        assert match_overlap(ri.match, rj.match)
        # neither contains the other
        assert not match_subset(ri.match, rj.match)
        assert not match_subset(rj.match, ri.match)


def test_over_permissive_findings_are_allow(vendor_rules):
    _, rules = vendor_rules
    for f in detect_over_permissive(rules):
        ref = f.rules[0]
        rule = next(r for r in rules if r.rule_id == ref["rule_id"])
        assert rule.action == "allow"
        assert f.details["conditions"]


def test_pf_dst_zone_na_never_blocks_same_iface_pairs():
    # Two pf rules on the same interface with subset/same action ⇒ redundancy
    # is still detectable despite dst_zone being N/A (N/A excluded, not 'any').
    a = mkrule(1, vendor="pfsense", action="allow", src_zone="lan",
               dst_zone="N/A", protocol="tcp", dst_port="443",
               src_addr="192.168.0.0/16")
    b = mkrule(2, vendor="pfsense", action="allow", src_zone="lan",
               dst_zone="N/A", protocol="tcp", dst_port="443",
               src_addr="192.168.1.0/24")
    findings = detect_pairwise([a, b])
    assert [f.anomaly_type for f in findings] == ["redundancy"]
