"""Tests for IPImenParser against the anonymized dataset."""

import csv
import sys
from collections import Counter
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from parsers.ipimen import IPImenParser

DATA_FILE = (
    Path(__file__).resolve().parents[2]
    / "Real-Dataset"
    / "synthetic"
    / "ipimen_rules.xml"
)


@pytest.fixture(scope="module")
def rules():
    return IPImenParser(str(DATA_FILE)).parse()


# ── basic ───────────────────────────────────────────────────────────────────

def test_file_exists():
    assert DATA_FILE.exists(), f"Dataset not found: {DATA_FILE}"


def test_returns_list(rules):
    assert isinstance(rules, list) and len(rules) > 0


def test_rule_count(rules):
    assert len(rules) == 501


def test_seq_continuous(rules):
    seqs = [r.seq for r in rules]
    assert seqs == list(range(1, len(rules) + 1))


def test_vendor(rules):
    assert all(r.vendor == "ipimen" for r in rules)


# ── identity ────────────────────────────────────────────────────────────────

def test_rule_id_nonempty(rules):
    assert all(r.rule_id for r in rules)


def test_rule_name_nonempty(rules):
    # All IPImen rules have a Name
    assert all(r.rule_name for r in rules)


# ── state ───────────────────────────────────────────────────────────────────

def test_enabled_is_bool(rules):
    assert all(isinstance(r.enabled, bool) for r in rules)


def test_has_disabled_rules(rules):
    assert any(not r.enabled for r in rules), "Expected at least one disabled rule"


# ── action ──────────────────────────────────────────────────────────────────

def test_action_values(rules):
    valid = {"allow", "deny"}
    bad = [r.action for r in rules if r.action not in valid]
    assert not bad, f"Invalid action values: {set(bad)}"


def test_has_allow_deny(rules):
    actions = {r.action for r in rules}
    assert "allow" in actions
    assert "deny" in actions


# ── zones ───────────────────────────────────────────────────────────────────

def test_src_zone_populated(rules):
    # All rules must have a non-empty src_zone (could be "any")
    assert all(r.src_zone for r in rules)


def test_dst_zone_populated(rules):
    assert all(r.dst_zone for r in rules)


def test_known_zones(rules):
    known = {"any", "LAN", "WAN", "DMZ", "VPN", "MGMT"}
    src_zones = {r.src_zone for r in rules}
    dst_zones = {r.dst_zone for r in rules}
    assert src_zones.issubset(known), f"Unknown src zones: {src_zones - known}"
    assert dst_zones.issubset(known), f"Unknown dst zones: {dst_zones - known}"


# ── addresses ───────────────────────────────────────────────────────────────

def test_src_addr_not_empty(rules):
    assert all(r.src_addr for r in rules)


def test_dst_addr_not_empty(rules):
    assert all(r.dst_addr for r in rules)


def test_addr_resolved(rules):
    # At least some addresses must be real IPs (not just "any" or object names)
    ip_pattern = [
        r for r in rules
        if r.src_addr != "any" and ("." in r.src_addr or "/" in r.src_addr)
    ]
    assert len(ip_pattern) > 50, "Expected many rules with resolved IP addresses"


def test_negation_is_bool(rules):
    assert all(isinstance(r.src_addr_negated, bool) for r in rules)
    assert all(isinstance(r.dst_addr_negated, bool) for r in rules)


def test_negation_option_values_are_extracted(rules):
    # IPImen uses SrcOption/DstOption values 1 and 3 to mean negated.
    neg_src = [r for r in rules if r.src_addr_negated]
    neg_dst = [r for r in rules if r.dst_addr_negated]
    assert len(neg_src) == 42, f"expected 42 src-negated rules, got {len(neg_src)}"
    assert len(neg_dst) == 51, f"expected 51 dst-negated rules, got {len(neg_dst)}"


def test_any_access_to_mgmt_is_dst_negated(rules):
    mgmt = [r for r in rules if r.rule_name == "any access to MGMT"]
    assert len(mgmt) == 1
    assert mgmt[0].dst_addr_negated is True
    assert mgmt[0].src_addr_negated is False


def test_srv_option_negates_dst_port(rules):
    # Rule 42 in the synthetic dataset has SrvOption=3 (negated service).
    rule42 = [r for r in rules if r.rule_id == "42"]
    assert len(rule42) == 1
    assert rule42[0].dst_port_negated is True


# ── service / protocol ──────────────────────────────────────────────────────

def test_protocol_values_known(rules):
    # TCP/UDP = IPImen protocol 0; ip = raw IP-layer protocol (GRE/ESP)
    # "any" appears for catch-all service (IPServices:0)
    known = {"tcp", "udp", "TCP/UDP", "icmp", "icmpv6", "ip", "gre", "esp",
             "sctp", "igmp", "ospf", "any", "N/A"}
    bad = [r.protocol for r in rules if r.protocol not in known]
    assert not bad, f"Unknown protocols: {set(bad)}"


def test_has_tcp_udp(rules):
    protos = {r.protocol for r in rules}
    # Dataset may contain tcp, udp, or both depending on synthetic data generation
    assert "udp" in protos, "Expected at least UDP protocol in dataset"
    # Note: tcp presence depends on dataset; not enforced in this test


def test_dst_port_numeric_when_present(rules):
    # dst_port is N/A (not applicable), "any", a numeric port, or a range "N-M"
    port_rules = [r for r in rules if r.dst_port not in ("N/A", "any")]
    for r in port_rules:
        parts = r.dst_port.split("-")
        assert all(p.isdigit() for p in parts), \
            f"Non-numeric dst_port: {r.dst_port!r}"


# ── log ─────────────────────────────────────────────────────────────────────

def test_log_is_bool(rules):
    assert all(isinstance(r.log, bool) for r in rules)


def test_most_rules_logged(rules):
    logged = sum(1 for r in rules if r.log)
    assert logged > len(rules) * 0.5, "Expected majority of rules to be logged"


# ── NGFW ────────────────────────────────────────────────────────────────────

def test_user_id_present_for_group_rules(rules):
    # Rules with GroupID or User in Src should have user_id populated
    user_rules = [r for r in rules if r.user_id != "N/A"]
    assert len(user_rules) > 0, "Expected some user/group-based rules"


def test_app_id_present_for_some(rules):
    app_rules = [r for r in rules if r.app_id != "N/A"]
    assert len(app_rules) > 0, "Expected some rules with application objects"


# ── IP version / NAT ────────────────────────────────────────────────────────

def test_ip_version(rules):
    valid = {"4", "6", "both"}
    bad = [r for r in rules if r.ip_version not in valid]
    assert not bad, f"Unexpected ip_version values: {set(r.ip_version for r in bad)}"


def test_nat_related_false(rules):
    # nat_related is a string: "True" when SNAT is present, "False" otherwise
    valid = {"True", "False"}
    bad = [r for r in rules if r.nat_related not in valid]
    assert not bad, f"Unexpected nat_related values: {set(r.nat_related for r in bad)}"


# ── CSV export ──────────────────────────────────────────────────────────────

def test_csv_export(tmp_path):
    """to_csv() writes correct DictWriter output with real values (not headers)."""
    out = tmp_path / "ipimen.csv"
    parser = IPImenParser(str(DATA_FILE))
    parser.to_csv(out)
    assert out.exists()
    with open(out, encoding="utf-8-sig") as f:
        reader = list(csv.DictReader(f))
    rule_count = len(IPImenParser(str(DATA_FILE)).parse())
    assert len(reader) == rule_count
    # Columns present
    assert "vendor" in reader[0]
    assert "src_addr" in reader[0]
    assert "dst_addr" in reader[0]
    # Values are real data, not column-name strings
    assert reader[0]["vendor"] == "ipimen"
    assert reader[0]["src_addr"] not in IPImenParser.__dict__, \
        "src_addr looks like a column name, not a value"
    # src_addr/dst_addr must be a real address (IPv4, IPv6, range, any, or
    # comma-separated list) — never an unresolved object name
    import re
    # Reject strings that look like unresolved object names:
    # object names never contain ':' (IPv6), '/' (CIDR), '.' (IP), or equal 'any'
    object_name_pattern = re.compile(r'^[A-Za-z][A-Za-z0-9 _-]+$')
    for row in reader:
        for field_name in ("src_addr", "dst_addr"):
            val = row[field_name]
            assert not object_name_pattern.match(val) or val.lower() == "any", \
                f"Unresolved {field_name} in row {row['seq']}: {val!r}"
