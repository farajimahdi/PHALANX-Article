"""
Unit tests for PfSenseParser.
Runs against Real-Dataset/anonymized/pfsense_rules.xml.
"""
import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from parsers.pfsense import PfSenseParser
from core.schema import NA

FIXTURE = Path(__file__).resolve().parents[2] / "Real-Dataset" / "synthetic" / "pfsense_rules.xml"


@pytest.fixture(scope="module")
def rules():
    parser = PfSenseParser(FIXTURE)
    return parser.parse()


def test_file_exists():
    assert FIXTURE.exists(), f"Dataset not found: {FIXTURE}"


def test_returns_list(rules):
    assert isinstance(rules, list)
    assert len(rules) > 0, "Parser returned 0 rules"


def test_seq_continuous(rules):
    seqs = [r.seq for r in rules]
    assert seqs == list(range(1, len(rules) + 1)), "seq not 1-based continuous"


def test_vendor_field(rules):
    assert all(r.vendor == "pfsense" for r in rules)


def test_action_values(rules):
    valid = {"allow", "deny", "reject"}
    bad = [r for r in rules if r.action not in valid]
    assert not bad, f"Unexpected action values: {set(r.action for r in bad)}"


def test_ip_version_values(rules):
    valid = {"4", "6", "both"}
    bad = [r for r in rules if r.ip_version not in valid]
    assert not bad, f"Unexpected ip_version values: {set(r.ip_version for r in bad)}"


def test_dst_zone_na(rules):
    """pfSense has no dst_zone; must always be N/A."""
    bad = [r for r in rules if r.dst_zone != NA]
    assert not bad, f"{len(bad)} rules have non-N/A dst_zone"


def test_dst_iface_na(rules):
    bad = [r for r in rules if r.dst_iface != NA]
    assert not bad


def test_service_app_user_na(rules):
    # service is now resolved from port aliases (e.g. "DNS", "SMTP")
    # app_id and user_id remain N/A for pfSense (no NGFW layer)
    bad = [r for r in rules if r.app_id != NA or r.user_id != NA]
    assert not bad, "app_id and user_id must be N/A for pfSense"


def test_nat_related_false(rules):
    # pfSense has no NAT concept in filter rules
    assert all(r.nat_related == NA for r in rules)


def test_log_is_bool(rules):
    assert all(isinstance(r.log, bool) for r in rules)


def test_enabled_is_bool(rules):
    assert all(isinstance(r.enabled, bool) for r in rules)


def test_src_addr_not_empty(rules):
    bad = [r for r in rules if not r.src_addr]
    assert not bad, "src_addr must never be empty string"


def test_dst_addr_not_empty(rules):
    bad = [r for r in rules if not r.dst_addr]
    assert not bad


def test_csv_roundtrip(tmp_path, rules):
    """CSV written then re-read must have same row count and first rule_id."""
    import csv
    from parsers.pfsense import PfSenseParser
    out = tmp_path / "pfsense_test.csv"
    parser = PfSenseParser(FIXTURE)
    parser.to_csv(out)
    with out.open(encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == len(rules)
    assert rows[0]["rule_id"] == rules[0].rule_id


def test_negation_counts(rules):
    neg_src = [r for r in rules if r.src_addr_negated]
    neg_dst = [r for r in rules if r.dst_addr_negated]
    assert len(neg_src) == 42, f"expected 42 src-negated rules, got {len(neg_src)}"
    assert len(neg_dst) == 51, f"expected 51 dst-negated rules, got {len(neg_dst)}"


def test_any_access_to_mgmt_is_dst_negated(rules):
    mgmt = [r for r in rules if r.rule_name == "any access to MGMT"]
    assert len(mgmt) == 1
    assert mgmt[0].dst_addr_negated is True
    assert mgmt[0].src_addr_negated is False
