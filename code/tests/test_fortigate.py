"""Tests for FortiGateParser against the anonymized dataset."""

import csv
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from parsers.fortigate import FortiGateParser

DATA_FILE = (
    Path(__file__).resolve().parents[2]
    / "Real-Dataset"
    / "synthetic"
    / "fortigate_policy.conf"
)


@pytest.fixture(scope="module")
def rules():
    return FortiGateParser(str(DATA_FILE)).parse()


def test_file_exists():
    assert DATA_FILE.exists(), f"Dataset not found: {DATA_FILE}"


def test_returns_list(rules):
    assert isinstance(rules, list) and len(rules) > 0


def test_seq_continuous(rules):
    seqs = [r.seq for r in rules]
    assert seqs == list(range(1, len(rules) + 1))


def test_vendor_field(rules):
    assert all(r.vendor == "fortigate" for r in rules)


def test_action_values(rules):
    valid = {"allow", "deny", "reject"}
    assert all(r.action in valid for r in rules), \
        [r.action for r in rules if r.action not in valid]


def test_ip_version_is_4(rules):
    valid = {"4", "6", "both"}
    bad = [r for r in rules if r.ip_version not in valid]
    assert not bad, f"Unexpected ip_version values: {set(r.ip_version for r in bad)}"


def test_enabled_is_bool(rules):
    assert all(isinstance(r.enabled, bool) for r in rules)


def test_disabled_rules_exist(rules):
    assert any(not r.enabled for r in rules), "Expected at least one disabled rule"


def test_log_is_bool(rules):
    assert all(isinstance(r.log, bool) for r in rules)


def test_src_zone_not_empty(rules):
    from core.schema import NA
    assert all(r.src_zone != "" for r in rules)


def test_dst_zone_not_empty(rules):
    from core.schema import NA
    assert all(r.dst_zone != "" for r in rules)


def test_src_addr_not_empty(rules):
    assert all(r.src_addr != "" for r in rules)


def test_dst_addr_not_empty(rules):
    assert all(r.dst_addr != "" for r in rules)


def test_service_not_empty(rules):
    assert all(r.service != "" for r in rules)


def test_negation_exists(rules):
    """Dataset should contain at least one negated src or dst addr rule."""
    assert any(r.src_addr_negated or r.dst_addr_negated for r in rules), \
        "Expected at least one negated address rule"


def test_nat_exists(rules):
    """Dataset should contain at least one NAT-related rule."""
    assert any(r.nat_related for r in rules), "Expected at least one nat_related rule"


def test_app_id_present(rules):
    """FortiGate NGFW: at least some rules should have app_id set."""
    from core.schema import NA
    assert any(r.app_id != NA for r in rules), "Expected at least one rule with app_id"


def test_user_id_present(rules):
    """FortiGate NGFW: at least some rules should have user_id set."""
    from core.schema import NA
    assert any(r.user_id != NA for r in rules), "Expected at least one rule with user_id"


def test_csv_roundtrip(rules, tmp_path):
    csv_path = tmp_path / "fortigate.csv"
    parser = FortiGateParser(str(DATA_FILE))
    written = parser.to_csv(str(csv_path))
    assert Path(written).exists()
    with open(written, newline="", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == len(rules)
    assert rows[0]["vendor"] == "fortigate"
