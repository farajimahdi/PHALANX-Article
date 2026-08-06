"""Tests for OPNsenseParser against the anonymized dataset."""

import csv
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from parsers.opnsense import OPNsenseParser

DATA_FILE = (
    Path(__file__).resolve().parents[2]
    / "Real-Dataset"
    / "synthetic"
    / "opnsense_rules.xml"
)
OUT_CSV = (
    Path(__file__).resolve().parents[2]
    / "Real-Dataset"
    / "unified"
    / "opnsense.csv"
)


@pytest.fixture(scope="module")
def rules():
    return OPNsenseParser(str(DATA_FILE)).parse()


def test_file_exists():
    assert DATA_FILE.exists(), f"Dataset not found: {DATA_FILE}"


def test_returns_list(rules):
    assert isinstance(rules, list) and len(rules) > 0


def test_seq_continuous(rules):
    seqs = [r.seq for r in rules]
    assert seqs == list(range(1, len(rules) + 1))


def test_vendor_field(rules):
    assert all(r.vendor == "opnsense" for r in rules)


def test_action_values(rules):
    valid = {"allow", "deny", "reject"}
    assert all(r.action in valid for r in rules)


def test_ip_version_values(rules):
    valid = {"4", "6", "both"}
    assert all(r.ip_version in valid for r in rules)


def test_rule_id_is_uuid(rules):
    """OPNsense uses uuid attributes, not numeric tracker ids."""
    import re
    uuid_re = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    )
    assert all(uuid_re.match(r.rule_id) for r in rules), \
        "At least one rule_id is not a valid UUID"


def test_dst_zone_na(rules):
    from core.schema import NA
    assert all(r.dst_zone == NA for r in rules)


def test_dst_iface_na(rules):
    from core.schema import NA
    assert all(r.dst_iface == NA for r in rules)


def test_service_app_user_na(rules):
    from core.schema import NA
    # service is now resolved from port aliases; app_id/user_id remain N/A
    bad = [r for r in rules if r.app_id != NA or r.user_id != NA]
    assert not bad, "app_id and user_id must be N/A for OPNsense"


def test_nat_related_false(rules):
    from core.schema import NA
    assert all(r.nat_related == NA for r in rules)


def test_log_is_bool(rules):
    assert all(isinstance(r.log, bool) for r in rules)


def test_enabled_is_bool(rules):
    assert all(isinstance(r.enabled, bool) for r in rules)


def test_disabled_rules_exist(rules):
    """Dataset should contain at least one disabled rule."""
    assert any(not r.enabled for r in rules), \
        "Expected at least one disabled rule in the dataset"


def test_src_addr_not_empty(rules):
    assert all(r.src_addr != "" for r in rules)


def test_dst_addr_not_empty(rules):
    assert all(r.dst_addr != "" for r in rules)


def test_csv_roundtrip(rules, tmp_path):
    csv_path = tmp_path / "opnsense.csv"
    parser = OPNsenseParser(str(DATA_FILE))
    written = parser.to_csv(str(csv_path))
    assert Path(written).exists()
    with open(written, newline="", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == len(rules)


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
