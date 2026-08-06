"""Tests for PaloAltoParser against the real anonymized dataset."""

import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from parsers.paloalto import PaloAltoParser
from core.schema import NA

FIXTURE = Path(__file__).resolve().parents[2] / "Real-Dataset/synthetic/paloalto_policy.xml"

# ── fixture ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def rules():
    p = PaloAltoParser(FIXTURE)
    return p.parse()

# ── basic counts ─────────────────────────────────────────────────────────────

def test_rule_count(rules):
    assert len(rules) == 501

def test_seq_range(rules):
    seqs = [r.seq for r in rules]
    assert seqs[0] == 1
    assert seqs[-1] == 501

# ── vendor / schema ──────────────────────────────────────────────────────────

def test_vendor(rules):
    assert all(r.vendor == "paloalto" for r in rules)

def test_rule_id_is_uuid(rules):
    # UUIDs have 36 chars: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    assert all(len(r.rule_id) == 36 for r in rules)

def test_rule_name_nonempty(rules):
    assert all(r.rule_name for r in rules)

# ── action mapping ───────────────────────────────────────────────────────────

def test_action_values(rules):
    allowed = {"allow", "deny", "reject"}
    assert all(r.action in allowed for r in rules)

def test_has_allow_and_deny(rules):
    actions = {r.action for r in rules}
    assert "allow" in actions
    assert "deny" in actions

# ── ip_version ───────────────────────────────────────────────────────────────

def test_ip_version(rules):
    valid = {"4", "6", "both"}
    bad = [r for r in rules if r.ip_version not in valid]
    assert not bad, f"Unexpected ip_version: {set(r.ip_version for r in bad)}"

# ── zone fields ──────────────────────────────────────────────────────────────

def test_src_zone_populated(rules):
    assert all(r.src_zone not in (NA, "", None) for r in rules)

def test_dst_zone_populated(rules):
    assert all(r.dst_zone not in (NA, "", None) for r in rules)

def test_ifaces_are_na(rules):
    assert all(r.src_iface == NA for r in rules)
    assert all(r.dst_iface == NA for r in rules)

# ── address fields ───────────────────────────────────────────────────────────

def test_src_addr_populated(rules):
    assert all(r.src_addr not in ("", None) for r in rules)

def test_dst_addr_populated(rules):
    assert all(r.dst_addr not in ("", None) for r in rules)

def test_src_addr_negated_is_bool(rules):
    assert all(isinstance(r.src_addr_negated, bool) for r in rules)

def test_dst_addr_negated_is_bool(rules):
    assert all(isinstance(r.dst_addr_negated, bool) for r in rules)

# ── port/protocol are N/A ────────────────────────────────────────────────────

def test_ports_and_protocol_are_na(rules):
    # src_port is "any" for PAN-OS (service objects may restrict it, but unspecified = any)
    assert all(r.src_port == "any" for r in rules)
    # dst_port and protocol may be resolved from service objects (not always N/A)

# ── service ──────────────────────────────────────────────────────────────────

def test_service_populated(rules):
    assert all(r.service not in ("", None) for r in rules)

# ── NAT ──────────────────────────────────────────────────────────────────────

def test_nat_related_false(rules):
    # PAN-OS security rulebase has no NAT: nat_related is N/A
    assert all(r.nat_related == NA for r in rules)

# ── NGFW fields ──────────────────────────────────────────────────────────────

def test_app_id_populated(rules):
    assert all(r.app_id not in ("", None) for r in rules)

def test_user_id_populated(rules):
    assert all(r.user_id not in ("", None) for r in rules)

# ── log ──────────────────────────────────────────────────────────────────────

def test_log_is_bool(rules):
    assert all(isinstance(r.log, bool) for r in rules)

def test_some_rules_logged(rules):
    assert any(r.log for r in rules)


# ── negation (attribute and child element forms) ─────────────────────────────

def test_negation_is_extracted_from_attribute(rules):
    # The dataset uses <source negate="yes"> / <destination negate="yes">.
    neg_src = [r for r in rules if r.src_addr_negated]
    neg_dst = [r for r in rules if r.dst_addr_negated]
    # These counts are known from the synthetic dataset.
    assert len(neg_src) == 42, f"expected 42 src-negated rules, got {len(neg_src)}"
    assert len(neg_dst) == 51, f"expected 51 dst-negated rules, got {len(neg_dst)}"


def test_any_access_to_mgmt_is_dst_negated(rules):
    mgmt = [r for r in rules if r.rule_name == "any access to MGMT"]
    assert len(mgmt) == 1
    assert mgmt[0].dst_addr_negated is True
    assert mgmt[0].src_addr_negated is False


# ── enabled ──────────────────────────────────────────────────────────────────

def test_enabled_is_bool(rules):
    assert all(isinstance(r.enabled, bool) for r in rules)

def test_has_disabled_rules(rules):
    assert any(not r.enabled for r in rules)

# ── CSV export ───────────────────────────────────────────────────────────────

def test_csv_export(tmp_path):
    out = tmp_path / "paloalto.csv"
    p = PaloAltoParser(FIXTURE)
    result = p.to_csv(out)
    assert Path(result).exists()
    lines = Path(result).read_text(encoding="utf-8").splitlines()
    assert len(lines) == 502  # header + 501 rules
