"""
Maps individual policy rules to their associated anomaly findings and risk attributes.

Generates per-vendor and aggregated CSV reports for auditability.
"""
from __future__ import annotations

import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from core.anomaly import load_policy  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
UNIFIED_DIR = ROOT / "Real-Dataset" / "unified"
RESULTS_DIR = ROOT / "results"
ANOMALIES = RESULTS_DIR / "anomalies.jsonl"
SCORED = RESULTS_DIR / "scored_anomalies.jsonl"
OUT_DIR = RESULTS_DIR / "rule_status"

VENDORS = ["fortigate", "paloalto", "pfsense", "opnsense", "ipimen"]

# Columns that describe the rule itself.
RULE_FIELDS = [
    "vendor",
    "rule_id",
    "rule_name",
    "seq",
    "enabled",
    "action",
    "src_zone",
    "dst_zone",
    "src_iface",
    "dst_iface",
    "src_addr",
    "src_addr_negated",
    "src_port",
    "src_port_negated",
    "dst_addr",
    "dst_addr_negated",
    "dst_port",
    "dst_port_negated",
    "protocol",
    "service",
    "ip_version",
    "app_id",
    "user_id",
]

# Columns that describe the anomaly status of the rule.
STATUS_FIELDS = [
    "anomaly_status",
    "anomaly_count",
    "anomaly_types",
    "related_rule_ids",
    "related_rule_names",
    "related_seqs",
    "related_roles",
    "explanations",
    "overlap_details",
    "risk_scores",
]

FIELDNAMES = RULE_FIELDS + STATUS_FIELDS


def load_scored_findings(path: Path) -> dict[tuple[str, str, str], dict]:
    """Index scored findings by (vendor, rule_id, anomaly_type) -> finding.

    For pairwise findings the key uses the *later* rule's id (the one that is
    shadowed/redundant, or the second member of a conflict/generalization).
    For over_permissive findings the single rule's id is used.
    """
    scored: dict[tuple[str, str, str], dict] = {}
    if not path.exists():
        return scored
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            f = json.loads(line)
            vendor = f["vendor"]
            atype = f["anomaly_type"]
            rules = f.get("rules", [])
            if atype == "over_permissive" and rules:
                key = (vendor, str(rules[0]["rule_id"]), atype)
                scored[key] = f
            elif len(rules) == 2:
                # Key on the later rule (rules[1]) since that is the row we
                # most often want to annotate in a per-rule view.
                key = (vendor, str(rules[1]["rule_id"]), atype)
                scored[key] = f
    return scored


def collect_findings_per_rule(path: Path) -> dict[tuple[str, str], list[dict]]:
    """Return {(vendor, rule_id): [finding, ...]} for every rule mentioned."""
    per_rule: dict[tuple[str, str], list[dict]] = defaultdict(list)
    if not path.exists():
        return per_rule
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            f = json.loads(line)
            vendor = f["vendor"]
            for rule in f.get("rules", []):
                rid = str(rule["rule_id"])
                per_rule[(vendor, rid)].append(f)
    return per_rule


def format_overlap(overlap: dict) -> str:
    """Render overlap details as a compact, readable string."""
    parts = []
    for dim in ["src_ip", "dst_ip", "src_port", "dst_port", "protocol"]:
        val = overlap.get(dim, "")
        if val and val != "∅":
            parts.append(f"{dim}={val}")
    return "; ".join(parts)


def _is_near_universal_allow(rule_row: dict) -> bool:
    """True when an allow rule is open in >=4 of the 5 core dimensions.

    This mirrors the engine's _is_near_universal() so that the per-rule
    status view can collapse the explosion of containment relations caused
    by a single catch-all allow anchor, matching the headline reporting
    convention used in the paper.
    """
    if rule_row.get("action") != "allow":
        return False
    dims = [
        rule_row.get("src_addr", ""),
        rule_row.get("dst_addr", ""),
        rule_row.get("src_port", ""),
        rule_row.get("dst_port", ""),
        rule_row.get("protocol", ""),
    ]
    # Only explicit 'any' counts as open; N/A is absence of the concept.
    return sum(1 for d in dims if d == "any") >= 4


def _empty_status_row(rule_row: dict) -> dict:
    row = {k: rule_row.get(k, "") for k in RULE_FIELDS}
    row.update({
        "anomaly_status": "clean",
        "anomaly_count": 0,
        "anomaly_types": "",
        "related_rule_ids": "",
        "related_rule_names": "",
        "related_seqs": "",
        "related_roles": "",
        "explanations": "",
        "overlap_details": "",
        "risk_scores": "",
    })
    return row


def _role_and_related(finding: dict, rid: str) -> tuple[str, list[dict]]:
    """Return (this_rule_role, related_rules) for a finding w.r.t. rule rid."""
    atype = finding["anomaly_type"]
    rules = finding.get("rules", [])
    this_index = None
    for idx, r in enumerate(rules):
        if str(r.get("rule_id")) == rid:
            this_index = idx
            break

    if atype == "over_permissive" and rules:
        return "over_permissive", []
    if len(rules) == 2 and this_index is not None:
        role = rules[this_index].get("role", "")
        related = [rules[1 - this_index]]
        return role, related
    return "", []


def _risk_for_finding(finding: dict,
                      scored: dict[tuple[str, str, str], dict]) -> str:
    """Look up the risk score for a single finding."""
    vendor = finding.get("vendor", "")
    atype = finding["anomaly_type"]
    rules = finding.get("rules", [])
    if atype == "over_permissive" and rules:
        skey = (vendor, str(rules[0]["rule_id"]), atype)
    elif len(rules) == 2:
        # Scoring pipeline keys pairwise findings on the later rule (rules[1]).
        skey = (vendor, str(rules[1]["rule_id"]), atype)
    else:
        return ""
    sf = scored.get(skey)
    if sf and sf.get("risk") not in (None, ""):
        return f"{sf['risk']:.4f}"
    return ""


def build_status_row(rule_row: dict, findings: list[dict],
                     scored: dict[tuple[str, str, str], dict]) -> dict:
    """Create one CSV row summarising all findings for a single rule.

    Containment relations (generalization / redundancy) caused by a near-
    universal allow anchor are collapsed into a single entry on the anchor's
    row, matching the headline reporting convention. The specific rules still
    keep their individual entries for auditability.
    """
    rid = str(rule_row.get("rule_id", ""))
    seq = str(rule_row.get("seq", ""))

    if not findings:
        return _empty_status_row(rule_row)

    is_anchor = _is_near_universal_allow(rule_row)
    anchor_groups: dict[str, list[dict]] = defaultdict(list)
    normal_findings: list[dict] = []

    for f in findings:
        atype = f["anomaly_type"]
        role, _ = _role_and_related(f, rid)
        collapse = (
            is_anchor
            and atype in ("generalization", "redundancy")
            and (
                (atype == "generalization" and role == "general")
                or (atype == "redundancy" and role == "covering")
            )
        )
        if collapse:
            anchor_groups[atype].append(f)
        else:
            normal_findings.append(f)

    types: list[str] = []
    ids: list[str] = []
    names: list[str] = []
    seqs: list[str] = []
    roles: list[str] = []
    exps: list[str] = []
    ovs: list[str] = []
    rks: list[str] = []

    def append_finding(f: dict) -> None:
        atype = f["anomaly_type"]
        role, related = _role_and_related(f, rid)
        types.append(atype)
        roles.append(role)
        if related:
            ids.append(",".join(str(r.get("rule_id", "")) for r in related))
            names.append(",".join(str(r.get("rule_name", "")) for r in related))
            seqs.append(",".join(str(r.get("seq", "")) for r in related))
        else:
            ids.append("N/A (single-rule)")
            names.append("N/A (single-rule)")
            seqs.append("N/A (single-rule)")
        exps.append(f.get("explanation", "").replace("\n", " "))
        overlap = f.get("details", {}).get("overlap", {})
        ovs.append(format_overlap(overlap))
        rks.append(_risk_for_finding(f, scored))

    for f in normal_findings:
        append_finding(f)

    # Add one collapsed entry per anchor-side containment relation type.
    for atype in ("generalization", "redundancy"):
        group = anchor_groups.get(atype, [])
        if not group:
            continue
        related = []
        for f in group:
            _, rel = _role_and_related(f, rid)
            related.extend(rel)
        related_ids_list = [str(r.get("rule_id", "")) for r in related]
        related_names_list = [str(r.get("rule_name", "")) for r in related]
        related_seqs_list = [str(r.get("seq", "")) for r in related]
        n = len(group)
        if atype == "generalization":
            role = "general (anchor)"
            exp = (
                f"Rule {rid} (seq {seq}) is a near-universal permit-all anchor "
                f"for {n} generalization relationships with specific rules "
                f"({', '.join(related_ids_list)}). RECOMMENDATION: restrict or "
                f"remove the over-permissive anchor rule; do NOT remove the "
                f"specific least-privilege rules."
            )
        else:
            role = "covering (anchor)"
            exp = (
                f"Rule {rid} (seq {seq}) is a near-universal allow anchor that "
                f"makes {n} specific rules ({', '.join(related_ids_list)}) "
                f"functionally redundant; however, those specific rules encode "
                f"the intended least-privilege policy. RECOMMENDATION: restrict "
                f"or remove the over-permissive anchor rule {rid}; do NOT remove "
                f"the specific rules."
            )

        types.append(atype)
        roles.append(role)
        ids.append(",".join(related_ids_list))
        names.append(",".join(related_names_list))
        seqs.append(",".join(related_seqs_list))
        exps.append(exp)
        ovs.append(f"collapsed: {n} overlaps")
        rks.append("")

    row = {k: rule_row.get(k, "") for k in RULE_FIELDS}
    row.update({
        "anomaly_status": "affected",
        "anomaly_count": len(types),
        "anomaly_types": " | ".join(types),
        "related_rule_ids": " | ".join(ids),
        "related_rule_names": " | ".join(names),
        "related_seqs": " | ".join(seqs),
        "related_roles": " | ".join(roles),
        "explanations": " | ".join(exps),
        "overlap_details": " | ".join(ovs),
        "risk_scores": " | ".join(rks),
    })
    return row


def write_vendor_csv(vendor: str, csv_path: Path, per_rule: dict,
                     scored: dict[tuple[str, str, str], dict],
                     out_path: Path) -> int:
    """Write the per-rule status CSV for one vendor. Returns number of rows."""
    rows: list[dict] = []
    with csv_path.open(encoding="utf-8-sig", newline="") as fh:
        for rule_row in csv.DictReader(fh):
            rid = str(rule_row.get("rule_id", ""))
            findings = per_rule.get((vendor, rid), [])
            rows.append(build_status_row(rule_row, findings, scored))

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def main() -> None:
    per_rule = collect_findings_per_rule(ANOMALIES)
    scored = load_scored_findings(SCORED)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    all_rows: list[dict] = []
    totals = {"rules": 0, "affected": 0, "clean": 0, "findings": 0}

    for vendor in VENDORS:
        csv_path = UNIFIED_DIR / f"{vendor}.csv"
        if not csv_path.exists():
            print(f"SKIP {vendor}: {csv_path} not found")
            continue
        out_path = OUT_DIR / f"{vendor}_rule_status.csv"
        n = write_vendor_csv(vendor, csv_path, per_rule, scored, out_path)
        affected = sum(1 for r in csv.DictReader(out_path.open(encoding="utf-8-sig", newline=""))
                       if r["anomaly_status"] == "affected")
        clean = n - affected
        totals["rules"] += n
        totals["affected"] += affected
        totals["clean"] += clean
        print(f"OK   {vendor}: {n} rules, {affected} affected, {clean} clean -> {out_path.name}")

        # Re-read for the combined file.
        with out_path.open(encoding="utf-8-sig", newline="") as fh:
            all_rows.extend(list(csv.DictReader(fh)))

    combined = OUT_DIR / "all_rules_status.csv"
    with combined.open("w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(all_rows)

    totals["findings"] = sum(len(v) for v in per_rule.values())
    print(f"\nCombined: {combined.name} ({totals['rules']} rows)")
    print(f"Totals: {totals['affected']} affected rules, {totals['clean']} clean rules, "
          f"{totals['findings']} total findings")


if __name__ == "__main__":
    main()
