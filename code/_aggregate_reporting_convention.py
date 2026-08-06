"""
Reporting helper that collapses per-anchor generalization rows for summary statistics.

Raw findings remain fully traceable in the detailed output files; this module only adjusts the headline per-vendor counts.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.anomaly import (  # noqa: E402
    ANOMALY_CLASSES,
    Rule,
    _is_near_universal,
    detect_all,
    load_policy,
)

DATASET = Path(__file__).resolve().parents[1] / "Real-Dataset" / "unified"
VENDORS = ["fortigate", "paloalto", "pfsense", "opnsense", "ipimen"]


def _anchor_of(finding, rules_by_id: dict[str, Rule]) -> str | None:
    """Return anchor rule_id if this generalization row should be collapsed."""
    if finding.anomaly_type != "generalization":
        return None
    for ref in finding.rules:
        r = rules_by_id.get(ref["rule_id"])
        if r is None:
            continue
        if r.action == "allow" and _is_near_universal(r):
            return r.rule_id
    return None


def aggregate_counts(vendor: str) -> dict:
    rules = load_policy(DATASET / f"{vendor}.csv", enabled_only=True)
    rules_by_id = {r.rule_id: r for r in rules}
    findings = detect_all(rules)

    counts = {c: 0 for c in ANOMALY_CLASSES}
    collapsed_anchors: set[str] = set()
    for f in findings:
        anchor = _anchor_of(f, rules_by_id)
        if anchor is not None:
            collapsed_anchors.add(anchor)
        else:
            counts[f.anomaly_type] += 1
    counts["generalization"] += len(collapsed_anchors)
    counts["generalization_raw"] = sum(
        1 for f in findings if f.anomaly_type == "generalization"
    )
    counts["collapsed_anchors"] = len(collapsed_anchors)
    return counts


def main() -> None:
    print("Reporting-convention headline counts")
    print("=" * 70)
    header = f"{'vendor':<11} " + " ".join(f"{c[:5]:>7}" for c in ANOMALY_CLASSES) + \
        "  raw_gen  anchors"
    print(header)
    print("-" * len(header))
    for vendor in VENDORS:
        counts = aggregate_counts(vendor)
        row = f"{vendor:<11} " + " ".join(f"{counts[c]:>7}" for c in ANOMALY_CLASSES) + \
            f"  {counts['generalization_raw']:>7}  {counts['collapsed_anchors']:>7}"
        print(row)


if __name__ == "__main__":
    main()
