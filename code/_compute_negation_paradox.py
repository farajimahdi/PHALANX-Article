"""Calculates negation frequency and associated anomaly counts to quantify the negation paradox."""
from __future__ import annotations

import csv
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.anomaly import (  # noqa: E402
    Rule,
    _is_near_universal,
    detect_all,
    load_policy,
)

DATASET = Path(__file__).resolve().parents[1] / "Real-Dataset" / "unified"
VENDORS = ["fortigate", "paloalto", "pfsense", "opnsense", "ipimen"]


def _has_negation(rule: Rule) -> bool:
    """True if any negation flag in the rule is True."""
    return any(
        str(rule.raw.get(field, "")).strip().lower() == "true"
        for field in [
            "src_addr_negated", "src_port_negated",
            "dst_addr_negated", "dst_port_negated",
        ]
    )


def _rule_has_negation_field(row: dict) -> bool:
    return any(
        str(row.get(field, "")).strip().lower() == "true"
        for field in [
            "src_addr_negated", "src_port_negated",
            "dst_addr_negated", "dst_port_negated",
        ]
    )


def ipimen_negation_decomposition() -> dict:
    rules = load_policy(DATASET / "ipimen.csv")
    by_id = {r.rule_id: r for r in rules}
    findings = detect_all(rules)
    conflicts = [f for f in findings if f.anomaly_type == "conflict"]
    total = len(conflicts)
    with_neg = 0
    without_neg = 0
    for f in conflicts:
        neg = any(_has_negation(by_id[r["rule_id"]]) for r in f.rules)
        if neg:
            with_neg += 1
        else:
            without_neg += 1
    return {
        "total": total,
        "with_negation": with_neg,
        "without_negation": without_neg,
    }


def normalized_comparison() -> list[dict]:
    rows = []
    for vendor in ["fortigate", "paloalto", "ipimen"]:
        rules = load_policy(DATASET / f"{vendor}.csv")
        by_id = {r.rule_id: r for r in rules}
        findings = detect_all(rules)
        total_conflicts = sum(1 for f in findings if f.anomaly_type == "conflict")
        if vendor in ("fortigate", "paloalto"):
            rows.append({
                "vendor": vendor,
                "raw_conflicts": total_conflicts,
                "excluding_negation": "n/a (no negation capability)",
            })
        else:
            # Count conflicts where neither rule uses negation.
            no_neg_conflicts = sum(
                1 for f in findings
                if f.anomaly_type == "conflict"
                and not any(_has_negation(by_id[r["rule_id"]]) for r in f.rules)
            )
            rows.append({
                "vendor": vendor,
                "raw_conflicts": total_conflicts,
                "excluding_negation": no_neg_conflicts,
            })
    return rows


def main() -> None:
    decomp = ipimen_negation_decomposition()
    print("ipimen conflict decomposition by negation involvement")
    print("-" * 60)
    total = decomp["total"]
    print(f"{'Metric':<50} {'Count':>6} {'%':>8}")
    print(f"{'Total ipimen conflicts':<50} {total:>6} {100.0:>7.1f}")
    print(
        f"{'Conflicts involving >=1 negated field':<50} "
        f"{decomp['with_negation']:>6} "
        f"{100.0 * decomp['with_negation'] / total:>7.1f}"
    )
    print(
        f"{'Conflicts with no negation involved':<50} "
        f"{decomp['without_negation']:>6} "
        f"{100.0 * decomp['without_negation'] / total:>7.1f}"
    )

    print("\nNormalized comparison")
    print("-" * 60)
    print(f"{'Vendor':<12} {'Raw conflicts':>15} {'Excluding negation-driven':>30}")
    for row in normalized_comparison():
        print(
            f"{row['vendor']:<12} {row['raw_conflicts']:>15} "
            f"{str(row['excluding_negation']):>30}"
        )


if __name__ == "__main__":
    main()
