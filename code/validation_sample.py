"""
Generates a stratified, deterministic validation sample for expert review.

Extracts a balanced set of anomaly findings across vendors and anomaly types to prepare CSV forms for manual annotation.
"""
from __future__ import annotations

import csv
import json
import random
from collections import defaultdict
from pathlib import Path

SEED = 42
PER_CELL = 4  # findings per (vendor, anomaly_type) cell; 5 x 5 x 4 = 100 total

ROOT = Path(__file__).resolve().parent.parent
SCORED = ROOT / "results" / "scored_anomalies.jsonl"
OUT = ROOT / "results" / "validation_sample.csv"

FIELDS = [
    "sample_id",
    "vendor",
    "anomaly_type",
    "rule_ids",
    "rule_names",
    "seqs",
    "risk",
    "explanation",
    "label_rater1",
    "label_rater2",
    "notes",
]


def load_findings(path: Path) -> list[dict]:
    """Read the scored anomaly JSONL file into a list of finding dicts."""
    findings: list[dict] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                findings.append(json.loads(line))
    return findings


def stratified_sample(findings: list[dict]) -> list[dict]:
    """Return up to PER_CELL findings from every (vendor, anomaly_type) cell.

    Each cell is sorted deterministically before sampling so the draw depends
    only on the fixed seed, not on input file order.
    """
    cells: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for finding in findings:
        cells[(finding["vendor"], finding["anomaly_type"])].append(finding)

    rng = random.Random(SEED)
    sampled: list[dict] = []
    for key in sorted(cells):
        group = sorted(
            cells[key],
            key=lambda f: (
                tuple(rule.get("seq", 0) for rule in f["rules"]),
                json.dumps(f, sort_keys=True, ensure_ascii=False),
            ),
        )
        count = min(PER_CELL, len(group))
        sampled.extend(rng.sample(group, count))
    return sampled


def to_row(index: int, finding: dict) -> dict:
    """Flatten a finding into a CSV row with empty label columns."""
    rules = finding.get("rules", [])
    return {
        "sample_id": index,
        "vendor": finding["vendor"],
        "anomaly_type": finding["anomaly_type"],
        "rule_ids": "|".join(str(r.get("rule_id", "")) for r in rules),
        "rule_names": "|".join(str(r.get("rule_name", "")) for r in rules),
        "seqs": "|".join(str(r.get("seq", "")) for r in rules),
        "risk": finding.get("risk", ""),
        "explanation": finding.get("explanation", ""),
        "label_rater1": "",
        "label_rater2": "",
        "notes": "",
    }


def main() -> None:
    findings = load_findings(SCORED)
    sampled = stratified_sample(findings)
    with OUT.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        for index, finding in enumerate(sampled, start=1):
            writer.writerow(to_row(index, finding))
    print(f"Wrote {len(sampled)} sampled findings to {OUT}")


if __name__ == "__main__":
    main()
