#!/usr/bin/env python3
"""
PHALANX framework entry point.

Runs end-to-end policy processing, anomaly analysis, risk scoring, and evaluation routines.

Usage:
    python main.py          # Interactive step selection
    python main.py --all    # Run core pipeline steps (1-9) non-interactively
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent

STEPS: list[dict] = [
    {
        "id": 1,
        "title": "Build unified CSVs from synthetic policy files",
        "desc": (
            "Parses raw vendor configs (Real-Dataset/synthetic/) into unified "
            "CSV files under Real-Dataset/unified/.  Must be re-run whenever "
            "a parser is modified."
        ),
        "cmd": [sys.executable, str(ROOT / "code" / "build_unified.py")],
        "outputs": ["Real-Dataset/unified/fortigate.csv",
                     "Real-Dataset/unified/paloalto.csv",
                     "Real-Dataset/unified/pfsense.csv",
                     "Real-Dataset/unified/opnsense.csv",
                     "Real-Dataset/unified/ipimen.csv"],
    },
    {
        "id": 2,
        "title": "Run anomaly detection (core engine)",
        "desc": (
            "Deterministic pairwise + over-permissive detection over all five "
            "vendor policies.  Produces anomalies.jsonl and summary.json."
        ),
        "cmd": [sys.executable, str(ROOT / "code" / "core" / "anomaly.py")],
        "outputs": ["results/anomalies.jsonl", "results/summary.json"],
    },
    {
        "id": 3,
        "title": "Aggregate headline counts (reporting convention)",
        "desc": (
            "Collapses generalization rows sharing a near-universal allow "
            "anchor into one headline finding per anchor.  Prints the paper's "
            "Table 7"
        ),
        "cmd": [sys.executable, str(ROOT / "code" / "_aggregate_reporting_convention.py")],
        "outputs": [],
    },
    {
        "id": 4,
        "title": "Compute risk scores for unified",
        "desc": (
            "Assigns a scalar risk score in [0,1] to every finding, using "
            "blast-radius, exposure and permissiveness factors.  Writes "
            "scored_anomalies.jsonl and scoring_summary.json."
        ),
        "cmd": [sys.executable, str(ROOT / "code" / "scoring" / "risk.py")],
        "outputs": ["results/scored_anomalies.jsonl", "results/scoring_summary.json"],
    },
    {
        "id": 5,
        "title": "Run sensitivity (ranking-stability) analysis - Table 9",
        "desc": (
            "Perturbs risk weights (beta) and class severities (sigma) and "
            "measures Spearman correlation and top-k overlap against the "
            "default ranking.  Writes sensitivity.json."
        ),
        "cmd": [sys.executable, str(ROOT / "code" / "scoring" / "sensitivity.py")],
        "outputs": ["results/sensitivity.json"],
    },
    {
        "id": 6,
        "title": "Compute negation-paradox decomposition (IPImen)",
        "desc": (
            "Breaks down ipimen conflicts by negation involvement"
        ),
        "cmd": [sys.executable, str(ROOT / "code" / "_compute_negation_paradox.py")],
        "outputs": [],
    },
    {
        "id": 7,
        "title": "Generate per-rule status CSVs",
        "desc": (
            "Produces one CSV per vendor (results/rule_status/) mapping every "
            "rule to its anomaly status, related rules, explanations, overlap "
            "details, and risk scores.  Also writes a combined all_rules_status.csv."
        ),
        "cmd": [sys.executable, str(ROOT / "code" / "rule_anomaly_status.py")],
        "outputs": ["results/rule_status/fortigate_rule_status.csv",
                     "results/rule_status/paloalto_rule_status.csv",
                     "results/rule_status/pfsense_rule_status.csv",
                     "results/rule_status/opnsense_rule_status.csv",
                     "results/rule_status/ipimen_rule_status.csv",
                     "results/rule_status/all_rules_status.csv"],
    },
    {
        "id": 8,
        "title": "Run rule-status pipeline (headline findings) - Table 7",
        "desc": (
            "Re-runs detection with the reporting-convention + negation-paradox "
            "filters applied, and persists the *final* headline findings to "
            "anomalies_rule_status.jsonl and summary_rule_status.json.  This is "
            "the input for risk_rule_status.py (step 9)."
        ),
        "cmd": [sys.executable, str(ROOT / "code" / "core" / "anomaly.py"),
                "--rule-status"],
        "outputs": ["results/anomalies_rule_status.jsonl",
                     "results/summary_rule_status.json"],
    },
    {
        "id": 9,
        "title": "Compute risk scores on rule-status findings - Table 8",
        "desc": (
            "Scores the *filtered* headline findings (reporting convention + "
            "negation paradox) read from anomalies_rule_status.jsonl.  Writes "
            "scored_anomalies_rule_status.jsonl and scoring_summary_rule_status.json."
        ),
        "cmd": [sys.executable, str(ROOT / "code" / "scoring" / "risk_rule_status.py")],
        "outputs": ["results/scored_anomalies_rule_status.jsonl",
                     "results/scoring_summary_rule_status.json"],
    },
    {
        "id": 10,
        "title": "Generate validation sample (for expert labeling)",
        "desc": (
            "Draws a stratified, seeded sample of scored anomalies for manual "
            "expert adjudication.  Requires scored_anomalies.jsonl "
            "to exist."
        ),
        "cmd": [sys.executable, str(ROOT / "code" / "validation_sample.py")],
        "outputs": ["results/validation_sample.csv"],
    },
    {
        "id": 11,
        "title": "Compute validation metrics (after labeling) - Cohen's kappa",
        "desc": (
            "After both raters have filled label_rater1 and label_rater2 in "
            "validation_sample.csv, computes precision, actionable rate, "
            "G/(G+L) ratio, A-ratio, and Cohen's kappa.  Writes "
            "validation_metrics.json."
        ),
        "cmd": [sys.executable, str(ROOT / "code" / "validation_metrics.py")],
        "outputs": ["results/validation_metrics.json"],
    },
    {
        "id": 12,
        "title": "Run scalability experiment (synthetic data) - Table 10",
        "desc": (
            "Generates random policies of increasing size and measures "
            "wall-clock detection time (paper Table 10).  Independent of "
            "real dataset."
        ),
        "cmd": [sys.executable, str(ROOT / "code" / "scalability.py")],
        "outputs": ["results/scalability.json"],
    },
    {
        "id": 13,
        "title": "Run full test suite",
        "desc": "Executes all parser and anomaly tests (pytest).",
        "cmd": [sys.executable, "-m", "pytest", str(ROOT / "code" / "tests"), "-q"],
        "outputs": [],
    },
]


def print_banner() -> None:
    print()
    print("=" * 70)
    print("  PHALANX — Vendor-agnostic Firewall Policy Hygiene Framework")
    print("=" * 70)
    print()
    print("Select a step to run (1-13), or enter 'all' to run steps 1-9 in")
    print("order, or 'q' to quit.  Steps 10-11 require manual labeling and must")
    print("be run interactively.")
    print()


def print_menu() -> None:
    for step in STEPS:
        print(f"  [{step['id']:>2}]  {step['title']}")
        print(f"       {step['desc']}")
        print()


def run_step(index: int) -> None:
    step = STEPS[index]
    print(f"\n>>> Running step {step['id']}: {step['title']}")
    print(f"    command: {' '.join(step['cmd'])}")
    print()
    result = subprocess.run(step["cmd"], cwd=str(ROOT))
    if result.returncode != 0:
        print(f"\n    Step {step['id']} exited with code {result.returncode}")
    else:
        print(f"\n    Step {step['id']} completed OK.")
        for out in step.get("outputs", []):
            p = ROOT / out
            if p.exists():
                print(f"      -> {out}")
            else:
                print(f"      -> {out}  (WARNING: not found after run)")


def main() -> None:
    if "--all" in sys.argv:
        for i in range(9):  # steps 1-9
            run_step(i)
        return

    print_banner()
    print_menu()

    while True:
        try:
            choice = input("Enter step number (1-13), 'all', or 'q': ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if choice.lower() in ("q", "quit", "exit"):
            break
        if choice.lower() == "all":
            for i in range(9):
                run_step(i)
            continue

        try:
            num = int(choice)
            if 1 <= num <= len(STEPS):
                run_step(num - 1)
            else:
                print(f"    Invalid step number: {num}. Choose 1-{len(STEPS)}.")
        except ValueError:
            print(f"    Invalid input: '{choice}'. Enter a number, 'all', or 'q'.")


if __name__ == "__main__":
    main()