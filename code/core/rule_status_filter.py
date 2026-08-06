"""Post-processing filters that transform raw structural findings into the
headline (reporting-convention) view used by the paper and saved to
``results/anomalies_rule_status.jsonl``.

Two filters are applied:

1. Reporting convention (anchor collapsing)
   ----------------------------------------
   Generalization rows that share the same near-universal allow anchor rule
   (action=allow AND open in >=4 of the 5 core dimensions) are collapsed into
   ONE structural finding per anchor for headline statistics.  The detailed
   per-pair rows are still available in ``results/anomalies.jsonl``.

2. Negation paradox (IPImen)
   --------------------------
   Conflict rows where at least one involved rule uses a negated field
   (src/dst address or port negation) are excluded from the headline view,
   because these conflicts are driven by the vendor's negation semantics
   rather than by a genuine policy-design contradiction.

The module is shared by the ``--rule-status`` mode of ``core/anomaly.py``
and by ``scoring/risk_rule_status.py`` so that one filter definition is
used everywhere.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from core.anomaly import (
    ANOMALY_CLASSES,
    Finding,
    Rule,
    _is_near_universal,
)

NEGATION_FIELDS = (
    "src_addr_negated",
    "src_port_negated",
    "dst_addr_negated",
    "dst_port_negated",
)


# ── negation helper ───────────────────────────────────────────────────────────
def has_negation(rule: Rule) -> bool:
    """True if any negation flag in the rule is True."""
    return any(
        str(rule.raw.get(field, "")).strip().lower() == "true"
        for field in NEGATION_FIELDS
    )


def is_anchor_rule(rule: Rule) -> bool:
    """True when a rule is a near-universal allow anchor.

    This is the exact condition used by ``_aggregate_reporting_convention.py``:
    action == allow and the rule is open in >= 4 of the 5 core dimensions.
    """
    return rule.action == "allow" and _is_near_universal(rule)


def anchor_of(finding: Finding, rules_by_id: dict[str, Rule]) -> str | None:
    """Return the anchor rule_id for a generalization finding, or None.

    The anchor is the involved rule that is a near-universal allow.  In the
    engine's output for an anchor-driven generalization the anchor appears
    first (role='general'); we still scan both refs for robustness.
    """
    if finding.anomaly_type != "generalization":
        return None
    for ref in finding.rules:
        r = rules_by_id.get(ref["rule_id"])
        if r is None:
            continue
        if is_anchor_rule(r):
            return r.rule_id
    return None


# ── filter 1: reporting convention (anchor collapsing) ───────────────────────
def apply_reporting_convention(
    findings: Iterable[Finding],
    rules_by_id: dict[str, Rule],
) -> list[Finding]:
    """Collapse generalization rows per near-universal allow anchor.

    For each distinct anchor only the first generalization finding is kept as
    a representative; its ``details`` dict gains a ``collapsed_count`` field.
    All other generalization rows for the same anchor are removed.
    """
    kept: list[Finding] = []
    representatives: dict[str, Finding] = {}
    counts: dict[str, int] = defaultdict(int)

    for f in findings:
        anchor = anchor_of(f, rules_by_id)
        if anchor is not None:
            counts[anchor] += 1
            if anchor not in representatives:
                representatives[anchor] = f
        else:
            kept.append(f)

    for anchor, rep in representatives.items():
        rep.details = dict(rep.details)
        rep.details["collapsed_anchor"] = anchor
        rep.details["collapsed_count"] = counts[anchor]
        kept.append(rep)

    return kept


# ── filter 2: negation paradox (IPImen) ──────────────────────────────────────
def apply_negation_paradox(
    findings: Iterable[Finding],
    rules_by_id: dict[str, Rule],
) -> tuple[list[Finding], int]:
    """Remove conflict findings that involve at least one negated rule.

    Returns (kept_findings, excluded_count).  Only ``conflict`` rows are
    filtered; all other anomaly classes are unaffected.
    """
    kept: list[Finding] = []
    excluded = 0
    for f in findings:
        if f.anomaly_type == "conflict":
            involved = [rules_by_id.get(r["rule_id"]) for r in f.rules]
            involved = [r for r in involved if r is not None]
            if any(has_negation(r) for r in involved):
                excluded += 1
                continue
        kept.append(f)
    return kept, excluded


# Vendors that actually support field negation in the unified model.  The
# negation-paradox filter is applied ONLY to these vendors.  For the others
# (FortiGate, Palo Alto, pfSense, OPNsense) the concept is absent in the
# dataset, so no conflict is excluded there — mirroring the behaviour of
# ``_compute_negation_paradox.py`` which reports "n/a (no negation capability)".
NEGATION_CAPABLE_VENDORS = ("ipimen",)


# ── combined filter used by the rule-status pipeline ─────────────────────────
def filter_for_rule_status(
    findings: Iterable[Finding],
    rules_by_id: dict[str, Rule],
    vendor: str,
) -> tuple[list[Finding], dict[str, int]]:
    """Apply both filters (anchor collapsing + negation paradox).

    The negation-paradox filter is applied For all vendors.

    Returns (filtered_findings, meta) where ``meta`` carries the numbers
    needed for the summary report:

        * collapsed_anchors          — number of near-universal allow anchors
        * generalization_raw         — raw generalization rows before collapse
        * generalization_collapsed   — generalization rows removed by collapse
        * negation_excluded          — conflicts removed by negation filter
    """
    findings = list(findings)
    raw_gen = sum(1 for f in findings if f.anomaly_type == "generalization")

    collapsed = apply_reporting_convention(findings, rules_by_id)
    collapsed_anchors = sum(
        1 for f in collapsed if f.anomaly_type == "generalization"
        and f.details.get("collapsed_anchor") is not None
    )

    if vendor in NEGATION_CAPABLE_VENDORS:
        filtered, neg_excluded = apply_negation_paradox(collapsed, rules_by_id)
    else:
        filtered, neg_excluded = list(collapsed), 0

    meta = {
        "collapsed_anchors": collapsed_anchors,
        "generalization_raw": raw_gen,
        "generalization_collapsed": raw_gen - collapsed_anchors,
        "negation_excluded": neg_excluded,
    }
    return filtered, meta


# ── count helper for the summary file ────────────────────────────────────────
def count_by_class(findings: Iterable[Finding]) -> dict[str, int]:
    counts = {c: 0 for c in ANOMALY_CLASSES}
    for f in findings:
        counts[f.anomaly_type] = counts.get(f.anomaly_type, 0) + 1
    return counts