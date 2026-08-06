"""
Transparent risk scoring for detected anomalies

    Risk(α) = σ(c(α)) · Φ(α),   Φ(α) = Σ_k β_k · φ̂_k(α),   k ∈ {ρ, ε, π}

The score is a transparent weighted linear combination, never a black box.
Each contextual factor is normalised to [0, 1] and is reported separately so
that a network administrator can see how much each one contributes:

    ρ  blast radius   — log-scaled flow-space volume of the affected region,
                        normalised by the largest span in the same policy.
    ε  exposure       — upward trust-boundary crossing, derived from a small
                        per-deployment zone trust order (never guessed by the
                        framework). For pf-based products whose dst_zone is
                        N/A, exposure is approximated from the source zone
                        alone (consistent with D9/D10: N/A is absence of the
                        concept, not unrestricted access).
    π  permissiveness — fraction of {src_addr, dst_addr, dst_port, protocol}
                        set to "any".

Severity σ is the ordinal class weight of Table 5. For shadowing it depends
on the action of the shadowed (later) rule: a shadowed deny/reject is
critical, a shadowed allow is moderate.

No machine learning is involved here. The learning hook of D3 (adapting β and
σ from administrator feedback) is out of scope for this module; the defaults
are deliberately neutral (β_ρ = β_ε = β_π = 1/3).
"""

from __future__ import annotations

import json
import math
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.anomaly import (  # noqa: E402
    PORT_MAX,
    IntervalSet,
    Match,
    ProtoSet,
    StringDim,
    Rule,
    detect_all,
    load_policy,
)

# ── default parameters (Section 5.4.3 / 5.4.4) ───────────────────────────────
DEFAULT_BETAS = (1.0 / 3.0, 1.0 / 3.0, 1.0 / 3.0)  # (ρ, ε, π) — neutral

# Placeholder universe size for app_id / user_id dimensions in blast-radius
# volume. Because the unified model does not carry a global app/user catalog,
# "any" is treated as a fixed large set; the value only affects absolute
# volume, while normalisation by the maximum within each policy keeps the
# relative scores stable.
_STRING_UNIVERSE_SIZE = 1000

DEFAULT_SEVERITY = {
    "over_permissive": 1.00,
    "shadowing_deny": 1.00,
    "shadowing_allow": 0.50,
    "conflict": 0.75,
    "generalization": 0.25,
    "redundancy": 0.25,
    # classes 6-8 (future work) kept here so the table is complete
    "stale": 0.75,
    "duplicate_object": 0.50,
    "unused": 0.25,
}

# Per-deployment zone trust order (Section 5.4.2, factor ε). This is an input
# of the deployment, not a result produced by the framework. The values below
# are the documented default for the study dataset: WAN is the least trusted
# (Internet facing) and the management plane is the most trusted.
DEFAULT_ZONE_TRUST = {"wan": 0, "dmz": 1, "vpn": 2, "lan": 3, "mgmt": 4}
TRUST_MIN, TRUST_MAX = 0, 4

_SEP = re.compile(r"[;,]")


# ── set-size helpers (flow-space volume) ─────────────────────────────────────
def _iset_size(s: IntervalSet) -> int:
    return sum(hi - lo + 1 for lo, hi in s.intervals)


def _proto_size(p: ProtoSet) -> int:
    # The IP protocol number space has 256 values; treat "any" as that cap.
    return 256 if p.universal else max(1, len(p.tokens))


def _proto_inter_size(a: ProtoSet, b: ProtoSet) -> int:
    if a.universal and b.universal:
        return 256
    if a.universal:
        return max(1, len(b.tokens))
    if b.universal:
        return max(1, len(a.tokens))
    return len(a.tokens & b.tokens)


def _string_dim_size(d: StringDim) -> int:
    """Size of an identity dimension for volume calculation.

    N/A (concept absent) contributes 1 so it does not shrink the volume.
    'any' contributes the universal count APP_UNIVERSE / USER_UNIVERSE.
    Specific tokens contribute their count.
    """
    if d.na:
        return 1
    if d.universal:
        return _STRING_UNIVERSE_SIZE
    return max(1, len(d.tokens))


def _string_inter_size(a: StringDim, b: StringDim) -> int:
    """|A ∩ B| for identity dimensions."""
    if a.na or b.na:
        # Non-discriminating dimension: use the other dimension's size.
        return _string_dim_size(b if a.na else a)
    if a.universal and b.universal:
        return _STRING_UNIVERSE_SIZE
    if a.universal:
        return max(1, len(b.tokens))
    if b.universal:
        return max(1, len(a.tokens))
    return len(a.tokens & b.tokens)


def _match_volume(m: Match) -> int:
    """|M(R)| over the flow space (per-family IP product, summed)."""
    ip_term = 0
    for f in (4, 6):
        ip_term += _iset_size(m.src_ip.fam(f)) * _iset_size(m.dst_ip.fam(f))
    return (
        ip_term
        * _iset_size(m.src_port)
        * _iset_size(m.dst_port)
        * _proto_size(m.proto)
        * _string_dim_size(m.app_id)
        * _string_dim_size(m.user_id)
    )


def _intersection_volume(a: Match, b: Match) -> int:
    """|M(Ri) ∩ M(Rj)| over the flow space."""
    ip_term = 0
    for f in (4, 6):
        s = _iset_size(a.src_ip.fam(f).intersection(b.src_ip.fam(f)))
        d = _iset_size(a.dst_ip.fam(f).intersection(b.dst_ip.fam(f)))
        ip_term += s * d
    sp = _iset_size(a.src_port.intersection(b.src_port))
    dp = _iset_size(a.dst_port.intersection(b.dst_port))
    pr = _proto_inter_size(a.proto, b.proto)
    ai = _string_inter_size(a.app_id, b.app_id)
    ui = _string_inter_size(a.user_id, b.user_id)
    return ip_term * sp * dp * pr * ai * ui


def _log_volume(vol: int) -> float:
    return math.log10(vol) if vol > 0 else 0.0


# ── factor ρ: blast radius ───────────────────────────────────────────────────
def blast_log(rules: list[Rule]) -> float:
    """Raw log-volume of the affected region (pre-normalisation)."""
    if len(rules) == 1:
        return _log_volume(_match_volume(rules[0].match))
    return _log_volume(_intersection_volume(rules[0].match, rules[1].match))


# ── factor ε: exposure ───────────────────────────────────────────────────────
def _zone_trust(zone: str, role: str, trust: dict) -> Optional[int]:
    z = (zone or "").strip().lower()
    if z in ("", "n/a"):
        return None  # concept absent (non-discriminating, not "open")
    if z == "any":
        # Conservative: an "any" source includes the least-trusted zone, an
        # "any" destination includes the most-trusted zone — either way this
        # maximises the measured crossing.
        return TRUST_MIN if role == "src" else TRUST_MAX
    levels = [trust.get(p.strip()) for p in _SEP.split(z)]
    levels = [lv for lv in levels if lv is not None]
    if not levels:
        return None
    return min(levels) if role == "src" else max(levels)


def exposure(rule: Rule, trust: dict = DEFAULT_ZONE_TRUST) -> float:
    """Upward trust-boundary crossing in [0, 1]."""
    span = TRUST_MAX - TRUST_MIN
    ts = _zone_trust(rule.raw.get("src_zone", ""), "src", trust)
    td = _zone_trust(rule.raw.get("dst_zone", ""), "dst", trust)
    if td is None and ts is None:
        return 0.0
    if td is None:                     # pf-based: estimate from source only
        return (TRUST_MAX - ts) / span if ts is not None else 0.0
    if ts is None:
        return 0.0
    return max(0, td - ts) / span


# ── factor π: permissiveness ─────────────────────────────────────────────────
def permissiveness(rule: Rule) -> float:
    """Fraction of applicable {src_addr, dst_addr, dst_port, protocol, app_id,
    user_id} dimensions set to any.

    app_id / user_id are only counted when the vendor supports them (i.e.
    they are not N/A). N/A means the concept does not exist for that vendor
    and therefore is not a permissive choice.
    """
    ipv = rule.raw.get("ip_version", "both")
    dims = [
        rule.match.src_ip.is_universal(ipv),
        rule.match.dst_ip.is_universal(ipv),
        rule.match.dst_port.intervals == [(0, PORT_MAX)],
        rule.match.proto.universal,
    ]
    if not rule.match.app_id.na:
        dims.append(rule.match.app_id.universal)
    if not rule.match.user_id.na:
        dims.append(rule.match.user_id.universal)
    return sum(1 for d in dims if d) / len(dims)


# ── severity σ ───────────────────────────────────────────────────────────────
def severity_key(finding) -> str:
    if finding.anomaly_type == "shadowing":
        shadowed_action = finding.details.get("later_action", "")
        return "shadowing_deny" if shadowed_action in ("deny", "reject") else "shadowing_allow"
    return finding.anomaly_type


def severity(finding, severities: dict = DEFAULT_SEVERITY) -> float:
    return severities[severity_key(finding)]


# ── scored finding ───────────────────────────────────────────────────────────
@dataclass
class ScoredFinding:
    vendor: str
    anomaly_type: str
    rules: list
    explanation: str
    risk: float
    sigma: float
    phi: float
    rho: float          # φ̂_ρ (normalised blast radius)
    epsilon: float      # φ̂_ε (exposure)
    pi: float           # φ̂_π (permissiveness)
    severity_key: str

    def to_dict(self) -> dict:
        return {
            "vendor": self.vendor,
            "anomaly_type": self.anomaly_type,
            "rules": self.rules,
            "risk": round(self.risk, 4),
            "sigma": self.sigma,
            "phi": round(self.phi, 4),
            "factors": {
                "blast_radius": round(self.rho, 4),
                "exposure": round(self.epsilon, 4),
                "permissiveness": round(self.pi, 4),
            },
            "explanation": self.explanation,
        }


def _finding_rules(finding, by_seq: dict) -> list[Rule]:
    return [by_seq[ref["seq"]] for ref in finding.rules]


def score_policy(
    findings: list,
    rules: list[Rule],
    betas: tuple[float, float, float] = DEFAULT_BETAS,
    severities: dict = DEFAULT_SEVERITY,
    trust: dict = DEFAULT_ZONE_TRUST,
) -> list[ScoredFinding]:
    """Score every finding of one policy. Blast radius is normalised by the
    largest log-volume observed within this same policy (Section 5.4.2)."""
    by_seq = {r.seq: r for r in rules}
    b_rho, b_eps, b_pi = betas

    raw = []
    for f in findings:
        involved = _finding_rules(f, by_seq)
        raw.append((
            f,
            blast_log(involved),
            max(exposure(r, trust) for r in involved),
            max(permissiveness(r) for r in involved),
        ))

    max_blast = max((b for _, b, _, _ in raw), default=0.0) or 1.0

    scored: list[ScoredFinding] = []
    for f, b_log, expo, perm in raw:
        rho = b_log / max_blast
        phi = b_rho * rho + b_eps * expo + b_pi * perm
        sigma = severity(f, severities)
        scored.append(ScoredFinding(
            vendor=f.vendor,
            anomaly_type=f.anomaly_type,
            rules=f.rules,
            explanation=f.explanation,
            risk=sigma * phi,
            sigma=sigma,
            phi=phi,
            rho=rho,
            epsilon=expo,
            pi=perm,
            severity_key=severity_key(f),
        ))
    return scored


# ── runner / CLI ─────────────────────────────────────────────────────────────
VENDORS = ["fortigate", "paloalto", "pfsense", "opnsense", "ipimen"]


def _default_dataset_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "Real-Dataset" / "unified"


def run(dataset_dir: Optional[Path] = None, out_dir: Optional[Path] = None) -> dict:
    """Score every vendor policy and persist the ranked findings."""
    dataset_dir = dataset_dir or _default_dataset_dir()
    out_dir = out_dir or (Path(__file__).resolve().parents[2] / "results")
    out_dir.mkdir(parents=True, exist_ok=True)

    report: dict = {"per_vendor": {}}
    all_scored: list[dict] = []

    for vendor in VENDORS:
        csv_path = dataset_dir / f"{vendor}.csv"
        if not csv_path.exists():
            continue
        rules = load_policy(csv_path, enabled_only=True)
        findings = detect_all(rules)
        scored = score_policy(findings, rules)
        scored.sort(key=lambda s: s.risk, reverse=True)
        report["per_vendor"][vendor] = {
            "findings": len(scored),
            "risk_max": round(scored[0].risk, 4) if scored else 0.0,
            "risk_mean": round(sum(s.risk for s in scored) / len(scored), 4) if scored else 0.0,
            "top5": [s.to_dict() for s in scored[:5]],
        }
        all_scored.extend(s.to_dict() for s in scored)

    with open(out_dir / "scored_anomalies.jsonl", "w", encoding="utf-8") as fh:
        for s in all_scored:
            fh.write(json.dumps(s, ensure_ascii=False) + "\n")
    with open(out_dir / "scoring_summary.json", "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)

    return report


def _print_report(report: dict) -> None:
    print(f"{'vendor':<11} {'findings':>8} {'risk_max':>9} {'risk_mean':>10}")
    print("-" * 42)
    for vendor, v in report["per_vendor"].items():
        print(f"{vendor:<11} {v['findings']:>8} {v['risk_max']:>9} {v['risk_mean']:>10}")
    print("\nTop finding per vendor:")
    for vendor, v in report["per_vendor"].items():
        if v["top5"]:
            t = v["top5"][0]
            ids = "+".join(r["rule_id"] for r in t["rules"])
            print(f"  {vendor:<10} risk={t['risk']:<6} {t['anomaly_type']:<15} "
                              f"[{ids}] rho={t['factors']['blast_radius']} "
                              f"eps={t['factors']['exposure']} pi={t['factors']['permissiveness']}")


if __name__ == "__main__":
    _print_report(run())
