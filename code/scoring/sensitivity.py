"""
Ranking-stability (sensitivity) analysis for the risk metric (Section 5.4.5).

The absolute risk scores are by design conventional; what the framework
claims is not that the weights are "correct" but that the induced *priority
ordering* of high-risk findings is stable under reasonable re-parameterisation
of the weights β and the class severities σ.

This module measures that stability. The contextual factors (φ̂_ρ, φ̂_ε, φ̂_π)
are held fixed — they are computed once per finding — while β and σ are
perturbed; each perturbed ranking is compared with the default ranking using

    * Top-k overlap  — fraction of the default top-k still present in the
                       perturbed top-k (k ∈ {10, 20, 50}); and
    * Spearman ρ     — rank correlation over all findings (ties averaged).

All sampling is seeded, so the analysis is fully reproducible.
"""

from __future__ import annotations

import json
import math
import random
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.anomaly import detect_all, load_policy  # noqa: E402
from scoring.risk import (  # noqa: E402
    DEFAULT_BETAS,
    DEFAULT_SEVERITY,
    score_policy,
)

VENDORS = ["fortigate", "paloalto", "pfsense", "opnsense", "ipimen"]
K_VALUES = (10, 20, 50)


# ── ranking primitives ───────────────────────────────────────────────────────
def _rescore(items: list[tuple], betas, severities: dict) -> dict:
    """Recompute risk for every finding from its fixed factors."""
    b_rho, b_eps, b_pi = betas
    out = {}
    for fid, rho, eps, pi, key in items:
        out[fid] = severities[key] * (b_rho * rho + b_eps * eps + b_pi * pi)
    return out


def _order(scores: dict) -> list:
    """Finding ids sorted by descending risk (ties broken by id for determinism)."""
    return [fid for fid, _ in sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))]


def _topk_overlap(order_a: list, order_b: list, k: int) -> float:
    k = min(k, len(order_a))
    if k == 0:
        return 1.0
    return len(set(order_a[:k]) & set(order_b[:k])) / k


def _average_ranks(scores: dict) -> dict:
    """id → rank with tied scores receiving their averaged position (1 = top)."""
    order = sorted(scores.items(), key=lambda kv: -kv[1])
    ranks: dict = {}
    i, n = 0, len(order)
    while i < n:
        j = i
        while j + 1 < n and order[j + 1][1] == order[i][1]:
            j += 1
        avg = (i + j) / 2.0 + 1.0
        for t in range(i, j + 1):
            ranks[order[t][0]] = avg
        i = j + 1
    return ranks


def _pearson(x: list, y: list) -> float:
    n = len(x)
    if n < 2:
        return 1.0
    mx, my = sum(x) / n, sum(y) / n
    num = sum((xi - mx) * (yi - my) for xi, yi in zip(x, y))
    dx = math.sqrt(sum((xi - mx) ** 2 for xi in x))
    dy = math.sqrt(sum((yi - my) ** 2 for yi in y))
    if dx == 0 or dy == 0:
        return 1.0
    return num / (dx * dy)


def _spearman(scores_a: dict, scores_b: dict) -> float:
    ra, rb = _average_ranks(scores_a), _average_ranks(scores_b)
    ids = list(ra.keys())
    return _pearson([ra[i] for i in ids], [rb[i] for i in ids])


# ── perturbation samplers (seeded) ───────────────────────────────────────────
def _beta_samples(rng: random.Random, n_random: int) -> list[tuple]:
    """Default + simplex corners/edges + uniform-Dirichlet random draws."""
    fixed = [
        (1 / 3, 1 / 3, 1 / 3),
        (1.0, 0.0, 0.0), (0.0, 1.0, 0.0), (0.0, 0.0, 1.0),
        (0.5, 0.5, 0.0), (0.5, 0.0, 0.5), (0.0, 0.5, 0.5),
    ]
    rand = []
    for _ in range(n_random):
        g = [rng.gammavariate(1.0, 1.0) for _ in range(3)]
        s = sum(g) or 1.0
        rand.append((g[0] / s, g[1] / s, g[2] / s))
    return fixed + rand


def _beta_bounded(rng: random.Random, n_random: int, conc: float = 16.0) -> list[tuple]:
    """Reasonable beta perturbation: a Dirichlet concentrated near the neutral
    centre, so each weight stays in a sensible band around 1/3 instead of
    collapsing onto a single factor."""
    out = [(1 / 3, 1 / 3, 1 / 3)]
    for _ in range(n_random):
        g = [rng.gammavariate(conc, 1.0) for _ in range(3)]
        s = sum(g) or 1.0
        out.append((g[0] / s, g[1] / s, g[2] / s))
    return out


def _sigma_samples(rng: random.Random, n_random: int, delta: float = 0.125) -> list[dict]:
    """Default severities + jittered copies within ±delta (≈ half a level)."""
    out = [dict(DEFAULT_SEVERITY)]
    for _ in range(n_random):
        out.append({
            k: min(1.0, max(0.1, v + rng.uniform(-delta, delta)))
            for k, v in DEFAULT_SEVERITY.items()
        })
    return out


# ── per-policy stability ─────────────────────────────────────────────────────
def _items_from_scored(scored: list) -> list[tuple]:
    return [
        (i, s.rho, s.epsilon, s.pi, s.severity_key)
        for i, s in enumerate(scored)
    ]


def _stability_for_items(items: list[tuple], mode: str, seed: int,
                         n_random: int) -> dict:
    """Compare every perturbed ranking against the default ranking."""
    rng = random.Random(seed)
    default_scores = _rescore(items, DEFAULT_BETAS, DEFAULT_SEVERITY)
    default_order = _order(default_scores)

    if mode == "beta_simplex":
        params = [(b, DEFAULT_SEVERITY) for b in _beta_samples(rng, n_random)]
    elif mode == "beta_bounded":
        params = [(b, DEFAULT_SEVERITY) for b in _beta_bounded(rng, n_random)]
    elif mode == "sigma":
        params = [(DEFAULT_BETAS, s) for s in _sigma_samples(rng, n_random)]
    else:  # combined (reasonable: bounded beta + sigma jitter)
        betas = _beta_bounded(rng, n_random)
        sigmas = _sigma_samples(rng, n_random)
        params = [(betas[i % len(betas)], sigmas[(i + 1) % len(sigmas)])
                  for i in range(n_random)]

    spearmans: list[float] = []
    topk: dict = {k: [] for k in K_VALUES}
    for betas, severities in params:
        scores = _rescore(items, betas, severities)
        order = _order(scores)
        spearmans.append(_spearman(default_scores, scores))
        for k in K_VALUES:
            topk[k].append(_topk_overlap(default_order, order, k))

    return {
        "n_perturbations": len(params),
        "spearman_mean": round(sum(spearmans) / len(spearmans), 4),
        "spearman_min": round(min(spearmans), 4),
        "topk_overlap_mean": {k: round(sum(v) / len(v), 4) for k, v in topk.items()},
        "topk_overlap_min": {k: round(min(v), 4) for k, v in topk.items()},
    }


# ── runner / CLI ─────────────────────────────────────────────────────────────
def _default_dataset_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "Real-Dataset" / "unified"


def run(dataset_dir: Optional[Path] = None, out_dir: Optional[Path] = None,
        seed: int = 42, n_random: int = 200) -> dict:
    dataset_dir = dataset_dir or _default_dataset_dir()
    out_dir = out_dir or (Path(__file__).resolve().parents[2] / "results")
    out_dir.mkdir(parents=True, exist_ok=True)

    report: dict = {"seed": seed, "n_random": n_random, "per_vendor": {}, "aggregate": {}}
    modes = ("beta_bounded", "sigma", "combined", "beta_simplex")
    agg: dict = {
        m: {
            "spearman_mean": [], "spearman_min": [],
            "topk_mean": {k: [] for k in K_VALUES},
            "topk_min": {k: [] for k in K_VALUES},
        }
        for m in modes
    }

    for vendor in VENDORS:
        csv_path = dataset_dir / f"{vendor}.csv"
        if not csv_path.exists():
            continue
        rules = load_policy(csv_path, enabled_only=True)
        scored = score_policy(detect_all(rules), rules)
        items = _items_from_scored(scored)
        report["per_vendor"][vendor] = {}
        for mode in modes:
            st = _stability_for_items(items, mode, seed, n_random)
            report["per_vendor"][vendor][mode] = st
            agg[mode]["spearman_mean"].append(st["spearman_mean"])
            agg[mode]["spearman_min"].append(st["spearman_min"])
            for k in K_VALUES:
                agg[mode]["topk_mean"][k].append(st["topk_overlap_mean"][k])
                agg[mode]["topk_min"][k].append(st["topk_overlap_min"][k])

    for mode in modes:
        report["aggregate"][mode] = {
            "spearman_mean": round(sum(agg[mode]["spearman_mean"]) / len(agg[mode]["spearman_mean"]), 4),
            "spearman_min": round(min(agg[mode]["spearman_min"]), 4),
            "topk_overlap_mean": {k: round(sum(agg[mode]["topk_mean"][k]) / len(agg[mode]["topk_mean"][k]), 4) for k in K_VALUES},
            "topk_overlap_min": {k: round(min(agg[mode]["topk_min"][k]), 4) for k in K_VALUES},
        }

    with open(out_dir / "sensitivity.json", "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)
    return report


def _print_report(report: dict) -> None:
    print(f"seed={report['seed']}  perturbations/mode~{report['n_random']}\n")
    print(f"{'mode':<13} {'sprmn_mean':>10} {'sprmn_min':>9} "
          f"{'t10_mean':>8} {'t10_min':>8} {'t50_mean':>8} {'t50_min':>8}")
    print("-" * 70)
    for mode, a in report["aggregate"].items():
        tm, tn = a["topk_overlap_mean"], a["topk_overlap_min"]
        print(f"{mode:<13} {a['spearman_mean']:>10} {a['spearman_min']:>9} "
              f"{tm[10]:>8} {tn[10]:>8} {tm[50]:>8} {tn[50]:>8}")


if __name__ == "__main__":
    _print_report(run())
