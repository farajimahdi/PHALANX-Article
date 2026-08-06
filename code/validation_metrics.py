"""
Calculates validation metrics and inter-rater agreement from labeled validation samples.

Computes precision estimates with confidence intervals, class breakdowns, and Cohen's kappa agreement statistics.
"""
from __future__ import annotations

import csv
import json
import math
import random
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "results" / "validation_sample.csv"
OUT = ROOT / "results" / "validation_metrics.json"

VALID = {"G", "L", "A"}

CONFIDENCE = 0.95
BOOTSTRAP_RESAMPLES = 10_000
BOOTSTRAP_SEED = 20260805  # fixed so the reported interval is reproducible

# Bands of Landis and Koch (1977), Biometrics 33(1):159-174, as (inclusive
# upper bound, descriptor, printed span). The authors themselves called the
# cut-points arbitrary, so the band travels with its interval, never alone.
LANDIS_KOCH_BANDS = (
    (0.00, "poor", "< 0.00"),
    (0.20, "slight", "0.00-0.20"),
    (0.40, "fair", "0.21-0.40"),
    (0.60, "moderate", "0.41-0.60"),
    (0.80, "substantial", "0.61-0.80"),
    (1.00, "almost perfect", "0.81-1.00"),
)

def norm(label: str) -> str:
    """Normalise a raw cell value to an upper-case label code."""
    return (label or "").strip().upper()


def load_rows() -> list[dict]:
    with SAMPLE.open(encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


# ---------------------------------------------------------------------------
# exact binomial interval
# ---------------------------------------------------------------------------

def _binom_cdf(successes: int, trials: int, prob: float) -> float:
    """P(X <= successes) for X ~ Binomial(trials, prob)."""
    return sum(
        math.comb(trials, i) * prob**i * (1.0 - prob) ** (trials - i)
        for i in range(successes + 1)
    )


def _bisect(func, low: float, high: float, tol: float = 1e-10) -> float:
    """Root of a monotone func on [low, high]."""
    for _ in range(200):
        mid = 0.5 * (low + high)
        if high - low < tol:
            return mid
        if func(low) * func(mid) <= 0:
            high = mid
        else:
            low = mid
    return 0.5 * (low + high)


def clopper_pearson(successes: int, trials: int,
                    confidence: float = CONFIDENCE) -> dict:
    """Exact (Clopper-Pearson) two-sided interval for a binomial proportion."""
    if trials == 0:
        return {"lower": None, "upper": None}
    tail = (1.0 - confidence) / 2.0
    if successes == 0:
        lower = 0.0
    else:
        lower = _bisect(
            lambda p: (1.0 - _binom_cdf(successes - 1, trials, p)) - tail,
            0.0, 1.0,
        )
    if successes == trials:
        upper = 1.0
    else:
        upper = _bisect(
            lambda p: _binom_cdf(successes, trials, p) - tail, 0.0, 1.0
        )
    return {"lower": round(lower, 4), "upper": round(upper, 4)}


# ---------------------------------------------------------------------------
# precision
# ---------------------------------------------------------------------------

def _summarise(counter: Counter) -> dict:
    total = sum(counter.values())
    return {
        "n": total,
        "genuine": counter["G"],
        "legitimate": counter["L"],
        "artifact": counter["A"],
        "precision": round(counter["G"] / total, 4) if total else None,
        "precision_ci95": clopper_pearson(counter["G"], total),
        "artifact_rate": round(counter["A"] / total, 4) if total else None,
        "artifact_rate_ci95": clopper_pearson(counter["A"], total),
    }


def overall_precision(rows: list[dict], rater: str) -> dict:
    counter: Counter = Counter()
    for row in rows:
        label = norm(row.get(rater, ""))
        if label in VALID:
            counter[label] += 1
    return _summarise(counter)


def precision_by_class(rows: list[dict], rater: str) -> dict:
    by_class: dict[str, Counter] = defaultdict(Counter)
    for row in rows:
        label = norm(row.get(rater, ""))
        if label in VALID:
            by_class[row["anomaly_type"]][label] += 1
    return {cls: _summarise(counter) for cls, counter in sorted(by_class.items())}


# ---------------------------------------------------------------------------
# agreement
# ---------------------------------------------------------------------------

def _labeled_pairs(rows: list[dict]) -> list[tuple[str, str]]:
    pairs = []
    for row in rows:
        first = norm(row.get("label_rater1", ""))
        second = norm(row.get("label_rater2", ""))
        if first in VALID and second in VALID:
            pairs.append((first, second))
    return pairs


def _kappa(pairs: list[tuple[str, str]]) -> float | None:
    """Cohen's kappa for a list of (rater1, rater2) label pairs."""
    count = len(pairs)
    if count == 0:
        return None
    observed = sum(1 for first, second in pairs if first == second) / count
    marginal_first = Counter(first for first, _ in pairs)
    marginal_second = Counter(second for _, second in pairs)
    expected = sum(
        (marginal_first[c] / count) * (marginal_second[c] / count)
        for c in sorted(VALID)
    )
    # expected == 1 means both raters used a single category throughout, so
    # chance alone explains the agreement and kappa degenerates.
    return 1.0 if expected == 1 else (observed - expected) / (1 - expected)


def _expected_agreement(pairs: list[tuple[str, str]]) -> float:
    count = len(pairs)
    marginal_first = Counter(first for first, _ in pairs)
    marginal_second = Counter(second for _, second in pairs)
    return sum(
        (marginal_first[c] / count) * (marginal_second[c] / count)
        for c in sorted(VALID)
    )


def bootstrap_kappa_ci(pairs: list[tuple[str, str]],
                       resamples: int = BOOTSTRAP_RESAMPLES,
                       confidence: float = CONFIDENCE,
                       seed: int = BOOTSTRAP_SEED) -> dict:
    """Percentile bootstrap interval for Cohen's kappa.

    Rows are resampled with replacement; the interval is read off the
    empirical quantiles of the resampled coefficients.
    """
    count = len(pairs)
    if count < 2:
        return {"resamples": 0, "lower": None, "upper": None}
    rng = random.Random(seed)
    draws: list[float] = []
    for _ in range(resamples):
        sample = [pairs[rng.randrange(count)] for _ in range(count)]
        value = _kappa(sample)
        if value is not None:
            draws.append(value)
    draws.sort()
    tail = (1.0 - confidence) / 2.0
    low_index = int(math.floor(tail * len(draws)))
    high_index = min(len(draws) - 1, int(math.ceil((1.0 - tail) * len(draws))) - 1)
    return {
        "resamples": len(draws),
        "seed": seed,
        "lower": round(draws[low_index], 4),
        "upper": round(draws[high_index], 4),
    }

def landis_koch_band(kappa: float | None) -> dict | None:
    """Descriptor and span of the Landis-Koch band containing kappa.

    Recorded for provenance. The cut-points are a reporting convention rather
    than a measurement threshold, and competing scales place the same value in
    a differently named band, so the manuscript quotes the coefficient with
    its interval and mentions the band once.
    """
    if kappa is None:
        return None
    if kappa < 0.0:
        return {"label": "poor", "span": "< 0.00"}
    for upper, label, span in LANDIS_KOCH_BANDS[1:]:
        if kappa <= upper:
            return {"label": label, "span": span}
    return {"label": "almost perfect", "span": "0.81-1.00"}

def cohens_kappa(rows: list[dict]) -> dict:
    """Cohen's kappa between rater1 and rater2 over jointly labeled rows."""
    pairs = _labeled_pairs(rows)
    count = len(pairs)
    if count == 0:
        return {"n": 0, "kappa": None, "observed_agreement": None}

    observed = sum(1 for first, second in pairs if first == second) / count
    expected = _expected_agreement(pairs)
    kappa = _kappa(pairs)
    confusion: Counter = Counter(pairs)
    interval = bootstrap_kappa_ci(pairs)
    used = sorted({label for pair in pairs for label in pair})
    lower_band = landis_koch_band(interval["lower"])
    upper_band = landis_koch_band(interval["upper"])
    return {
        "n": count,
        "kappa": round(kappa, 4) if kappa is not None else None,
        "kappa_ci95_bootstrap": interval,
        "landis_koch": landis_koch_band(kappa),
        "landis_koch_ci_bands": {
            "at_lower_limit": lower_band,
            "at_upper_limit": upper_band,
            "interval_spans_two_bands": bool(
                lower_band and upper_band
                and lower_band["label"] != upper_band["label"]
            ),
        },
        "observed_agreement": round(observed, 4),
        "expected_agreement": round(expected, 4),
        "disagreements": count - sum(1 for f, s in pairs if f == s),
        "categories_used": used,
        # With one category unused the chance term for it vanishes, so the
        # three-category coefficient equals the two-category one.
        "reduces_to_two_category": len(used) == 2,
        "confusion": {f"{f}->{s}": n for (f, s), n in sorted(confusion.items())},
    }


def main() -> None:
    rows = load_rows()
    report = {
        "sample_size": len(rows),
        "confidence_level": CONFIDENCE,
        "rater1": {
            "overall": overall_precision(rows, "label_rater1"),
            "by_class": precision_by_class(rows, "label_rater1"),
        },
        "rater2": {
            "overall": overall_precision(rows, "label_rater2"),
            "by_class": precision_by_class(rows, "label_rater2"),
        },
        "cohens_kappa": cohens_kappa(rows),
    }
    OUT.write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    first = report["rater1"]["overall"]
    ci = first["precision_ci95"]
    print(f"Sample size: {report['sample_size']}")
    print(
        f"Rater 1 labeled {first['n']}  precision(actionable)={first['precision']}"
        f"  95% CI [{ci['lower']}, {ci['upper']}]"
        f"  (G={first['genuine']} L={first['legitimate']} A={first['artifact']})"
    )
    art = first["artifact_rate_ci95"]
    print(f"  artifact rate {first['artifact_rate']}  95% CI [{art['lower']}, {art['upper']}]")
    kappa = report["cohens_kappa"]
    if kappa["n"]:
        kci = kappa["kappa_ci95_bootstrap"]
        band = kappa["landis_koch"]
        bands = kappa["landis_koch_ci_bands"]
        print(
            f"Cohen's kappa (n={kappa['n']}): {kappa['kappa']}"
            f"  95% CI [{kci['lower']}, {kci['upper']}]"
            f"  observed agreement {kappa['observed_agreement']}"
            f"  ({kappa['disagreements']} disagreements)"
        )
        print(
            f"  Landis-Koch: {band['label']} ({band['span']})"
            f"  |  CI runs from {bands['at_lower_limit']['label']}"
            f" ({bands['at_lower_limit']['span']}) to"
            f" {bands['at_upper_limit']['label']}"
            f" ({bands['at_upper_limit']['span']})"
        )
        if bands["interval_spans_two_bands"]:
            print("  note: the interval covers more than one band, so the "
                  "descriptor is weaker evidence than the coefficient")
        if kappa["reduces_to_two_category"]:
            used = ", ".join(kappa["categories_used"])
            print(f"  categories used: {used}  "
                  f"(one code unused; kappa equals the two-category value)")
        print(f"  confusion: {kappa['confusion']}")
    else:
        print("Cohen's kappa: not computed (fill both rater columns first)")


if __name__ == "__main__":
    main()