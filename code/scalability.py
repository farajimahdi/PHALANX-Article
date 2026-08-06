"""
Scalability benchmark for the deterministic detection engine.

Generates synthetic rulebases of varying sizes to measure detection execution time as a function of rule count.
"""

from __future__ import annotations

import json
import math
import platform
import random
import statistics
import sys
import time
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))

from core.anomaly import detect_all, rule_from_row  # noqa: E402

# A broad address/zone vocabulary keeps the overlap density realistic: like a
# real policy, most rules are specific and intersect only occasionally, so the
# number of findings grows roughly linearly and the O(n^2) pairwise comparison
# (not finding construction) is what the timing reflects.
ZONES = ["LAN", "DMZ", "VPN", "MGMT", "WAN", "any"]
ZONE_WEIGHTS = [21, 21, 21, 21, 12, 4]          # "any" is deliberately rare
PROTOCOLS = ["tcp", "tcp", "udp", "udp", "tcp/udp", "icmp", "any"]
ACTIONS = ["allow", "allow", "allow", "deny", "deny", "reject"]
PORTS = ["22", "53", "80", "123", "161", "389", "443", "445", "636", "993",
         "3306", "3389", "5432", "8080", "8443", "1000-2000", "any"]
_V4_BLOCKS = 64   # number of distinct /16 pools the addresses are drawn from


def _rand_v4(rng: random.Random) -> str:
    r = rng.random()
    if r < 0.06:
        return "any"
    b, c = rng.randint(0, _V4_BLOCKS), rng.randint(0, 255)
    if r < 0.55:                                  # /32 host (large space)
        return f"10.{b}.{c}.{rng.randint(1, 254)}/32"
    if r < 0.85:                                  # /24
        return f"10.{b}.{c}.0/24"
    return f"172.{16 + (b % 16)}.{c}.{rng.choice([0, 64, 128, 192])}/26"


def _rand_v6(rng: random.Random) -> str:
    if rng.random() < 0.10:
        return "any"
    return f"fd00:{rng.randint(0, 255):x}:{rng.randint(0, 255):x}::/64"


def generate_policy(n: int, seed: int = 42) -> list:
    """Build n deterministic synthetic unified rules (scalability only)."""
    rng = random.Random(seed)
    rules = []
    for i in range(1, n + 1):
        fam = rng.choices(["4", "6", "both"], weights=[86, 11, 3])[0]
        if fam == "6":
            src_addr, dst_addr = _rand_v6(rng), _rand_v6(rng)
        elif fam == "both":
            src_addr, dst_addr = "any", _rand_v4(rng)
        else:
            src_addr, dst_addr = _rand_v4(rng), _rand_v4(rng)
        row = {
            "vendor": "synthetic", "rule_id": str(i), "rule_name": f"syn-{i}",
            "seq": str(i),
            "enabled": "True" if rng.random() > 0.15 else "False",
            "action": rng.choice(ACTIONS), "ip_version": fam,
            "src_zone": rng.choices(ZONES, weights=ZONE_WEIGHTS)[0],
            "dst_zone": rng.choices(ZONES, weights=ZONE_WEIGHTS)[0],
            "src_iface": "any", "dst_iface": "any",
            "src_addr": src_addr, "src_addr_negated": "False",
            "src_port": "any", "src_port_negated": "False",
            "dst_addr": dst_addr,
            "dst_addr_negated": "True" if rng.random() < 0.04 else "False",
            "dst_port": rng.choice(PORTS), "dst_port_negated": "False",
            "protocol": rng.choice(PROTOCOLS), "service": "N/A",
            "schedule": "always", "log": "True", "nat_related": "N/A",
            "app_id": "any", "user_id": "any", "icmp_type": "N/A",
            "notes": "synthetic, scalability only",
        }
        rules.append(rule_from_row(row))
    return rules


# ── benchmark ────────────────────────────────────────────────────────────────
DEFAULT_SIZES = [250, 500, 1000, 2000, 4000]


def benchmark(sizes: Optional[list[int]] = None, seed: int = 42) -> list[dict]:
    sizes = sizes or DEFAULT_SIZES
    results = []
    for n in sizes:
        rules = generate_policy(n, seed)
        enabled = [r for r in rules if r.enabled]
        repeats = 3 if n <= 1000 else 1
        times, count = [], 0
        for _ in range(repeats):
            t0 = time.perf_counter()
            findings = detect_all(enabled)
            times.append(time.perf_counter() - t0)
            count = len(findings)
        best = min(times)
        results.append({
            "n": n,
            "enabled": len(enabled),
            "time_s": round(best, 5),
            "findings": count,
            "us_per_pair": round(best * 1e6 / max(1, len(enabled) ** 2 / 2), 4),
        })
    return results


def fit_exponent(results: list[dict]) -> float:
    """Slope of log(time) vs log(n): the empirical scaling exponent."""
    pts = [(math.log(r["n"]), math.log(r["time_s"]))
           for r in results if r["time_s"] > 0]
    n = len(pts)
    mx = sum(x for x, _ in pts) / n
    my = sum(y for _, y in pts) / n
    num = sum((x - mx) * (y - my) for x, y in pts)
    den = sum((x - mx) ** 2 for x, _ in pts)
    return num / den if den else float("nan")


def run(out_dir: Optional[Path] = None, sizes: Optional[list[int]] = None,
        seed: int = 42) -> dict:
    out_dir = out_dir or (Path(__file__).resolve().parents[1] / "results")
    out_dir.mkdir(parents=True, exist_ok=True)
    results = benchmark(sizes, seed)
    report = {
        "label": "synthetic, scalability only",
        "seed": seed,
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
        },
        "results": results,
        "fitted_exponent": round(fit_exponent(results), 3),
        "theoretical": "O(n^2) pairwise (Section 6.7)",
    }
    with open(out_dir / "scalability.json", "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)
    return report


def _print_report(report: dict) -> None:
    print(f"{report['label']}  |  python {report['environment']['python']}")
    print(f"{'n':>6} {'enabled':>8} {'time_s':>10} {'findings':>9} {'us/pair':>9}")
    print("-" * 46)
    for r in report["results"]:
        print(f"{r['n']:>6} {r['enabled']:>8} {r['time_s']:>10} "
              f"{r['findings']:>9} {r['us_per_pair']:>9}")
    print("-" * 46)
    print(f"fitted scaling exponent (log-log) = {report['fitted_exponent']}  "
          f"(theory: 2.0)")


if __name__ == "__main__":
    _print_report(run())
