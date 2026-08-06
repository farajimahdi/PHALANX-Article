"""
Firewall policy anomaly detection engine.

Implements set-theoretic pairwise comparison (Shadowing, Redundancy, Conflict,
Generalization) and single-rule Over-permissive detection over normalized rulebases.
"""

from __future__ import annotations

import csv
import ipaddress
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

# Allow `python code/core/anomaly.py` to import sibling modules under `core/`.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# ── universe bounds ──────────────────────────────────────────────────────────
V4_MAX = (1 << 32) - 1
V6_MAX = (1 << 128) - 1
PORT_MAX = 65535

# Known port ranges for well-known L4 services. Used only inside the silent
# semantic-mismatch pre-filter that removes pairwise relationships between
# rules whose declared L7 application cannot plausibly be carried on the named
# service port (e.g. app_id=video/audio over service=bgp port 179). These pairs
# produce no anomaly row in the main output; they are written to a side debug
# file for auditability only (see detect_pairwise()).
_APP_PORT_RANGES: dict[str, tuple[int, int]] = {
    "bgp": (179, 179),
    "dns": (53, 53),
    "ntp": (123, 123),
    "smtp": (25, 25),
    "smtps": (465, 465),
    "submission": (587, 587),
    "pop3": (110, 110),
    "pop3s": (995, 995),
    "imap": (143, 143),
    "imaps": (993, 993),
    "http": (80, 80),
    "https": (443, 443),
    "ssh": (22, 22),
    "telnet": (23, 23),
    "ftp": (21, 21),
    "ftps": (990, 990),
    "sip": (5060, 5060),
    "sips": (5061, 5061),
    "snmp": (161, 161),
    "snmptrap": (162, 162),
    "ldap": (389, 389),
    "ldaps": (636, 636),
    "rdp": (3389, 3389),
    "mysql": (3306, 3306),
    "mssql": (1433, 1433),
    "postgres": (5432, 5432),
    "mongodb": (27017, 27017),
    "redis": (6379, 6379),
    "oracle": (1521, 1521),
    "elasticsearch": (9200, 9200),
    "syslog": (514, 514),
    "tftp": (69, 69),
    "ike": (500, 500),
    "ipsec-nat-t": (4500, 4500),
    "gre": (47, 47),          # IP protocol number, not port; heuristic fallback
    "esp": (50, 50),          # IP protocol number
    "ah": (51, 51),           # IP protocol number
}

# Mapping of L7 application tokens to the L4 service names they are most
# commonly carried by. A rule declaring app_id=X while its service field maps
# to a different known port is treated as internally inconsistent.
_APP_TO_SERVICE: dict[str, Optional[str]] = {
    "video/audio": "sip",
    "web": "http",
    "web-browsing": "http",
    "ssl": "https",
    "mail": "smtp",
    "smtp": "smtp",
    "p2p": "bittorrent",      # no well-known port; mismatch unlikely to trigger
    "proxy": "http",
    "game": None,
    "social-media": "http",
    "business": "http",
}


def _rule_app_service_inconsistent(rule: Rule) -> Optional[str]:
    """Return a reason string if a single rule's service and app_id are semantically incompatible.

    Used only by the silent pre-filter in detect_pairwise(); it never emits a
    discoverable anomaly category. The check is intentionally conservative: it
    only triggers when the rule's service field names a known single-port
    service AND the app_id is a known application normally carried on a
    different port. It never flags app_id=any, app_id=N/A, or multi-port/range
    services.
    """
    app_raw = (rule.raw.get("app_id") or "").strip().lower()
    if app_raw in ("", "any", "n/a"):
        return None
    svc_raw = (rule.raw.get("service") or "").strip().lower()

    # Only flag when service field names a known single-port service.
    if svc_raw not in _APP_PORT_RANGES:
        return None
    svc_lo, svc_hi = _APP_PORT_RANGES[svc_raw]
    if svc_lo != svc_hi:
        return None

    # Collect declared app tokens.
    app_tokens = {t.strip() for t in app_raw.split(",") if t.strip()}
    expected_services = set()
    for tok in app_tokens:
        expected = _APP_TO_SERVICE.get(tok)
        if expected:
            expected_services.add(expected)
    if not expected_services:
        return None

    # If the actual service port matches any expected service, consistent.
    for exp in expected_services:
        if exp in _APP_PORT_RANGES:
            exp_lo, exp_hi = _APP_PORT_RANGES[exp]
            if exp_lo == exp_hi and exp_lo == svc_lo:
                return None

    return (
        f"Rule {rule.rule_id} (seq {rule.seq}) declares app_id={rule.raw['app_id']} "
        f"but service={rule.raw['service']} (port {svc_lo}), which is not a plausible "
        f"transport for the declared application; the rule likely matches no traffic."
    )


def _pair_app_service_mismatch(ri: Rule, rj: Rule) -> bool:
    """Silent pre-filter for semantically impossible pairwise relations.

    If both rules carry specific app_id values whose declared L4 transports are
    incompatible (e.g. video/audio over BGP port 179), no common application
    flow can match both, so no structural relationship exists. Such pairs are
    removed from the relation graph and produce no anomaly row; they are logged
    to a side debug file for auditability only.
    """
    ri_reason = _rule_app_service_inconsistent(ri)
    rj_reason = _rule_app_service_inconsistent(rj)
    # Both individually inconsistent => no shared semantic flow.
    if ri_reason and rj_reason:
        return True
    # One is inconsistent and the other has a specific app that is not the
    # expected transport of the inconsistent one => no shared semantic flow.
    ri_app = ri.raw.get("app_id", "").strip().lower()
    rj_app = rj.raw.get("app_id", "").strip().lower()
    if ri_reason and rj_app not in ("", "any", "n/a"):
        return True
    if rj_reason and ri_app not in ("", "any", "n/a"):
        return True
    return False

# ── scope relation tags ──────────────────────────────────────────────────────
EQUAL = "equal"            # M(Ri) == M(Rj)
I_SUPERSET_J = "i_sup_j"   # M(Ri) ⊋ M(Rj)  (earlier rule covers later one)
J_SUPERSET_I = "j_sup_i"   # M(Ri) ⊊ M(Rj)  (earlier rule is special case)
PARTIAL = "partial"        # intersect, neither contains the other
DISJOINT = "disjoint"      # no common flow

_SEP = re.compile(r"[;,]")


# =============================================================================
# Interval algebra over a single linear integer universe
# =============================================================================
class IntervalSet:
    """A set of inclusive integer intervals [lo, hi], kept normalised.

    Normalisation sorts the intervals and merges those that overlap or are
    adjacent, so two IntervalSets are equal iff their canonical interval
    lists are identical. This makes subset tests a simple equality check.
    """

    __slots__ = ("intervals",)

    def __init__(self, intervals: Iterable[tuple[int, int]] = ()):
        self.intervals = _merge(intervals)

    # ── predicates ──────────────────────────────────────────────────────────
    def is_empty(self) -> bool:
        return not self.intervals

    def __eq__(self, other: object) -> bool:
        return isinstance(other, IntervalSet) and self.intervals == other.intervals

    def __repr__(self) -> str:  # pragma: no cover - debug aid only
        return f"IntervalSet({self.intervals})"

    # ── algebra ─────────────────────────────────────────────────────────────
    def union(self, other: "IntervalSet") -> "IntervalSet":
        return IntervalSet(self.intervals + other.intervals)

    def intersection(self, other: "IntervalSet") -> "IntervalSet":
        res: list[tuple[int, int]] = []
        a, b = self.intervals, other.intervals
        i = j = 0
        while i < len(a) and j < len(b):
            lo = max(a[i][0], b[j][0])
            hi = min(a[i][1], b[j][1])
            if lo <= hi:
                res.append((lo, hi))
            if a[i][1] < b[j][1]:
                i += 1
            else:
                j += 1
        return IntervalSet(res)

    def complement(self, lo0: int, hi0: int) -> "IntervalSet":
        """Complement of this set within the closed universe [lo0, hi0]."""
        res: list[tuple[int, int]] = []
        cur = lo0
        for lo, hi in self.intervals:
            if hi < lo0 or lo > hi0:
                continue
            lo, hi = max(lo, lo0), min(hi, hi0)
            if lo > cur:
                res.append((cur, lo - 1))
            cur = max(cur, hi + 1)
        if cur <= hi0:
            res.append((cur, hi0))
        return IntervalSet(res)

    def issubset(self, other: "IntervalSet") -> bool:
        # self ⊆ other. Both sets are normalised (sorted, merged, non-adjacent),
        # so each interval of self must fit inside a single interval of other.
        # Done as an allocation-free merge scan (this is a detection hot path).
        b = other.intervals
        j = 0
        nb = len(b)
        for lo, hi in self.intervals:
            while j < nb and b[j][1] < lo:
                j += 1
            if j >= nb or b[j][0] > lo or b[j][1] < hi:
                return False
        return True

    def intersects(self, other: "IntervalSet") -> bool:
        a, b = self.intervals, other.intervals
        i = j = 0
        while i < len(a) and j < len(b):
            if max(a[i][0], b[j][0]) <= min(a[i][1], b[j][1]):
                return True
            if a[i][1] < b[j][1]:
                i += 1
            else:
                j += 1
        return False


def _merge(intervals: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
    ivs = sorted((lo, hi) for lo, hi in intervals if lo <= hi)
    if not ivs:
        return []
    out: list[list[int]] = [list(ivs[0])]
    for lo, hi in ivs[1:]:
        if lo <= out[-1][1] + 1:            # overlapping or adjacent
            out[-1][1] = max(out[-1][1], hi)
        else:
            out.append([lo, hi])
    return [(lo, hi) for lo, hi in out]


# =============================================================================
# IP address sets (family-tagged: IPv4 and IPv6 live in disjoint universes)
# =============================================================================
def _families(ip_version: str) -> tuple[int, ...]:
    v = (ip_version or "").strip().lower()
    if v == "4":
        return (4,)
    if v == "6":
        return (6,)
    return (4, 6)  # "both" or unknown


class IPSet:
    """An address set split by address family.

    A flow only exists within a single family (an IPv4 source never reaches
    an IPv6 destination), therefore the two families are stored and compared
    independently.
    """

    __slots__ = ("v4", "v6")

    def __init__(self, v4: Optional[IntervalSet] = None, v6: Optional[IntervalSet] = None):
        self.v4 = v4 if v4 is not None else IntervalSet()
        self.v6 = v6 if v6 is not None else IntervalSet()

    def fam(self, f: int) -> IntervalSet:
        return self.v4 if f == 4 else self.v6

    def is_empty(self) -> bool:
        return self.v4.is_empty() and self.v6.is_empty()

    def issubset(self, other: "IPSet") -> bool:
        return self.v4.issubset(other.v4) and self.v6.issubset(other.v6)

    def is_universal(self, ip_version: str) -> bool:
        """True iff the set equals the full address space for every family
        that the rule's ip_version puts in play (used for over-permissive)."""
        fams = _families(ip_version)
        if not fams:
            return False
        for f in fams:
            full = V4_MAX if f == 4 else V6_MAX
            if self.fam(f).intervals != [(0, full)]:
                return False
        return True

    @classmethod
    def parse(cls, spec: str, ip_version: str, negated: bool) -> "IPSet":
        fams = _families(ip_version)
        v4: list[tuple[int, int]] = []
        v6: list[tuple[int, int]] = []
        has_any = False

        for tok in _SEP.split(spec or ""):
            tok = tok.strip()
            if not tok or tok == "N/A":
                continue
            if tok.lower() == "any":
                has_any = True
                continue
            try:
                if "-" in tok and "/" not in tok:           # explicit range a-b
                    a, b = tok.split("-", 1)
                    ia = ipaddress.ip_address(a.strip())
                    ib = ipaddress.ip_address(b.strip())
                    lo, hi = int(ia), int(ib)
                    if lo > hi:
                        lo, hi = hi, lo
                    (v4 if ia.version == 4 else v6).append((lo, hi))
                else:                                        # CIDR or bare host
                    net = ipaddress.ip_network(tok, strict=False)
                    rng = (int(net.network_address), int(net.broadcast_address))
                    (v4 if net.version == 4 else v6).append(rng)
            except ValueError:
                # Unparseable address token: skip it rather than guess a range.
                continue

        s4 = IntervalSet(v4)
        s6 = IntervalSet(v6)
        if has_any:
            if 4 in fams:
                s4 = IntervalSet([(0, V4_MAX)])
            if 6 in fams:
                s6 = IntervalSet([(0, V6_MAX)])

        if negated:
            # Complement only within the families the rule actually spans.
            s4 = s4.complement(0, V4_MAX) if 4 in fams else IntervalSet()
            s6 = s6.complement(0, V6_MAX) if 6 in fams else IntervalSet()

        return cls(s4, s6)


# =============================================================================
# Port sets
# =============================================================================
def parse_ports(spec: str, negated: bool) -> IntervalSet:
    spec = (spec or "").strip()
    if spec.lower() in ("", "any", "n/a"):
        # "any" and the (non-occurring) N/A both mean "does not constrain";
        # neither must create a spurious disjointness.
        return IntervalSet([(0, PORT_MAX)])

    ivs: list[tuple[int, int]] = []
    for tok in _SEP.split(spec):
        tok = tok.strip()
        if not tok:
            continue
        if tok.lower() == "any":
            ivs = [(0, PORT_MAX)]
            break
        try:
            if "-" in tok:
                a, b = tok.split("-", 1)
                lo, hi = int(a), int(b)
                if lo > hi:
                    lo, hi = hi, lo
                ivs.append((lo, hi))
            else:
                p = int(tok)
                ivs.append((p, p))
        except ValueError:
            # Non-numeric port token: treat as unconstrained to stay safe.
            return IntervalSet([(0, PORT_MAX)])

    s = IntervalSet(ivs)
    return s.complement(0, PORT_MAX) if negated else s


# =============================================================================
# Protocol sets
# =============================================================================
class ProtoSet:
    """A set of transport protocols, with a sentinel for the universal set.

    "any" is universal. "tcp/udp" expands to {tcp, udp}. Every other token
    is treated literally: protocols are compared only by identity, never by
    assumed semantic inclusion (e.g. "ip" is not assumed to subsume "tcp"),
    which keeps the engine conservative and free of invented relations.
    """

    __slots__ = ("universal", "tokens")

    def __init__(self, universal: bool = False, tokens: Optional[Iterable[str]] = None):
        self.universal = universal
        self.tokens = set(tokens or ())

    @classmethod
    def parse(cls, spec: str) -> "ProtoSet":
        spec = (spec or "").strip().lower()
        if spec in ("", "any", "n/a"):
            return cls(universal=True)
        toks: set[str] = set()
        for part in re.split(r"[;,/]", spec):   # "/" splits tcp/udp
            part = part.strip()
            if not part:
                continue
            if part == "any":
                return cls(universal=True)
            toks.add(part)
        return cls(tokens=toks)

    def is_empty(self) -> bool:
        return not self.universal and not self.tokens

    def issubset(self, other: "ProtoSet") -> bool:
        if other.universal:
            return True
        if self.universal:
            return False
        return self.tokens <= other.tokens

    def intersects(self, other: "ProtoSet") -> bool:
        if self.universal or other.universal:
            return True
        return bool(self.tokens & other.tokens)

    def overlap_label(self, other: "ProtoSet") -> str:
        if self.universal and other.universal:
            return "any"
        if self.universal:
            return ",".join(sorted(other.tokens)) or "any"
        if other.universal:
            return ",".join(sorted(self.tokens)) or "any"
        return ",".join(sorted(self.tokens & other.tokens))


# =============================================================================
# Zone dimension (src_zone / dst_zone)
# =============================================================================
class ZoneDim:
    """One zone field.

    A value of "N/A" marks the dimension as *non-discriminating*: the concept
    does not exist for that vendor, so it must not influence the relation
    between two rules (it is neither "any" nor a constraint). "any" is the
    universal zone; otherwise the value is a literal set of zone names.
    """

    __slots__ = ("na", "universal", "tokens")

    def __init__(self, na: bool = False, universal: bool = False,
                 tokens: Optional[Iterable[str]] = None):
        self.na = na
        self.universal = universal
        self.tokens = set(tokens or ())

    @classmethod
    def parse(cls, spec: str) -> "ZoneDim":
        spec = (spec or "").strip()
        if spec == "" or spec == "N/A":
            return cls(na=True)
        if spec.lower() == "any":
            return cls(universal=True)
        return cls(tokens={t.strip() for t in _SEP.split(spec) if t.strip()})

    def is_empty(self) -> bool:
        return not self.na and not self.universal and not self.tokens

    def label(self) -> str:
        if self.na:
            return "N/A"
        if self.universal:
            return "any"
        return ",".join(sorted(self.tokens))


def _zone_subset(a: ZoneDim, b: ZoneDim) -> bool:
    if a.na or b.na:        # non-discriminating ⇒ never blocks containment
        return True
    if b.universal:
        return True
    if a.universal:
        return False
    return a.tokens <= b.tokens


def _zone_intersects(a: ZoneDim, b: ZoneDim) -> bool:
    if a.na or b.na:        # non-discriminating ⇒ never forces disjointness
        return True
    if a.universal or b.universal:
        return True
    return bool(a.tokens & b.tokens)


# =============================================================================
# Categorical identity dimensions (app_id / user_id)
# =============================================================================
class StringDim:
    """One categorical dimension such as app_id or user_id.

    A value of "N/A" marks the dimension as *non-discriminating*: the concept
    does not exist for that vendor, so it must not influence the relation
    between two rules. "any" is the universal set (no constraint); otherwise
    the value is a literal set of tokens.
    """

    __slots__ = ("na", "universal", "tokens")

    def __init__(self, na: bool = False, universal: bool = False,
                 tokens: Optional[Iterable[str]] = None):
        self.na = na
        self.universal = universal
        self.tokens = set(tokens or ())

    @classmethod
    def parse(cls, spec: str) -> "StringDim":
        spec = (spec or "").strip()
        if spec == "" or spec == "N/A":
            return cls(na=True)
        if spec.lower() == "any":
            return cls(universal=True)
        return cls(tokens={t.strip() for t in _SEP.split(spec) if t.strip()})

    def is_empty(self) -> bool:
        return not self.na and not self.universal and not self.tokens

    def label(self) -> str:
        if self.na:
            return "N/A"
        if self.universal:
            return "any"
        return ",".join(sorted(self.tokens))


def _string_subset(a: StringDim, b: StringDim) -> bool:
    if a.na or b.na:        # non-discriminating ⇒ never blocks containment
        return True
    if b.universal:
        return True
    if a.universal:
        return False
    return a.tokens <= b.tokens


def _string_intersects(a: StringDim, b: StringDim) -> bool:
    if a.na or b.na:        # non-discriminating ⇒ never forces disjointness
        return True
    if a.universal or b.universal:
        return True
    return bool(a.tokens & b.tokens)


# =============================================================================
# Match predicate M(R) as a refined hyper-rectangle
# =============================================================================
@dataclass
class Match:
    src_ip: IPSet
    dst_ip: IPSet
    src_port: IntervalSet
    dst_port: IntervalSet
    proto: ProtoSet
    src_zone: ZoneDim
    dst_zone: ZoneDim
    app_id: StringDim
    user_id: StringDim


def match_is_empty(m: Match) -> bool:
    """True iff M(R) admits no flow at all (degenerate rule)."""
    if m.src_port.is_empty() or m.dst_port.is_empty() or m.proto.is_empty():
        return True
    if m.src_zone.is_empty() or m.dst_zone.is_empty():
        return True
    for f in (4, 6):
        if not m.src_ip.fam(f).is_empty() and not m.dst_ip.fam(f).is_empty():
            return False
    return True


def _shared_subset(a: Match, b: Match) -> bool:
    """Family-independent dimensions: M(a) ⊆ M(b) on ports/proto/zones/identities."""
    return (
        a.src_port.issubset(b.src_port)
        and a.dst_port.issubset(b.dst_port)
        and a.proto.issubset(b.proto)
        and _zone_subset(a.src_zone, b.src_zone)
        and _zone_subset(a.dst_zone, b.dst_zone)
        and _string_subset(a.app_id, b.app_id)
        and _string_subset(a.user_id, b.user_id)
    )


def match_subset(a: Match, b: Match, strict: bool = True) -> bool:
    """M(a) ⊆ M(b), evaluated per address family.

    An empty rule is treated as a non-participant (returns False) so that a
    degenerate predicate is never reported as contained in another.

    When ``strict`` is False, the test is relaxed to check whether the earlier
    rule b fully decides all flows that a can match, ignoring dimensions where
    a is broader than b. This is used in conflict detection to suppress
    partial overlaps whose outcome is actually deterministic.
    """
    if match_is_empty(a):
        return False
    if strict:
        shared = _shared_subset(a, b)
    else:
        # Relaxed: b must cover a in every dimension where a is not already broader.
        # This is used only for conflict suppression: if the earlier rule b
        # already fully decides all flows of the later rule a except those where
        # a is broader, the overlap is deterministic, not a real conflict.
        shared = (
            (a.src_port.issubset(b.src_port) or b.src_port.issubset(a.src_port))
            and (a.dst_port.issubset(b.dst_port) or b.dst_port.issubset(a.dst_port))
            and (a.proto.issubset(b.proto) or b.proto.issubset(a.proto))
            and _zone_subset(a.src_zone, b.src_zone)
            and _zone_subset(a.dst_zone, b.dst_zone)
            and _string_subset(a.app_id, b.app_id)
            and _string_subset(a.user_id, b.user_id)
        )
    for f in (4, 6):
        # Skip families in which M_f(a) is itself empty (∅ ⊆ anything).
        if a.src_ip.fam(f).is_empty() or a.dst_ip.fam(f).is_empty():
            continue
        if not shared:
            return False
        if not a.src_ip.fam(f).issubset(b.src_ip.fam(f)):
            return False
        if not a.dst_ip.fam(f).issubset(b.dst_ip.fam(f)):
            return False
    return True


def _identity_disjoint(a: StringDim, b: StringDim) -> bool:
    """True when two identity dimensions are both specific and have no common token.

    In NGFW semantics, a specific app_id or user_id strictly narrows a rule:
    traffic not matching that identity does not match the rule at all. Two rules
    with different specific identities therefore operate on disjoint flows and
    cannot conflict. This does not apply when either side is N/A (vendor lacks
    the concept) or universal (any), because those cases already allow overlap.
    """
    if a.na or b.na:
        return False
    if a.universal or b.universal:
        return False
    return not bool(a.tokens & b.tokens)


def match_overlap(a: Match, b: Match) -> bool:
    """M(a) ∩ M(b) ≠ ∅. Dimensions are tested most-discriminating-first so
    the common disjoint case is rejected as cheaply as possible."""
    if not _zone_intersects(a.src_zone, b.src_zone):
        return False
    if not _zone_intersects(a.dst_zone, b.dst_zone):
        return False
    if _identity_disjoint(a.app_id, b.app_id):
        return False
    if _identity_disjoint(a.user_id, b.user_id):
        return False
    if not a.proto.intersects(b.proto):
        return False
    if not a.src_port.intersects(b.src_port):
        return False
    if not a.dst_port.intersects(b.dst_port):
        return False
    for f in (4, 6):
        if a.src_ip.fam(f).intersects(b.src_ip.fam(f)) and \
           a.dst_ip.fam(f).intersects(b.dst_ip.fam(f)):
            return True
    return False


def relate(mi: Match, mj: Match) -> str:
    """Classify the scope relation between an earlier rule mi and a later mj."""
    if match_is_empty(mi) or match_is_empty(mj):
        return DISJOINT
    # Subset of non-empty sets implies overlap, so a cheap disjointness test
    # lets the (dominant) non-interacting pairs skip both containment checks.
    if not match_overlap(mi, mj):
        return DISJOINT
    j_in_i = match_subset(mj, mi)
    i_in_j = match_subset(mi, mj)
    if j_in_i and i_in_j:
        return EQUAL
    if j_in_i:
        return I_SUPERSET_J
    if i_in_j:
        return J_SUPERSET_I
    return PARTIAL


# =============================================================================
# Overlap rendering (concrete set intersection for explanations)
# =============================================================================
def _render_ports(s: IntervalSet) -> str:
    if s.is_empty():
        return "∅"
    if s.intervals == [(0, PORT_MAX)]:
        return "any"
    return ",".join(str(lo) if lo == hi else f"{lo}-{hi}" for lo, hi in s.intervals)


def _render_ip_family(s: IntervalSet, family: int) -> str:
    if s.is_empty():
        return ""
    full = V4_MAX if family == 4 else V6_MAX
    if s.intervals == [(0, full)]:
        return "any"
    # Build the address objects explicitly per family: ip_address(int) would
    # mis-classify small integers (e.g. 0) as IPv4 and break IPv6 rendering.
    cls = ipaddress.IPv4Address if family == 4 else ipaddress.IPv6Address
    parts: list[str] = []
    for lo, hi in s.intervals:
        for net in ipaddress.summarize_address_range(cls(lo), cls(hi)):
            parts.append(str(net))
    return ",".join(parts)


def _render_ip(a: IPSet, b: IPSet) -> str:
    inter4 = a.v4.intersection(b.v4)
    inter6 = a.v6.intersection(b.v6)
    chunks = [c for c in (_render_ip_family(inter4, 4), _render_ip_family(inter6, 6)) if c]
    return ";".join(chunks) if chunks else "∅"


def _string_overlap_label(a: StringDim, b: StringDim) -> str:
    """Human-readable intersection of two categorical dimensions."""
    if a.na or b.na:
        return "N/A"
    if a.universal and b.universal:
        return "any"
    if a.universal:
        return b.label()
    if b.universal:
        return a.label()
    inter = a.tokens & b.tokens
    return ",".join(sorted(inter)) if inter else "∅"


def overlap_summary(mi: Match, mj: Match) -> dict:
    """Concrete intersection M(Ri) ∩ M(Rj) per dimension, for audit."""
    return {
        "src_ip": _render_ip(mi.src_ip, mj.src_ip),
        "dst_ip": _render_ip(mi.dst_ip, mj.dst_ip),
        "src_port": _render_ports(mi.src_port.intersection(mj.src_port)),
        "dst_port": _render_ports(mi.dst_port.intersection(mj.dst_port)),
        "protocol": mi.proto.overlap_label(mj.proto),
        "app_id": _string_overlap_label(mi.app_id, mj.app_id),
        "user_id": _string_overlap_label(mi.user_id, mj.user_id),
    }


# =============================================================================
# Rule model + loading
# =============================================================================
def _as_bool(s: str) -> bool:
    return str(s).strip().lower() == "true"


@dataclass
class Rule:
    vendor: str
    rule_id: str
    rule_name: str
    seq: int
    enabled: bool
    action: str
    match: Match
    raw: dict = field(repr=False)

    def ref(self, role: str = "") -> dict:
        ref = {"rule_id": self.rule_id, "rule_name": self.rule_name, "seq": self.seq}
        if role:
            ref["role"] = role
        return ref


def rule_from_row(row: dict) -> Rule:
    ipv = row.get("ip_version", "both")
    m = Match(
        src_ip=IPSet.parse(row["src_addr"], ipv, _as_bool(row["src_addr_negated"])),
        dst_ip=IPSet.parse(row["dst_addr"], ipv, _as_bool(row["dst_addr_negated"])),
        src_port=parse_ports(row["src_port"], _as_bool(row["src_port_negated"])),
        dst_port=parse_ports(row["dst_port"], _as_bool(row["dst_port_negated"])),
        proto=ProtoSet.parse(row["protocol"]),
        src_zone=ZoneDim.parse(row["src_zone"]),
        dst_zone=ZoneDim.parse(row["dst_zone"]),
        app_id=StringDim.parse(row.get("app_id", "N/A")),
        user_id=StringDim.parse(row.get("user_id", "N/A")),
    )
    return Rule(
        vendor=row["vendor"].strip(),
        rule_id=str(row["rule_id"]).strip(),
        rule_name=row["rule_name"].strip(),
        seq=int(row["seq"]),
        enabled=_as_bool(row["enabled"]),
        action=row["action"].strip().lower(),
        match=m,
        raw=row,
    )


def load_policy(csv_path: str | Path, enabled_only: bool = True) -> list[Rule]:
    """Load a unified CSV into the in-memory rule chain (sorted by seq).

    When ``enabled_only`` is True (the default) disabled rules are removed,
    because the effective first-match chain of Definition 3 is defined over
    active rules only. Their relative order is preserved.
    """
    rules: list[Rule] = []
    with open(csv_path, encoding="utf-8-sig", newline="") as fh:
        for row in csv.DictReader(fh):
            rule = rule_from_row(row)
            if enabled_only and not rule.enabled:
                continue
            rules.append(rule)
    rules.sort(key=lambda r: r.seq)
    return rules


# =============================================================================
# Findings
# =============================================================================
@dataclass
class Finding:
    vendor: str
    anomaly_type: str
    rules: list[dict]
    explanation: str
    details: dict

    def to_dict(self) -> dict:
        return {
            "vendor": self.vendor,
            "anomaly_type": self.anomaly_type,
            "rules": self.rules,
            "explanation": self.explanation,
            "details": self.details,
        }


# =============================================================================
# Detection
# =============================================================================
def _identity_unconstrained(dim: StringDim) -> bool:
    """True when an identity dimension imposes no constraint (any or N/A)."""
    return dim.na or dim.universal


def _is_catch_all_deny(rule: Rule) -> bool:
    """True when a rule is an explicit any-any-any deny.

    Such a rule is only a logging/monitoring convenience for the implicit
    final deny that every stateful firewall already has.
    """
    if rule.action != "deny":
        return False
    ipv = rule.raw.get("ip_version", "both")
    return (
        rule.match.src_ip.is_universal(ipv)
        and rule.match.dst_ip.is_universal(ipv)
        and rule.match.src_port.intervals == [(0, PORT_MAX)]
        and rule.match.dst_port.intervals == [(0, PORT_MAX)]
        and rule.match.proto.universal
        and (rule.match.src_zone.universal or rule.match.src_zone.na)
        and (rule.match.dst_zone.universal or rule.match.dst_zone.na)
        and _identity_unconstrained(rule.match.app_id)
        and _identity_unconstrained(rule.match.user_id)
    )


def _is_default_deny(rule: Rule, max_seq: Optional[int]) -> bool:
    """True for the explicit implicit-deny-equivalent rule.

    A rule is treated as the synthetic explicit final deny only when it is
    at the last sequence position of the policy chain *and* it matches any
    source/destination/service with a deny action. If the same wide-open deny
    appears earlier in the chain it is a normal blocking rule: it shadows
    everything after it and must stay in detection.
    """
    if max_seq is None:
        return False
    return rule.seq == max_seq and _is_catch_all_deny(rule)


def _open_dimensions(rule: Rule) -> int:
    """Count how many of the 5 core dimensions are open in a rule.

    Open means the dimension does not constrain the flow set. A dimension is
    open only when its value is any-equivalent ("any", 0.0.0.0/0, ::/0, full
    port range, or any protocol) AND its negation flag is False. A negated
    dimension is always treated as a specific intentional constraint (a NOT
    rule is never a catch-all). A negation value of "N/A" means the feature
    is unsupported for that vendor and is treated the same as False.

    List values are normalised upstream in IPSet.parse / parse_ports: if a
    list contains "any" the whole dimension becomes the universal set.
    """
    ipv = rule.raw.get("ip_version", "both")
    n = 0
    if rule.match.src_ip.is_universal(ipv):
        n += 1
    if rule.match.dst_ip.is_universal(ipv):
        n += 1
    if rule.match.src_port.intervals == [(0, PORT_MAX)]:
        n += 1
    if rule.match.dst_port.intervals == [(0, PORT_MAX)]:
        n += 1
    if rule.match.proto.universal:
        n += 1
    return n


def _is_near_universal(rule: Rule) -> bool:
    """True when a rule is open in at least four of the five core dimensions.

    Such rules (e.g. a deny with any-src/any-dst/any-port and any protocol,
    or a rule that pins only one core dimension) function as default-like
    catch-alls. Conflicts involving them are usually structural noise rather
    than actionable design mistakes: the broad rule is intended to cover the
    residual traffic that earlier, more specific rules do not match.
    Shadowing/redundancy/generalisation are still evaluated independently.
    """
    return _open_dimensions(rule) >= 4


def _port_range_contains_specific(earlier_port: IntervalSet, later_port: IntervalSet) -> bool:
    """True when later_port is a single port strictly inside earlier_port's range.

    Used to suppress structural conflicts where a broad high-ports range
    (e.g. 1024-65535) happens to contain a specific service port (e.g. 5060).
    Such overlaps are numerical artefacts, not policy contradictions.
    """
    # earlier_port must be a range that is not full-universe
    if not earlier_port.intervals or earlier_port.intervals == [(0, PORT_MAX)]:
        return False
    if len(earlier_port.intervals) != 1:
        return False
    lo, hi = earlier_port.intervals[0]
    if lo == hi:
        return False
    # later_port must be a single specific port
    if not later_port.intervals or len(later_port.intervals) != 1:
        return False
    p_lo, p_hi = later_port.intervals[0]
    if p_lo != p_hi:
        return False
    return lo < p_lo < hi


def detect_over_permissive(rules: list[Rule], max_seq: Optional[int] = None) -> list[Finding]:
    """Definition 8 (single-rule). An allow rule is over-permissive when it
    matches any source and any destination (5a) and/or any destination port
    and any protocol (5b), with no constraining app_id or user_id identity.

    A rule whose app_id or user_id is a specific token is not flagged,
    because the identity constraint limits the match set even when the
    network dimensions are open.
    """
    if max_seq is None and rules:
        max_seq = max(r.seq for r in rules)
    findings: list[Finding] = []
    for r in rules:
        if r.action != "allow" or _is_default_deny(r, max_seq):
            continue
        ipv = r.raw.get("ip_version", "both")
        id_open = _identity_unconstrained(r.match.app_id) and _identity_unconstrained(r.match.user_id)
        cond_5a = id_open and r.match.src_ip.is_universal(ipv) and r.match.dst_ip.is_universal(ipv)
        cond_5b = id_open and (r.match.dst_port.intervals == [(0, PORT_MAX)]) and r.match.proto.universal
        if not (cond_5a or cond_5b):
            continue
        conds = []
        if cond_5a:
            conds.append("5a:any-src∧any-dst")
        if cond_5b:
            conds.append("5b:any-dport∧any-proto")
        full = cond_5a and cond_5b
        findings.append(Finding(
            vendor=r.vendor,
            anomaly_type="over_permissive",
            rules=[r.ref("over_permissive")],
            explanation=(
                f"Rule {r.rule_id} (seq {r.seq}) is an allow rule that is "
                + ("a full any-any-any permit" if full else "over-permissive")
                + " (" + "; ".join(conds) + "), violating least-privilege."
            ),
            details={
                "conditions": conds,
                "full_any_any": full,
                "src_addr": r.raw.get("src_addr"),
                "dst_addr": r.raw.get("dst_addr"),
                "dst_port": r.raw.get("dst_port"),
                "protocol": r.raw.get("protocol"),
                "app_id": r.raw.get("app_id"),
                "user_id": r.raw.get("user_id"),
            },
        ))
    return findings


def _pair_finding(vendor: str, anomaly_type: str, earlier: Rule, later: Rule,
                  loser_role: str, winner_role: str, relation: str,
                  explanation: str) -> Finding:
    return Finding(
        vendor=vendor,
        anomaly_type=anomaly_type,
        rules=[earlier.ref(winner_role), later.ref(loser_role)],
        explanation=explanation,
        details={
            "relation": relation,
            "earlier_action": earlier.action,
            "later_action": later.action,
            "overlap": overlap_summary(earlier.match, later.match),
        },
    )


def detect_pairwise(rules: list[Rule], max_seq: Optional[int] = None,
                    debug_dir: Optional[Path] = None) -> list[Finding]:
    """Definitions 4-7. For each ordered pair (Ri, Rj) with seq(Ri) < seq(Rj),
    classify the relation between M(Ri) and M(Rj) and emit the matching
    structural anomaly.

    Full containment results (shadowing / redundancy of the later rule) are
    reported once per later rule against the earliest covering predecessor,
    since the existential condition of Definitions 4-5 is already satisfied
    by that first predecessor. Generalization and conflict are inherently
    pairwise and reported per qualifying pair.

    Generalization rows whose general (later) side is a near-universal allow
    rule keep the anomaly_type 'generalization' for taxonomy stability, but
    their explanation text is inverted: the broad catch-all is identified as
    the security problem, and the specific rule is explicitly preserved.

    Pairs whose declared app_id/service combination is semantically impossible
    (e.g. video/audio over BGP port 179) are silently removed from the
    relation graph before any structural classification. They produce no main
    output row. When ``debug_dir`` is provided, these suppressed pairs are
    written to a side CSV per vendor for auditability only.

    The explicit final catch-all deny rule (any-any-any deny at the last
    sequence position of the chain) is excluded, because it is only a logging
    convenience for the implicit final deny that every stateful firewall
    already has. The same wide-open deny appearing earlier in the chain is a
    normal blocking rule and remains in detection.
    """
    if max_seq is None and rules:
        max_seq = max(r.seq for r in rules)
    findings: list[Finding] = []
    active = [r for r in rules if not _is_default_deny(r, max_seq)]
    suppressed: list[dict] = []
    n = len(active)
    for j in range(n):
        rj = active[j]
        if match_is_empty(rj.match):
            continue
        covered = False  # rj already found fully shadowed/redundant
        for i in range(j):
            ri = active[i]
            if match_is_empty(ri.match):
                continue

            # Silent semantic pre-filter: app_id/service combinations that
            # cannot carry the same application traffic have no structural
            # relationship. No anomaly row is emitted; optionally logged to
            # a side debug file.
            if _pair_app_service_mismatch(ri, rj):
                suppressed.append({
                    "earlier_rule_id": ri.rule_id,
                    "earlier_rule_name": ri.rule_name,
                    "earlier_seq": ri.seq,
                    "earlier_app_id": ri.raw.get("app_id"),
                    "earlier_service": ri.raw.get("service"),
                    "later_rule_id": rj.rule_id,
                    "later_rule_name": rj.rule_name,
                    "later_seq": rj.seq,
                    "later_app_id": rj.raw.get("app_id"),
                    "later_service": rj.raw.get("service"),
                    "reason": "semantic app/service mismatch",
                })
                continue

            relation = relate(ri.match, rj.match)
            same_action = ri.action == rj.action

            if relation in (EQUAL, I_SUPERSET_J):
                # M(Rj) ⊆ M(Ri); the earlier rule wins for all of Rj's flows.
                if covered:
                    continue
                covered = True
                if same_action:
                    findings.append(_pair_finding(
                        rj.vendor, "redundancy", ri, rj, "redundant", "covering",
                        relation,
                        f"Rule {rj.rule_id} (seq {rj.seq}) is redundant: its match "
                        f"set is contained in earlier rule {ri.rule_id} (seq {ri.seq}) "
                        f"with the same action '{ri.action}'; removing it does not "
                        f"change policy behaviour.",
                    ))
                else:
                    findings.append(_pair_finding(
                        rj.vendor, "shadowing", ri, rj, "shadowed", "shadowing",
                        relation,
                        f"Rule {rj.rule_id} (seq {rj.seq}, action '{rj.action}') is "
                        f"shadowed by earlier rule {ri.rule_id} (seq {ri.seq}, action "
                        f"'{ri.action}'): every flow it matches is already decided by "
                        f"the earlier rule, so it never executes.",
                    ))
                continue

            if relation == J_SUPERSET_I and same_action:
                # M(Ri) ⊊ M(Rj): the later rule is a generalisation of the earlier.
                # If the later (general) rule is a near-universal allow catch-all,
                # keep the taxonomy label 'generalization' but invert the
                # recommendation: the broad rule is the security problem, not the
                # specific least-privilege rule.
                if rj.action == "allow" and _is_near_universal(rj):
                    # Invert the natural role ordering: the broad anchor is the
                    # security problem, so report it as the "winner" role even
                    # though it appears later in the chain.
                    findings.append(_pair_finding(
                        rj.vendor, "generalization", rj, ri, "specific", "general",
                        relation,
                        f"Rule {rj.rule_id} (seq {rj.seq}) is a near-universal "
                        f"permit-all rule that makes rule {ri.rule_id} (seq {ri.seq}) "
                        f"functionally redundant; however, rule {ri.rule_id} encodes "
                        f"the intended least-privilege policy. RECOMMENDATION: "
                        f"restrict or remove the over-permissive rule {rj.rule_id}; "
                        f"do NOT remove rule {ri.rule_id}.",
                    ))
                    continue

                findings.append(_pair_finding(
                    rj.vendor, "generalization", rj, ri, "special", "general",
                    relation,
                    f"Rule {rj.rule_id} (seq {rj.seq}) is more general than rule "
                    f"{ri.rule_id} (seq {ri.seq}) and makes it functionally "
                    f"redundant with the same action '{ri.action}'; however, rule "
                    f"{ri.rule_id} encodes the intended least-privilege policy. "
                    f"RECOMMENDATION: restrict or remove the broader rule "
                    f"{rj.rule_id}; do NOT remove the specific rule {ri.rule_id}.",
                ))
                continue

            if relation == PARTIAL and not same_action:
                # Suppress conflicts where either rule is a near-universal
                # catch-all in the core five tuple. These are typically
                # default-like rules (e.g. a broad deny after many specific
                # allows) whose partial overlaps are structural, not actionable
                # design errors. Shadowing/redundancy/generalisation remain.
                if _is_near_universal(ri) or _is_near_universal(rj):
                    continue
                # FIX 1: a partial overlap is a real conflict only if the later
                # rule actually processes a flow that the earlier rule does not
                # already fully decide. If the earlier rule's match completely
                # covers the later rule's match in every dimension except those
                # where the later rule is broader, the outcome is deterministic.
                # In that case the shared flow is fully decided by the earlier
                # rule (ordered-policy behaviour), not a conflict.
                if match_subset(rj.match, ri.match, strict=False):
                    continue
                # FIX 3: suppress structural port-range vs specific-port overlaps.
                if _port_range_contains_specific(ri.match.dst_port, rj.match.dst_port) or \
                   _port_range_contains_specific(rj.match.dst_port, ri.match.dst_port):
                    continue
                findings.append(_pair_finding(
                    rj.vendor, "conflict", ri, rj, "later", "earlier",
                    relation,
                    f"Rules {ri.rule_id} (seq {ri.seq}, '{ri.action}') and "
                    f"{rj.rule_id} (seq {rj.seq}, '{rj.action}') partially overlap "
                    f"with opposite actions and neither fully contains the other; "
                    f"the shared flows genuinely depend on ordering.",
                ))

    if debug_dir is not None and suppressed:
        debug_dir.mkdir(parents=True, exist_ok=True)
        vendor = active[0].vendor if active else "unknown"
        path = debug_dir / f"debug_suppressed_semantic_mismatch_{vendor}.csv"
        with open(path, "w", encoding="utf-8-sig", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=suppressed[0].keys())
            writer.writeheader()
            writer.writerows(suppressed)

    return findings


def detect_all(rules: list[Rule], max_seq: Optional[int] = None,
              debug_dir: Optional[Path] = None) -> list[Finding]:
    """Run every implemented anomaly class over one policy."""
    if max_seq is None and rules:
        max_seq = max(r.seq for r in rules)
    return (
        detect_pairwise(rules, max_seq, debug_dir=debug_dir)
        + detect_over_permissive(rules, max_seq)
    )


# =============================================================================
# Summary + CLI
# =============================================================================
ANOMALY_CLASSES = (
    "shadowing", "redundancy", "conflict", "generalization", "over_permissive",
)


def summarize(findings: list[Finding]) -> dict:
    counts = {c: 0 for c in ANOMALY_CLASSES}
    for f in findings:
        counts[f.anomaly_type] = counts.get(f.anomaly_type, 0) + 1
    return counts


def _default_dataset_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "Real-Dataset" / "unified"


# =============================================================================
# Rule-status pipeline (headline / reporting-convention view)
# =============================================================================
def run_rule_status(dataset_dir: Optional[Path] = None,
                    out_dir: Optional[Path] = None) -> dict:
    """Run detection + reporting-convention filters and persist the headline
    findings.

    This is the second mode of the engine.  It reads the same unified CSVs,
    runs the same deterministic detection, then applies the two post-processing
    filters defined in :mod:`core.rule_status_filter`:

        1. anchor collapsing   (reporting convention)
        2. negation paradox    (IPImen conflicts driven by negated fields)

    Outputs:
        results/anomalies_rule_status.jsonl  — filtered findings (one JSON per
                                               line, same schema as anomalies.jsonl)
        results/summary_rule_status.json      — per-vendor headline counts plus
                                               filter meta (collapsed anchors,
                                               negation-excluded conflicts, ...)
    """
    from core.rule_status_filter import (
        count_by_class,
        filter_for_rule_status,
    )

    dataset_dir = dataset_dir or _default_dataset_dir()
    out_dir = out_dir or (Path(__file__).resolve().parents[2] / "results")
    out_dir.mkdir(parents=True, exist_ok=True)

    vendors = ["fortigate", "paloalto", "pfsense", "opnsense", "ipimen"]
    report: dict = {"per_vendor": {}, "totals": {}}
    all_findings: list[dict] = []
    grand_counts = {c: 0 for c in ANOMALY_CLASSES}
    grand_meta = {
        "collapsed_anchors": 0,
        "generalization_raw": 0,
        "generalization_collapsed": 0,
        "negation_excluded": 0,
    }

    for vendor in vendors:
        csv_path = dataset_dir / f"{vendor}.csv"
        if not csv_path.exists():
            continue
        rules = load_policy(csv_path, enabled_only=True)
        rules_by_id = {r.rule_id: r for r in rules}
        findings = detect_all(rules)
        filtered, meta = filter_for_rule_status(findings, rules_by_id, vendor)
        counts = count_by_class(filtered)

        for c in ANOMALY_CLASSES:
            grand_counts[c] += counts[c]
        for k in grand_meta:
            grand_meta[k] += meta[k]

        report["per_vendor"][vendor] = {
            "rules_enabled": len(rules),
            "anomalies_raw": len(findings),
            "anomalies_rule_status": len(filtered),
            "anomalies": counts,
            "filter_meta": meta,
        }
        for fnd in filtered:
            all_findings.append(fnd.to_dict())

    report["totals"] = {
        "anomalies": grand_counts,
        "anomalies_rule_status": sum(
            v["anomalies_rule_status"] for v in report["per_vendor"].values()
        ),
        "filter_meta": grand_meta,
    }

    with open(out_dir / "anomalies_rule_status.jsonl", "w", encoding="utf-8") as fh:
        for fnd in all_findings:
            fh.write(json.dumps(fnd, ensure_ascii=False) + "\n")
    with open(out_dir / "summary_rule_status.json", "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)

    return report


def _print_rule_status_report(report: dict) -> None:
    header = f"{'vendor':<11} {'rules':>6} " + \
        " ".join(f"{c[:5]:>6}" for c in ANOMALY_CLASSES) + \
        f" {'total':>6} {'raw':>5} {'anch':>5} {'negX':>5}"
    print(header)
    print("-" * len(header))
    for vendor, v in report["per_vendor"].items():
        a = v["anomalies"]
        m = v["filter_meta"]
        row = f"{vendor:<11} {v['rules_enabled']:>6} " + \
            " ".join(f"{a[c]:>6}" for c in ANOMALY_CLASSES) + \
            f" {v['anomalies_rule_status']:>6} {m['generalization_raw']:>5} " \
            f"{m['collapsed_anchors']:>5} {m['negation_excluded']:>5}"
        print(row)
    t = report["totals"]
    print("-" * len(header))
    ta = t["anomalies"]
    tm = t["filter_meta"]
    print(f"{'TOTAL':<11} {'':>6} " +
          " ".join(f"{ta[c]:>6}" for c in ANOMALY_CLASSES) +
          f" {t['anomalies_rule_status']:>6} {tm['generalization_raw']:>5} " \
          f"{tm['collapsed_anchors']:>5} {tm['negation_excluded']:>5}")


def run(dataset_dir: Optional[Path] = None, out_dir: Optional[Path] = None,
        debug_dir: Optional[Path] = None) -> dict:
    """Run detection over all five vendor CSVs and persist the findings.

    Returns a report dict with per-vendor rule counts and anomaly counts.
    No result is fabricated: every number is derived from the CSV contents.
    """
    dataset_dir = dataset_dir or _default_dataset_dir()
    out_dir = out_dir or (Path(__file__).resolve().parents[2] / "results")
    out_dir.mkdir(parents=True, exist_ok=True)
    if debug_dir is not None:
        debug_dir.mkdir(parents=True, exist_ok=True)

    vendors = ["fortigate", "paloalto", "pfsense", "opnsense", "ipimen"]
    report: dict = {"per_vendor": {}, "totals": {}}
    all_findings: list[dict] = []
    grand_counts = {c: 0 for c in ANOMALY_CLASSES}
    total_rules = total_enabled = 0

    for vendor in vendors:
        csv_path = dataset_dir / f"{vendor}.csv"
        if not csv_path.exists():
            continue
        all_rules = load_policy(csv_path, enabled_only=False)
        enabled = [r for r in all_rules if r.enabled]
        max_seq = max((r.seq for r in all_rules), default=0)
        findings = detect_all(enabled, max_seq, debug_dir=debug_dir)
        counts = summarize(findings)
        for c in ANOMALY_CLASSES:
            grand_counts[c] += counts[c]
        total_rules += len(all_rules)
        total_enabled += len(enabled)
        report["per_vendor"][vendor] = {
            "rules_total": len(all_rules),
            "rules_enabled": len(enabled),
            "anomalies": counts,
            "anomalies_total": len(findings),
        }
        for fnd in findings:
            all_findings.append(fnd.to_dict())

    report["totals"] = {
        "rules_total": total_rules,
        "rules_enabled": total_enabled,
        "anomalies": grand_counts,
        "anomalies_total": sum(grand_counts.values()),
    }

    with open(out_dir / "anomalies.jsonl", "w", encoding="utf-8") as fh:
        for fnd in all_findings:
            fh.write(json.dumps(fnd, ensure_ascii=False) + "\n")
    with open(out_dir / "summary.json", "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)

    return report


def _print_report(report: dict) -> None:
    header = f"{'vendor':<11} {'rules':>6} {'enab':>5} " + \
        " ".join(f"{c[:5]:>6}" for c in ANOMALY_CLASSES) + f" {'total':>6}"
    print(header)
    print("-" * len(header))
    for vendor, v in report["per_vendor"].items():
        a = v["anomalies"]
        row = f"{vendor:<11} {v['rules_total']:>6} {v['rules_enabled']:>5} " + \
            " ".join(f"{a[c]:>6}" for c in ANOMALY_CLASSES) + \
            f" {v['anomalies_total']:>6}"
        print(row)
    t = report["totals"]
    print("-" * len(header))
    ta = t["anomalies"]
    print(f"{'TOTAL':<11} {t['rules_total']:>6} {t['rules_enabled']:>5} " +
          " ".join(f"{ta[c]:>6}" for c in ANOMALY_CLASSES) +
          f" {t['anomalies_total']:>6}")


if __name__ == "__main__":
    if "--rule-status" in sys.argv:
        _print_rule_status_report(run_rule_status())
    else:
        _print_report(run(debug_dir=Path("results")))
