"""
Parser for pfSense filter rule definitions.

Translates pfSense interface filter rules, alias definitions, and protocol options into UnifiedRule format.
"""

import html
import ipaddress
import re
import sys
from pathlib import Path
from typing import List, Optional, Tuple
from xml.etree import ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.schema import NA, UnifiedRule
from parsers.base import BaseParser

# ── action mapping ──────────────────────────────────────────────────────────
_ACTION_MAP = {
    "pass": "allow",
    "block": "deny",
    "reject": "deny",
}

# ── ip_version mapping ──────────────────────────────────────────────────────
_IPVER_MAP = {
    "inet": "4",
    "inet6": "6",
    "inet46": "both",
}

# ── IP-layer protocol → (normalised_protocol, service_name) ────────────────
# For non-TCP/UDP protocols pf surfaces as literal protocol names.
_PROTO_SERVICE_MAP = {
    "icmp":  ("icmp", "ICMP-PING"),
    "icmp6": ("icmp", "ICMP-PING"),
    "esp":   ("ip",   "IPSec-ESP"),
    "gre":   ("ip",   "GRE-TUNNEL"),
}


def _text(elem: Optional[ET.Element], tag: str, default: str = "") -> str:
    """Return stripped text of a child element, or default if absent/empty."""
    child = elem.find(tag) if elem is not None else None
    if child is None:
        return default
    return (child.text or "").strip()


def _has_tag(elem: Optional[ET.Element], tag: str) -> bool:
    """Return True if elem has child with given tag (regardless of content)."""
    if elem is None:
        return False
    return elem.find(tag) is not None


def _compress_addr_list(entries: List[str]) -> str:
    """
    Compress a list of IP/CIDR/range strings.
    Consecutive bare IPs or /32 hosts are merged into range notation.
    e.g. ["192.168.1.1/32", "192.168.1.2/32", "10.0.0.0/8"]
         → "192.168.1.1-192.168.1.2,10.0.0.0/8"
    """
    hosts: List[ipaddress.IPv4Address] = []
    others: List[str] = []

    for entry in entries:
        entry = entry.strip()
        if not entry:
            continue
        # Bare IP (no mask, no dash range) → treat as /32 host
        if "/" not in entry and "-" not in entry:
            try:
                hosts.append(ipaddress.IPv4Address(entry))
                continue
            except ValueError:
                pass
        elif entry.endswith("/32"):
            try:
                hosts.append(ipaddress.IPv4Address(entry[:-3]))
                continue
            except ValueError:
                pass
        others.append(entry)

    hosts.sort()
    result: List[str] = []
    i = 0
    while i < len(hosts):
        start = hosts[i]
        end = hosts[i]
        while i + 1 < len(hosts) and int(hosts[i + 1]) == int(end) + 1:
            i += 1
            end = hosts[i]
        if start == end:
            result.append(str(start) + "/32")
        else:
            result.append(f"{start}-{end}")
        i += 1

    result.extend(others)
    return ",".join(result) if result else "any"


def _build_alias_maps(root: ET.Element) -> Tuple[dict, dict]:
    """
    Build two lookup maps from <aliases><alias> entries:
    - addr_map : name → resolved IP/CIDR/range string  (host / network aliases)
    - port_map : name → port number / range string     (port aliases)

    pfSense alias types:
    - host   : space-separated IPs (bare or /32) → compressed to range notation
    - network: space-separated CIDRs/ranges → compressed similarly
    - port   : port number or range stored in <address>
    """
    addr_map: dict = {}
    port_map: dict = {}

    aliases = root.find("aliases")
    if aliases is not None:
        for alias in aliases.findall("alias"):
            name = _text(alias, "name")
            typ = _text(alias, "type")
            addr_text = _text(alias, "address")

            if not name:
                continue

            if typ == "port":
                # pfSense uses ":" as port-range separator; normalise to "-"
                port_map[name] = addr_text.replace(":", "-") if addr_text else name
            elif typ in ("host", "network"):
                entries = addr_text.split() if addr_text else []
                addr_map[name] = _compress_addr_list(entries) if entries else name
            else:
                addr_map[name] = addr_text if addr_text else name

    return addr_map, port_map


def _build_alias_map(root: ET.Element) -> dict:
    """Legacy shim: returns only the address alias map (port aliases excluded)."""
    addr_map, _ = _build_alias_maps(root)
    return addr_map


def _parse_addr_block(block: Optional[ET.Element], alias_map: dict) -> tuple[str, bool]:
    """
    Parse a <source> or <destination> block.
    Returns (address_string, negated_bool).
    address_string: "any" | IP | CIDR | "IP1-IP2"
    """
    if block is None:
        return "any", False

    negated = _has_tag(block, "not")

    if _has_tag(block, "any"):
        return "any", negated

    addr = _text(block, "address")
    if addr:
        # Resolve alias name to IP(s) if present in alias_map
        resolved = alias_map.get(addr, addr)
        return resolved, negated

    # network element (pfSense uses <network> for interface-based aliases)
    net = _text(block, "network")
    if net:
        resolved = alias_map.get(net, net)
        return resolved, negated

    return "any", negated


def _parse_port(block: Optional[ET.Element]) -> str:
    """Return port / port-range string from a src/dst block, or N/A."""
    if block is None:
        return NA
    port = _text(block, "port")
    return port if port else NA


def _clean_descr(raw: str) -> str:
    """Decode HTML entities that pfSense embeds in CDATA descriptions."""
    return html.unescape(raw).strip()


class PfSenseParser(BaseParser):
    """Parse pfSense filter rules into UnifiedRule instances."""

    vendor = "pfsense"

    def parse(self) -> List[UnifiedRule]:
        tree = ET.parse(self.filepath)
        root = tree.getroot()

        # Build interface → logical name map from <interfaces> section.
        # Key = tag name (e.g. "wan", "lan", "dmz"); kept as-is for zone label.
        iface_tags: set[str] = set()
        interfaces_elem = root.find("interfaces")
        if interfaces_elem is not None:
            for iface_elem in interfaces_elem:
                iface_tags.add(iface_elem.tag.lower())

        alias_map, port_map = _build_alias_maps(root)

        rules: List[UnifiedRule] = []
        seq = 0

        filter_elem = root.find("filter")
        if filter_elem is None:
            return rules

        for rule_elem in filter_elem.findall("rule"):
            seq += 1

            # ── identity ────────────────────────────────────────────────────
            tracker = _text(rule_elem, "tracker") or f"seq_{seq}"
            descr = _clean_descr(_text(rule_elem, "descr"))

            # ── state ───────────────────────────────────────────────────────
            enabled = not _has_tag(rule_elem, "disabled")

            # ── action ──────────────────────────────────────────────────────
            raw_type = _text(rule_elem, "type", "pass").lower()
            action = _ACTION_MAP.get(raw_type, raw_type)

            # ── ip version ──────────────────────────────────────────────────
            ipproto = _text(rule_elem, "ipprotocol", "inet").lower()
            ip_version = _IPVER_MAP.get(ipproto, "4")

            # ── zone / interface ────────────────────────────────────────────
            iface = _text(rule_elem, "interface", "").lower()
            src_zone = iface if iface else NA
            src_iface = iface if iface else NA
            dst_zone = NA   # pf has no dst-zone concept
            dst_iface = NA

            # ── source ──────────────────────────────────────────────────────
            src_block = rule_elem.find("source")
            src_addr, src_addr_neg = _parse_addr_block(src_block, alias_map)
            # src_port: resolve alias if present; absent → "any"
            raw_src_port = _text(src_block, "port") if src_block is not None else ""
            if raw_src_port:
                if raw_src_port in port_map:
                    src_port = port_map[raw_src_port]
                else:
                    src_port = raw_src_port
            else:
                src_port = "any"
            src_port_neg = False

            # ── destination ─────────────────────────────────────────────────
            dst_block = rule_elem.find("destination")
            dst_addr, dst_addr_neg = _parse_addr_block(dst_block, alias_map)
            # dst_port / service: resolve alias if present; absent → "any"
            raw_dst_port = _text(dst_block, "port") if dst_block is not None else ""
            if raw_dst_port:
                if raw_dst_port in port_map:
                    service = raw_dst_port
                    dst_port = port_map[raw_dst_port]
                else:
                    service = NA
                    dst_port = raw_dst_port
            else:
                service = NA
                dst_port = "any"
            dst_port_neg = False

            # ── protocol ────────────────────────────────────────────────────
            proto_tag = rule_elem.find("protocol")
            protocol = (proto_tag.text or "any").strip().lower() if proto_tag is not None else "any"

            # When no protocol restriction and no port restriction, service = "any"
            if proto_tag is None and not raw_dst_port:
                service = "any"

            # IP-layer protocol with no port alias: derive service name
            if protocol in _PROTO_SERVICE_MAP and service == NA:
                protocol, service = _PROTO_SERVICE_MAP[protocol]
                dst_port = "any"

            # ── icmp type (informational only) ──────────────────────────────
            icmp_type = _text(rule_elem, "icmptype", NA)

            # ── log ─────────────────────────────────────────────────────────
            # Presence of <log/> (even empty) = logging enabled.
            log = _has_tag(rule_elem, "log")

            # ── schedule ────────────────────────────────────────────────────
            sched_val = _text(rule_elem, "sched")
            schedule = sched_val if sched_val else "always"

            rules.append(
                UnifiedRule(
                    vendor=self.vendor,
                    rule_id=tracker,
                    rule_name=descr,
                    seq=seq,
                    enabled=enabled,
                    action=action,
                    ip_version=ip_version,
                    src_zone=src_zone,
                    dst_zone=dst_zone,
                    src_iface=src_iface,
                    dst_iface=dst_iface,
                    src_addr=src_addr,
                    src_addr_negated=src_addr_neg,
                    src_port=src_port,
                    src_port_negated=src_port_neg,
                    dst_addr=dst_addr,
                    dst_addr_negated=dst_addr_neg,
                    dst_port=dst_port,
                    dst_port_negated=dst_port_neg,
                    protocol=protocol,
                    service=service,
                    schedule=schedule,
                    log=log,
                    nat_related=NA,  # pfSense has no NAT in filter rules
                    app_id=NA,
                    user_id=NA,
                    icmp_type=icmp_type,
                    notes="",
                )
            )

        return rules
