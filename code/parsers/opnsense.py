"""
Parser for OPNsense filter rules export.

Extracts OPNsense policy rules and maps UUID, interface, and action properties into UnifiedRule format.
"""

import html
import ipaddress
import sys
from pathlib import Path
from typing import List, Optional, Tuple
from xml.etree import ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.schema import NA, UnifiedRule
from parsers.base import BaseParser

_ACTION_MAP = {
    "pass": "allow",
    "block": "deny",
    "reject": "deny",
}

_IPVER_MAP = {
    "inet": "4",
    "inet6": "6",
    "inet46": "both",
}

# IP-layer protocol → (normalised_protocol, service_name)
_PROTO_SERVICE_MAP = {
    "icmp":  ("icmp", "ICMP-PING"),
    "icmp6": ("icmp", "ICMP-PING"),
    "esp":   ("ip",   "IPSec-ESP"),
    "gre":   ("ip",   "GRE-TUNNEL"),
}


def _text(elem: Optional[ET.Element], tag: str, default: str = "") -> str:
    child = elem.find(tag) if elem is not None else None
    if child is None:
        return default
    return (child.text or "").strip()


def _has_tag(elem: Optional[ET.Element], tag: str) -> bool:
    if elem is None:
        return False
    return elem.find(tag) is not None


def _parse_addr_block(block: Optional[ET.Element],
                      addr_map: Optional[dict] = None) -> Tuple[str, bool]:
    if block is None:
        return "any", False
    negated = _has_tag(block, "not")
    if _has_tag(block, "any"):
        return "any", negated
    addr = _text(block, "address")
    if addr:
        if addr_map and addr in addr_map:
            return addr_map[addr], negated
        return addr, negated
    net = _text(block, "network")
    if net:
        if addr_map and net in addr_map:
            return addr_map[net], negated
        return net, negated
    return "any", negated


def _compress_addr_list(entries: List[str]) -> str:
    """
    Compress a list of IP/CIDR/range strings.
    OPNsense already uses range notation in <content>, so mostly this just
    joins the space-separated tokens with commas and adds /32 to bare IPs.
    """
    result: List[str] = []
    for entry in entries:
        entry = entry.strip()
        if not entry:
            continue
        # Bare IP without mask or dash → add /32
        if "/" not in entry and "-" not in entry:
            try:
                ipaddress.IPv4Address(entry)
                entry = entry + "/32"
            except ValueError:
                pass
        result.append(entry)
    return ",".join(result) if result else "any"


def _build_alias_maps(root: ET.Element) -> Tuple[dict, dict]:
    """
    Build addr_map and port_map from OPNsense alias definitions.

    Aliases live at: <opnsense><OPNsense><Firewall><Alias><aliases>
    Each alias uses <content> (space-separated) instead of <address>.

    - type=host    : bare IPs or ranges in <content>  → addr_map
    - type=network : CIDR or ranges in <content>      → addr_map
    - type=port    : port number or range in <content> → port_map
    """
    addr_map: dict = {}
    port_map: dict = {}

    aliases_elem = root.find("OPNsense/Firewall/Alias/aliases")
    if aliases_elem is None:
        return addr_map, port_map

    for alias in aliases_elem.findall("alias"):
        name = _text(alias, "name")
        typ = _text(alias, "type")
        content = _text(alias, "content")

        if not name:
            continue

        if typ == "port":
            # OPNsense uses colon for port ranges (e.g. "1024:65535")
            port_map[name] = content.replace(":", "-") if content else name
        elif typ in ("host", "network"):
            entries = content.split() if content else []
            addr_map[name] = _compress_addr_list(entries) if entries else name
        else:
            addr_map[name] = content if content else name

    return addr_map, port_map


class OPNsenseParser(BaseParser):
    """Parse OPNsense filter rules into UnifiedRule instances."""

    vendor = "opnsense"

    def parse(self) -> List[UnifiedRule]:
        tree = ET.parse(self.filepath)
        root = tree.getroot()

        addr_map, port_map = _build_alias_maps(root)

        rules: List[UnifiedRule] = []
        seq = 0

        filter_elem = root.find("filter")
        if filter_elem is None:
            return rules

        for rule_elem in filter_elem.findall("rule"):
            seq += 1

            # ── identity ────────────────────────────────────────────────────
            uuid = rule_elem.get("uuid", f"seq_{seq}")
            descr = html.unescape(_text(rule_elem, "descr")).strip()

            # ── state ───────────────────────────────────────────────────────
            disabled_val = _text(rule_elem, "disabled", "0")
            enabled = disabled_val != "1"

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
            dst_zone = NA
            dst_iface = NA

            # ── source ──────────────────────────────────────────────────────
            src_block = rule_elem.find("source")
            src_addr, src_addr_neg = _parse_addr_block(src_block, addr_map)
            # src_port: resolve alias if present; absent → "any"
            raw_src_port = _text(src_block, "port") if src_block is not None else ""
            if raw_src_port:
                src_port = port_map.get(raw_src_port, raw_src_port)
            else:
                src_port = "any"
            src_port_neg = False

            # ── destination ─────────────────────────────────────────────────
            dst_block = rule_elem.find("destination")
            dst_addr, dst_addr_neg = _parse_addr_block(dst_block, addr_map)
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

            # ── log ─────────────────────────────────────────────────────────
            log = _text(rule_elem, "log", "0") == "1"

            # ── schedule ────────────────────────────────────────────────────
            sched_val = _text(rule_elem, "sched")
            schedule = sched_val if sched_val else "always"

            rules.append(
                UnifiedRule(
                    vendor=self.vendor,
                    rule_id=uuid,
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
                    nat_related=NA,  # OPNsense has no NAT in filter rules
                    app_id=NA,
                    user_id=NA,
                    icmp_type=NA,
                    notes="",
                )
            )

        return rules
