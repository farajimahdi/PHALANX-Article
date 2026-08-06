"""
Parser for IPImen XML policy configurations.

Parses TrafficRules, IPAccesses, IPServices, and user/app definitions into UnifiedRule format.
"""

import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.schema import NA, UnifiedRule
from parsers.base import BaseParser

_ACTION_MAP = {
    "0": "allow",
    "1": "deny",
    "2": "deny",
}

# IPImen-specific protocol number mapping.
# Protocol 0 means "any TCP/UDP" in IPImen (not HOPOPT).
# Numbers 47 and 50 are raw IP-layer protocols (GRE / ESP) → reported as "ip".
_PROTO_MAP = {
    "0": "TCP/UDP",
    "1": "icmp",
    "2": "igmp",
    "6": "tcp",
    "17": "udp",
    "47": "ip",   # GRE
    "50": "ip",   # IPSec ESP
    "89": "ospf",
    "132": "sctp",
}


def _get_vars(item: ET.Element) -> Dict[str, Optional[str]]:
    """Return {name: text} dict for all <variable> children of a listitem."""
    return {v.get("name", ""): v.text for v in item.findall("variable")}


def _build_zone_map(root: ET.Element) -> Dict[str, str]:
    """Build Id → zone Name map. Id "0" → "any"."""
    zone_map: Dict[str, str] = {"0": "any"}
    lst = root.find("list[@name='Zones']")
    if lst is not None:
        for item in lst.findall("listitem"):
            v = _get_vars(item)
            zid = v.get("Id", "")
            zname = v.get("Name", "") or ""
            if zid:
                zone_map[zid] = zname
    return zone_map


def _build_addr_map(root: ET.Element) -> Dict[str, str]:
    """
    Build Id → resolved-IP/CIDR map from IPAccesses.
    Id "0" → "any".
    Value format: "<ip_or_cidr_or_range>;type=N;desc=..."
    """
    addr_map: Dict[str, str] = {"0": "any"}
    lst = root.find("list[@name='IPAccesses']")
    if lst is not None:
        for item in lst.findall("listitem"):
            v = _get_vars(item)
            aid = v.get("Id", "")
            raw = v.get("Value", "") or ""
            if not aid:
                continue
            # Extract IP part before first semicolon
            ip_part = raw.split(";")[0].strip() if raw else ""
            if ip_part:
                # Normalize host: if no slash, add /32
                if "/" not in ip_part and "-" not in ip_part and ip_part:
                    addr_map[aid] = f"{ip_part}/32"
                else:
                    addr_map[aid] = ip_part
            else:
                addr_map[aid] = v.get("Name", aid) or aid
    return addr_map


def _build_svc_map(root: ET.Element) -> Dict[str, tuple]:
    """
    Build Id → (protocol, dst_port, name) map for IPServices.

    IPService fields:
    - Protocol: IPImen protocol number (0=TCP/UDP, 1=ICMP, 6=TCP, 17=UDP,
                47=IP/GRE, 50=IP/ESP, ...)
    - Condition: "dport==N" → TCP/UDP destination port; absent → any

    Id "0" is the built-in "any service" sentinel.
    """
    svc_map: Dict[str, tuple] = {
        "0": ("any", "any", "any"),   # IPServices:0 = any service
    }
    lst = root.find("list[@name='IPServices']")
    if lst is not None:
        for item in lst.findall("listitem"):
            v = _get_vars(item)
            sid = v.get("Id", "")
            sname = v.get("Name", "") or ""
            proto_num = v.get("Protocol", "0") or "0"
            condition = v.get("Condition", "") or ""

            if not sid:
                continue

            proto = _PROTO_MAP.get(proto_num, f"proto:{proto_num}")

            # Parse destination port from Condition field
            if "dport==" in condition:
                pm = re.search(r"dport==(\d+)", condition)
                dst_port = pm.group(1) if pm else "any"
            elif "<=dport<=" in condition:
                # Range format: N<=dport<=M  (e.g. 1024<=dport<=65535)
                pm = re.search(r"(\d+)<=dport<=(\d+)", condition)
                dst_port = f"{pm.group(1)}-{pm.group(2)}" if pm else "any"
            else:
                dst_port = "any"

            svc_map[sid] = (proto, dst_port, sname)

    return svc_map


def _build_app_map(root: ET.Element) -> Dict[str, str]:
    """Build Id → app group Name map for APPList."""
    app_map: Dict[str, str] = {}
    lst = root.find("list[@name='APPList']")
    if lst is not None:
        for item in lst.findall("listitem"):
            v = _get_vars(item)
            aid = v.get("Id", "")
            aname = v.get("Name", "") or ""
            if aid:
                app_map[aid] = aname
    return app_map


def _build_group_map(root: ET.Element) -> Dict[str, List[str]]:
    """
    Build user-group name → list of member usernames from <list name="Group">.

    Each group listitem has a Name variable and one or more Member variables.
    """
    group_map: Dict[str, List[str]] = {}
    lst = root.find("list[@name='Group']")
    if lst is not None:
        for item in lst.findall("listitem"):
            name = ""
            members: List[str] = []
            for var in item.findall("variable"):
                if var.get("name") == "Name":
                    name = var.text or ""
                elif var.get("name") == "Member" and var.text:
                    members.append(var.text)
            if name:
                group_map[name] = members
    return group_map


def _resolve_endpoint(raw: Optional[str], addr_map: Dict[str, str],
                      group_map: Dict[str, List[str]]) -> tuple:
    """
    Parse Src/Dst field and return (resolved_addr, user_list).

    Patterns:
      "IPAccesses:<id>"       → (addr, [])
      "GroupID:'<name>'"      → ("any", [member users of group])
      "User:'<name>'"         → ("any", ["<name>"])
      None / empty            → ("any", [])
    """
    if not raw:
        return ("any", [])

    if raw.startswith("IPAccesses:"):
        aid = raw.split(":")[1].strip()
        return (addr_map.get(aid, aid), [])

    m = re.match(r"""(GroupID|User):\s*['"](.+?)['"]\s*$""", raw)
    if m:
        kind, name = m.group(1), m.group(2)
        if kind == "GroupID":
            # Expand group to its member users
            return ("any", list(group_map.get(name, [name])))
        return ("any", [name])

    return (raw, [])


def _resolve_service(raw: Optional[str], svc_map: Dict[str, tuple]) -> tuple:
    """
    Parse Srv field and return (protocol, dst_port, service_name).

    Patterns:
      None / empty               → ("any", "any", NA)  — no service = any
      "Port:<proto>:dport==<N>"  → (_PROTO_MAP[proto], str(N), NA)
      "IPServices:<id>"          → use svc_map[id] = (proto, port, name)
    """
    if not raw:
        return ("any", "any", NA)

    if raw.startswith("Port:"):
        parts = raw.split(":")
        # parts: ["Port", "6", "dport==25"]
        proto_num = parts[1] if len(parts) > 1 else ""
        proto = _PROTO_MAP.get(proto_num, proto_num)
        port_expr = parts[2] if len(parts) > 2 else ""
        # Extract port number from "dport==25"
        pm = re.search(r"==(\d+)", port_expr)
        dst_port = pm.group(1) if pm else NA
        return (proto, dst_port, NA)

    if raw.startswith("IPServices:"):
        sid = raw.split(":")[1].strip()
        if sid in svc_map:
            proto, port, sname = svc_map[sid]
            # Issue C: data-normalisation bug. A service named "any" is the
            # vendor's any-service sentinel and means the service/port dimension
            # is unconstrained. To match the other four vendors, such services
            # are normalised to ("any", "any", "any"). Real TCP/UDP services
            # (e.g. DNS) keep their specific protocol and port.
            if sname and sname.lower() == "any":
                return ("any", "any", "any")
            return (proto, port, sname)
        else:
            return (NA, NA, sid)

    return (NA, NA, raw)


def _resolve_app(raw: Optional[str], app_map: Dict[str, str]) -> str:
    """Parse Application field "APPList:<id>:1" → app name."""
    if not raw:
        return NA
    if raw.startswith("APPList:"):
        parts = raw.split(":")
        aid = parts[1] if len(parts) > 1 else ""
        return app_map.get(aid, aid) if aid else NA
    return raw


class IPImenParser(BaseParser):
    """Parse IPImen firewall policy XML into UnifiedRule instances."""

    vendor = "ipimen"

    def parse(self) -> List[UnifiedRule]:
        tree = ET.parse(self.filepath)
        root = tree.getroot()

        # Build lookup tables
        zone_map = _build_zone_map(root)
        addr_map = _build_addr_map(root)
        svc_map = _build_svc_map(root)
        app_map = _build_app_map(root)
        group_map = _build_group_map(root)

        rules_lst = root.find("list[@name='TrafficRules']")
        if rules_lst is None:
            return []

        # Sort by Order field (integer) to preserve policy sequence
        all_items = list(rules_lst.findall("listitem"))
        all_items.sort(
            key=lambda x: int(
                next(
                    (v.text or "0")
                    for v in x.findall("variable")
                    if v.get("name") == "Order"
                ),
                # fallback handled by int() below
            )
            if False
            else int(
                next(
                    (v.text or "0")
                    for v in x.findall("variable")
                    if v.get("name") == "Order"
                )
            )
        )

        rules: List[UnifiedRule] = []

        for seq, item in enumerate(all_items, start=1):
            v = _get_vars(item)
            # Collect all variable elements for multi-value fields
            all_vars = item.findall("variable")

            rule_id = v.get("Id", str(seq)) or str(seq)
            rule_name = v.get("Name", "") or ""
            enabled = (v.get("Enabled", "1") or "1") == "1"
            action = _ACTION_MAP.get(v.get("Action", "0") or "0", "deny")
            notes = v.get("Description", "") or ""

            # Zone: "src_id:dst_id"
            zone_raw = v.get("Zone", "0:0") or "0:0"
            zone_parts = zone_raw.split(":")
            src_zone_id = zone_parts[0] if len(zone_parts) > 0 else "0"
            dst_zone_id = zone_parts[1] if len(zone_parts) > 1 else "0"
            src_zone = zone_map.get(src_zone_id, src_zone_id)
            dst_zone = zone_map.get(dst_zone_id, dst_zone_id)

            # Collect ALL Src and Dst variable values (multiple elements allowed)
            src_raw_list = [var.text for var in all_vars
                            if var.get("name") == "Src" and var.text]
            dst_raw_list = [var.text for var in all_vars
                            if var.get("name") == "Dst" and var.text]

            src_addrs: List[str] = []
            src_users: List[str] = []
            for s in src_raw_list:
                addr, users = _resolve_endpoint(s.strip(), addr_map, group_map)
                if addr and addr not in src_addrs:   # include "any", deduplicate
                    src_addrs.append(addr)
                for u in users:
                    if u not in src_users:
                        src_users.append(u)
            # Collapse all-any list to single "any"
            src_addr = "any" if all(a == "any" for a in src_addrs) else ",".join(src_addrs) if src_addrs else "any"

            dst_addrs: List[str] = []
            dst_users: List[str] = []
            for d in dst_raw_list:
                addr, users = _resolve_endpoint(d.strip(), addr_map, group_map)
                if addr and addr not in dst_addrs:   # include "any", deduplicate
                    dst_addrs.append(addr)
                for u in users:
                    if u not in dst_users:
                        dst_users.append(u)
            dst_addr = "any" if all(a == "any" for a in dst_addrs) else ",".join(dst_addrs) if dst_addrs else "any"

            # Combine users from both src/dst
            user_parts = src_users + dst_users
            user_id = ",".join(user_parts) if user_parts else "any"

            # Negate flags (SrcOption/DstOption/SrvOption: "1" or "3" = negate)
            src_addr_neg = (v.get("SrcOption", "0") or "0") in ("1", "3")
            dst_addr_neg = (v.get("DstOption", "0") or "0") in ("1", "3")
            srv_neg = (v.get("SrvOption", "0") or "0") in ("1", "3")

            # Service — use last Srv variable (typically single-valued)
            srv_raw = v.get("Srv")
            protocol, dst_port, service = _resolve_service(srv_raw, svc_map)

            # Application — collect ALL Application variable values
            app_raw_list = [var.text for var in all_vars
                            if var.get("name") == "Application" and var.text]
            app_names: List[str] = []
            for app_raw in app_raw_list:
                resolved = _resolve_app(app_raw, app_map)
                if resolved and resolved != NA:
                    app_names.append(resolved)
            app_id = ",".join(app_names) if app_names else "any"

            # Log
            log = (v.get("LogCon", "0") or "0") == "1"

            # SNAT detection: presence of SNAT variable → nat_related=True
            snat_val = v.get("SNAT")
            nat_related = "True" if snat_val else "False"

            # ip_version: Family field (2=IPv4, 28=IPv6, 0=both)
            family = v.get("Family", "2") or "2"
            ip_version = {"2": "4", "28": "6", "0": "both"}.get(family, "4")

            # schedule: default "always"
            schedule_val = v.get("Schedule", "") or ""
            schedule = schedule_val if schedule_val else "always"

            # iface = zone (B10: src_iface/dst_iface = zone names)
            src_iface = src_zone
            dst_iface = dst_zone

            rules.append(
                UnifiedRule(
                    vendor=self.vendor,
                    rule_id=rule_id,
                    rule_name=rule_name,
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
                    src_port="any",
                    src_port_negated=False,
                    dst_addr=dst_addr,
                    dst_addr_negated=dst_addr_neg,
                    dst_port=dst_port,
                    dst_port_negated=srv_neg,
                    protocol=protocol,
                    service=service,
                    schedule=schedule,
                    log=log,
                    nat_related=nat_related,
                    app_id=app_id,
                    user_id=user_id,
                    icmp_type=NA,
                    notes=notes,
                )
            )

        return rules
