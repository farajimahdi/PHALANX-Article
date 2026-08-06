"""
Parser for Palo Alto PAN-OS security policy export files.

Parses security rulebases, address/service groups, and user bindings into UnifiedRule representations.
"""

import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.schema import NA, UnifiedRule
from parsers.base import BaseParser

# PAN-OS action → unified action
_ACTION_MAP = {
    "allow": "allow",
    "deny": "deny",
    "drop": "deny",
    "reset-both": "deny",
    "reset-client": "deny",
    "reset-server": "deny",
}


def _build_service_map(root: ET.Element) -> dict:
    """
    Build name → (protocol, dst_port) from PAN-OS service objects.

    Service types:
    - <protocol><tcp><port>80</port></tcp></protocol>  → ("tcp", "80")
    - <protocol><udp><port>53</port></udp></protocol>  → ("udp", "53")
    - both tcp+udp → ("tcp/udp", tcp_port)
    - <protocol><ip-protocol><ip-protocol-number>1</ip-protocol-number></ip-protocol>
      → 1 = ICMP → ("icmp", "any"); 47/50/others → ("ip", "any")
    - service-group members: resolved recursively
    """
    # IP protocol numbers that map to a named protocol rather than generic "ip".
    # Only ICMP (1) gets its own name; all other raw IP protocols report as "ip".
    _IP_PROTO_NAMES = {"1": "icmp"}

    svc_map: dict = {}

    # <service> objects
    for entry in root.findall(".//service/entry"):
        name = entry.get("name", "")
        if not name:
            continue
        proto_elem = entry.find("protocol")
        if proto_elem is None:
            svc_map[name] = (NA, NA)
            continue

        tcp_elem = proto_elem.find("tcp")
        udp_elem = proto_elem.find("udp")
        ip_proto_elem = proto_elem.find("ip-protocol")

        tcp_port = None
        udp_port = None

        if tcp_elem is not None:
            port_elem = tcp_elem.find("port")
            if port_elem is not None and port_elem.text:
                tcp_port = port_elem.text.strip()

        if udp_elem is not None:
            port_elem = udp_elem.find("port")
            if port_elem is not None and port_elem.text:
                udp_port = port_elem.text.strip()

        if tcp_port and udp_port:
            svc_map[name] = ("tcp/udp", tcp_port)
        elif tcp_port:
            svc_map[name] = ("tcp", tcp_port)
        elif udp_port:
            svc_map[name] = ("udp", udp_port)
        elif ip_proto_elem is not None:
            num_elem = ip_proto_elem.find("ip-protocol-number")
            num = (num_elem.text or "").strip() if num_elem is not None else ""
            proto_name = _IP_PROTO_NAMES.get(num, "ip")
            svc_map[name] = (proto_name, "any")
        else:
            svc_map[name] = (NA, NA)

    # <service-group> objects
    for entry in root.findall(".//service-group/entry"):
        name = entry.get("name", "")
        if not name:
            continue
        members = [m.text.strip() for m in entry.findall("members/member") if m.text]
        if members:
            for m in members:
                if m in svc_map:
                    svc_map[name] = svc_map[m]
                    break
            else:
                svc_map[name] = (NA, NA)
        else:
            svc_map[name] = (NA, NA)

    return svc_map


def _build_addr_map(root: ET.Element) -> dict:
    """
    Build name → IP/CIDR map from PAN-OS address and address-group objects.

    Address types handled:
    - ip-netmask  : "1.2.3.4/24" or "1.2.3.4" (host)
    - ip-range    : "1.2.3.4-1.2.3.10"
    - fqdn        : kept as fqdn string
    - address-group members: resolved recursively
    """
    addr_map: dict = {}

    # <address> objects
    for entry in root.findall(".//address/entry"):
        name = entry.get("name", "")
        if not name:
            continue
        nm = entry.find("ip-netmask")
        if nm is not None and nm.text:
            addr_map[name] = nm.text.strip()
            continue
        ir = entry.find("ip-range")
        if ir is not None and ir.text:
            addr_map[name] = ir.text.strip()
            continue
        fq = entry.find("fqdn")
        if fq is not None and fq.text:
            addr_map[name] = fq.text.strip()
            continue
        addr_map[name] = name  # fallback

    # <address-group> objects
    for entry in root.findall(".//address-group/entry"):
        name = entry.get("name", "")
        if not name:
            continue
        members = [
            m.text.strip()
            for m in entry.findall("static/member")
            if m.text
        ]
        resolved = [addr_map.get(m, m) for m in members]
        addr_map[name] = ",".join(resolved) if resolved else name

    return addr_map


def _resolve_addrs(names: List[str], addr_map: dict) -> str:
    """Resolve list of address-object names to IP/CIDR values.

    When a mix of 'any' and specific addresses is present the combined value
    is returned (e.g. ['any', '10.0.0.0/8'] → 'any,10.0.0.0/8').
    If every entry resolves to 'any' a single 'any' is returned.
    """
    if not names:
        return "any"
    resolved = []
    for n in names:
        val = "any" if n.lower() == "any" else addr_map.get(n, n)
        if val not in resolved:
            resolved.append(val)
    if all(v == "any" for v in resolved):
        return "any"
    return ",".join(resolved)


def _members(element, tag: str) -> List[str]:
    """Return list of <member> texts under element/tag, or [] if absent."""
    container = element.find(tag)
    if container is None:
        return []
    return [m.text or "" for m in container.findall("member") if m.text]


def _join_members(element, tag: str) -> str:
    """Join members; 'any' members are kept as-is."""
    vals = _members(element, tag)
    if not vals:
        return NA
    non_any = [v for v in vals if v.lower() != "any"]
    return ",".join(non_any) if non_any else "any"


def _text(element, tag: str, default: str = NA) -> str:
    el = element.find(tag)
    if el is None or not el.text:
        return default
    return el.text.strip()


def _build_group_map(root: ET.Element) -> dict:
    """
    Build user-group name → list of member usernames.

    Parses <user-group><entry name="..."><user><member>...</member></user>.
    """
    group_map: dict = {}
    for entry in root.findall(".//user-group/entry"):
        name = entry.get("name", "")
        if not name:
            continue
        members = [m.text.strip()
                   for m in entry.findall("user/member") if m.text]
        group_map[name] = members
    return group_map


class PaloAltoParser(BaseParser):
    """Parse Palo Alto security policy XML into UnifiedRule instances."""

    vendor = "paloalto"

    def parse(self) -> List[UnifiedRule]:
        tree = ET.parse(self.filepath)
        root = tree.getroot()

        addr_map = _build_addr_map(root)
        svc_map = _build_service_map(root)
        group_map = _build_group_map(root)

        rules_el = root.find(".//security/rules")
        if rules_el is None:
            return []

        rules: List[UnifiedRule] = []
        seq = 0

        for entry in rules_el.findall("entry"):
            seq += 1
            rule_name = entry.get("name", "")
            rule_id = entry.get("uuid", str(seq))

            # ── state ───────────────────────────────────────────────────────
            disabled_text = _text(entry, "disabled", "no").lower()
            enabled = disabled_text != "yes"

            # ── action ──────────────────────────────────────────────────────
            raw_action = _text(entry, "action", "allow").lower()
            action = _ACTION_MAP.get(raw_action, "deny")

            # ── ip version: resolved from addresses (see below) ─────────────
            ip_version = "4"   # placeholder; overwritten after address resolution

            # ── zone ────────────────────────────────────────────────────────
            src_zone = _join_members(entry, "from")
            dst_zone = _join_members(entry, "to")
            # PAN-OS: interface lives in Network config, not security rule
            src_iface = NA
            dst_iface = NA

            # ── addresses ───────────────────────────────────────────────────
            src_el = entry.find("source")
            dst_el = entry.find("destination")
            src_names = _members(entry, "source")
            dst_names = _members(entry, "destination")
            src_addr = _resolve_addrs(src_names, addr_map)
            dst_addr = _resolve_addrs(dst_names, addr_map)

            # PAN-OS encodes negation as an attribute on the source/destination
            # element: <source negate="yes"> or <destination negate="yes">.
            # Some exports also use child elements <negate-source>yes</negate-source>.
            def _is_negated(el, child_tag: str) -> bool:
                if el is None:
                    return False
                if (el.get("negate") or "").strip().lower() == "yes":
                    return True
                child = el.find(child_tag)
                return child is not None and (child.text or "").strip().lower() == "yes"

            src_addr_neg = _is_negated(src_el, "negate-source")
            dst_addr_neg = _is_negated(dst_el, "negate-destination")

            # ── ip_version ──────────────────────────────────────────────────
            # "any/any" = catch-all → both; ":" in address = IPv6 present.
            _has_v6 = (":" in src_addr or ":" in dst_addr)
            _has_v4 = ("." in src_addr or "." in dst_addr)
            if src_addr == "any" and dst_addr == "any":
                ip_version = "both"
            elif _has_v6 and _has_v4:
                ip_version = "both"
            elif _has_v6:
                ip_version = "6"
            else:
                ip_version = "4"

            # ── service ─────────────────────────────────────────────────────
            service_names = _members(entry, "service")
            service = ",".join(service_names) if service_names else NA
            
            # ── port / protocol from service objects ───────────────────────
            src_port = "any"
            dst_port = NA
            protocol = NA
            
            # Resolve protocol/port from first service
            for sname in service_names:
                if sname.lower() == "any":
                    protocol = "any"
                    dst_port = "any"
                    break
                if sname in svc_map:
                    protocol, dst_port = svc_map[sname]
                    break

            # ── schedule ────────────────────────────────────────────────────
            schedule_val = _text(entry, "schedule", "")
            schedule = schedule_val if schedule_val else "always"

            # ── log ─────────────────────────────────────────────────────────
            log_end = _text(entry, "log-end", "no").lower()
            log = log_end == "yes"

            # ── NAT ─────────────────────────────────────────────────────────
            nat_related = NA  # PAN-OS security rulebase has no NAT concept

            # ── NGFW fields ─────────────────────────────────────────────────
            app_val = _join_members(entry, "application")
            app_id = app_val if app_val != NA else "any"

            # source-user contains both individual users and group names.
            # Group references are expanded to their member users.
            user_members = _members(entry, "source-user")
            user_list: List[str] = []
            for u in user_members:
                if u.lower() == "any":
                    if "any" not in user_list:
                        user_list.append("any")
                elif u in group_map:
                    for member in group_map[u]:
                        if member not in user_list:
                            user_list.append(member)
                elif u not in user_list:
                    user_list.append(u)
            if not user_list or all(x == "any" for x in user_list):
                user_id = "any"
            else:
                user_id = ",".join(user_list)

            # ── notes ───────────────────────────────────────────────────────
            notes = _text(entry, "description", "")

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
                    src_port=src_port,
                    src_port_negated=False,
                    dst_addr=dst_addr,
                    dst_addr_negated=dst_addr_neg,
                    dst_port=dst_port,
                    dst_port_negated=False,
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
