"""
Parser for FortiGate FortiOS policy configurations.

Extracts firewall rules, address objects, services, and groups into UnifiedRule format.
"""

import re
import sys
from pathlib import Path
from typing import List

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.schema import NA, UnifiedRule
from parsers.base import BaseParser

_ACTION_MAP = {
    "accept": "allow",
    "deny": "deny",
    "reject": "deny",
}

# Matches:  set <key> "val1" "val2" ...
# or:       set <key> val1 val2
_SET_RE = re.compile(r'^\s+set\s+(\S+)\s+(.*)', re.MULTILINE)
_QUOTED_RE = re.compile(r'"([^"]*)"')


def _extract_values(raw: str) -> List[str]:
    """Return list of values from a 'set' line RHS (quoted or unquoted)."""
    quoted = _QUOTED_RE.findall(raw)
    if quoted:
        return quoted
    return raw.strip().split()


def _join(values: List[str], default: str = NA) -> str:
    if not values:
        return default
    joined = ",".join(v for v in values if v and v.lower() != "all")
    return joined if joined else "any"


def _parse_policy_block(block_text: str) -> dict:
    """Parse all 'set' lines from a single edit...next block into a dict."""
    fields: dict = {}
    for m in _SET_RE.finditer(block_text):
        key = m.group(1).lower()
        vals = _extract_values(m.group(2))
        fields[key] = vals
    return fields


def _build_addr_map(content: str) -> dict:
    """
    Build a dict mapping address-object name → resolved IP/CIDR string.

    Handles:
    - set subnet <ip> <mask>       → CIDR
    - set type ipmask / iprange / fqdn / geography / wildcard
    - set start-ip / end-ip        → "start-end"
    - set fqdn "..."               → fqdn string
    - config firewall addrgrp: resolved recursively (name → members)

    If an object cannot be resolved, its name is kept as-is.
    """
    import ipaddress

    addr_map: dict = {}  # name → resolved string

    def _parse_block_for_addr(block_text: str) -> dict:
        result: dict = {}
        for m in _SET_RE.finditer(block_text):
            result[m.group(1).lower()] = _extract_values(m.group(2))
        return result

    def _to_cidr(ip_str: str, mask_str: str) -> str:
        try:
            net = ipaddress.IPv4Network(f"{ip_str}/{mask_str}", strict=False)
            return str(net)
        except Exception:
            return f"{ip_str}/{mask_str}"

    # --- firewall address6 (IPv6) ---
    addr6_match = re.search(
        r'^config firewall address6\s*\n(.*?)^\s*end\s*$',
        content,
        re.MULTILINE | re.DOTALL,
    )
    if addr6_match:
        blocks = re.split(r'^\s+next\s*$', addr6_match.group(1), flags=re.MULTILINE)
        for block in blocks:
            em = re.match(r'^\s+edit\s+"([^"]+)"', block)
            if not em:
                continue
            name = em.group(1)
            fields = _parse_block_for_addr(block)
            addr_type = (fields.get("type", ["ipprefix"])[0]).lower()
            if "ip6" in fields:
                # Standard IPv6 host/network object: "set ip6 <prefix/len>"
                addr_map[name] = fields["ip6"][0]
            elif "ip6-prefix" in fields:
                addr_map[name] = fields["ip6-prefix"][0]
            elif addr_type == "iprange6":
                start = fields.get("start-ip6", [name])[0]
                end = fields.get("end-ip6", [name])[0]
                addr_map[name] = f"{start}-{end}"
            else:
                addr_map[name] = name

    # --- firewall address ---
    addr_match = re.search(
        r'^config firewall address\s*\n(.*?)^\s*end\s*$',
        content,
        re.MULTILINE | re.DOTALL,
    )
    if addr_match:
        blocks = re.split(r'^\s+next\s*$', addr_match.group(1), flags=re.MULTILINE)
        for block in blocks:
            em = re.match(r'^\s+edit\s+"([^"]+)"', block)
            if not em:
                continue
            name = em.group(1)
            fields = _parse_block_for_addr(block)
            addr_type = (fields.get("type", ["ipmask"])[0]).lower()

            if addr_type in ("ipmask", "ipmask6") or "subnet" in fields:
                subnet = fields.get("subnet", [])
                if len(subnet) >= 2:
                    addr_map[name] = _to_cidr(subnet[0], subnet[1])
                elif len(subnet) == 1:
                    addr_map[name] = subnet[0]
                else:
                    addr_map[name] = name
            elif addr_type == "iprange":
                start = fields.get("start-ip", [name])[0]
                end = fields.get("end-ip", [name])[0]
                addr_map[name] = f"{start}-{end}"
            elif addr_type == "fqdn":
                fqdn_vals = fields.get("fqdn", [])
                addr_map[name] = fqdn_vals[0] if fqdn_vals else name
            else:
                # wildcard, geography, etc. — keep name
                addr_map[name] = name

    # --- firewall addrgrp (resolve member names already in addr_map) ---
    grp_match = re.search(
        r'^config firewall addrgrp\s*\n(.*?)^\s*end\s*$',
        content,
        re.MULTILINE | re.DOTALL,
    )
    if grp_match:
        blocks = re.split(r'^\s+next\s*$', grp_match.group(1), flags=re.MULTILINE)
        for block in blocks:
            em = re.match(r'^\s+edit\s+"([^"]+)"', block)
            if not em:
                continue
            grp_name = em.group(1)
            fields = _parse_block_for_addr(block)
            members = fields.get("member", [])
            resolved = []
            for m in members:
                resolved.append(addr_map.get(m, m))
            addr_map[grp_name] = ",".join(resolved) if resolved else grp_name

    return addr_map


def _build_service_map(content: str) -> dict:
    """
    Build a dict mapping service-object name → (protocol, dst_port).

    Rules:
    - set tcp-portrange <range>  → ("TCP", <range>)
    - set udp-portrange <range>  → ("UDP", <range>)
    - both tcp+udp exist         → ("TCP/UDP", <tcp_range>)  [prefer tcp range]
    - set protocol ICMP          → ("ICMP", "N/A")
    - set protocol IP            → ("IP", "N/A")   [protocol-number ignored]
    - none of the above          → ("N/A", "N/A")

    Built-in service names not in custom section default to N/A.
    """
    svc_map: dict = {}

    svc_match = re.search(
        r'^config firewall service custom\s*\n(.*?)^\s*end\s*$',
        content,
        re.MULTILINE | re.DOTALL,
    )
    if not svc_match:
        return svc_map

    blocks = re.split(r'^\s+next\s*$', svc_match.group(1), flags=re.MULTILINE)
    for block in blocks:
        em = re.match(r'^\s+edit\s+"([^"]+)"', block)
        if not em:
            continue
        name = em.group(1)
        fields: dict = {}
        for m in _SET_RE.finditer(block):
            fields[m.group(1).lower()] = _extract_values(m.group(2))

        tcp_range = fields.get("tcp-portrange", [])
        udp_range = fields.get("udp-portrange", [])
        sctp_range = fields.get("sctp-portrange", [])
        proto = (fields.get("protocol", [""])[0]).upper()

        if proto in ("ICMP", "ICMP6"):
            svc_map[name] = (proto, "any")
        elif proto == "IP":
            svc_map[name] = ("IP", "any")
        elif tcp_range and udp_range:
            svc_map[name] = ("TCP/UDP", tcp_range[0])
        elif tcp_range:
            svc_map[name] = ("TCP", tcp_range[0])
        elif udp_range:
            svc_map[name] = ("UDP", udp_range[0])
        elif sctp_range:
            svc_map[name] = ("SCTP", sctp_range[0])
        else:
            svc_map[name] = (NA, NA)

    return svc_map


def _build_group_map(content: str) -> dict:
    """
    Build a dict mapping user-group name → list of member usernames.

    Parses the 'config user group' section:
        config user group
            edit "Finance-Team"
                set member "backup.user" "network.admin" "user1"
            next
        end
    """
    group_map: dict = {}
    grp_match = re.search(
        r'^config user group\s*\n(.*?)^\s*end\s*$',
        content,
        re.MULTILINE | re.DOTALL,
    )
    if not grp_match:
        return group_map

    blocks = re.split(r'^\s+next\s*$', grp_match.group(1), flags=re.MULTILINE)
    for block in blocks:
        em = re.match(r'^\s+edit\s+"([^"]+)"', block)
        if not em:
            continue
        name = em.group(1)
        members: List[str] = []
        for m in _SET_RE.finditer(block):
            if m.group(1).lower() == "member":
                members = _extract_values(m.group(2))
        group_map[name] = members

    return group_map


def _resolve_addrs(names: List[str], addr_map: dict) -> str:
    """
    Resolve a list of address-object names to their IP/CIDR values.

    Rules:
    - 'all' resolves to 'any'.
    - If a mix of 'any' and specific addresses is present, keep all
      (e.g. ['all', 'Helpdesk'] → 'any,172.16.10.192/32').
    - If every entry resolves to 'any', return a single 'any'.
    """
    if not names:
        return "any"
    resolved = []
    for n in names:
        val = "any" if n.lower() == "all" else addr_map.get(n, n)
        if val not in resolved:
            resolved.append(val)
    if all(v == "any" for v in resolved):
        return "any"
    return ",".join(resolved)


class FortiGateParser(BaseParser):
    """Parse FortiGate firewall policy config into UnifiedRule instances."""

    vendor = "fortigate"

    def parse(self) -> List[UnifiedRule]:
        with open(self.filepath, encoding="utf-8") as f:
            content = f.read()

        # Build address-object and service-object lookup tables
        addr_map = _build_addr_map(content)
        svc_map = _build_service_map(content)
        group_map = _build_group_map(content)

        # Extract the 'config firewall policy' ... 'end' block
        policy_match = re.search(
            r'^config firewall policy\s*\n(.*?)^\s*end\s*$',
            content,
            re.MULTILINE | re.DOTALL,
        )
        if not policy_match:
            return []

        policy_body = policy_match.group(1)

        # Split into individual edit...next blocks
        # Pattern: edit <id> ... next
        edit_blocks = re.split(r'^\s+next\s*$', policy_body, flags=re.MULTILINE)

        rules: List[UnifiedRule] = []
        seq = 0

        for block in edit_blocks:
            edit_match = re.match(r'^\s+edit\s+(\d+)', block)
            if not edit_match:
                continue
            rule_id = edit_match.group(1)
            seq += 1

            f = _parse_policy_block(block)

            # ── identity ────────────────────────────────────────────────────
            name_vals = f.get("name", [])
            rule_name = name_vals[0] if name_vals else ""

            # ── state ───────────────────────────────────────────────────────
            status_vals = f.get("status", [])
            enabled = not (status_vals and status_vals[0].lower() == "disable")

            # ── action ──────────────────────────────────────────────────────
            raw_action = (f.get("action", ["accept"])[0]).lower()
            action = _ACTION_MAP.get(raw_action, raw_action)

            # ── ip version ──────────────────────────────────────────────────
            # Set above when resolving addresses ("6" if srcaddr6/dstaddr6 used)

            # ── zone / interface ────────────────────────────────────────────
            src_intfs = f.get("srcintf", [])
            dst_intfs = f.get("dstintf", [])
            # "any" interface → keep as "any"
            src_zone = ",".join(src_intfs) if src_intfs else NA
            dst_zone = ",".join(dst_intfs) if dst_intfs else NA
            src_iface = src_zone
            dst_iface = dst_zone

            # ── addresses ───────────────────────────────────────────────────
            src_addrs_v4 = f.get("srcaddr", [])
            src_addrs_v6 = f.get("srcaddr6", [])
            dst_addrs_v4 = f.get("dstaddr", [])
            dst_addrs_v6 = f.get("dstaddr6", [])
            # Combine both address families into a single resolved field
            src_addr = _resolve_addrs(src_addrs_v4 + src_addrs_v6, addr_map)
            dst_addr = _resolve_addrs(dst_addrs_v4 + dst_addrs_v6, addr_map)

            # ip_version: "both" only when EXPLICIT IPv6 address fields exist
            # alongside IPv4 fields. A catch-all (any/any from IPv4 'all') is "4".
            has_v4 = bool(src_addrs_v4 or dst_addrs_v4)
            has_v6 = bool(src_addrs_v6 or dst_addrs_v6)
            if has_v4 and has_v6:
                ip_version = "both"
            elif has_v6:
                ip_version = "6"
            else:
                ip_version = "4"

            src_addr_neg = (f.get("srcaddr-negate", ["disable"])[0].lower() == "enable")
            dst_addr_neg = (f.get("dstaddr-negate", ["disable"])[0].lower() == "enable")

            # ── service ─────────────────────────────────────────────────────
            svc_vals = f.get("service", [])
            # Normalise: "ALL" means any service
            svc_vals_norm = ["any" if s.upper() == "ALL" else s for s in svc_vals]
            service = ",".join(svc_vals_norm) if svc_vals_norm else NA

            # ── port / protocol ─────────────────────────────────────────────
            # Derive protocol/dst_port from service objects.
            # "ALL" service → any traffic; service not in custom map → resolved if possible.
            src_port = "any"
            protocol = NA
            dst_port = NA
            if any(s.upper() == "ALL" for s in svc_vals):
                protocol = "any"
                dst_port = "any"
            else:
                for svc_name in svc_vals:
                    if svc_name in svc_map:
                        protocol, dst_port = svc_map[svc_name]
                        break

            # ── schedule ────────────────────────────────────────────────────
            sched_vals = f.get("schedule", [])
            schedule = sched_vals[0] if sched_vals else NA

            # ── log ─────────────────────────────────────────────────────────
            # logtraffic: all | utm → True; disable (or absent) → False
            log_val = (f.get("logtraffic", ["disable"])[0]).lower()
            log = log_val in ("all", "utm")

            # ── NAT ─────────────────────────────────────────────────────────
            nat_val = (f.get("nat", ["disable"])[0]).lower()
            nat_related = str(nat_val == "enable")

            # ── NGFW fields ─────────────────────────────────────────────────
            app_vals = f.get("application-list", [])
            app_id = app_vals[0] if app_vals else "any"

            # Combine direct users + group members into user_id.
            # Group references (set groups) are expanded to their member users.
            raw_user_parts = f.get("users", []) + f.get("groups", [])
            user_list: List[str] = []
            for u in raw_user_parts:
                if u in group_map:
                    for member in group_map[u]:
                        if member not in user_list:
                            user_list.append(member)
                elif u not in user_list:
                    user_list.append(u)
            user_id = ",".join(user_list) if user_list else "any"

            # ── notes ───────────────────────────────────────────────────────
            comments = f.get("comments", [])
            notes = comments[0] if comments else ""

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
