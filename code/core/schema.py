"""
Canonical rule representation schema for PHALANX.

Defines UnifiedRule data structure and CSV serialization order.
"""
from dataclasses import dataclass, field, fields
from typing import Optional


# Default sentinel for vendor-unsupported or missing fields.
NA = "N/A"


@dataclass
class UnifiedRule:
    # Rule metadata
    vendor: str            # Vendor platform identifier
    rule_id: str           # Native rule ID or tracker tag
    rule_name: str         # Human-readable label
    seq: int               # 1-based evaluation order

    # State & action
    enabled: bool          # Active status flag
    action: str            # "allow", "deny", or "reject"
    ip_version: str        # "4", "6", or "both"

    # Interfaces and security zones
    src_zone: str          # Source security zone
    dst_zone: str          # Destination security zone
    src_iface: str         # Source interface binding
    dst_iface: str         # Destination interface binding

    # Source parameters
    src_addr: str          # Address specification
    src_addr_negated: bool
    src_port: str          # Source port range
    src_port_negated: bool

    # Destination parameters
    dst_addr: str
    dst_addr_negated: bool
    dst_port: str
    dst_port_negated: bool

    # Transport and service definition
    protocol: str          # Transport layer protocol
    service: str           # Named service object

    # Supplementary metadata
    schedule: str          # Active time window
    log: bool              # Audit logging flag
    nat_related: str       # NAT linkage status

    # Application & identity controls
    app_id: str            # Application identification
    user_id: str           # User or group identity

    # Vendor-specific extension
    icmp_type: str = field(default=NA)
    notes: str = field(default="")

    @staticmethod
    def csv_columns() -> list[str]:
        """Return list of attribute names matching CSV output layout."""
        return [f.name for f in fields(UnifiedRule)]

    def to_csv_row(self) -> dict:
        """Map instance fields to a dictionary for CSV exports."""
        return {f.name: getattr(self, f.name) for f in fields(self)}