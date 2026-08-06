"""
Abstract base class for vendor policy parsers.

Defines the core parsing interface and utility methods to export UnifiedRule collections to CSV.
"""
import csv
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.schema import UnifiedRule


class BaseParser(ABC):
    """Parse a vendor-specific firewall policy file into unified rules."""

    vendor: str = ""

    def __init__(self, filepath: str | Path):
        self.filepath = Path(filepath)
        if not self.filepath.exists():
            raise FileNotFoundError(f"Policy file not found: {self.filepath}")

    @abstractmethod
    def parse(self) -> List[UnifiedRule]:
        """Return ordered list of UnifiedRule (seq 1-based)."""

    def to_csv(self, output_path: str | Path) -> Path:
        """Write unified rules to CSV; return the output path."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        rules = self.parse()
        with output_path.open("w", newline="", encoding="utf-8-sig") as fh:
            writer = csv.DictWriter(fh, fieldnames=UnifiedRule.csv_columns())
            writer.writeheader()
            for rule in rules:
                row = rule.to_csv_row()
                # Issue A: only IPImen supports service/port negation.
                # For all other vendors mark dst_port_negated as unsupported.
                if self.vendor != "ipimen":
                    row["dst_port_negated"] = "N/A"
                writer.writerow(row)
        return output_path
