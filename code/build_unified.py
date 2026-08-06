"""
Generates normalized CSV datasets from raw vendor configuration files.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from parsers.fortigate import FortiGateParser
from parsers.paloalto import PaloAltoParser
from parsers.pfsense import PfSenseParser
from parsers.opnsense import OPNsenseParser
from parsers.ipimen import IPImenParser

BASE = Path(__file__).resolve().parents[1]
SRC = BASE / "Real-Dataset" / "synthetic"
OUT = BASE / "Real-Dataset" / "unified"

VENDORS = [
    (FortiGateParser, SRC / "fortigate_policy.conf", OUT / "fortigate.csv"),
    (PaloAltoParser, SRC / "paloalto_policy.xml", OUT / "paloalto.csv"),
    (PfSenseParser, SRC / "pfsense_rules.xml", OUT / "pfsense.csv"),
    (OPNsenseParser, SRC / "opnsense_rules.xml", OUT / "opnsense.csv"),
    (IPImenParser, SRC / "ipimen_rules.xml", OUT / "ipimen.csv"),
]


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for ParserClass, src, dst in VENDORS:
        if not src.exists():
            print(f"SKIP {src.name} — file not found")
            continue
        parser = ParserClass(src)
        out_path = parser.to_csv(dst)
        rules = parser.parse()
        print(f"OK   {src.name} -> {out_path.name}  ({len(rules)} rules)")


if __name__ == "__main__":
    main()