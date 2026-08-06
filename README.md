# PHALANX (Policy-Hygiene Analysis Layer for ANomaly eXamination)

PHALANX (named after the ancient defensive formation) parses firewall configurations from multiple vendors, converts them to a single schema, and flags structural issues such as shadowed, redundant, or over-permissive rules, without relying on any ML model or vendor-specific heuristics guessing.

Companion code and dataset for the paper:
*PHALANX: A Reproducible Multi-Vendor Framework for Structural Firewall Policy Analysis and Finding Prioritization*

## Status

Manuscript submitted, currently under review.

## Supported Vendors

- FortiGate (FortiOS 8.0.0)
- Palo Alto (PAN-OS 12.1)
- IPImen (8.0.0)
- pfSense (2.8.1)
- OPNsense (26.1.2)


pfSense and OPNsense are treated as firewalls/UTMs, not NGFWs.

## Detected Anomalies

Deterministic/graph-based: shadowing, redundancy, conflict, generalization
Risk-oriented: over-permissiveness, stale rules, duplicate objects, unused rules

## Running

```bash
python main.py
```

`main.py` walks through the full pipeline (parsing, unification, anomaly detection, risk scoring, sensitivity analysis, reporting). Results are written to `results/`.

## Layout

- `Real-Dataset/` — anonymized and synthetic firewall configs, unified CSV output
- `paper/` — manuscript sections and references
- `code/` — parsers, anomaly detection, risk scoring, tests
- `results/` — generated reports and metrics

See `STRUCTURE.md` for the full file tree.

## Reproducibility

All numbers reported in the paper come from running the code in this repository on the datasets in `real-dataset/`. No result is hand-crafted or simulated.

## Citation

To be added after acceptance.

## License

Apache License 2.0