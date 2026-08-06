PHALANX-Article/
├── Real-Dataset/                                       # Project anonymized datasets
│   ├── anonymized/                                     # Deterministically anonymized firewall policies
│   │   ├── fortigate_policy.conf                       # Anonymized FortiGate configuration
│   │   ├── ipimen_rules.xml                            # Anonymized IPImen configuration
│   │   ├── opnsense_rules.xml                          # Anonymized OPNsense configuration
│   │   ├── paloalto_policy.xml                         # Anonymized Palo Alto configuration
│   │   ├── pfsense_rules.xml                           # Anonymized pfSense configuration
│   │   └── unified_rules.jsonl                         # Anonymized vendor rules in the unified format
│   ├── synthetic/                                      # Synthetic datasets for scalability evaluation only
│   │   ├── fortigate_policy.conf                       # Synthetic FortiGate policy
│   │   ├── ipimen_rules.xml                            # Synthetic IPImen policy
│   │   ├── opnsense_rules.xml                          # Synthetic OPNsense policy
│   │   ├── paloalto_policy.xml                         # Synthetic Palo Alto policy
│   │   ├── pfsense_rules.xml                           # Synthetic pfSense policy
│   │   └── unified_rules.jsonl                         # Synthetic vendor rules in the unified format
│   └── unified/                                        # Parser outputs in the unified CSV format
│       ├── fortigate.csv                               # Unified FortiGate output (generated after execution)
│       ├── ipimen.csv                                  # Unified IPImen output (generated after execution)
│       ├── opnsense.csv                                # Unified OPNsense output (generated after execution)
│       ├── paloalto.csv                                # Unified Palo Alto output (generated after execution)
│       └── pfsense.csv                                 # Unified pfSense output (generated after execution)
├── paper/                                              # Scientific paper documentation and source files
│   ├── en/                                             # English manuscript organized by section
│   │   └── PHALANX, Mahdi Faraji, 2026.pdf             # Paper
│   └── biblio.bib		                                # BibTeX references
├── code/                                               # PHALANX framework implementation
│   ├── core/                                           # Core engine for deterministic and graph-based structural anomaly detection
│   │   ├── __init__.py                                 # Marks the directory as a Python package
│   │   ├── anomaly.py                                  # Main script for detecting conflicts, shadowing, generalization, and redundancy
│   │   ├── rule_status_filter.py                       # Post-processing filters for the final output (Reporting Convention and Negation Paradox)
│   │   └── schema.py                                   # Unified data model and rule class definitions
│   ├── parsers/                                        # Vendor-specific configuration parsers and conversion to the unified format
│   │   ├── __init__.py                                 # Marks the directory as a Python package
│   │   ├── base.py                                     # Common base class for all parsers
│   │   ├── fortigate.py                                # Native FortiGate parser (FortiOS 8.0.0)
│   │   ├── ipimen.py                                   # Native IPImen parser (IPImen 8.0.0)
│   │   ├── opnsense.py                                 # Native OPNsense parser (OPNsense 26.1.2)
│   │   ├── paloalto.py                                 # Native Palo Alto parser (PAN-OS 12.1)
│   │   └── pfsense.py                                  # Native pfSense parser (pfSense 2.8.1)
│   ├── scoring/                                        # Risk assessment and sensitivity analysis modules based on the mathematical model
│   │   ├── __init__.py                                 # Marks the directory as a Python package
│   │   ├── risk.py                                     # Computes numerical risk scores for each anomaly (Blast Radius, Exposure, etc.)
│   │   ├── risk_rule_status.py                         # Computes risk scores for the final filtered findings (anomalies_rule_status.jsonl)
│   │   └── sensitivity.py                              # Sensitivity analysis of ranking under weight variations (Spearman correlation)
│   ├── tests/                                          # Unit tests for verifying implementation correctness
│   │   ├── test_anomaly.py                             # Anomaly detection tests
│   │   ├── test_fortigate.py                           # FortiGate parser tests
│   │   ├── test_ipimen.py                              # IPImen parser tests
│   │   ├── test_opnsense.py                            # OPNsense parser tests
│   │   ├── test_paloalto.py                            # Palo Alto parser tests
│   │   ├── test_pfsense.py                             # pfSense parser tests
│   │   ├── test_risk.py                                # Risk scoring tests
│   │   └── test_scalability.py                         # Scalability algorithm and scenario tests
│   ├── _aggregate_reporting_convention.py              # Report aggregation script following the paper convention
│   ├── _compute_negation_paradox.py                    # Helper script for analyzing inconsistencies caused by negated fields
│   ├── build_unified.py                                # Main script for generating unified files from vendor configurations
│   ├── rule_anomaly_status.py                          # Generates the final per-rule status report for administrators
│   ├── scalability.py                                  # Scalability evaluation on synthetic datasets of varying sizes
│   ├── validation_metrics.py                           # Computes evaluation metrics and Cohen's kappa agreement
│   └── validation_sample.py                            # Random sampling for human annotation and expert evaluation
├── results/                                            # Output files and experimental results
│   ├── rule_status/                                    # Vendor-specific rule status reports
│   │   ├── all_rules_status.csv                        # Aggregated status report for all vendor rules
│   │   ├── fortigate_rule_status.csv                   # FortiGate rule status report
│   │   ├── ipimen_rule_status.csv                      # IPImen rule status report
│   │   ├── opnsense_rule_status.csv                    # OPNsense rule status report
│   │   ├── paloalto_rule_status.csv                    # Palo Alto rule status report
│   │   ├── pfsense_rule_status.csv                     # pfSense rule status report
│   │   └── README.md                                   # Documentation for rule status reports
│   ├── anomalies.jsonl                                 # Project-wide detected anomalies
│   ├── anomalies_rule_status.jsonl                     # Final findings after applying the Reporting Convention and Negation Paradox filters
│   ├── scalability.json                                # Raw scalability benchmark results
│   ├── scored_anomalies.jsonl                          # All anomalies with detailed risk scores
│   ├── scored_anomalies_rule_status.jsonl              # Final filtered findings with risk scores (input to risk_rule_status.py)
│   ├── scoring_summary.json                            # Statistical summary of risk scores by vendor
│   ├── scoring_summary_rule_status.json                # Risk score summary of the final filtered findings, grouped by vendor
│   ├── sensitivity.json                                # Sensitivity analysis results and Spearman correlation coefficients
│   ├── summary.json                                    # Statistical summary of all detected anomalies
│   ├── summary_rule_status.json                        # Statistical summary of the final filtered findings, including filter metadata (removed anchors and negation cases)
│   ├── validation_metrics.json                         # Validity metrics, Cohen's kappa, precision, and recall
│   ├── validation_sample_label_rater1.csv              # Evaluation sample labels by Rater 1
│   ├── validation_sample_label_rater2.csv              # Evaluation sample labels by Rater 2
│   └── validation_sample.csv                           # Randomly sampled instances for human annotation
├── main.py                                             # Interactive menu and end-to-end execution pipeline (Steps 1–11)
└── README.md                                           # Project overview, anomaly definitions, and reproducibility guide