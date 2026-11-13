# PCI DSS v4.0.1 coverage matrix

This document summarizes Magebean evidence coverage. It is not a PCI DSS compliance statement, certification, SAQ, ROC, or substitute for an assessor. Human verification is mandatory for every requirement before Magebean output is used as assessment evidence.

The machine-readable matrix is `src/Rules/standards/pci-dss-v4.0.1-coverage.json`. It contains one entry for every registry requirement, including conditional Appendix A overlays.

## Coverage semantics

- `DIRECT`: a Magebean rule tests the complete technical criterion represented by that mapping.
- `PARTIAL`: Magebean tests a material subset; additional evidence is required.
- `SUPPORTING`: Magebean provides relevant evidence but does not test the complete requirement.
- `UNMAPPED`: the current profile produces no Magebean evidence for the requirement.

Even `DIRECT` coverage requires a person to confirm applicability, scope, provenance, environment, and evidence acceptance.

## Current summary

| Coverage | Requirements |
|---|---:|
| Direct | 1 |
| Partial | 25 |
| Supporting | 9 |
| Unmapped | 245 |
| **Total** | **280** |

The 68 profile rules create 94 mappings and cover 35 unique requirements. The default scan runs 67 non-manual rules; `--include-manual-review` includes all 68.

## Coverage by principal requirement

| Requirement | Total | Direct | Partial | Supporting | Unmapped |
|---|---:|---:|---:|---:|---:|
| 1 | 19 | 0 | 1 | 0 | 18 |
| 2 | 11 | 0 | 4 | 0 | 7 |
| 3 | 29 | 0 | 4 | 2 | 23 |
| 4 | 6 | 0 | 1 | 0 | 5 |
| 5 | 13 | 0 | 0 | 0 | 13 |
| 6 | 19 | 0 | 4 | 1 | 14 |
| 7 | 12 | 0 | 2 | 1 | 9 |
| 8 | 29 | 1 | 6 | 0 | 22 |
| 9 | 27 | 0 | 0 | 0 | 27 |
| 10 | 27 | 0 | 2 | 1 | 24 |
| 12 | 37 | 0 | 0 | 3 | 34 |
| 11 | 21 | 0 | 1 | 1 | 19 |
| A1 | 7 | 0 | 0 | 0 | 7 |
| A2 | 3 | 0 | 0 | 0 | 3 |
| A3 | 20 | 0 | 0 | 0 | 20 |

Appendix A requirements remain visible but are selected only by the applicability compiler when their overlay is enabled.

## Workflow

1. Compile applicability with `--pci-context`.
2. Run the PCI profile for Magebean technical evidence.
3. Import authoritative external evidence with `--pci-evidence`.
4. Add `--include-manual-review` to list criterion-specific human actions.
5. Write the evidence-readiness result with `--pci-report`.

The 245 unmapped requirements are classified as 121 external-system evidence, 48 contextual-applicability, and 76 human-only. All former automation candidates received criterion-level review.
