# PCI DSS v4.0.1 gap triage

This is the engineering classification of the 245 requirements for which the profile currently produces no Magebean evidence. It does not decide compliance, applicability, or assessment results.

## Results

| Category | Requirements | Meaning |
|---|---:|---|
| `AUTOMATION_CANDIDATE` | 0 | Awaiting criterion-level engineering review. |
| `EXTERNAL_SYSTEM_EVIDENCE` | 121 | Primary evidence belongs to an authoritative external system. |
| `CONTEXTUAL_APPLICABILITY` | 48 | Entity role, payment architecture, or overlay must be resolved first. |
| `HUMAN_ONLY` | 76 | Documents, interviews, observations, governance, or operational records are required. |
| **Total** | **245** | |

All 71 former automation candidates in Requirements 3, 4, 6, 7, 8, and 10 received criterion-level review. Seven requirements now reuse bounded local evidence; 34 were classified as external-system evidence, three as contextual, and 27 as human-only. No speculative new automated rules were added. See `docs/archive/reviews/pci-dss-v4.0.1-automation-candidate-review.md`.

External evidence is imported through a credential-free structured package. Human-only items are listed only when `--include-manual-review` is supplied, and each item states the assessment scope. Appendix A and entity-restricted requirements remain controlled by the applicability compiler.
