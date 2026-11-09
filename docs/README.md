# Magebean CLI documentation

## Start here

- [README](../README.md): installation, quick start and profile selection.
- [CLI reference](cli-reference.md): commands, options, modes and agent operations.
- [Magebean Security Baseline v1](magebean-baseline-v1.md): 100 Magebean rules grouped by control, mirrored from the Magebean catalog; excludes PCI DSS and OWASP ASVS clauses.
- [Requirement source families](requirement-source-families.md): catalog authority, family boundaries and current inventory.
- [Requirement model](requirement-model.md): identities, reusable checks, obligations and outcomes.

## Magebean profiles and operation

- [Automated-only profile contract](magebean-automated-only-profiles.md): Basic, Hardening and Magebean OWASP membership and evidence limits.
- [Production machine policy](automation-feasibility/production-policy.md): capabilities and typed machine inputs.
- [Findings-first reporting](magebean-findings-first.md): findings and collection guidance.
- [API reference and data disclosure](api-reference.md): API-backed checks and transmitted data.
- [Release packaging](release-packaging.md): building and validating the PHAR.
- [Architecture](architecture.md): implementation boundaries and scan pipeline.

## External standards and CLI integration

ASVS and PCI DSS are separate source families, not chapters of the Magebean baseline. Use their official versioned documents for standard requirements; no separate Magebean baseline documentation of those clauses is maintained. The links below provide source references and CLI-specific implementation and evidence scope. The Magebean `owasp` profile uses Top 10 taxonomy and is not an ASVS assessment.

| Source | Local official document | CLI implementation |
|---|---|---|
| OWASP ASVS 5.0.0 | [ASVS document](OWASP_Application_Security_Verification_Standard_5.0.0_en.pdf) | [Native evidence scope](asvs-native-evidence.md) |
| PCI DSS 4.0.1 | [PCI DSS document](PCI-DSS-v4_0_1.pdf) | [Evidence workflow](pci-dss-v4.0.1-workflow.md), [coverage](pci-dss-v4.0.1-coverage.md) |

## Migration and engineering records

[Requirement migration](requirement-migration.md), [ASVS migration](asvs-requirement-migration.md), review ledgers, QA reports and automation-feasibility artifacts document implementation work at their recorded revisions. Historical counts, legacy MB-R examples and earlier profile contracts do not override the current source-family catalogs or automated-only profile contract. They remain useful as engineering evidence and compatibility history.

Documentation changes must preserve the distinction between a Magebean criterion, an official standard clause, a reusable check and a profile selection. Use current `MB-…` identities in user examples; label legacy selectors explicitly when discussing compatibility.
