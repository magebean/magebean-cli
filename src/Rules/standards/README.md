# Standards registries

Standards registries provide canonical requirement identifiers and applicability metadata independently from Magebean rule mappings. They do not select scan rules and do not claim compliance.

## Requirement identity and assessment definitions

The target contract is one assessment definition per standard/version/requirement, with reusable checks beneath it. See [Requirement model](../../../docs/reference/requirement-model.md) and [ASVS L1/L2 migration inventory](../../../docs/archive/migrations/asvs-requirement-migration.md). Existing coverage files remain evidence mappings; RequirementCatalog compiles ASVS profiles into executable one-to-one requirement definitions. A mapped technical result does not establish the complete standard criterion. PCI and ASVS IDs must remain in separate versioned namespaces.


## PCI DSS v4.0.1

`pci-dss-v4.0.1.json` is derived from the official June 2024 document in `docs/PCI-DSS-v4_0_1.pdf`. It contains:

- 12 principal requirements;
- 63 core objective groups;
- 250 core Defined Approach requirement IDs;
- 30 additional requirement IDs across overlays A1, A2, and A3;
- testing-method categories, entity restrictions, effective-date metadata, approach availability, source pages, and source fingerprints.

The registry intentionally does not reproduce full PCI DSS requirement text. Requirement interpretation and assessment must use the official standard, applicability notes, testing procedures, and the applicable PCI validation program.

`pci-dss-v4.0.1-coverage.json` records evidence coverage for all 280 requirements; 35 currently have DIRECT, PARTIAL, or SUPPORTING Magebean evidence.

`pci-dss-v4.0.1-gap-triage.json` classifies the 245 unmapped requirements. The automation-candidate backlog is zero after the criterion review in `pci-dss-v4.0.1-automation-candidate-review.json`.

`pci-dss-v4.0.1-requirement-02-review.json` records the Requirement 2 decisions. MB-R371 implements the 2.2.2 hybrid evidence contract in `pci-dss-v4.0.1-2.2.2-evidence.schema.json`; complete evidence still cannot produce a PCI compliance conclusion.

`pci-dss-v4.0.1-context.schema.json` and `pci-dss-v4.0.1-external-evidence.schema.json` define the applicability and external-evidence inputs used by the PCI report workflow.

The three Appendix A overlays are not enabled globally:

- `A1`: multi-tenant service providers;
- `A2`: qualifying legacy card-present POS POI TLS environments;
- `A3`: designated entities subject to supplemental validation.

Run the semantic integrity check with:

```bash
php tests/PciDssRegistryTest.php
php tests/PciDssCoverageMatrixTest.php
php tests/PciDssGapTriageTest.php
php tests/PciDssRequirement02ReviewTest.php
php tests/PciDssRequirement022EvidenceDesignTest.php
```

`owasp-asvs-v5.0.0.json` pins the official 345 requirement identifiers and introduced levels. It validates compiled ASVS identities; it contains no full standard text. Source: https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0/5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.json
