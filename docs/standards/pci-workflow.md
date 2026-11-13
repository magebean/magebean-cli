# PCI DSS v4.0.1 evidence-readiness workflow

Magebean collects and organizes evidence; it does not certify PCI DSS compliance or produce an attestation of compliance.

## Inputs

- Applicability context: `src/Rules/standards/pci-dss-v4.0.1-context.schema.json`
- External evidence: `src/Rules/standards/pci-dss-v4.0.1-external-evidence.schema.json`
- Vendor-default-account evidence: `src/Rules/standards/pci-dss-v4.0.1-2.2.2-evidence.schema.json`

Examples are under `docs/examples/`. Evidence packages must contain references and SHA-256 fingerprints, never passwords, PAN, CVV, PIN blocks, tokens, or other credential material.

## Run

```bash
php magebean.phar scan \
  --path=/var/www/magento \
  --profile=pci \
  --pci-context=.magebean/pci-context.json \
  --pci-evidence=.magebean/pci-evidence.json \
  --include-manual-review \
  --pci-report=var/report/magebean-pci.json
```

Without `--pci-context`, core applicability remains `NOT_DETERMINED`, while disabled overlays and incompatible entity-only requirements are explicitly `NOT_APPLICABLE`. A `NOT_APPLICABLE` override requires a written rationale.

Without `--include-manual-review`, criterion-specific human actions are omitted from console and report output. Their omission does not waive human verification.

## Report statuses

- `TECHNICAL_FINDING`: a Magebean rule found an issue for the requirement.
- `EVIDENCE_COLLECTED_HUMAN_VERIFICATION_REQUIRED`: external evidence was accepted structurally; a person must still assess it.
- `HUMAN_VERIFICATION_REQUIRED`: the applicable requirement still requires human assessment and supporting evidence.
- `NOT_APPLICABLE`: excluded by an explicit entity, overlay, or requirement decision with rationale.
- `NOT_DETERMINED`: scope or applicability has not been established.

No PCI report status is equivalent to `PASS` or PCI DSS compliance.
