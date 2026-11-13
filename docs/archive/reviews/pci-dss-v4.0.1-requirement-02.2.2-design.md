# PCI DSS 2.2.2 hybrid evidence implementation

MB-R371 implements the hybrid evidence boundary for vendor default accounts and maps to PCI DSS 4.0.1 requirement 2.2.2 at `PARTIAL` coverage. It does not establish compliance.

The `pci_vendor_default_accounts_evidence` check validates the JSON contract in `src/Rules/standards/pci-dss-v4.0.1-2.2.2-evidence.schema.json`, including unique IDs, complete references, timestamps, fingerprints, account dispositions, scope attestations, and forbidden credential fields.

## Outcomes

- `FAIL`: a used confirmed vendor-default account declares an unchanged default credential, or an unused confirmed default account remains enabled.
- `UNKNOWN`: evidence is missing, unreadable, malformed, invalid, stale, or internally inconsistent.
- `HUMAN_VERIFICATION_REQUIRED`: classification, state, inventory, scope, or attestation remains incomplete.
- `EVIDENCE_COMPLETE`: the package is structurally and semantically complete, but the mandatory human check keeps MB-R371 at `HUMAN VERIFICATION REQUIRED`.

Names such as `admin` or `root` never prove vendor-default status. Password hashes, timestamps, and absent records never prove a credential was changed or an account removed. The evidence file must not contain passwords, password hashes, tokens, secrets, private keys, authentication cookies, or credential values.

MB-R371 is hidden by default and runs only with `--include-manual-review`. Explicit unsafe evidence can still produce a technical failure; no safe evidence path produces a PCI compliance pass.