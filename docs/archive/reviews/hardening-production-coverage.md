# Superseded contract

The mixed human-evidence design below is historical. Current contract: [Magebean automated-only profiles](../../guides/profiles.md).

# Hardening production coverage

Hardening revision 2 includes **107 distinct Magebean requirements**: every Basic requirement (37), every Magebean OWASP Top 10 profile requirement (77), and the existing deeper production controls. Shared IDs execute once; no ASVS or PCI clauses are merged into this profile. Inventory remains 742 overall because this is a membership change, not new identities.

Default LOCAL selection is **57 no-human technical requirements**. Another **50 requirements need independent human evidence** and are explicitly listed in JSON, CLI and HTML as not assessed when omitted. `--include-manual-review` includes their supporting observations and review tasks, but successful supporting checks cannot turn the independent review into PASS.

All six Basic external evidence groups are retained: authentication/least privilege; effective runtime permissions/document root/config locks; edge/Admin/SSH controls; scheduled scans and notification ownership; backup/restore; complete store/cache/static/scheduler runtime coverage. They remain outside automated pass counts. All Hardening members have a security/readiness lane.

CLI profile validation and Console import reject Hardening catalogs that lose a Basic/OWASP member or Basic evidence task. After changing a constituent profile, update the persisted Hardening union with `artifacts/expand-hardening-coverage.py` and rerun the coverage tests before import. Historical source-family manifests and assessment snapshots remain unchanged.

## Reading production results

`coverage_summary` distinguishes inventory, executed, not evaluated, unresolved and external evidence groups. Technical `scan_complete` continues to describe collection completion; it is **not** production assessment completion. The profile cannot report complete assessment while requirements or external evidence remain unassessed. A clean technical exit code is not an attestation of protection.

LOCAL, REMOTE and capability restrictions still apply. URL-only execution cannot establish local filesystem, configuration, database or installed scheduler state; omitted requirements remain visible with their reason. Project filters or selected-rule scans reduce assessed coverage and do not shrink the advertised production inventory.

Payment-specific data flows, card-data retention, payment-script inventory/integrity/monitoring and payment-webhook requirements remain a separate scope, as in the preceding Hardening contract. A payment deployment must review that scope as well. Formal ASVS and PCI assessments use their independent catalogs. Profile membership alone does not validate every detector or demonstrate resistance to exploitation.

## Deployment

Deploy both CLI/catalog and Console importer/report updates, then import `src/Rules` into Console. New assessments use the new membership; existing assessments keep their original snapshots and need an explicit profile refresh/new assessment to include added controls. CLI/agent binaries must contain the new catalog; importing Console does not rebuild the PHAR.

## Validation

All 102 CLI test files passed. The Hardening coverage test verifies union membership, uniqueness, inherited evidence, default/full selections, human outcomes, coverage accounting, report exports and rejection of lost coverage. The related Console run passed 22 tests / 125 assertions, including transactional rejection of incomplete Hardening imports. Console local imported 742 requirements / 7 profiles and verified Hardening107 plus remediation parity. Production was not deployed and the PHAR was not rebuilt.
