Current profile contract supersedes the external checklist described below: [automated-only Magebean profiles](../../guides/profiles.md).

# Basic Adobe review implementation

Basic revision 2 selects **37 Magebean technical requirements: 30 security and 7 readiness**, with **six external evidence task groups**. The previous review files describe the original 20-member profile and remain historical evidence.

## Added coverage

| Requirements | Observation |
|---|---|
| MB-0773–MB-0776 | Resolved native Admin secret keys, case sensitivity, account sharing and password reset protection/throttles |
| MB-0777–MB-0779 | Separate Admin HTTPS entrypoint, verified endpoint certificate and scoped framing policy |
| MB-0780–MB-0782 | Media executable filenames, six bounded sensitive HTTP paths and current Git index exclusion of env.php |
| MB-0783–MB-0785 | Installed every-minute scheduler cadence, published theme/locale CSS/JS and recent cron success/backlog |
| MB-0009, MB-0027, MB-0042, MB-0100 | Reused reviewed Magebean session configuration, HSTS, log placement and Admin role relational integrity |

MFA now uses native provider engines, never fictional provider modules. Enabled IMS modules, unknown engines and unforced provider configuration require further evidence. A configured provider does not establish enrollment or enforcement. Common Admin routes `admin` and `backend` fail the declared-route policy.

Storefront HTTPS works with a URL alone. Admin HTTPS is a separate local observation. HSTS uses the same one-year Magebean threshold in both modes. Remote cache headers no longer stand in for a persisted FPC declaration. Existing FPC remains explicitly a local state observation; runtime cache effectiveness is an evidence task.

Security/readiness labels and counts appear in CLI, JSON, HTML and Console. A readiness failure still affects the existing scan exit policy, but carries its readiness label. External tasks have `NOT_ASSESSED` status, do not become findings or PASS, and do not block execution of the technical checks.

## External evidence

The six groups cover authentication/enrollment/least privilege; effective runtime permissions/document root/config locks; WAF/Admin access/SSH MFA; scheduled security scans and notification ownership; backups/restore; and full deployment coverage across stores, cache, static delivery and schedulers. These groups are checklist metadata, **not thirteen or six additional automated proofs**. Deployment architecture and unavailable evidence remain explicit.

Numeric thresholds identify Magebean as policy owner. Adobe guidance supplies topic provenance and applicability, rather than a claim that every threshold is mandated by Adobe. Framing policy evaluation respects enforced CSP precedence over XFO, as specified by [CSP Level 3](https://www.w3.org/TR/CSP/#frame-ancestors-and-frame-options).

## Identity and synchronization

Thirteen fresh identities MB-0773–MB-0785 expand Magebean from 104 to 117 and total inventory from 729 to 742. The global no-human technical inventory is 57; ASVS 345 and PCI 280 remain separate and unchanged. Allocation next ID is 786, with retired identities reserved. Aggregate, allocation and reconciliation files agree. Historical family-separation manifests retain their original counts.

Console local imported **742 requirements / 7 profiles**, with Basic membership, lanes, policy provenance and evidence checklist matching CLI. Existing assessments retain immutable snapshots. Production was not deployed, and the PHAR was not rebuilt.

## Validation and limits

- CLI regression: **100 test files passed**, including safe/violating/missing-data fixtures, URL-only HTTP, native/IMS/provider handling, framing precedence, bounded inventories, alternate scheduler forms, policy provenance and output contracts.
- Console related regression: **12 tests passed, 61 assertions**; profile synchronization verification passed.
- Compatibility snapshot changed only its rule listing, reflecting intentional catalog/title/membership changes.

These are fixture and application contract tests, not a full Magento release/edition integration matrix or a production penetration test. Automated configuration and bounded observations cannot establish all active-store behavior, MFA enrollment, effective web identity permissions, WAF effectiveness or recovery readiness. Missing evidence is never silently counted as PASS.
