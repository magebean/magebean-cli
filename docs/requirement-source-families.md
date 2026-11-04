# Requirement source families

[Magebean Baseline v1](magebean-baseline-v1.md) documents only the `magebean` family. Official ASVS and PCI DSS documents own their independent clauses; neither family is included in the baseline. See the [documentation index](README.md) for their source documents and implementation guides.

The active catalog separates three sources of assessment criteria:

| Family | Authority | Profiles | Requirements |
|---|---|---|---:|
| `magebean` | Magebean deployment and application security criteria | Basic, Hardening, OWASP Top 10, Module Integrity, Module Source, Module Lifecycle, Module Reliability | 99 |
| `asvs` | OWASP ASVS 5.0.0, one requirement per document clause | ASVS L1 / L2 / L3 | 345 |
| `pci` | PCI DSS 4.0.1, one requirement per document clause | PCI readiness | 280 |

The physical files are `src/Rules/requirements/magebean-catalog.json`, `asvs-catalog.json` and `pci-catalog.json`. They are authoritative for runtime loading. `internal-catalog.json` remains a compatibility aggregate and must mirror all three exactly.

Basic, Hardening, OWASP, Module Integrity and Module Source contain only Magebean requirements. An OWASP Top 10 profile describes Magebean's security coverage categories; it is not an ASVS document profile. ASVS and PCI clauses retain their own version, reference, criterion and source provenance. Profiles cannot mix the families, including custom profiles.

Technical checks may be reused across families when their arguments and observation scope match. Assessment conclusions remain independent: a successful Magento setting check cannot certify an entire ASVS or PCI clause. Human evidence gates still apply; this migration does not promote automation or establish compliance.

The active inventory is 724. Source-family separation restored independent source-bound definitions (729 at that migration); the Basic Adobe review added thirteen Magebean definitions using fresh IDs MB-0773–MB-0785, and the later automation review adds 22 exact scoped predicates at MB-0786–MB-0807. Basic selects 37 automated requirements with no human checklist. Retired IDs remain reserved. Historical allocation redirects and semantic-consolidation records preserve their original values; active legacy selectors resolve source-bound replacements recorded in `family-separation-manifest.json`. Historical assessment results must not be copied into new clauses as if they were fresh conclusions.

Earlier automation/profile audit artifacts describe the catalog at their recorded revision. Their counts and cross-family unions are superseded by this source-family model; they remain historical evidence, not the current inventory contract.
The current native Magebean profile contract is automated-only: Basic 37, Hardening 79 and OWASP 51, without manual checklists. Default LOCAL selection is 37/67/41 respectively; the remaining members require explicit machine context or strict policy capabilities. Fifty previous mixed-profile members retain their original definitions in the automation engineering backlog, outside executable profiles. New narrower observations do not certify those broader original criteria. See [the automated-only contract](magebean-automated-only-profiles.md). ASVS/PCI evidence workflows remain separate.

Deploy the CLI catalog and Console importer together, then re-import the catalog into Console. Verify eleven customer profiles and family membership after import. Existing assessments retain their historical requirement revisions.

