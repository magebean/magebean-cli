# Automation requirement quality review — 2026-10-07

The review covers the active requirement inventory and prioritizes checks that can produce automated conclusions. The machine-readable per-ID inventory and review provenance are in [automation-inventory-audit.json](automation-inventory-audit.json).

## Inventory and review boundaries

- 687 active identities: structural validation passed for all 687; all 625 version-qualified standard references remain present.
- All 47 initially autonomous requirements received detector, criterion-scope and collection-action review. 44 retain autonomous conclusions.
- MB-0082, MB-0083 and MB-0086 require database/payment-flow evidence beyond source patterns; supporting matches do not prove absence of stored card data or runtime payment behavior. They retain explicit human scope.
- All 643 human requirements received evidence-contract desk review: 344 ASVS-aligned and 299 PCI/unaligned definitions. They require independent evidence. This desk review does not establish deployment conformance. Automated supporting checks do not replace that evidence.

## Changes

- Cache frontends, Redis credential presence and dependency API coverage reject incomplete/unsupported observations instead of clean PASS.
- Cron readiness/backlog use read-only Magento cron_schedule queries. Indexer readiness uses recorded indexer_state rows. ACL checks validate relationship integrity and reject incomplete evidence.
- Git-history search uses PCRE with an explicitly line-based scope. Unreadable PHP artifacts and Composer lock files remain collection failures; they do not become false findings.
- Payment-source observations redact PAN/CVV snippets.
- Optional heuristic obligations in 44 human requirements were corrected to supporting evidence; their collection gaps retain per-check actions. Human evidence handoff instructions were clarified. Three PCI clauses were restored from the complete persisted source registry after detecting truncation or PDF page-continuation fragments.
- Every primary UNKNOWN result includes collection_guidance: category, owner, action, resources and reason code. Actions travel in existing agent evidence as well as CLI/report output.
- Typed transport actions take precedence over generic guesses. TLS trust errors retain verification; known store URLs do not automatically produce a request to supply --url.
- Internal detector exceptions produce an actionable tool-owned result and allow subsequent primary checks to run. Worker checkpoint/cancellation exceptions retain propagation.
- Default primary scans containing only automated requirements classify unavailable observations as execution errors and return exit code 3. Human assessments remain opt-in. Wire statuses and the agent result envelope remain compatible.

## Evidence

The full suite passed 89 test scripts, and the newly added HumanPciUnalignedDeskReviewTest also passed (90 scripts total). AutomationDiagnosticsTest passed 196 assertions across all 44 autonomous definitions, including forced unavailable evidence, collector actions, exception containment/redaction, worker callbacks, detailed console guidance and agent transport. The inventory contract passed 716 assertions.

The QA PHAR passed source/PHAR smoke checks. On the local Magento deployment, six config/database checks completed with three PASS and three policy FAIL, with zero collection errors. The OWASP scan had no unvalidated-binding rows, human sections or INCONCLUSIVE sections; the final run returned 15 PASS, 14 FAIL and two execution errors for private-certificate trust and HTTP-only cookie observations, both with actions. A transient directory timeout from the earlier run was also reported with a specific action and cleared on the final run. Those environmental observations are not converted to PASS.

Reports:
- [Configuration/runtime audit](automation-config-audit.json)
- [Source/dependency audit](automation-source-dependency-audit.json)
- [Network audit](automation-network-audit.json)
- [Compatibility snapshot review](automation-compatibility-snapshot-review.json)
- [ASVS human evidence desk review](automation-human-asvs-desk-review.json)
- [PCI and unaligned human desk review](human-pci-unaligned-desk-review.json)
- [Restored PCI source clauses](human-pci-source-corrections.json)

QA build: artifacts/magebean-internal-qa.phar. Production deployment is not part of this review.
