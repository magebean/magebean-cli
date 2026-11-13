# Requirement architecture verification and semantic limits

The primary runtime owns one revisioned internal requirement and its evidence obligations. Standard references are metadata. The inventory has 684 active identities after 13 approved semantic consolidation groups retired 42 additional IDs; all 625 ASVS/PCI references remain represented. The allocator retains 727 historical allocations, including the earlier Composer duplicate retirement. Combined criteria retain their source clauses, scope and provenance and remain pending detector-sufficiency review.

## Verified behavior

- Default CLI selection and listing use internal IDs; profiles select existing definitions.
- Requirement assessment executes outside the reusable check registry. Primary definitions cannot invoke another requirement, a legacy wrapper or a fake manual check.
- Verified predicates, heuristics, supporting observations and mandatory human evidence have separate semantics. Missing necessary evidence is UNKNOWN; unreviewed bindings and human judgment cannot establish conformance.
- Agent schema 1.0 keeps requested IDs, assessment-item mapping, redaction and exact supported/unsupported cardinality. Explicit historical IDs, project packs and historical custom profiles execute through the compatibility adapter.
- Local and hybrid execution share local recipes. Default remote execution selects nine canonical assessments from the original ten target selectors. Profile context omissions remain visible and cannot certify non-applicability.
- Primary reports retain identity, revision, criterion, alignment and scope. PCI views use version-qualified alignment, and human instructions use atomic criteria.

The regression matrix exercises positive and negative observations for all 625 standard criteria. It protects against promoting partial evidence to PASS or unreviewed evidence to a normative FAIL. This is an outcome-safety test, not proof that every detector is accurate.

## Existing detector limits retained in review

The team reviewed the original 101 baseline bindings and identified cases needing deeper proof or implementation repair. Examples include file metadata failures that can be treated as mode zero, silent stat failures during world-writable traversal, incomplete traversal scope, and Composer ancestor-file fallback or malformed-section handling. These observations cannot currently serve as verified predicates in primary assessments. Historical compatibility execution retains the historical behavior; migrating identity does not repair every legacy detector.

Remediation suggestions and payment-scope discovery now support explicit criteria about actionable remediation plans and documented payment/data-flow scope. Their observations do not prove the required human assessment. The Composer prefer-stable binding now requires exact project-local manifest provenance; the ancestor fallback remains only in historical compatibility execution.

Twenty-one bounded predicates are accepted after the basic-profile detector review. Strict filesystem observations require complete traversal or a concrete counterexample; missing metadata and unresolved symlinks are UNKNOWN. Module state is declaration-scoped. Composer policies use only the project-local manifest and reject malformed shapes as UNKNOWN. Other standard bindings remain pending security review; MB-0379 now has a reviewed default-scope debug counterexample and still requires human evidence for its full positive conclusion. Further promotion needs criterion-specific scope, failure/unknown semantics, complete evidence, meaningful fixtures and review of false positives and false negatives. Human evidence collection does not yet include an independent approval workflow.

## Deployment boundary

CLI transport compatibility is tested locally. Registering new internal IDs and assessment items in the deployed dashboard, and removing the historical adapter, require separate coordinated migration. This change does not deploy or modify the dashboard.

## Human evidence versus implementation limitations

Human evidence is reserved for genuine external evidence or judgment. Sixty baseline policies removed developer-only human gates; six gained verified predicates and 54 retain inconclusive technical coverage. Unvalidated technical bindings return UNKNOWN / REQUIREMENT_BINDING_UNVALIDATED; insufficient reviewed heuristic coverage returns UNKNOWN / REQUIREMENT_AUTOMATION_INSUFFICIENT. Missing observations remain REQUIREMENT_EVIDENCE_INCOMPLETE. None of these development limitations is an instruction for the scan user to approve an implementation.

After the 2026-10-07 detector review, the basic profile has eighteen accepted bounded automated predicates and two merged requirements retaining actual human evidence. Runtime HTTP/TLS, unavailable advisory data, missing Git metadata, incomplete cron collection and malformed configuration can still produce UNKNOWN, with the detector explanation surfaced in the report. Unknown is not PASS. Default console counts only FAIL as confirmed findings; human review and inconclusive assessments have separate sections.

## Basic profile detector completion — 2026-10-07

Fifteen requirement revisions address the inconclusive screenshot: fourteen gain reviewed bounded predicates and debug policy gains a verified default configuration counterexample. Config resolution uses locked env.php/config.php values before read-only default-scope core_config_data. HTTPS/TLS/cookie probes can discover the configured base URL; explicit canonical target URLs win. Source-only observations are separated from runtime recipes. Git, static artifact and advisory criteria state their exact inspected scope, and criterion history retains earlier wording. No broader security certificate is implied by a scoped PASS.

Missing evidence messages now retain the actual detector reason. The nine remote primary recipes, 684 identities and all 625 standard references remain intact.

## Basic deployment automation profile

Basic now selects twenty reviewed automated deployment predicates with no human obligations. It uses MB-0728/0729/0730 for observed admin-password policy, declared project debug flags, and deployed working-tree pattern scanning. Broad ASVS MB-0209/0379 and Git-history MB-0072 remain unchanged outside basic. Use a named assessment profile or explicit `--rules` selection; the former full-inventory profile and its `all`/`magebean` aliases are no longer available. The global inventory is 687 identities; historical allocations730, next ID731, all625 standard references preserved.

Basic marks missing/invalid collection as execution errors, scan_complete=false and exit3; its console has no INCONCLUSIVE or human-review section. Internal UNKNOWN remains compatible with existing transport; classification=execution_error and execution_status=ERROR explicitly distinguish incomplete execution from policy violations. Existing security exit codes0/1/2 remain unchanged for completed scans. This policy does not convert missing evidence to PASS or security FAIL.

## OWASP scan quality review — 2026-10-07

The OWASP deployment profile has 31 automated requirements by default and 38 requiring explicit human evidence. Broad heuristic checks require `--include-manual-review`; reviewed bounded criteria can conclude PASS/FAIL. Git history is replaced in this deployment profile by existing MB-0730, with MB-0072 retained globally. Missing runtime/API evidence includes concrete collection guidance rather than instructions to fix a tool implementation gate. See [the 33-item security review](owasp-scan-quality-review.md).
