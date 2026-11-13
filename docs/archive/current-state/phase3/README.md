# Phase 3 — finding meaning and policy boundaries

Phase 3 changes interpretation and reporting of collected evidence, while preserving requirement identities, assessments, raw check evidence, agent correspondence and existing category/confidence enums. It does not add a profile, merge duplicate issues or certify runtime exploitability.

## Findings and confidence

`MagebeanFindingSemantics` classifies the reviewed predicates across all 110 active Magebean rules. This dispatch table is an interpretation contract, not evidence that a target passed or failed. Actual check results, typed detector evidence and the executed synthetic QA probes remain the basis of findings.

- `security`: observed technical conditions, scoped advisory/patch matches and supported review candidates.
- `correctness`: observed declaration, signature, reference or state inconsistencies.
- `policy`: explicit coding, deployment, threshold, backend and maintenance comparisons.
- `informational`: evidence-record lint and non-actionable review context.

`confirmed` describes the observed condition or relationship; it never means confirmed exploitation. Source patterns with unverified credential validity, serving behavior, alternate authentication or input influence remain `suspected`. Typed detectors retain their more specific category/confidence. Unknown custom predicates do not inherit a confirmed security claim from proof metadata. Empty legacy evidence cannot establish confirmed confidence.

Additive fields include `claim_type`, `confidence_basis`, `exploitability` and `guidance`. Advisory identity/version matches remain actionable security observations, with installation/locked scope from Phase 2. Advisory publication age, release age, abandonment and archival remain maintenance context; they are not measured remediation SLA, EOL or exploitation proof.

## Policy presentation

Default projected policy severity is at most medium; syntax-only and maintenance policies are at most low. Raw requirement severity and assessment status remain intact. An explicit project severity override is respected as priority and does not change category or exploitation confidence. Policy messages have a short `Policy:` prefix so ordinary output does not imply a vulnerability from a benign API occurrence.

Strict native API capability gates remain. A fixed shell command, local file read, harmless randomness, constant deserialization or a query-named non-SQL method can fail the selected syntax policy without becoming a proven injection, secret exposure or cryptographic defect. Supported request-to-sink and concrete declaration findings retain their detector severity and evidence. Backend preferences and ownership/threshold conventions are labeled policy, rather than blanket claims about the safety of alternatives.

Remediation now distinguishes investigation, action, functional verification and the exact rule/scope to rerun. API replacement is not input validation; declaration changes are not proof of runtime enforcement. An approved exception does not automatically change a scan result or the underlying predicate.

## Evidence records

MB-0093 is opt-in through `evidence_document_lint`. MB-0806 retains its existing `dependency_mitigation_policy` capability and required supplied policy context. The proposed evidence profile and final membership changes remain Phase 5 work; current membership files are unchanged.

Document-topic and record structure/expiry failures are informational observations, not ordinary technical findings. They do not establish PCI compliance or mitigation effectiveness. Where a supplied record has a usable package/version/advisory identity and an independent technical finding has the same identity, the structured report includes `evidence_record_links`. Links preserve dependency scope, do not alter finding status/severity and explicitly do not verify a fix. Unmatched claims are not linked to invented technical issues.

## Diagnostics and compatibility

Collection errors, parser failures, unsupported expressions and missing data are only in collection diagnostics, not ordinary risk findings. A real issue and an independent collection gap can coexist. Raw UNKNOWN/status evidence, assessment cardinality, scan completeness and incomplete-scan exit code 3 remain; zero risk findings does not mean complete coverage.

SARIF places Magebean collection gaps in invocation tool-execution notifications, not vulnerability results. JSON retains structured gaps and adds category counts for ordinary findings; the existing detector-only category counter keeps its original scope. Default console output stays quiet, keeps summary borders and does not restore per-issue confidence or remediation text. Detailed `--rules` output still includes diagnostics and guidance.

Legacy `summary.failed` and agent fail/error statuses describe assessments. `needs_attention` describes technical/policy findings, while informational observations and collection diagnostics are separate. Consumers should use completeness/diagnostics rather than inferring a clean scan from a zero finding count.

## Validation

- 140 CLI test files, including contract checks for quiet/default output, detailed collection guidance, exit codes, redaction, agent mapping and unchanged assessment correspondence.
- 263 Phase 3 assertions: semantic dispatch coverage plus executed source-policy counterexamples, suspected CSRF bypass, advisory evidence, typed request-to-sink severity, parser diagnostics, SARIF notifications, opt-in records, exact evidence links and explicit severity override.
- 23 original Phase 3 QA observations are re-executed and checked in `acceptance-results.json`; fresh evidence is in `part1-probes.json` and `part2-probes.json`. `tools/verify-phase3-qa.php` verifies their expected classification. Captured observations belonging to other phases are not claims of completion here.
- Both PHAR variants run the same Phase 3 test using their own archived autoloader, alongside Phase 1/2, restored-rule and profile qualification.
- ASVS/PCI definitions, historical retirement archive and profile membership remain unchanged. No live-store qualification is implied by these synthetic/loopback fixtures.

Phase 4 follows with canonical issue correlation and duplicate control. No duplicate grouping has been introduced in Phase 3.
