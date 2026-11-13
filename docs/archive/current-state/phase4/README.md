# Phase 4 — canonical issues and duplicate control

Phase 4 adds a target-relative canonical issue view. It groups supported observations by their actual subject and evidence identity; it does not merge requirement definitions, rewrite historical results or claim unrelated predicates equivalent. Profile membership remains unchanged.

## Correlation implemented

| Observations | Shared identity and boundary |
|---|---|
| MB-0728 / MB-0731 | One admin-password-minimum component for the same source, key and threshold. Prefer MB-0728 when present; MB-0731 remains an accepted selector with its own assessment. A legacy-only selection has the same verified issue ID. |
| MB-0038 / MB-0741 | Share the exact no-file-backend component per config key. The stronger Redis/Varnish preference is retained separately; these full criteria are not equivalent. |
| MB-0061 / MB-0744 | One abandoned-package observation per package/version, status publisher/revision and dependency scope. Library-only checks are reused, while the aggregate keeps module and other package coverage. |
| MB-0049 / MB-0055 / MB-0056 / MB-0059 | One package/version/advisory observation within the same feed and dependency scope. Dependency chain, published fixed version, blocked constraints and publication age are supporting context. Only the violating follow-up subset is projected. |
| MB-0828 and online advisory views | Supplied snapshot provenance stays separate from an online feed. Different declared revisions, publishers or installed/locked scopes are not guessed equivalent. |
| MB-0733 / MB-0736 | One output-encoding observation for the same source bytes, expression byte position and context. Other output expressions, including ones on the same line, stay distinct. |
| MB-0780 / MB-0800 | Compatible filename/PHP-tag signals describe the same upload artifact path. Handler declarations form a separate family. All signals remain available. |
| MB-0790 / MB-0822 | A native-command policy occurrence can support the flow-aware command candidate at the exact same call position in the same source snapshot. The flow candidate retains its uncertainty; confirmed syntax does not confirm injection. |
| MB-0795 / MB-0814 | One direct-request-logging policy observation at the same request occurrence in the same source snapshot. |

Cron installation, cadence, execution recency, backlog and success remain distinct facts. Coarse and scoped static artifact checks, declaration versus process/HTTP observations and unsupported source relationships are not merged because they share a file or line. Query-named methods are not automatically treated as proven SQL receiver identities.

## Evidence and stable IDs

Source/template evidence now includes a byte offset and SHA-256 of the collected source bytes. Hashing occurs once per file; source is not included in the new identity fields. Typed module detector metadata is version 1.2 for the added precision. Backtick command syntax is emitted once per AST ShellExec node instead of once per delimiter.

Verified `mb-issue-v1:` identities exclude rule ID, severity, selection order and collection timestamps. They include the supported issue family, subject, location and relevant source/scope identity. Repeated scans of the same evidence retain their IDs. Source edits, context/baseline changes, dependency scope changes or a different declared feed/snapshot can intentionally produce a different scoped identity. IDs are target-relative; a multi-store consumer must retain its store/instance namespace.

Older line-only data, unsupported identity shapes and over-budget fragment lists remain explicitly `unresolved` observations. They are not auto-merged or silently dropped. Original evidence remains available even when a canonical view cannot safely split or correlate it. The canonical count is a count of projected issue groups, including these retained aggregate observations, not certification that all possible duplication has been solved.

## Reports and compatibility

- `findings` and `risk_findings` retain their per-requirement assessments and observations. `canonical_issues` is the added presentation view, with `rule_ids`, `assessment_outcomes`, contributors, exact identities and actionable context.
- CLI and HTML use the canonical view. Default output keeps summary borders, quiet guidance/confidence behavior and a single footer hint. Related rule IDs identify the grouped predicates. Detailed output includes dependency/constraint/age context.
- Assembled report `summary.needs_attention`, `canonical_issue_count` and `findings_by_category` describe the projected groups. `assessments_needing_attention`, `assessment_observations_by_category` and the existing detector-only totals preserve their distinct meanings. `uncorrelated_observations` makes unresolved correlation visible in structured data.
- SARIF writes one result per canonical issue and preserves contributor evidence, primary and related assessment outcomes, canonical fingerprints, informational observations and independent collection notifications.
- Agent schema stays v1. Requested keys, assessment item IDs, statuses, per-assessment `needs_attention` and result cardinality are preserved. Canonical refs are attached before requested/legacy keys are remapped; `summary.canonical_issue_count` is additive. Consumers can group views without deleting assessment history.

Integration QA also found a coverage-propagation gap: a known failed check carrying incomplete dependency/feed/status/range/date evidence could appear complete in the risk projection. Such checks now keep the known issue and separate coverage diagnostics. Partial data does not become a new website finding or a clean scan; incomplete automatic scans keep exit code 3.

## Qualification

- All 141 CLI test files pass.
- `CurrentStatePhase4CorrelationTest.php`: 46 assertions using real inert source/upload/template fixtures, actual loopback advisory responses, exact component call counters, negative identity cases and CLI/HTML/SARIF/agent projections.
- The ten original Phase 4 QA observations become five evidence-correlated issues while preserving all ten per-rule observations. `acceptance-results.json` records the pairs; `overlap-probes.json` and `middle-probes.json` retain fresh risk envelopes. Reproduce with `python3 tools/verify-phase4-qa.py`.
- The isolated Console ingestion check passes one test / 36 assertions. It uses the archived AgentResultMapper with freshly executed policy and typed-flow evidence, requested-key fixture bindings and raw fail/error statuses. Two rule observations and two assessment projections survive the shared canonical ref; same-request re-ingestion is idempotent, and a subsequent scan retains independent history. Source SHA/byte metadata round-trips. SQLite is explicitly in-memory; Console production files are not modified. Reproduce with `python3 tools/verify-phase4-console.py` when the sibling Console workspace is available.
- Both standard and one-time PHARs pass their archived-code 46-assertion gate, alongside earlier phase/profile/restoration qualification.
- Protected ASVS/PCI definitions, historical retirement archive, active rule identities and profile membership remain unchanged. Synthetic fixtures are not live-store qualification; wider release/UI/benchmark work remains Phase 6.

Phase 5 follows with reviewed membership for restored rules and the opt-in evidence profile. No new profile or membership change is included here.
