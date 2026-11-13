# Magebean current-state findings and reporting

Magebean reports observed technical weaknesses in the collected store/source/deployment state. Requirements identify assessments; findings describe evidence-backed conditions. A bounded snapshot does not certify every business flow or overall safety.

## Evidence and uncertainty

A real negative observation may be reported even when another check is incomplete. Missing input, access failures, parser errors and collection budgets are diagnostics, not security findings. An unknown outcome is not a pass. The ordinary list stays quiet; detailed `--rules` output exposes evidence, remediation and collection guidance. Incomplete native Magebean scans retain exit code 3 even when there are zero risk findings.

Categories distinguish security, correctness, explicit policy and informational record lint. Confidence describes what was observed, not confirmed exploitation. Installed/locked/dev dependency provenance and declaration/process/HTTP scope stay inspectable. Supplied evidence records do not prove implemented controls or close technical issues automatically.

## Report views

Raw JSON `findings` keeps one result for each selected assessment. `risk_findings` and `collection_issues` separate observations and diagnostics. `canonical_issues` groups only verified shared evidence identities, preserving contributors, related rule IDs and original outcomes. `summary.needs_attention` counts canonical issues in assembled CLI reports; `assessments_needing_attention` retains per-assessment counts. Category counts expose the same distinction.

Console text, HTML and SARIF use the canonical issue view. SARIF collection gaps are invocation tool-execution notifications, not vulnerability results. Default text keeps summary borders and hides per-issue borders, confidence labels and remediation paragraphs. One footer explains how to select rule details. The summary shows `Rules  74 selected · 12 require additional context` when omissions need capability context. Rules removed by selection/filtering are labeled `not selected` instead. This is a selection count, not a claim of complete assessment; collection completeness remains in diagnostics and structured coverage.

Agent schema 1.0 retains raw per-request fail/error/pass results and existing per-assessment attention counts. Additive canonical references and canonical_issue_count do not replace requested keys, snapshots or historical assessment identities. The Console ingestion contract retains per-assessment projections/findings; one canonical issue does not collapse two historical assessment items into one database row. Consumers should not sum CLI canonical counts with per-assessment agent counts.

## Profiles and agent context

`evidence` opts into two supplied document/record lint assessments. Core technical profiles exclude them. Development remains offline unless online maintenance is explicitly enabled. Profile context defaults are selection intent, not collected evidence. Missing supplied files are never created as scan prerequisites.

The current Console importer synchronizes profile membership and server-owned rule metadata. It does not persist CLI default_capabilities or add them to queued manifests. Agent execution therefore retains its explicit manifest capability gate; gated checks without context remain unsupported/incomplete. Importing a profile does not establish CLI/agent default-selection parity. A future server context editor/manifest contract is separate work.

See [Phase 6 qualification and limitations](../archive/current-state/phase6/README.md), [Phase 3 meaning](../archive/current-state/phase3/README.md), [Phase 4 correlation](../archive/current-state/phase4/README.md) and [Phase 5 memberships](../archive/current-state/phase5/README.md).
