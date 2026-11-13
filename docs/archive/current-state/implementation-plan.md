# Magebean current-state audit — phased implementation

Status: Phases 0–6 completed locally. Phase 6 qualification and limitations: [Phase 6](phase6/README.md). Phase 5 implementation and validation: [Phase 5](phase5/README.md). Phase 4 implementation and validation: [Phase 4](phase4/README.md). Phase 3 implementation and validation: [Phase 3](phase3/README.md). Phase 2 implementation and validation: [Phase 2](phase2/README.md). Phase 1 implementation and validation: [Phase 1](phase1/README.md). Baseline and acceptance artifacts: [Phase 0](phase0/README.md). Implementation plan and profile decisions prepared from the110-rule QA. Completed phases have local source and qualified PHAR changes; Phase 6 used isolated Console SQLite and synthetic performance fixtures, with no live-store validation; reviewed profile rollout is complete in Phase 5. Baseline:110 Magebean,345ASVS,280PCI;14built-in profiles; development28members/27default, prelaunch52/51default, takeover78members. Sources: current-state-qa-report.md, the three per-rule QA parts and current-state-qa-inventory.json.

## Product contract

Core audit reads current collected store/source/deployment state, emits evidence-backed technical issues, records uncertainty and gives reproducible remediation. Output must distinguish observed defect, suspected risk, explicit policy and informational context. A successful bounded scan is not certification of all business flows or overall store safety. Missing inputs and collection limits remain structured scanner diagnostics, with the quiet default overview retained.

## Phase0 — baseline and executable acceptance inventory

Deliverables:
- Freeze all110 reviewed IDs/checks/profiles/capabilities and the50inactive-reference decisions. Preserve historical rule revisions and external-standard definitions.
- Turn49 current-state QA observations into regression cases with explicit expected corrected behavior; record which probes are design/policy observations rather than bugs.
- Define canonical issue families, input provenance (locked/installed/dev/enabled, declared/resolved/process/HTTP), category/confidence and stable correlation fields before changing presentation.

Acceptance: everyQAfinding maps to a phase/test; every restored ID has a profile decision below; no production profile membership changes are mixed into the baseline step.

## Phase1 — correctness and misleading scope fixes

Implement:
- MB-0815/0816/0818: inherited constructor visibility/instantiability; unresolved construction cannot return clean.
- MB-0062: strict absolute calendar timestamp validation; reject impossible and relative dates.
- MB-0059: reject future/malformed publication dates; remove organizational remediation-SLA claims from publication-age evidence.
- MB-0072/0730: separate expected runtime secret storage from committed/history/unexpected/public exposure. Keep sensitive values redacted; mode0600 alone is not a complete access proof, but a secret-pattern match in expected env config is not itself exposure.
- MB-0805 malformedinventory validation and MB-0817 callable-array shape: return incomplete evidence where the supported claim is not established.

Acceptance: pairedpositive/negative/malformedcases, protectedenvnotreportedCriticalsolelyforbeingexpectedsecretstorage, exactprivate-ctorreprodoesnotPASS. No broad unsupported claim is silently converted into a narrow PASS.

## Phase2 — current component and observation provenance

Implement:
- One dependency inventory that distinguishes composer.lock, installed Composer metadata, require-dev and declared module enablement. Preserve source path/package version/evidence time.
- Default deployed-store findings identify components supported by installed/deployment evidence. Locked-only/dev/build risks are separately scoped; development mode can legitimately include dev dependencies.
- Reuse the existing online advisory/status clients and managed cache behavior. Preserve offline source analysis; no invented mandatory .magebean/osv-db.json input. Local supplied snapshots stay opt-in with explicit coverage.
- Share advisory results for0049/0055/0056/0059/0828 and configuration observations for aggregate/specific rules. Source/process/HTTP claims keep separate provenance and build correlation remains unverified unless evidence establishes it.
- Treat working indexers and cron freshness/queue/success as different facts; add duration/context before claiming a stuck or unhealthy process.

Acceptance: production--no-dev fixture does not label a lock-only devpackage as installed runtime vulnerability; actual installed vulnerablepackage remains actionable; source/cache/feed gaps preserve knownfindings; dev mode remainsusableoffline.

## Phase3 — issue taxonomy and policy boundaries

Implement:
- Core confirmed technical defects, suspected issues, explicit policy violations and informational observations use separate categories. Confirmed syntax is not labeled confirmed exploitability.
- Coding API bans, backend preference, prefer-stable/wildcard/dev constraints, latest-release/freshness thresholds remain explicit policy/maintenance context. Keep existing strict capability gates and define additional baseline inputs where needed.
- MB-0093 checklist and MB-0806 mitigation-record lint move to opt-in evidence/governance selection, linked to relevant actual technical issues where applicable.
- Keep collection diagnostics out of ordinary finding lists; preserve structured coverage and current exit-code distinctions. Do not restore noisy per-issue guidance/confidence by default.
- Improve why-care/remediation/retest text for the exact file/key/module/area or package condition.

Acceptance: benign local read/fixed command/nonsecurity randomness is not called a proven vulnerability; advisory/policy classification remains inspectable; genuine unsafe source-to-sink/declaration findings retain severity and evidence.

## Phase4 — canonical issues and duplicate control

Implement:
- MB-0728/0731 share one canonical password-minimum predicate. Prefer0728 for profile selection, keep0731 as a compatible selector with historical snapshots preserved. Do not retain two independent findings for identical evidence.
- Reuse exact components0038/0741 and0061/0744 without pretending their full scopes are identical; library-only scope remains selectable.
- Group0049/0055/0056/0059 by package/version/advisory/scope, attaching dependency chain, fixed-version constraints and age as context.
- Group shared0733/0736templatepositions,0780/0800uploadartifactsignals,0790/0822commandlocations and0795/0814logginglocations.
- Preserve complementary cron, static artifact and declared/process/HTTP evidence; never dedupe all issues merely because they share a file.

Acceptance: the six overlap probes become grouped observations without losing distinct evidence; repeated scans have stable issue identity; agent/import cardinality and historical assessment identities remain compatible.

## Phase5 — apply reviewed profile membership

Add restored coverage only after phases1–4 establish its semantics. Profiles choose focus; they do not change the underlying meaning of a finding silently. module/declaration vs enabled-runtime scope is explicit in evidence.

| Restored ID | Target profile(s) | Selection and overlap rule |
|---|---|---|
| MB-0043 | hardening, takeover | Conditional logging-config observation when a relevant supplied/installed candidate is collectable. No mandatory invented devops file and no claim installation was proved. |
| MB-0093 | proposed evidence profile (opt-in) | Document-topic lint outside core security findings; no insertion into the separate PCI-family profile. |
| MB-0731 | canonical MB-0728 in basic, hardening, prelaunch, takeover | Keep0731 compatible, execute one password-minimum predicate; add appropriate prelaunch coverage once scope is qualified. |
| MB-0733 | development, prelaunch, takeover, hardening | Supported PHTML context syntax coverage. Collection/unsupported contexts remain explicit. |
| MB-0736 | development, prelaunch, takeover, hardening | Supported inline-JS coverage, grouped with0733 on the same PHTML position; retain additional supported template scope. |
| MB-0739 | prelaunch, takeover, hardening | Supplied ini declaration evidence; correlate with0729 and keep web-worker runtime claims separate. |
| MB-0740 | prelaunch, takeover, hardening | Named declaration evidence; share observed path with0729 instead of a duplicate defect. |
| MB-0741 | hardening; conditional prelaunch/takeover when an explicit deployment baseline requires it | Backendpolicy comparison, not proof that any non-Redis alternative is insecure. Share0038backendfacts. |
| MB-0742 | prelaunch, takeover, hardening | Named hints/translation declarations; share0729 facts and preserve explicitmissing-vsdisabledstate. |
| MB-0744 | hardening, prelaunch, takeover; optional development maintenance scope | Library-maintenance subset, share0061 inventory/status evidence. Keep dev source scan offline by default. |

Proposed evidence profile groups0093 and0806 only as document/record lint. It is optional, Magebean-owned and does not mix ASVS/PCI identities. Its introduction and exact count must be validated alongside existing profile discovery/help.

Additional profile actions:
- basic stays small and evidence-oriented; no automatic inclusion of strict coding/build/governance policies.
- development gains supported template coverage and source consistency; no production-mode/TLS/live-cron requirements.
- prelaunch combines qualified source and deployed security/config evidence; local store URL discovery remains shared.
- takeover includes current technical debt/maintenance context and marks scope candidates distinctly from confirmed deployment defects.
- hardening carries explicit stricter baseline selections, not a blanket claim that every policy violation is a vulnerability.

Counts are finalized from the executable manifest after canonical selection and capability filtering. Do not advertise a larger rule count as success.

## Phase6 — integration, release and handoff

Deliverables:
- Full CLI regression; source/standardPHAR/one-timePHAR coverage for restored rules and grouped findings.
- Console SQLite import/re-import and agent/report compatibility. PreserveASVS/PCI definitions and historical snapshots.
- Representative small/medium target measurements for time, files/bytes and collection limits. Live-store validation only on a supplied authorized target; fixtures are not presented as live qualification.
- Updated rules:list, help, profile memberships, category/confidence/scope documentation, migration notes and smoke-gated PHAR builds.

Acceptance: all regressions green; no public API dependency silently made mandatory for offline development; no missing-data securityfinding; no duplicate counts in the agreed repros; profile discovery agrees with actualplans; releaseartifacts pass candidate gates before replacement.

## Execution order and milestones

0→1→2→3→4→5→6. Phase1 can be reviewed as a narrow corrective release. Data-contract/correlation decisions in phases2–4 precede final profile rollout, so newly restored coverage does not immediately duplicate existing findings. Each phase ships code, evidence-focused tests, updatedscope/revisionmetadata where needed and a concise completed/remaining report.
