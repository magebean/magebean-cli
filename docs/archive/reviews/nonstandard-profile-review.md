# Nonstandard profile QA review

Review date: 2026-10-08. Historical design proposal. The later removal of the full-inventory profile supersedes recommendations below to retain `baseline` and its `all`/`magebean` aliases; use `basic`, `hardening`, standards profiles, or explicit `--rules` selectors. Counts and observations below describe the reviewed snapshot.

Scope: basic, hardening, baseline, external, compatibility aliases and custom profile selection. ASVS L1-L3, OWASP Top 10 and PCI memberships are excluded. Three QA reviewers examined purpose, per-requirement membership, and CLI/dashboard contracts. Membership inventories are in [nonstandard-profile-review.json](nonstandard-profile-review.json).

## Decision

Expose two main production security presets: basic and hardening. Use explicit selectors or custom profiles for expert assessment work; retain external as the REMOTE execution preset. Aliases are alternate names, not additional profiles. Do not add operations, performance or maintenance profiles just to house every existing check; contextual policies can remain explicit/custom selections or optional tags.

| Canonical selector | Current inventory | Current autonomous / human | Proposed role and membership |
|---|---:|---:|---|
| basic | 20 | 20 / 0 | Default deployment security scan: 18 autonomous criteria |
| hardening | 82 | 41 / 41 | basic plus deeper protections: 21 autonomous + 32 optional human criteria = 53 |
| baseline | 684 | 41 / 643 | Expert assessment inventory, not another routine automation tier |
| external | 9 | 8 / 1 | REMOTE target preset: six HTTP/TLS criteria after remote binding corrections |

Counts precede target/capability filtering. External's eight nominal automated entries do not currently mean eight valid automated conclusions. The proposed 18/53 counts are a security-focused candidate, not new deployed behavior.

## Findings

1. **hardening and baseline run the same 41 autonomous IDs.** Baseline adds 602 human criteria beyond hardening, not extra default automated protection. Calling baseline a stronger daily scan misstates its scope.
2. **hardening is not a superset of basic.** Both hardening and baseline omit basic's MB-0728/0729/0730. They instead contain broad human password/debug criteria and Git-history scope. Production legitimately may not contain Git metadata. Hardening should retain basic's bounded production checks.
3. **Mandatory policy checks can overstate security findings.** Static artifacts, FPC enabled, Redis architecture, indexer state, cron recency/backlog, release age/latest version and Composer development conventions are not universal security requirements. An observably failed policy is not necessarily a vulnerability. Preserve their identities for appropriate contexts; move them out of generic security membership and use policy/informational classification where justified.
4. **MB-0055 overlaps MB-0049.** Both call the same Composer advisory checker; 0049 covers the collected lock inventory while 0055 selects its transitive subset and adds required_by. They can report the same package/advisory twice. Keep 0049 in nonstandard defaults and reuse transitive relationship evidence rather than count another vulnerability. Also test cross-source advisory grouping for 0049/0050; this review does not claim every pair is a demonstrated duplicate.
5. **REMOTE HSTS does not match its criterion.** MB-0027's remote variant requires only 15552000 seconds and remains heuristic, while the canonical scoped criterion requires 31536000. Even technical success cannot conclude the current remote requirement. Use an equivalent reviewed predicate and threshold.
6. **REMOTE FPC signals cannot prove a local declaration.** MB-0037's criterion reads env.php full_page cache declaration; its remote check observes HTTP cache signals and is heuristic. Remove it from remote security membership rather than imply configuration access. Human filtering currently occurs before recipe substitution, so target-mode proof must be checked as part of planning.
7. **REMOTE target-detection failure returns exit 0 without running requirements.** ScanCommand.php:208-214 returns SUCCESS if fingerprinting cannot confirm Magento, including transport failure. Distinguish inaccessible/indeterminate target from a confirmed unsupported target, report cause/action and return incomplete/failure status as appropriate. Empty primary requirement selection already fails; do not misdiagnose that path.
8. **Profile scope is not faithfully surfaced.** rules:list uses LOCAL membership/recipes even for external. It needs a mode-aware listing showing omissions and reasons; it does not currently return an empty external list. Explicit --rules intentionally selects outside profile membership; label these as explicit/subset scans instead of implying full profile coverage.
9. **Dashboard and CLI profile semantics differ.** The importer includes all members in assessments; CLI hides human criteria by default. The importer does not consume target mode or automation metadata and imports external as an ordinary profile. Agent manifests omit capability context used by the primary planner. Preserve assessment snapshots and compatible optional manifest fields when fixing these contracts.
10. **Documentation is stale.** README mentions basic21, hardening81 automated and baseline211 technical in places, while current primary counts are 20/41/41. Baseline's title says complete inventory although its 684 membership intentionally excludes three basic scoped alternatives from the 687-entry catalog. Report inventory, selected autonomous criteria, human criteria and supporting checks separately.
11. **Custom schemas need a clear boundary.** requirement_ids JSON is the primary selector schema; legacy profiles/packs have separate inheritance and named project lookup behavior. Arbitrary custom profile IDs/automation_only metadata can affect selection or classification. Derive execution semantics from the selected mode-specific obligations, not user-supplied labels.

## Proposed basic membership

Keep: MB-0001/0002/0003/0005/0007/0011/0026/0028/0029/0030/0031/0049/0050/0728/0729/0730.

Add MB-0009 (bounded configured admin session lifetime) and MB-0027 (observed HSTS).

Move these four to optional readiness/policy selection:

| ID | Rationale |
|---|---|
| MB-0006 | Changing an admin route is a policy/obscurity measure; absence alone does not establish high-severity exposure. |
| MB-0035 | Published static artifacts measure readiness. |
| MB-0037 | FPC enabled primarily measures cache/performance policy; high security severity is misleading. |
| MB-0046 | Installed cron entry does not establish successful execution; operations context is required. |

Do not pad membership merely to preserve the old count of 20. Publish the change as a revised profile and preserve old assessment snapshots. Basic still depends on readable filesystem/configuration, effective Magento settings, advisory API data and reachable trusted HTTP/TLS; it is not an offline scan and its speed must be measured.

## Proposed hardening membership

Automation: proposed basic18 plus MB-0042 (webroot log/report exposure), MB-0070 (declared lock/inventory consistency) and MB-0100 (admin-role relationship integrity). Their scoped conclusions do not prove global log retention, artifact authenticity or least privilege.

Retain 32 human security criteria through the human flag; exact IDs are in the proposal JSON. They cover runtime write/execute restrictions, broader authentication/access control, injection/data handling, CSRF/SSRF, upload safety, audit/security logging, payment-page CSP, headers and integrations. Human status is not a reason to discard a legitimate security requirement.

Move the following current memberships out of this general-purpose security preset:

| IDs | Context/action |
|---|---|
| 0006 | Optional admin-route policy. |
| 0014,0034 | Source/deployment conventions, rather than proof of exploitable input handling. |
| 0035,0037,0038,0039 | Static assets, cache enablement/backend choice and indexer readiness. |
| 0040 | Current criterion mandates Redis. It should be contextual to deployments using Redis and reviewed against their authentication/isolation model, rather than penalize other session backends. |
| 0046,0047,0048 | Installation, execution freshness and backlog are operations monitoring with schedule-specific thresholds. |
| 0055 | Transitive CVEs already covered by 0049; retain dependency-chain context as evidence. |
| 0056,0059 | Remediation feasibility/age should inform an existing issue or explicit policy. |
| 0057,0061,0062,0063,0065,0066,0067,0069 | Withdrawn/abandoned/old/inactive/latest package and Composer conventions are contextual supply-chain/maintenance signals. |
| 0072 | Source-history security belongs in a readable Git checkout; keep production working-tree secret scope0730. |
| 0102 | Existing criterion demands named PCI evidence artifacts. Do not require that documentation in general hardening; vendor-default-account protection itself remains valuable. |
| 0043,0052,0058,0060,0064 | Log lifecycle, module maintenance, extension currency, vendor support and forks need declared environment/security policy. They are not universally unnecessary; retain explicit human/custom policy use. |
| 0051,0053,0054 | Patch planning, compensating mitigation and KEV prioritization should attach conditionally to actual issues instead of count extra independent vulnerabilities. |

This removes 23 automated and nine human memberships and adds the three scoped basic alternatives, producing 53 total. It does not delete any global requirement or alter standard-profile membership. Severity/classification revisions need their own criterion-level review; changing a preset alone cannot fix a misleading result when an excluded criterion is selected explicitly.

## Baseline, external and aliases

The former full-inventory profile is removed. Expert assessment work uses explicit selectors or custom profiles. Global inventory enumeration should return687 without implying that scanning every criterion produces independent findings.

External candidate: MB-0005/0026/0027/0028/0029/0030. Fix the HSTS remote predicate first. Move static readiness0035 to explicit selection and exclude local-FPC0037 and broad human debug0379 from the remote security preset. A trusted HTTPS endpoint remains necessary for the scoped observations.

Keep default/best-practices -> basic and production/production-hardening -> hardening as compatibility aliases. The former full-inventory aliases all/magebean are removed. Display canonical names in product selection. Do not delete imported profile keys or silently reset existing baselines.

## Implementation sequence

1. Finalize a precise revised-profile specification: purpose, mode, version, requirements, prerequisites, human opt-in and policy classification. Produce before/after membership diffs; preserve OWASP/ASVS/PCI.
2. Fix shared correctness defects: mode-specific criterion binding/filtering, remote failure exit/action, custom automation metadata validation, mode-aware listing and explicit-scope report labels. Add focused regressions before changing memberships.
3. Introduce the revised basic/hardening/remote memberships through profile version metadata and coordinated dashboard import. Preserve existing baseline/assessment/result snapshots and profile keys; apply new membership to new or explicitly refreshed assessments. Document custom-schema/aliases and regenerate counts from catalog.
4. Verify invariants: basic subset of hardening; no default duplicate CVE evidence; all default selected mode recipes can conclude scoped PASS/FAIL with complete observations; missing prerequisites have actionable execution errors; human requirements need the flag; CLI/agent/dashboard counts, capabilities and frozen profile versions agree. Benchmark LOCAL/HYBRID/REMOTE on representative deployments before claiming fast execution.

No production deployment, catalog mutation, application code change or scan against external sites was performed for this review.

## Review evidence

The offline [selection/assessment probe](nonstandard-profile-observations.json) confirmed basic20, hardening41 and baseline41 default LOCAL counts, identical hardening/baseline autonomous ID sets, and the three missing basic criteria. For the default REMOTE profile, all eight checks were given synthetic successful observations: six criteria passed, while MB-0027 and MB-0037 still returned REQUIREMENT_AUTOMATION_INSUFFICIENT. No HTTP/API requests were issued by this probe. `rules:list --profile=external` was also executed: it lists eight LOCAL definitions, confirming the mode/view mismatch rather than an empty-profile claim.

Source anchors for follow-up implementation:

- `src/Rules/requirements/internal-profiles.json:696` basic; `:728` hardening; `:1170` baseline; `:1862` external.
- `src/Rules/requirements/internal-catalog.json:1314` remote HSTS threshold; `:1827` remote cache-signals observation.
- `src/Engine/ScanPlanner.php:66` human filtering; `:99` mode recipe substitution; `:69` explicit selection; `:125` automation metadata.
- `src/Console/ScanCommand.php:208` fingerprint rejection and success return; `src/Console/RulesListCommand.php:84` LOCAL-default catalog listing.
- `src/Engine/Checks/Families/ComposerAdvisoryChecks.php:40` all-package advisory method; `:729` transitive subset method; `:794` delegation to the same advisory method.
- Console sibling `app/Services/ImportSecurityCatalog.php:70` profile import, `:106` imported presentation metadata and `:133` default-included membership; `app/Actions/AgentJobs/QueueAssessmentScan.php:59` manifest generation.
