# Production profile specification — proposal

Date: 2026-10-08. This supersedes the security-only hardening21 proposal for Production. No application code or catalog membership is changed by this document.

## Purpose

Production verifies security controls, deployment readiness and operational health of a Magento deployment. It is entirely automated. Genuine human requirements remain in inventory/custom assessment; ASVS level and PCI profiles retain their standard scope.

Candidate membership: 40 requirements = current41 autonomous hardening members + basic scoped0728/0729/0730 -0014/0055/0069/0072. Forty is a design inventory, not a claim that every deployment should execute or fail every item. Profile promotion requires the criterion and applicability revisions below first.

| Group | IDs | Count |
|---|---|---:|
| Security and production configuration | 0001,0002,0003,0005,0006,0007,0009,0011,0100,0026,0027,0028,0029,0030,0031,0042,0049,0050,0728,0729,0730 | 21 |
| Deployment/cache/session readiness | 0034,0035,0037,0038,0039,0040 | 6 |
| Scheduled execution | 0046,0047,0048 | 3 |
| Dependency/release policy | 0056,0057,0059,0061,0062,0063,0065,0066,0067,0070 | 10 |

All IDs use the MB- prefix and four digits. Classification is per requirement; a group label does not turn every member into a security finding. The current basic20 membership is a subset of this candidate40.

## Conditions before rollout

- 0006 custom admin route: advisory/policy, never high-severity exposure merely because the route is admin.
- 0034/0035 artifacts: respect deployment mode, installed scope/locales/themes and external build/CDN strategy. A convenience file is not proof of serving readiness. Label observed artifact scope precisely.
- 0037 FPC enabled: operational/performance policy, not a high security defect. Respect explicitly disabled cache and deployment context.
- 0038 Redis/Varnish: current predicate mandates architecture. It must be revised to assess the configured supported cache backend against declared deployment policy, not require Redis/Varnish universally. Until reviewed, retain the old criterion as optional custom policy; it is not ready for generic Production membership.
- 0040 Redis session auth: apply only when Redis session storage is actually used. Review authentication and isolation alternatives; a nonempty password string does not prove authentication enforcement. Other backends are not failures of a Redis-specific requirement.
- 0039 indexers: assess installed indexer states and observation time. Transient working status should be contextual operational attention, not a confirmed security defect. Missing state remains collection error.
- 0046 scheduler installation: acknowledge system cron, managed/platform schedulers and container orchestration. A host crontab is not the only legitimate scheduling mechanism.
- 0047/0048 schedule/backlog: derive or declare expected schedule, observation window and warning/critical thresholds. Current fixed900seconds/1000jobs must not be universal vulnerability criteria. Distinguish expected idle deployments and failed/stuck jobs; retain read-only cron_schedule evidence.
- 0056 fixed-version feasibility and0059 advisory age: relate to the affected dependency/advisory and declared remediation policy. Attach remediation context to the existing incident instead of counting another CVE.
- 0057/0061/0062/0063: withdrawn, abandoned, release age and unavailable source repositories are lifecycle/policy signals. None independently establishes an exploitable vulnerability. Private repositories and an unchanged maintained library need valid applicability/evidence, not a false FAIL.
- 0065/0066/0067: declared Composer policy signals. Locked production versions are distinct from future update constraints. Without an enforced project policy, show advisory observations rather than mandatory security failures.
- 0049/0050: preserve separate requirement conclusions and data provenance, but group the same advisory/package/version incident across sources. Advisory data must be complete for the selected inventory; missing data is not PASS.

Removed from generic Production:

- 0014: blanket superglobal prohibition is a development convention, not proof of exploitation.
- 0055: transitive advisory findings already covered by0049; dependency-chain evidence can be reused.
- 0069: not being the latest stable version does not establish insecurity.
- 0072: full Git-history review belongs in a readable source checkout. Production uses0730 working-tree secret scope; retain0072 for explicit/custom source review.

## Execution and reporting contract

Use security, operational and policy/advisory classifications with separate counts. Display deployment readiness and security posture separately. Actual security failures remain FAIL; operational failures are actionable operational results; informational lifecycle signals do not inflate security finding totals.

Applicability must use positive evidence or declared configuration. Supported nonapplicability is distinct from PASS and missing evidence. Examples: a file-session deployment is not applicable to a Redis-auth criterion, but an unreadable env.php cannot establish its backend. An unresolved condition remains an actionable execution error. Introduce applicability presentation/wire behavior compatibly rather than inventing a PASS or silently omitting coverage.

Every incomplete check carries input/source, reason, action and responsible operator/provider/tool owner. Internal detector exceptions remain isolated; deadlines and worker cancellation retain their contracts. Scan summaries must never appear clean when mandatory collection failed.

Declare prerequisites: read-only filesystem/configuration, scoped database SELECT access, trusted reachable store URL, required PHP extensions and complete advisory API data. URL discovery should use deployment configuration/DB when available; --url overrides missing or incorrect discovery.

Execution order: inexpensive local configuration/inventory first, read-only DB observations next, HTTP/TLS/API collection last. Reuse observations only for the same target, arguments and scan; keep bounded deadlines and measure representative deployment performance before calling the profile fast. Do not re-run the same advisory query solely to repeat an incident.

## Rollout

Use production as the visible canonical profile and hardening as a compatibility alias only through a coordinated profile-key migration. Do not simply rename the JSON key: dashboard plan/access rules, imported keys and baseline references must be preserved. Keep old profile versions/assessment snapshots immutable and apply new memberships to new or explicitly refreshed assessments.

Before implementation, finalize the revised criteria and policy defaults above; assemble candidate membership from known IDs, then validate no human obligation, basic subset, contextual applicability, incident deduplication and CLI/agent/dashboard parity. Profile count alone is not an acceptance criterion.

This is a reviewable design proposal. Current production/hardening remains82 inventory members, with41 autonomous default selections.
