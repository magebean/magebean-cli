# Development profile QA

Scope: the current 28-member development profile, especially MB-0808–MB-0825 and MB-0828. Review performed by three independent QA agents plus integration review. The initial review was read-only. The remediation section below records the subsequent authorized fixes; original findings are retained as the audit trail.

## Verdict

The source-focused direction is appropriate, but the profile is not ready to describe as a dependable development audit without qualifications. It excludes production mode, deployed TLS, runtime cookies, cron health and generated-artifact checks as intended. However, ordinary source checkouts lose important DI and REST coverage, and some checks have reproducible correctness issues. Advisory data acquisition is not implemented.

## Confirmed findings

| Priority | Rules | Evidence and impact | Recommended action |
|---|---|---|---|
| P1 | MB-0828 | ComposerAdvisoryChecks::auditOffline reads lock packages without validateLockScope. A lock containing one valid dependency and another dependency missing its version can return a clean result after silently dropping the malformed dependency. Source: src/Engine/Checks/Families/ComposerAdvisoryChecks.php:504–521. | Reuse strict lock-scope validation before matching. Keep already established findings while reporting incomplete coverage. Add mixed-valid/invalid and duplicate-package regression cases. |
| P1 | MB-0787 | AutomatedSourcePolicyCheck.php:51 recognizes only the exact return true token sequence. validateForCsrf returning (true) is equally unconditional but is reported clean. | Resolve supported constant boolean expressions using the existing parser, and distinguish unsupported expressions from clean coverage. |
| P2 | MB-0789, MB-0790 | AutomatedSourcePolicyCheck.php:97–101 treats unqualified native-looking call names as native functions without namespace resolution. A namespace-local exec or unserialize function causes a false positive. | Resolve namespace-local declarations and use-function aliases; reserve definite native findings for resolved built-ins. |
| P2 | MB-0815–MB-0818 | MagentoDiConfiguration.php:23–24 returns no scopes when module order is unavailable. Development explicitly permits no app/etc/config.php, so all four DI checks are skipped in that supported checkout state. | Separate declaration-level source checks from effective merged configuration. Do not invent runtime merge order. Report missing runtime context separately. |
| P2 | MB-0815–MB-0818 | MagentoDiCheck.php:28 indexes only selected module symbols. Default app/code selection therefore cannot resolve many installed Magento interfaces and parent classes used by ordinary custom DI declarations. | Keep findings scoped to selected modules, but use bounded installed dependencies/core as symbol context. |
| P2 | MB-0812, MB-0813 | MagentoModuleIntegrityCheck.php:190–192 skips ACL/anonymous route inspection when module enablement is unknown. A source checkout without config.php loses declared access-boundary analysis. | Inspect declarations in development while explicitly avoiding a claim that those routes are deployed or enabled. Keep effective deployment semantics separate. |
| P2 | MB-0828 / profile prerequisite | A hardcoded .magebean/osv-db.json is required, but the CLI neither provides the dataset nor has an acquisition workflow. That path is only an expected input, not an existing project directory or supplied database. The missing input creates incomplete execution by default. | Design advisory availability explicitly using the existing feed/cache architecture or an opt-in snapshot. Preserve offline source analysis and distinguish unavailable evidence from a successful lookup. Do not silently replace this with a mandatory online dependency. |

### Additional source-analysis gaps

- MB-0822: MagentoModuleSourceCheck.php:199 skips named arguments and :209 requires fully qualified native function names. Reproduced flows(): exec($_GET['x']) in a namespace, fully qualified exec(command: $_GET['x']), and proc_open input yield no flow, whereas positional fully qualified exec does. MB-0790 may independently catch a broad API policy violation, so this is not a claim that the whole profile misses all such examples. Resolve call identities and argument binding or report unsupported syntax explicitly. The command API list is bounded and must be documented.
- MB-0820: MagentoModuleSourceCheck.php:78 silently skips absent/ambiguous parent symbols. Installed framework parents are normally outside selected source roots. This respects the narrowly scoped indexed-contract criterion but does not establish whole-module compatibility; report unresolved contract coverage.
- MB-0819 covers enumerated language features, not every incompatible syntax construct. Composer config.platform.php is an analysis target, not proof of the deployed PHP version. MB-0821 checks explicit Framework constraints against installed metadata, not all API compatibility.

## Coverage limitations, not confirmed defects

- MB-0825 verifies public methods on uniquely indexed handler symbols. An abstract handler can pass this narrow declaration test. That does not establish a valid runtime handler, but DI may supply a concrete implementation, so abstractness alone is not proof of a defect. Resolve effective construction before making stronger claims.
- Installed packages and local XSDs are reasonable prerequisites for schema and framework compatibility. Missing vendor data must remain an explicit coverage gap, not a security finding or a false clean result.
- Existing scoped unsafe-operation policies are not complete injection, SSRF, authorization or browser/template analyses. Profile membership must not imply those broader capabilities.
- Suspected source patterns must retain confidence independently from severity. Hiding confidence in the overview must not remove it from detailed/exported evidence.

## Verification

The following seven current tests passed during this QA: DevelopmentPrelaunchProfileTest, MagentoModuleAnalysisTest, MagentoModuleIntegrityProfileTest, AutomatedSourcePolicyTest, OptionalCustomSourceScopeTest, SourceInspectionFindingsTest and OsvSeverityTest. Output was recorded at /tmp/magebean-development-qa-tests.log. Independent adversarial fixtures exposed the issues above despite those passing tests. Passing this set is not a full-suite or real-project qualification.

## Required acceptance cases before closing QA

1. Source checkout with Composer identity and installed dependencies, without config.php/env.php, URL or database: meaningful declaration findings still appear; missing effective context is explicitly scoped.
2. A custom module referencing installed framework symbols: supported valid DI does not become unresolved merely because vendor modules were not selected for findings.
3. Equivalent unconditional CSRF acceptance syntax, namespace-local native-looking functions, function aliases and explicit built-ins.
4. Missing, malformed and usable advisory evidence; malformed lock entries alongside valid entries; successful zero-match lookup distinguished from unavailable evidence.
5. Source CLI and both packaged variants agree on membership and findings. Preserve external-standard profiles and existing rule identities.

## Implementation order

First address false-clean results and false positives. Next separate source declarations from runtime-dependent DI/REST context and add dependency symbols. Finally redesign advisory provisioning and requalify the default development workflow. Keep current requirement IDs and historical results; update criteria/revisions when behavior meaning changes.

## Remediation completed

- MB-0787 uses AST method bodies, including parenthesized true literals.
- Native unsafe-operation policies distinguish namespace-local functions from resolved built-ins; unresolved fallback/indirect calls retain gaps.
- MB-0812/0813 inspect development source declarations without claiming activation or live exposure.
- MB-0815–0818 use independent per-file source scopes when effective order is unavailable. They do not synthesize a merged module order. Installed Composer PSR-4/PSR-0/classmap references provide bounded passive symbol context without executing autoloaders.
- MB-0820 reports unresolved/ambiguous contracts and uses dependency symbol context. MB-0822 binds supported native named arguments and resolved call identities; unsupported bindings remain gaps. PHP target messages describe the analysis target.
- MB-0824/0825 use dependency symbols; patch graphs crossing outside the selected patch subjects remain explicit coverage gaps rather than clean graphs; inherited handlers can resolve, while abstract/interface construction remains unresolved coverage rather than a confirmed runtime defect.
- MB-0828 validates raw lock scope and is opt-in through local_advisory_snapshot. Default development/prelaunch selections are 27/51; full memberships remain 28/52. No dataset or project directory is fabricated.
- Changed source/effective criteria retain previous text in criterion_history with a new revision. Rule IDs and ASVS/PCI criteria remain unchanged.

Three focused regression files add 55 assertions: DevelopmentSourceQaRegressionTest (28), DevelopmentModuleDeclarationsTest (12), DevelopmentLifecycleAdvisoryRegressionTest (15). All passed. Final qualification: all 130 test files passed. Both standard and one-time PHAR builds passed their release checks, including packaged module, development/prelaunch and takeover fixtures. Logs: /tmp/magebean-development-fixes-final-suite.log and /tmp/magebean-development-fixes-final-{standard,one-time}.log.

Remaining limits: source policies are bounded static analysis; unresolved names, unsupported dispatch, missing dependencies, incomplete schema context and exceeded budgets remain explicit gaps. Declaration-only results do not establish runtime activation or a fully merged Magento DI configuration. No live customer Magento project has been qualified in this remediation run.
