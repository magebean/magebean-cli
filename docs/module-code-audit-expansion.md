# Module code audit expansion — Phase 0

Planning baseline: CLI `master` at `fef01d1b84f1da243b9a1b887d18fd31d85e6fa6`. CLI and Console working trees were clean at kickoff under WSL Git. Scope: reconcile revision 4 and prepare implementation decisions.

## Catalog and selection

- Magebean has 139 active definitions across 12 controls, including 60 with `human_evidence.required`. All 50 automation backlog IDs overlap those 60. Start retirement from that union, not 110 separate records. Run `RequirementPolicy::requiresHuman` plus an audit for implicit reviewer gates before freezing the retirement manifest. Basic, Hardening and Magebean OWASP have 37, 79 and 51 automated members respectively before capability gating.
- `MB-0094` and `MB-0099` are both human-required with heuristic supporting evidence despite their automated verification label. Archive the original criteria. Use fresh IDs for bounded ACL/resource and download authorization detectors. Never map an old ID to a narrower meaning.
- `RequirementCatalog` loads authoritative family catalogs. `RequirementProfileCatalog` validates native membership. Audit `ScanPlanner::planCli`, `planAgent`, `RequirementPolicy::resolveIds/apply`, legacy aliases and Console custom-profile/import and manifest creation paths. Use owning family throughout. Reject retired interactive selectors with the ID and migration guidance. For old agent manifests preserve one result per item with an explicit retirement diagnostic and preserve the historical snapshot. Test old aliases and exact retired IDs.
- Archive full definition and revision, former memberships and aliases, and retirement rationale. Keep reserved allocations. Treat `internal-catalog.json` as generated compatibility output. Verify strict equality of ASVS and PCI slices and add behavior fixtures for their manual selection, human gate and MANUAL_REVIEW. Update counts from authoritative data. Tests that currently assert live human Magebean criteria should assert archived definitions and retirement behavior instead.

## Detector allocation matrix

Each row is a candidate set. A criterion enters the executable catalog only when its supported scope, proof, fixture and binding exist.

| Domain | Reuse or revise | New or backlog |
|---|---|---|
| Inventory | Reuse CollectionSession, CollectorSet, Composer metadata readers and BoundedSourceInventory traversal policy. | New provenance index for installed/enabled modules, package paths and separate theme inventory. Inventory alone has no requirement ID. |
| A. Structure | Reuse Composer constraints where the criterion is identical. | New registration/identity, installed-schema XML, explicit dependency and enumerated reference predicates. Add bounded autoload validation once symbol resolution is usable. |
| B. DI | Reuse the XML and symbol indexes. | New preferences and virtual types first, then arguments and plugins per supported area. Backlog unsupported merge/interception behavior. |
| C. Code/types | Reuse explicit source policies where their semantics fit. | New opt-in compatibility/type policies with a pinned target matrix. Select an analyzer after passive fixture and PHAR trials. |
| D. Authorization | Reuse attack-surface signals from AuthorizationSourceChecks. Archive MB-0094/0099 as above. | New REST ACL reference and public declaration observations first. Add bounded ownership and download source/sink/guard heuristics later. |
| E. Input/output | Review C03/C12 and MB-0786–0798. Revise only when the same criterion can be versioned for expanded source scope. Native-call rules remain explicit policies. | New context-aware sinks where existing policy criteria differ. Keep browser/JS coverage separate from PHP/PHTML. |
| F. Lifecycle | Reuse XML/symbol indexes. | New schema and patch class/interface/dependency checks. Backlog broader upgrade behavior until evidence supports a detector. |
| G. Reliability | Reuse handler inventory for cron and queues. | New invalid handler/reference checks, then supported unchecked failure or fail-open patterns. |
| H. Performance | Reuse query/call and loop source facts. | Optional observations for unbounded work and calls in loops. Backlog quantified production claims. |

Additional security work by dependency:

| Topic | First useful scope | Later candidate |
|---|---|---|
| Attack surface | REST declarations and controller/route inventory with enabled state | GraphQL, cron, queue, CLI, observer and import/export/upload/download attribution |
| Authentication and recovery | Collect exposed routes and supported auth declarations | Token generation/comparison and sensitive account operations with control-flow evidence |
| Sessions and tokens | Reuse scoped admin lifetime and cookie rules after accuracy checks | URL/log leakage and supported invalidation paths |
| Object, field and store isolation | Record request IDs and selected resource operations | Suspected path with input, sink and recognized guard evidence |
| API abuse | Record exposure and limits when explicitly declared | Mass assignment and request-controlled unbounded sizes |
| Browser security | MB-0029 for its existing markup/CSS scope and MB-0802/0803 for named response checks | JS/template context, DOM sinks, redirects, CORS and browser storage |
| Integration trust | MB-0804 scoped debug policy and MB-0787 explicit CSRF override policy | Signature/replay and alternative webhook protection evidence |
| Sensitive data | MB-0795 narrow direct logging rule plus existing source signals | Redacted dataflow into response, logs, cache or queues |
| Failure behavior | Deterministic handler/config checks | Supported fail-open branches and catch-and-continue after failed verification |

## Compatibility and implementation decisions

1. Extend `MagebeanRiskObservation` and the existing evidence projection. Keep category, severity, confidence and completeness separate from requirement outcome. A completed heuristic can emit a suspected finding with the requirement still UNKNOWN, or finish with no findings. A genuine collection gap remains incomplete, including when confirmed and suspected findings coexist. Preserve legacy result cardinality and verified-alternative behavior.
2. Prefer additive fields in envelope v1 after validating both consumers. Console `ApplyScanObservationToItem::riskObservationFor` currently checks schema version 1 and trusted family. If v1 cannot carry the needed semantics, implement compatible readers before producers. Cover clean, partial, suppressed and truncated observations and existing finding closure. `AgentResultMapper::sanitize` limits arrays to 50 elements while the risk producer can retain 100 rows. Test the boundary and propagate truncation explicitly. SARIF currently projects assessment rows, so add Magebean-specific detector locations and confidence while retaining ASVS/PCI projection.
3. Module discovery uses static registration and installed metadata under allowed roots. Treat module state and provenance as separate facts. Avoid routing passive inventory through executable PHP config readers. Resolve XSDs locally from the installed release with network and external entities disabled. Missing schemas and unresolved symbols become scoped diagnostics. Subject PHP, Composer scripts/plugins and registration stay passive.
4. Initial allocation candidates are module identity, XML schema validity, explicit dependency availability, selected symbol references and REST ACL reference validity. Use planning keys until their exact scope is accepted. Allocation manifest currently reports `next_id: 808`. Check retirement, aliases, family separation and consolidation history before allocating any numeric ID. Preserve C01–C12 meanings. Consider new structure and integration control groups after reviewing overlap. Keep Basic small, and introduce `module-integrity` once its executable membership and selection semantics can be documented.
5. Package milestones with `tools/build-phar.php` and its guarded candidate smoke flow. Validate installed schema availability offline, source/PHAR parity, agent envelope and capability gating. Benchmark small and larger authorized fixtures before setting runtime budgets.

## Accuracy workstream dependencies

The separate accuracy brief describes six reproductions against this HEAD. These are handoff items, with fresh reproduction required before each fix.

| Brief item | Expansion impact |
|---|---|
| MB-0787 parenthesized CSRF acceptance | Share expression and PHP parser fixtures before widening source coverage. |
| MB-0790 namespaced function resolution | Share symbol resolution and native-call fixtures. Include imports, fully qualified calls and locally defined functions. |
| MB-0029 symlink directory omission | Share bounded traversal/completeness contract, including markup/CSS support and scope boundaries. |
| MB-0009 environment precedence | Coordinate configuration provenance and runtime scope. Keep system-setting precedence separate from DI area merge. |
| MB-0030 redirect cookie loss | Independent HTTP work. Coordinate session reporting only if new evidence fields overlap. |
| Withdrawn OSV advisories | Independent advisory work. Keep dependency availability and vulnerability status as different predicates. |

## Magento semantics reviewed for planning

- Separate Composer dependencies from module configuration ordering. Resolve `sequence` as load-order evidence, not as the full dependency graph. [Adobe component load order](https://developer.adobe.com/commerce/php/development/build/component-load-order)
- Registration and module metadata support static discovery. Resolve each module root and package relationship independently. [Adobe component file structure](https://developer.adobe.com/commerce/php/development/prepare/component-file-structure)
- Preserve initial, global and area-specific DI stages. For each supported Magento version, verify merge keys and precedence against installed source and fixtures before claiming effective results. [Adobe DI configuration](https://developer.adobe.com/commerce/php/development/build/dependency-injection-file) · [Adobe plugins](https://developer.adobe.com/commerce/php/development/components/plugins)
- Treat `anonymous` and `self` as special permission declarations. Keep declared public exposure separate from effective access and object authorization. [Adobe authorization](https://developer.adobe.com/commerce/php/development/security/authorization) · [Adobe anonymous API restrictions](https://developer.adobe.com/commerce/webapi/rest/use-rest/anonymous-api-security)

Implementation order is retirement → findings contract → inventory → first structure and AppSec release → DI → deeper source analysis → lifecycle and optional policy → release qualification. Each release milestone carries its own regression and packaging gate.

## Baseline validation

WSL PHP 8.4.27 ran the full CLI suite via `php tests/run.php`. All 121 test files passed. The accuracy reproductions and Console integration tests are separate implementation gates. The tracked release binaries were left in place.

## Phase 1 rollout

Baseline v1 remains the criterion model. The 2026-11-03 documentation revision records the retirement of 60 human-required definitions and 79 active Magebean criteria. Original definitions and revisions are in `magebean-retirements.json`. The allocation manifest still reserves their IDs. Profile counts remain 37 Basic, 79 Hardening and 51 Magebean OWASP before capability gating.

Re-import the updated compatibility catalog in Console to mark retired rules deprecated. Existing assessment items retain their snapshots. Refresh an assessment or select a current profile to execute the active scope. Older manifests keep their item IDs and receive an explicit unsupported result for retired criteria. Explicit legacy MB-R technical checks still use the distinct legacy execution adapter. Canonical policy aliases to retired criteria produce a retirement diagnostic.

The detector matrix remains a roadmap. Fresh criteria enter the baseline with their executable detector and evidence contract.

## Phase 2 detector contract

Use MagebeanDetectorAnalysis::result() for bounded Magebean detection. Provide a stable detector and version, a stable issue key, confidence, category, severity, reasoning, and redacted scope/evidence. An empty gap list declares completed execution within scope. Report missing required inputs as gaps with a useful remediation step. Supply scoped suppression summaries separately. The detector factory excludes arbitrary source fields and redacts recognized credential assignments as a second layer. Detector authors must still avoid putting secrets or customer values in messages.

The Magebean v1 risk envelope adds detector_runs, observations and per-finding metadata. Findings, suppression, truncation, and collection gaps are separate. Informational rows do not open a finding. Finding fingerprints use requirement, detector, check, issue key, subject and locations. JSON retains the original assessment row. SARIF projects individual observations and collection gaps for Magebean and retains the existing standards projection. Agent retains the v1 wire statuses and up to 100 rows in each envelope list. A completed detector may still produce wire error when the requirement conclusion is UNKNOWN. Consumers should use the envelope to interpret execution. Complete detection without a requirement conclusion cannot approve the requirement or close an existing finding.

Console reads the additive envelope using trusted assessment family and displays confidence and context on finding detail. Existing wire clients remain compatible. New detector behavior is exercised through fixtures, with production detector expansion scheduled for later phases.

## Phase 3 collection and indexes

Use the scan-scoped CollectorSet services magentoModules and magentoAnalysis. Inventory reads the literal Magento deployment module map, app/code, app/design and Composer installed.json. Composer v2 install paths are resolved from the metadata directory. Composer v1 uses the conventional Composer layout and labels that fallback. Standard registration.php declarations and named registration.php entries in Composer autoload files identify candidate roots. Multiple roots per package and duplicate identities retain separate provenance. Missing metadata and dynamic registrations surface as gaps. Discovery never executes the inspected PHP. Themes remain a separate inventory.

Source indexing requires explicit module names and a unique root per identity. It records discovered, selected, excluded and scanned root counts and keeps source text internal. PHP and XML reads use the existing bounded inventory with opt-in exclusions and stat checks. The read checks detect changes visible to filesystem metadata and do not provide an atomic snapshot. The root budget is 100 per invocation. The PHP index resolves declaration names, inheritance, interfaces, traits and method signatures using PHP-Parser 5.6.1. The index describes source declarations. It does not resolve Magento-generated classes or runtime autoload behavior.

The XML index records file, area, document kind, and declared schema URN. Optional validation resolves module and framework XSDs from the installed project. The bounded XSD graph supports project-local relative references and recognized Magento URNs. Libxml can read only preloaded schema dependencies through synthetic URIs. DTDs, remote schema references, missing schemas and unsupported graphs return an unavailable result. Schema rejection is reported separately. Effective configuration merges and detector/profile bindings follow in later phases.

## Phase 4 module integrity profile

Run `magebean scan --path=/path/to/magento --profile=module-integrity` for modules discovered in app/code. Add `--modules=Vendor_First,Vendor_Second` to replace that source scope with exact installed module names, including Composer packages. The profile selects seven local Magebean criteria and is exclusive. Agent manifests can specify the optional module_names list. Existing agent manifests selecting these IDs use the default app/code scope.

| ID | Detector kind | Evidence and boundary |
|---|---|---|
| MB-0808 | identity | Confirm literal registration versus module.xml mismatch and duplicate literal registrations. |
| MB-0809 | xml | Confirm malformed supported XML or rejection by its declared project-local installed XSD for module, routes, webapi and ACL documents. Missing schema or unsupported input is incomplete. |
| MB-0810 | dependencies | Confirm a declared package name is absent from installed metadata after checking installed provide/replace identities. Composer versions, platform requirements and module load-order semantics are outside scope. |
| MB-0811 | rest-service | Check directly indexed public service methods for global webapi.xml. External or inherited resolution outside the indexed subset is incomplete. |
| MB-0812 | rest-acl | Flag suspected unresolved ACL references using the static global ACL declarations of enabled modules. Reserved resources anonymous and self are recognized. |
| MB-0813 | rest-anonymous | Report REST and controller declarations as inventory. Flag suspected exposure for enabled anonymous REST routes matching the documented sensitive path segments. Effective access remains a runtime question. |
| MB-0814 | request-logging | Reuse the existing direct request logging syntax policy on selected module roots. This separate criterion preserves the original app/code rule scope. |

The release uses the Phase 2 detector envelope. Informational routes do not change the exit status. A confirmed finding can coexist with incomplete collection. Source analysis is passive and bounded by the Phase 3 limits. Composer source is opt-in and core module metadata can provide reference context. Phase 5 remains the boundary for effective DI analysis.

## Phase 5 DI integration

Module Integrity now includes MB-0815 through MB-0818 for preferences, virtual types, constructor arguments and plugins. The profile has 11 criteria. Effective declaration projection reads initial DI, enabled modules in deployment config order, and supported area overlays (frontend, adminhtml, graphql, webapi_rest, webapi_soap, crontab). Only effective declarations contributed by selected modules produce findings. Global and area-specific evidence carry file and line provenance. Source symbol lookup is limited to selected modules.

The checks cover preference compatibility, virtual type cycles, named constructor parameters, selected array mismatches, and directly configured enabled plugins on known non-interceptable targets. Plugin disables apply by exact configured subject and plugin name. Array item merge and value evaluation, generated classes, plugin signatures and ordering, runtime configuration, and nonstandard areas are outside the supported projection. Missing symbols and unresolvable inheritance are collection gaps. DI values are not exported.

## Phase 6 source analysis

Run magebean scan --path=/path/to/magento --profile=module-source for custom modules, or add --modules=Vendor_Module to select installed module source. This separate opt-in profile selects four local criteria.

| ID | Scope |
|---|---|
| MB-0819 | Compare selected PHP syntax features against Composer config.platform.php for PHP 8.1–8.4. Includes readonly classes, DNF types, typed class constants and property hooks/asymmetric visibility. An unspecified or unsupported target is incomplete. |
| MB-0820 | Compare directly redeclared methods to uniquely indexed public methods on their immediate parent or interface. Covers visibility and staticness. Variance, external symbols, trait composition and whole-program contracts are outside scope. |
| MB-0821 | Check explicit magento/framework Composer constraints against the installed numeric release version. Package API compatibility is outside scope. |
| MB-0822 | Report suspected request data reaching named query methods or resolved shell functions via direct concatenation, interpolation, or one local assignment. Does not follow calls, branch joins or property assignments. Bound SQL parameters and casts outside the recognized flow are excluded. |

The analyzer reuses PHP-Parser and Composer Semver and runs without loading the target project. PHP files and collection limits follow the module source inventory. Evidence contains file/line and module attribution without literal queries or input values. Browser/JavaScript analysis requires a separate parser and capability and is deferred. Existing criteria and profiles retain their memberships.

References: [PHP 8.2 features](https://www.php.net/releases/8.2/en.php), [PHP 8.3 features](https://www.php.net/releases/8.3/en.php), [PHP 8.4 features](https://www.php.net/releases/8.4/en.php), [Adobe SQL guidance](https://developer.adobe.com/commerce/php/best-practices/extensions/security).

## Phase 7 lifecycle and operations

Select module-lifecycle for schema, patches and handlers. Select module-reliability separately for optional source observations. Both profiles accept the existing module selection option and follow the bounded local inventory.

| ID | Scope |
|---|---|
| MB-0823 | Validate selected global db_schema.xml syntax and its declared local XSD. Missing XSDs are collection gaps. Database state and effective merged schema are outside scope. |
| MB-0824 | Match setup patch files to the classes derived from module name and path. Check concrete class and interface, and detect cycles and incompatible references in supported literal dependency lists. Dynamic dependencies, cross-kind dependencies and unresolved external symbols remain incomplete. |
| MB-0825 | Check public method references in global cron, enabled communication handlers and explicit handlers on default queue consumers. Custom consumers, handler precedence and dispatch execution are outside scope. |
| MB-0826 | Report empty catch bodies as suspected reliability observations. Intentional exception handling policy requires application context. |
| MB-0827 | Record direct query-like method calls in loop bodies as informational. They do not affect exit status or security counts. Runtime cost and loop cardinality require measurement. |

These checks read installed source and XML and do not run patch, setup, cron or queue commands. Transaction boundaries, idempotency, runtime retries and data retention remain outside the covered predicates.

References: [Adobe declarative schema](https://developer.adobe.com/commerce/php/development/components/declarative-schema/configuration), [setup patches](https://developer.adobe.com/commerce/php/development/components/declarative-schema/patches), [patch reader](https://raw.githubusercontent.com/magento/magento2/2.4-develop/lib/internal/Magento/Framework/Setup/Patch/PatchReader.php), [queue configuration](https://developer.adobe.com/commerce/php/development/components/message-queues/configuration).

## Phase 8 release qualification

The checksums in this section describe the Phase 8 snapshot. Later profile builds have their own manifests under build/.

The CLI suite passed all 125 test files under PHP 8.4.27 on WSL. Both PHAR builds passed the production dependency allowlist, listing and runtime smoke tests, and the module audit fixture. The build now runs that fixture against the candidate before replacing the local artifact. Variant-specific manifests are written under build/.

The aggregate was compared against all three authoritative catalogs. It contains 724 active requirements across 11 profiles. The 60 archived Magebean definitions match their original definitions and retain reserved IDs. ASVS and PCI requirements, aggregate slices and profile definitions match the original baseline.

An isolated Console SQLite test imported the original catalog, upgraded it to the new catalog, and repeated the import. It verified 724 rules, 11 profiles, exact membership in the four module profiles, deprecation of a retired rule with the same database ID, and preserved ASVS/PCI rule mappings, verification methods and profile membership.

The full Console suite is still red. In an equivalent isolated environment, the candidate ran 387 tests with the same 25 failures and one error as the 386-test clean HEAD baseline. The workspace run had one additional 403 in EmptyApplicationContextTest that did not reproduce with the candidate in the isolated environment. Catalog migration and the focused Magebean observation tests passed. Review the Console baseline failures before production rollout.

| Local artifact | Bytes | SHA-256 |
|---|---:|---|
| magebean.phar | 1819274 | 9400a36bd0bb6937f20f5b6f60a720c485691e5aef5c65131d71ac323359d764 |
| artifacts/magebean-one-time.phar | 1819274 | 3147326e823b08f89169517af18f8b6f59f334f4ba842176c44d4c6d27503d90 |

Each archive contains 702 files and 11 runtime packages. The release guard found zero forbidden files.

The benchmark used the standard PHAR on the same WSL host. Each synthetic fixture included enabled app/code modules, simple PHP classes, a static patch, installed schema references, a DI preference and a cron declaration. Each profile ran three separate CLI processes per fixture. The table reports median wall time and maximum process RSS using GNU time. All 24 runs returned exit 0. These figures describe the synthetic fixtures.

| Profile | 3 modules / 39 PHP files | 30 modules / 1,290 PHP files |
|---|---:|---:|
| module-integrity | 0.26 s / 60.3 MiB | 0.62 s / 63.6 MiB |
| module-source | 0.26 s / 60.1 MiB | 0.65 s / 60.9 MiB |
| module-lifecycle | 0.25 s / 60.2 MiB | 0.56 s / 62.4 MiB |
| module-reliability | 0.25 s / 60.0 MiB | 0.49 s / 60.1 MiB |

### Rollout

1. Stage the CLI artifact and matching src/Rules tree. Verify the checksum above and confirm the intended Console version accepts the v1 findings envelope.
2. In the intended Console environment, run `php artisan security:catalog:import /absolute/path/to/magebean-cli/src/Rules`. Verify the four module profiles contain 11, 4, 3 and 2 criteria respectively. Retired rules should be deprecated and historical assessments should retain their snapshots.
3. Run a local scan against an authorized staging Magento root with the desired module profile and explicit Composer module names where applicable. Review collection gaps before interpreting results. For module-source, set Composer config.platform.php to the deployment target.
4. For agent jobs, confirm the binary and Console catalog are from the same release and inspect the resulting v1 observation payload. Agent manifests may specify module_names. If the field is omitted, the module profiles inspect discovered app/code modules.

Browser/JavaScript analysis remains deferred. Setup mutations, effective runtime handler dispatch, and measured production performance remain outside these static checks.
