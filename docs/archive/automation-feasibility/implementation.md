# Magebean automation backlog implementation

Production scope clarification (2026-10-18): [production read-only review](production-readonly-review.md) supersedes any implication below that all pending adapters require a staging deployment or mutating integration tests. All 16 pending IDs were reassessed; read-only state/metadata predicates or supported static-semantic predicates are candidates, with explicit limitations. No additional checks were implemented by that review.

Validated 2026-10-18: all 111 CLI test files passed. The related Console suite passed 23 tests / 130 assertions. Local Console import loaded 764 requirements / 7 profiles; membership and structured remediation parity passed for all 139 Magebean definitions. Production was not deployed and the PHAR was not rebuilt.

Provider source diagnostics for Stripe, Adyen and legacy PayPal are documented separately in [provider-webhook-diagnostics.md](../../guides/provider-webhook-diagnostics.md). Their negative observations do not add verified webhook requirements or change the disposition of MB-0075. Current PayPal SDK/REST verification and complete end-to-end handler adapters remain pending.

This report maps all 50 historical backlog items to actual implementation. It does not claim that all 47 feasibility candidates were implemented or that production is fully protected. Original IDs and criteria stay preserved; new predicates use scoped identities.

| Disposition | Original backlog items |
|---|---:|
| ADAPTER_PENDING | 16 |
| NEW_SCOPED_CHECK | 24 |
| OUT_OF_SCOPE | 2 |
| REUSE_ACTIVE_SUBSET | 7 |
| SIGNAL_ONLY | 1 |

There are **22 distinct new scoped requirement IDs**. Multiple old items may share one new syntax predicate; those are counted once. Basic has 37, Hardening 79, and Magebean OWASP 51 catalog requirements. Actual selected checks depend on target mode and declared capabilities.

Strict native API bans require the `strict_native_api_policy` capability in the profile planner. These bans intentionally include benign uses and must be adopted as technical coding policy. Registry direct calls execute the requested predicate; they do not perform profile capability selection. Omissions and collection errors must remain visible, not implicit PASS.

Machine policy inputs are expected-state configuration. They do not contain statements that protection exists, reviewer approval or human evidence. Missing, malformed, stale or incomplete required inputs remain UNKNOWN.

```json
{"schema_version":1,"checks":{"production_direct_global_roles_approved":{"approved_role_ids":[2]},"production_integration_debug_defaults_disabled":{"paths":["example_vendor/debug/enabled"]},"dependency_mitigation_records":{"expected_ids":["temporary-1"]}}}
```

Place this in `.magebean/production-checks.json` only after replacing role IDs and vendor paths with the intended installed deployment policy. The example vendor path is illustrative, not a verified universal Magento integration setting. Worker readonly checks additionally require actual PHP-FPM worker PIDs and matching unprivileged scanner identity. Linux Xdebug checks require `.magebean/php-fpm-workers.json` with pool, PID and current process start_ticks. Invented or expired identities cannot pass.

Dependency source policy `.magebean/dependency-source-policy.json` uses `schema_version:1`, exact `root_repositories`, and a `packages` object keyed by package name. Each package must supply exact source/dist URL and nonempty reference plus expected replace declarations; explicit metadata-only metapackages are special. Both source and dist declarations are checked where present. This does not verify installed bytes or assert approved source is benign.

Mitigation `.magebean/mitigations.json` uses `schema_version:1`, current RFC3339 `generated_at`, and `records` with id, advisory, package, version, owner, action, rollback and future expires_at. The predicate validates declared record structure, freshness, expiry and nonempty configured expected IDs only. It cannot prove a mitigation is deployed, effective or comprehensively inventoried.

New finding guidance must describe exact observed syntax/config/runtime scope, safe remediation and rerun verification. Do not replace framework APIs solely to make a finding disappear; preserve validation, parameter binding, authorization, output-context handling and intended business behavior. Do not remove mandatory security logging to satisfy a debug policy. No payload contents, credentials, PHP process environ or memory addresses should be reported.

| Historical ID | Disposition | New scoped IDs | Related active IDs |
|---|---|---|---|
| MB-0004 | NEW_SCOPED_CHECK | MB-0799 | MB-0001, MB-0002 |
| MB-0748 | NEW_SCOPED_CHECK | MB-0800 | MB-0780 |
| MB-0731 | REUSE_ACTIVE_SUBSET |  | MB-0728 |
| MB-0010 | ADAPTER_PENDING |  | MB-0006, MB-0777 |
| MB-0101 | NEW_SCOPED_CHECK | MB-0801 | MB-0100 |
| MB-0102 | OUT_OF_SCOPE |  |  |
| MB-0732 | NEW_SCOPED_CHECK | MB-0786 |  |
| MB-0733 | ADAPTER_PENDING |  |  |
| MB-0736 | ADAPTER_PENDING |  |  |
| MB-0015 | NEW_SCOPED_CHECK | MB-0787 |  |
| MB-0016 | NEW_SCOPED_CHECK | MB-0788 |  |
| MB-0734 | NEW_SCOPED_CHECK | MB-0789 |  |
| MB-0735 | NEW_SCOPED_CHECK | MB-0790 |  |
| MB-0019 | NEW_SCOPED_CHECK | MB-0791 |  |
| MB-0020 | NEW_SCOPED_CHECK | MB-0792 |  |
| MB-0021 | NEW_SCOPED_CHECK | MB-0793 |  |
| MB-0023 | NEW_SCOPED_CHECK | MB-0794 |  |
| MB-0737 | NEW_SCOPED_CHECK | MB-0795 |  |
| MB-0743 | NEW_SCOPED_CHECK | MB-0795 |  |
| MB-0746 | NEW_SCOPED_CHECK | MB-0795 |  |
| MB-0025 | NEW_SCOPED_CHECK | MB-0796 |  |
| MB-0094 | ADAPTER_PENDING |  |  |
| MB-0095 | OUT_OF_SCOPE |  |  |
| MB-0097 | REUSE_ACTIVE_SUBSET |  | MB-0730 |
| MB-0098 | NEW_SCOPED_CHECK | MB-0797 |  |
| MB-0099 | ADAPTER_PENDING |  |  |
| MB-0089 | NEW_SCOPED_CHECK | MB-0802 | MB-0779 |
| MB-0096 | NEW_SCOPED_CHECK | MB-0803 | MB-0027, MB-0779 |
| MB-0738 | NEW_SCOPED_CHECK | MB-0807 | MB-0729 |
| MB-0739 | REUSE_ACTIVE_SUBSET |  | MB-0729 |
| MB-0740 | REUSE_ACTIVE_SUBSET |  | MB-0729 |
| MB-0742 | REUSE_ACTIVE_SUBSET |  | MB-0729 |
| MB-0745 | NEW_SCOPED_CHECK | MB-0804 |  |
| MB-0741 | REUSE_ACTIVE_SUBSET |  | MB-0038 |
| MB-0043 | ADAPTER_PENDING |  |  |
| MB-0051 | ADAPTER_PENDING |  | MB-0049, MB-0056 |
| MB-0052 | ADAPTER_PENDING |  | MB-0061, MB-0062, MB-0063 |
| MB-0053 | NEW_SCOPED_CHECK | MB-0806 |  |
| MB-0054 | ADAPTER_PENDING |  | MB-0049 |
| MB-0058 | ADAPTER_PENDING |  | MB-0061, MB-0062, MB-0063 |
| MB-0060 | ADAPTER_PENDING |  | MB-0063 |
| MB-0744 | REUSE_ACTIVE_SUBSET |  | MB-0061 |
| MB-0064 | NEW_SCOPED_CHECK | MB-0805 | MB-0063 |
| MB-0073 | NEW_SCOPED_CHECK | MB-0798 | MB-0026, MB-0029 |
| MB-0075 | ADAPTER_PENDING |  |  |
| MB-0076 | ADAPTER_PENDING |  |  |
| MB-0077 | SIGNAL_ONLY |  |  |
| MB-0078 | ADAPTER_PENDING |  | MB-0028, MB-0778 |
| MB-0079 | ADAPTER_PENDING |  | MB-0730 |
| MB-0081 | ADAPTER_PENDING |  |  |

Opt-in capabilities in the actual catalog:

| Capability | Scoped IDs |
|---|---|
| admin_role_policy | MB-0801 |
| dependency_mitigation_policy | MB-0806 |
| dependency_source_policy | MB-0805 |
| integration_debug_policy | MB-0804 |
| runtime_worker_access | MB-0799 |
| runtime_worker_inventory | MB-0807 |
| strict_native_api_policy | MB-0786, MB-0788, MB-0792, MB-0794, MB-0796, MB-0798 |

Declare intended capabilities through `--capabilities=NAME,NAME` when listing/scanning. Enabling a capability selects the predicate; it does not fabricate required policy files or runtime observations. For example `--profile=hardening --capabilities=dependency_source_policy` still needs the complete project-local source policy and lock metadata. Default scans report omitted capability-bound IDs; they do not claim those predicates passed.

Remaining adapters:
- Complete Magento route/role/ownership integration fixtures and protected-byte/side-effect oracles
- Provider-specific webhook HMAC/replay contracts and installed version mapping
- Context-aware HTML/JavaScript escaping and serializer semantics
- Effective secret-storage provenance across Magento config, database and actual secret stores
- Complete enabled-module/package and Marketplace/vendor support lifecycle/entitlement providers
- Dated complete KEV membership and CVE alias coverage contract
- Bound complete runtime logging architecture and retention/rotation adapters
- Namespace-aware effective firewall/CNI/gateway policy and complete cipher enumeration
- Actual integration ACL and network policy adapter with explicit integration inventory

Relevant regression tests:
- tests/AutomatedSourcePolicyTest.php
- tests/DependencyPolicyCheckTest.php
- tests/ProductionRuntimeCheckTest.php
- tests/ProductionCheckPolicyTest.php
- tests/LinuxWorkerObservationTest.php
- tests/AutomationBacklogRegistrySmokeTest.php
- tests/AutomationBacklogCollectionRegressionTest.php
- tests/HardeningCoverageTest.php

No production scan, production import or PHAR rebuild is implied by this report. Existing assessment snapshots retain their historical definitions; imported catalog changes require a fresh/updated assessment and new collected evidence.
