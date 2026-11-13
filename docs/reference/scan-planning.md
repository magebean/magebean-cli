# Scan planning

ScanContext holds the resolved target and its metadata. ScanRequest adds adapter options; ScanPlan contains the selected pack and execution metadata. ScanService delegates a compiled plan to ScanRunner and returns an immutable ScanReport.

## CLI selection

ScanPlanner::planCli loads project policy and canonicalizes capability list/map inputs. It resolves the source-family profile, applies validated profile default capabilities, target-mode applicability, explicit selection, control/manual filters, exclusions and overrides. Explicit project false values override profile context defaults; explicit CLI capabilities enable them. Profiles select assessment intent, not evidence that a condition works.

Basic remains the default. Hardening selects strict_native_api_policy, cache_backend_policy and dependency_maintenance by default. Development remains offline. Details and counts are in [profiles](../guides/profiles.md). Direct IDs respect family and capability boundaries; development/prelaunch enforce their member scope, with MB-0731 retained as a compatible selector where canonical MB-0728 is a member.

A selected rule may remain UNKNOWN after collection. Omitted context rules and rule/filter exclusions remain distinguishable from execution gaps. The text summary reports selection, not completed coverage. Raw metadata retains omitted requirements and diagnostics.

## Agent selection

ScanPlanner::planAgent compiles the bundled catalogue and manifest order, preserving requested keys and unsupported entries. It does not discover project profiles, inherit CLI defaults or perform console remote preflight. Capabilities must be supplied explicitly in the manifest. The current Console importer does not propagate CLI profile default context into queued manifests.

Empty unsupported-only agent plans retain the existing payload correspondence. AgentScanner owns redaction, title/timestamp transport metadata and mapping; PendingOutbox owns reliable delivery. See [contracts](scan-contracts.md), [reliability](scan-reliability.md) and [reporting](../guides/findings-and-output.md).
