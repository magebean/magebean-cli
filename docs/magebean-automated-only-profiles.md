# Magebean automated-only profile contract

This supersedes the earlier mixed technical/human Hardening expansion and Basic external-checklist presentation.

| Profile | Automated inventory | Human requirements | Manual checklist |
|---|---:|---:|---:|
| Basic | 37 | 0 | 0 |
| Hardening | 79 | 0 | 0 |
| Magebean OWASP | 51 | 0 | 0 |

Hardening contains all current automated Basic and OWASP members. Source-family separation remains unchanged. ASVS/PCI retain their own evidence assessment workflow.

The earlier Hardening107 count included50 criteria that cannot currently be established automatically. These are removed from executable profiles and recorded in `src/Rules/requirements/magebean-automation-backlog.json`, alongside the removed external tasks. Original definitions, IDs, criteria and historical results are preserved; supporting keyword checks are not relabelled as verified predicates. The original criteria subsequently moved to the non-executable Magebean retirement archive in baseline revision 2026-11-03. Their IDs and historical results remain available for reference.

The automation implementation adds **22 fresh scoped requirements (MB-0786–MB-0807)** while preserving all **50 original backlog definitions and criteria unchanged**. Thirteen cover explicit source coding policies and nine cover bounded production/runtime/dependency observations. These additions do not mean 22 original requirements are fully satisfied: several originals share one narrower observation, and some topics already have partial active coverage. See the per-ID integration manifests under `docs/automation-feasibility` for the exact mapping and limitations.

Default LOCAL selection is Basic **37**, Hardening **67** and OWASP **41**. Twelve Hardening members are omitted without explicit context: six strict native-API coding policies and six machine targeting/expected-policy checks. The complete local Hardening inventory is selected only with all applicable capabilities: `strict_native_api_policy`, `runtime_worker_access`, `admin_role_policy`, `integration_debug_policy`, `dependency_source_policy`, `dependency_mitigation_policy` and `runtime_worker_inventory`. Enabling a capability does not assert protection: each check must still collect its real observations and validate required typed inputs. Missing context is reported explicitly; missing or malformed inputs after selection produce UNKNOWN.

The new predicates do not prove full authorization, arbitrary-code absence, complete data flow, all-worker coverage, enrollment or operational effectiveness. Source bans and declaration checks are explicit policies rather than findings of confirmed exploitability. Basic remains unchanged by this expansion.

Both CLI profile validation and Console import reject human-evidence members or manual checklists in the three native Magebean profiles. The manual-review flag cannot add backlog entries. Missing source, runtime access or API data remains an execution error with collection guidance; it does not become a human evidence task or a clean result.

Re-import the current catalog after deploying Console/CLI updates. New assessments use automated-only membership; existing assessment snapshots retain their historical contents and need an explicit profile refresh/new assessment to adopt the new contract. Production was not deployed and the PHAR was not rebuilt by this change.
