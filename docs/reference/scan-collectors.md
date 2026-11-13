# Collectors and per-scan observations

CollectorSet separates acquisition from predicate interpretation and shares participating collectors through CheckRegistry for one runner invocation. It is not an atomic snapshot of a changing filesystem.

| Collector | Responsibility |
|---|---|
| FileCollector | Bounded/reusable local file observations for participating source/Composer checks. |
| CodeInventoryCollector | Extension/path inventories preserving scope and enumeration policy. |
| ComposerCollector | Legacy-safe JSON/lock projection for compatibility checks. |
| DependencyInventory | Current installed versus locked/dev dependency provenance, source hashes and module enablement declarations. |
| PhpArrayCollector | Passive literal-array parsing shared within a session. Unsupported/dynamic configuration is not converted to an empty clean declaration; legacy load callers retain fresh evaluation fallback. |
| HttpCollector | Existing HTTP transport, response/header observations and timeout/checkpoint behavior. |
| MagentoModuleInventory | Collected module identity, Composer ownership, source roots and declared activation state. |
| MagentoModuleAnalysis | Supported PHP/XML symbols and declaration indexes, selected roots, file/byte counts and explicit gaps. |

## Reuse and provenance

ScanRunner begins a CollectionSession for execution and releases it in finally, including failed scans. Successful reusable local observations are retained only within that session. Standalone reads and subsequent scans do not share a global cache. Metadata/source changes are not an atomic snapshot; provenance and scope must stay attached to findings.

Literal configuration observations are parsed passively. Legacy dynamic configuration fallback is fresh and has its calling check's behavior; this is not a general PHP sandbox. Module and source detectors parse their supported static declarations rather than bootstrapping Magento.

DependencyInventory selects installed metadata when available, separates locked-only and dev/build scope, and preserves package versions, source identities and evidence time. Installation is not proof of runtime reachability. Advisory/status callers reuse their selected observations without turning partial feed coverage into a clean result.

## Bounds

The default session retains at most 8 MiB of accounted payload across 256 entries; PHP object/array overhead is additional. Arrays above 50,000 items or oversized observations can be processed without retention. Loader exceptions, false and null are not cached. This constrains retention, not total process memory or every legacy I/O operation.

Bounded source inventories apply per-file, total-byte, file-count, time and path/link limits. Module analysis limits selected roots and supported dependency context. Gaps remain inspectable and can coexist with genuine findings; truncation does not prove absence. Session stats contain counts/sizes rather than raw file contents or secrets.

HTTP, process/database and legacy API paths retain their own scope and timeout semantics. Selected observations may reuse evidence within a scan; no broad persistent response cache or complete runtime/build equivalence is implied. [Reliability](scan-reliability.md) describes cooperative deadlines and delivery, and [reporting](../guides/findings-and-output.md) describes diagnostics.
