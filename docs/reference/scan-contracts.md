# Scan contracts and compatibility adapters

Current primary runtime: one internal `MB-…` requirement identity with reusable check functions and requirement-owned obligations. Profiles select identities; standards references are alignment metadata. Historical MB-R APIs/selectors/manifests remain compatibility adapters. Older examples and legacy API sections below must be read with that boundary. See [requirement model](requirement-model.md) and [migration contract](../archive/migrations/requirement-migration.md).


The engine exposes typed request, result and report boundaries while preserving explicit legacy adapters and agent result correspondence.

## Contracts

| Contract | Responsibility |
|---|---|
| `ScanRequest` | Immutable resolved context plus caller options. It does not resolve targets, validate profiles or select rules. |
| `ScanContext` | Immutable canonical path, URL and CVE data location, plus non-target settings. Reserved target keys cannot compete through the settings array. |
| `CheckOutcome` | The four existing check outcomes: PASS, FAIL, UNKNOWN, MANUAL_REVIEW. It does not introduce a new wire status or change rule truth tables. |
| `CheckResult` | Explicit outcome, message, evidence, optional reason code and dispatched check name; adapter for legacy positional arrays. |
| `ScanReport` | Immutable summary/findings/meta envelope, internal check observations in finding order, and lossless preservation of extension sections and serialization order. |

These objects use readonly properties and enums supported by the existing PHP >=8.1 requirement; they do not require PHP 8.2 readonly classes. Readonly arrays protect the container; injected objects within settings/evidence are not deeply frozen or cloned.

## Engine usage

```php
use Magebean\Engine\{ScanContext, ScanRequest, ScanRunner};

$request = new ScanRequest(
    new ScanContext('/var/www/shop', 'https://shop.example', '', ['meta' => ['target_mode' => 'HYBRID']]),
    ['profile' => 'basic']
);
// Planning/selection is still the caller's responsibility in this phase.
$report = (new ScanRunner($request->context, $pack))->runReport();
$legacyArray = $report->toLegacy();
```

Checks may opt into typed results while existing checks keep their current return types:

```php
use Magebean\Engine\{CheckOutcome, CheckResult};

$registry->register('fixture_review', static fn(array $args): CheckResult =>
    CheckResult::of(CheckOutcome::ManualReview, 'Confirm deployment controls', [], 'human_confirmation')
);
$result = $registry->runResult('fixture_review', []);
```

The registry assigns the actual dispatched name to a typed observation without mutating the producer's object. Reason codes and check identity remain available in the typed API and in `ScanReport::checkResults`, grouped in finding order. They are not appended to legacy evidence or wire payloads in this phase. Observations reflect only executed checks, including the existing any short circuit. Report enrichment retains them.

## Compatibility boundaries

- `Context` remains available, mutable and unchanged in its existing constructor/fromArray/get/abs behavior. `toScanContext()` is an explicit migration method; the legacy path/url/cveData properties become the canonical target and override conflicting extra target keys. Existing callers are not automatically migrated or silently reinterpreted.
- `ScanContext::toLegacy()` creates a fresh mutable Context with canonical target values also available through legacy get(). Mutation of that adapter does not alter the immutable target.
- `CheckRegistry::run()` still returns an array. Existing array-producing callbacks retain the exact original tuple, including omitted third elements. New typed callbacks are converted only for this legacy method.
- `CheckRegistry::runResult()` returns CheckResult. Legacy normalization matches the historical ScanRunner: absent/null evidence becomes [], scalar evidence is wrapped, messages are cast to strings, and legacy non-boolean passed values are retained in the tuple adapter.
- Only the legacy import adapter infers a manual outcome from `[MANUAL_REVIEW]`. New typed producers supply the enum directly; the export adapter inserts the prefix for legacy aggregation/rendering when required.
- New typed producers cannot supply a reserved `[MANUAL_REVIEW]` or `[UNKNOWN]` prefix that conflicts with their enum. Legacy import retains historical values rather than tightening the existing API.
- `ScanRunner` accepts Context or ScanContext. `run()` remains array-returning; `runReport()` returns the new envelope. Existing Context objects keep their historical semantics.
- CLI and agent now construct ScanRequest/ScanContext and consume runReport(), then explicitly adapt to the existing array format for enrichment, rendering or transport.
- `ScanReport::toLegacy()` and JSON serialization preserve summary/findings/meta and unknown sections, including null-valued extensions. An absent meta field is not invented during a round trip.
- `withMeta()` and `withSection()` return new envelopes. Extensions cannot overwrite summary/findings/meta through the extension API.

## Deliberately unchanged behavior

Rule op=all/any aggregation, passed/status inconsistencies already documented, first-success short circuit, messages, evidence merging, exception propagation, manual-rule filtering, agent result mapping and exit-code policy remain intact. No rule/detector implementation is refactored and no known QA defect is fixed here.

Legacy details/evidence remain their existing array structures. This phase introduces a stable typed boundary, not a complete migration of every finding/evidence record or a fix for provenance lost by rule-level array_merge. Shared planning and collectors can migrate those internals later without forcing an immediate dashboard schema change.

## Verification

```sh
php tests/ScanContractsTest.php
php tests/CompatibilityBaselineTest.php
php tests/run.php
```

Contract coverage includes immutable targets/options/evidence, canonical versus legacy context behavior, scalar/missing evidence normalization, typed and array callback interoperability, typed prefix dispatch, all 32 two-check all/any combinations, identical progress callbacks, retained check observations and short circuits, extension round trips and invalid report envelopes.

The compatibility snapshot also checks representative CLI LOCAL/HYBRID/REMOTE scans, PCI readiness JSON, offline CVE, agent payloads, commands/options, catalog digests and profile selections. New tests require no additional dependencies or live external services.

ScanReportAssembler preserves typed observations while adding report extensions. Console rendering and agent payload mapping are separate adapters. See [architecture](architecture.md) and [reporting](../guides/findings-and-output.md).

## Independent requirement runtime

`RequirementCatalog` loads persisted internal definitions and profile membership independently of legacy source objects. Each requirement owns its criterion, revision, applicability and evidence obligations; the check registry supplies reusable functions. The primary runner assesses one internal identity and attaches standard alignment as metadata. Legacy `ProfileLoader::apply`, `RulePackLoader` and historical explicit selector/manifest requests remain compatibility adapters. PCI reports use primary alignment rather than profile mappings. See [runtime migration](../archive/migrations/requirement-migration.md) for selection, report and transport acceptance gates.
