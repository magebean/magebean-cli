# Phase 6 — integration, local release and handoff

Completed local qualification of the current-state audit migration (Phases 0–6). This is a qualified local build, not a live-store audit or remote deployment. Active inventory remains 110 Magebean + 345 ASVS + 280 PCI = 735 requirements, with 15 built-in profiles.

## Executed evidence

- CLI regression: **142/142 test files passed**. [Full output](cli-regression.log).
- Both final PHAR builds passed release guard, profile fixtures, restored-rule CLI checks and all Phase 1–5 gates. [Standard build](build-standard.log), [one-time build](build-one-time.log).
- Each PHAR matches all **211 source files** under src, including physical and aggregate catalogues. [Hashes and parity](artifact-parity.json).
- Existing Console import/rollback/retirement/current-catalog eligibility regressions: **18 tests, 89 assertions** in explicit in-memory SQLite. [Output](console-catalog-regression.json).
- Each final PHAR mapper passed **58 assertions** against the actual Console ingestion API. Two independent assessment results retain their original fail/error status while sharing one canonical issue reference. Idempotent replay creates no duplicates; a later scan retains history. Full real catalogue imported twice: 735 rules, 15 profiles, stable rule identities and exact membership/order. Existing assessment snapshots, result rows and observations remain byte-for-byte unchanged. [Standard](console-validation-standard.json), [one-time](console-validation-one-time.json).
- Original QA requalification: 23 semantic cases and 10 overlapping observations grouped into five evidence-identified issues. [Canonical evidence](acceptance-results.json). Protected ASVS/PCI definitions and historical retirement archive pass the Phase 0 baseline verifier.

## Measurements

Each entry is the median of three fresh PHP processes on the same WSL host. Filesystem cache may be warm. Fixture generation is excluded. Scan time includes planning and execution, while process wall time/RSS include PHP startup. Full raw process measurements, check lists, input sizes, per-rule incompleteness and coverage are in [performance.json](performance.json).

| Fixture | Runtime | Input files / bytes | Median scan seconds | Peak RSS MiB |
|---|---|---:|---:|---:|
| small | source | 98 / 50894 | 0.258 | 60.7 |
| small | standard | 98 / 50894 | 0.268 | 54.9 |
| small | one-time | 98 / 50894 | 0.264 | 54.8 |
| medium | source | 1066 / 623400 | 2.112 | 73.7 |
| medium | standard | 1066 / 623400 | 2.120 | 68.5 |
| medium | one-time | 1066 / 623400 | 2.140 | 68.5 |

Small fixture: 4 modules; medium: 20 modules. Shared module analysis collected 89 files / 50,207 bytes and 1,041 files / 621,343 bytes respectively. This subset counts PHP/XML, not every template or metadata file. Both use the default 29-rule offline development selection and retain the deliberately supplied MB-0822 request-to-command finding. No online API/HTTP/TLS checks are selected.

The minimal fixture lacks installed Magento XSDs; MB-0809 remains incomplete. Other missing-input outcomes and exact selected checks are recorded, not converted to PASS. An additional bounded collection with max_files=10 returns file_budget_exceeded and incomplete coverage for both fixture sizes. A fast scan with incomplete evidence is not a clean bill of health. These measurements are not a throughput guarantee for real Magento stores.

## Migration and compatibility

- Reviewed membership and default-context changes: [Phase 5](../phase5/README.md). Development stays offline by default. Supplied logrotate and strict cache baseline remain conditional; evidence record lint lives in opt-in evidence.
- Finding categories/confidence and scope: [reporting contract](../../../guides/findings-and-output.md). Raw per-rule outcomes remain; canonical CLI/HTML/SARIF presentation avoids proven duplicates. Agent schema 1.0 keeps per-assessment counts and additive canonical refs. Console preserves per-assessment finding rows; it does not merge history on a canonical reference.
- The current Console importer synchronizes membership but does not persist CLI default_capabilities or add context to queued manifests. CLI/agent default selection is therefore not identical. Gated agent checks remain unsupported without explicit manifest context; importing a profile does not silently authorize online maintenance or strict policies. A server context editor/manifest change requires separate implementation.
- This work changes no Console production application files or live database. SQLite test adapters are generated under the CLI build directory and explicitly force :memory:. No authorized live-store target was supplied, so live validation remains unperformed.

## Reproduce

```sh
php tests/run.php
python3 tools/verify-current-state-baseline.py
php tools/verify-phase3-qa.php
python3 tools/verify-phase6-qa.py
php tools/build-phar.php
php tools/build-phar.php --one-time
php tools/verify-phase6-artifacts.php
python3 tools/verify-phase6-console-catalog.py
python3 tools/verify-phase6-console.py
python3 tools/verify-phase6-console.py artifacts/magebean-one-time.phar
python3 tools/benchmark-current-state.py
```

Console checks require the sibling console-magebean workspace and installed dependencies. Benchmark results depend on the host; reruns overwrite measurement evidence. Import into an actual deployment is a separate operational action using Console security:catalog:import and the CLI src/Rules path, after reviewing deployment context. No production import was run here.

[Machine-readable verification](verification.json).
