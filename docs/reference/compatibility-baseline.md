# Compatibility regression

The executable CLI snapshot lives in tests/fixtures/compatibility/baseline.json and is exercised by `php tests/CompatibilityBaselineTest.php`. It covers command options/help, catalogue/profile selection, scoped listing, synthetic local/remote requests, outcomes, offline advisories, PCI evidence and agent correspondence. Tests use isolated fixtures and loopback HTTP; they are not live-store qualification.

```sh
php tests/CompatibilityBaselineTest.php
php tests/run.php
```

The runner executes each tests/*Test.php in an isolated PHP process with a 45-second deadline. The current suite has 142 test files; runner output is authoritative.

A snapshot difference must be reviewed. For an accepted change, save the old JSON, run `php tests/CompatibilityBaselineTest.php --record-baseline`, inspect changed paths and rerun the test. Do not update snapshots to hide unexpected behavior.

The historical [migration snapshot](../archive/current-state/phase0/README.md) records 110 reviewed rules, original profile counts, acceptance cases and protected source hashes. Historical values remain unchanged when approved current membership changes. `python3 tools/verify-current-state-baseline.py` verifies traceability and protected normative/retirement definitions; `--check-current` is only the original Phase 0 freeze, not a gate for the migrated runtime.

Documentation drift uses `php tools/update-baseline-doc.php --check`; local links and relocation use `python3 tools/check-docs.py`.
