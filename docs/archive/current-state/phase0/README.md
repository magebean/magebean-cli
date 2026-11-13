# Phase 0 — baseline and acceptance contract

Phase 0 records the reviewed state without changing scan behavior, detectors, profile membership or packaged binaries.

- `baseline.json`: historical snapshot of 110 Magebean rules, 14 profiles and 50 inactive references, with production source hashes and protected standard/archive definitions.
- `acceptance.json`: all 49 raw QA observations linked by source and index to their implementation phase and expected behavior, plus eight additional regression gates. These are planned acceptance cases, not claims that corrections already pass.
- `finding-contract.json`: evidence, scope, impact, confidence, remediation and recheck requirements; stable correlation principles. It is a target contract, not a wire-schema migration.
- `profile-decisions.json`: conditional Phase 5 destinations for all ten restored rules. The proposed evidence profile and canonical selection have not been enabled.

Run `python3 tools/verify-current-state-baseline.py` to verify traceability and protected definitions. During Phase 0, add `--check-current` to verify every production source remains unchanged. Later phases intentionally change sources; the historical snapshot stays fixed, so this optional freeze must not become an evergreen runtime test.

Phase 1 follows with paired correctness cases for inherited constructors, dates, secret exposure scope, source inventory validation and callable arrays. Build PHARs after runtime changes and the relevant acceptance checks, not for this documentation-only baseline step.
