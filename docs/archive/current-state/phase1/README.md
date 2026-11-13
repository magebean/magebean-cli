# Phase 1 — correctness and evidence scope

Completed after Phase 0. Ten Phase 1 acceptance observations were re-run against their original synthetic QA fixtures; all match the corrected expected behavior. See `verification.json` and the three `part*-probes.json` evidence files. Other observations retained in those full probe outputs belong to later phases and are not claimed fixed here.

## Changes

- MB-0815/0816/0818 resolve inherited constructor visibility before declaring a preference, virtual type or plugin class instantiable. Private/protected constructors produce correctness findings; missing parent or unresolved trait construction produces a collection gap.
- MB-0817 no longer accepts an arbitrary array as proof of a callable. Without supported callable-shape and method-access evidence it remains UNKNOWN; supported array parameters and proven array/scalar mismatches preserve their outcomes.
- MB-0062 and MB-0059 accept absolute valid calendar dates only. Supported inputs are UTC date-only values or timestamps with an explicit offset (including fractional seconds). Impossible, relative, malformed and future dates cannot produce a clean age conclusion. Proven old-age violations remain visible alongside incomplete dates.
- MB-0059 messages describe publication age, not measured organizational remediation time. Additive `publication_age_threshold_days` and `age_basis` fields clarify this; existing numeric `sla_days`/`open_days` fields remain compatibility aliases.
- MB-0072 and MB-0730 exclude expected runtime `app/etc/env.php` from working-tree secret matching, including explicit single-file paths. Unexpected source and backup copies still match. MB-0072 separately scans staged Git index content and available ref history, including env.php unless explicitly excluded. Evidence never retains matched secret bytes. Missing Git metadata remains UNKNOWN, not a secret exposure finding. Expected storage does not prove effective permissions or HTTP protection.
- MB-0805 requires a nonblank string package version before a matching source identity can establish a clean result.

Only MB-0072 needed a revised criterion (revision 5); detector correctness fixes otherwise retain their existing scoped criteria. No profile membership, ASVS/PCI definitions or historical retirement archive changed. Provenance, taxonomy, overlap grouping and restored-rule profile rollout remain in Phases 2–5.

## Validation

- `php tests/CurrentStatePhase1CorrectnessTest.php`: 58 assertions, including independent PHP constructor runtime behavior, valid/invalid date pairs, source identities, redaction, staged secrets and removed historical copies.
- All 138 `tests/*Test.php` files passed after the final detector changes.
- `python3 tools/verify-current-state-baseline.py` passed; optional `--check-current` is intentionally a Phase 0 source freeze and no longer applies after approved runtime edits.
- Both PHAR variants are rebuilt with the same 58-assertion test executed using their own archived autoloader during qualification. Local artifacts are not a deployment to a customer store.
