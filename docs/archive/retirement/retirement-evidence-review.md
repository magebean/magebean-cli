# Evidence review of the 60 retired Magebean rules

This review tests implementation behavior and compares active predicates. The human/manual metadata is not evidence for an automation-impossibility claim. No active/retired catalog selection, rule ID or PHAR is changed by this review.

## Conclusions supported by the evidence

1. The blanket statement that all 60 criteria cannot be automated is unsupported. Several retired handlers automatically distinguish concrete positive and negative cases; some check implementations are still used by active rules.
2. A legacy handler returning PASS does not prove its full criterion. Counterexamples show source markers, file existence or keywords can satisfy a detector without establishing a runtime/business control.
3. Such counterexamples justify rejecting a broad clean conclusion from that implementation. They do not prove that a better detector cannot be implemented, and they do not automatically justify retiring the requirement identity.
4. Rule replacement is a separate question. A narrower active rule can preserve useful detection, but does not establish complete equivalence to the retired criterion.

## Reproducible execution baseline

Run:

```bash
php tools/verify-retired-bindings.php > /tmp/retirement-binding-probes.json
```

The saved [actual output](retirement-binding-probes.json) covers all 60 archived definitions and their 63 underlying check bindings. 62 bindings were executed on a new empty temporary project, with no runtime URL, lockfile or production credentials. The host firewall check was deliberately skipped. Outcomes: 26 PASS, 12 FAIL, 24 UNKNOWN and one skipped check. All 63 check names are registered.

These are direct detector results, not requirement conformance decisions. An empty project can legitimately have no custom-source matches; the results are not counted as 26 vulnerabilities or 26 wrong retirements. Missing evidence can also trigger an old FAIL; that is not proof of an actual deployment defect. The raw outcomes document behavior and collection boundaries only.

## Per-rule implementation and fixture evidence

- [Rules 1–20](retirement-evidence-part1.md): filesystem, source policies, maintenance and integration boundary.
- [Rules 21–40](retirement-evidence-part2.md): PII, integrations, payment flows, authorization, headers and XML.
- [Rules 41–60](retirement-evidence-part3.md): Admin ACL/accounts, password/configuration, SQL/output/logging, dependencies and uploads.

Each part distinguishes directly executed cases, existing regression coverage, static implementation review and untested external/runtime scope. A row labeled not proven must not be described as impossible to automate.

## Executed examples that reverse the blanket claim

| Retired rule | Executed input | Observed handler result | What it proves |
|---|---|---|---|
| MB-0043 | valid logrotate policy / rotate 0 | PASS / FAIL | Supported log-rotation configuration can be tested automatically. |
| MB-0731 | password minimum 12 / 4 | PASS / FAIL | A declared password-minimum policy is executable. |
| MB-0739 | display_errors Off / On | PASS / FAIL | The local declaration branch can be evaluated; its separate HTTP branch is not proved by this fixture. |
| MB-0741 | both cache frontends Redis / file backend | PASS / FAIL | The same automatic declaration check still exists under MB-0038. |
| MB-0744 | loopback maintained / abandoned / unknown package status | PASS / FAIL / UNKNOWN | Feed availability and complete inventory are data prerequisites, not proof of inherent manual-only evaluation. |
| MB-0089 | only CSP directive words in an unused source string | PASS | The old detector does not establish an enforced response policy; it does not prove response auditing cannot be automated. |
| MB-0733 | HTML escape helper in a JavaScript string context | PASS | Helper-name matching is insufficient for context-sensitive escaping. |

The three focused scripts recorded 38 + 40 + 54 = **132 direct fixture executions**, in addition to the 62 executed empty-project baseline bindings. These are synthetic/injected/loopback observations with per-case scope and overrides recorded in the parts, not 132 real-world security assessments. All three focused scripts were independently rerun by the primary agent. Per-rule evidence coverage was mechanically checked for all 60 unique archive IDs across the three parts.

Where a part recommends retiring a broad assertion, read that as rejecting the existing detector's unrestricted conformance conclusion. It is not proof that automation is impossible or that retiring the requirement identity is the only valid catalog decision. Six dependency topics in part 1 remain explicitly not proven beyond missing-input behavior; no live Marketplace/KEV/vendor-support evidence was fabricated.

## Concrete reuse already present in the executable catalog

- Retired MB-0741 uses php_no_file_cache_backend. Active MB-0038 still executes that same check with the same file/path arguments, alongside a stronger positive backend-configuration predicate. This establishes preserved automatic declaration checking, not live cache-health equivalence.
- Retired MB-0744 uses composer_abandoned_api. Active MB-0061 executes that handler, including the library-only scope, with strict inventory validation. Advisory/maintenance-source availability is a prerequisite, not evidence of inherent manual-only evaluation.
- Active MB-0728 assesses a bounded password-minimum declaration. The retired MB-0731 handler can be tested separately; neither predicate proves the quality of every actual password.

## Decision standard after this review

A keep/replace/retire decision needs rule-specific evidence: exact predicate, available inputs, observed positive/negative cases, false-positive/false-negative or unsupported-scope cases, and a verified replacement comparison if applicable. An unsupported full-scope conclusion should be separated from the useful automated observations. External evidence and explicit context can be prerequisites without making a whole criterion inherently manual.

This review does not claim complete exploitability, runtime integration or live vendor-support verification. It supplies observable implementation results and explicitly records where proof is still absent. Current active rule count remains 100 until a separately reviewed catalog decision is implemented.

## Subsequent implementation

The authorized [restoration and classification](retirement-reassessment.md) restores10 scoped revised IDs and fixes the counterexample detectors. This report and its raw JSON snapshots preserve the initial evidence; current probe output is expected to differ after repairs.
