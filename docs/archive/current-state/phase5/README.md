# Phase 5 — reviewed profile rollout

Completed locally. 110 active Magebean requirements remain unchanged in number; 15 built-in profiles now include the opt-in `evidence` profile. ASVS/PCI profiles, source definitions and historical retirement archive are preserved. Counts describe selected assessments, not unique defects or assurance.

| Profile | Inventory | Default LOCAL selection |
|---|---:|---:|
| basic | 37 | 37 |
| development | 31 | 29 |
| prelaunch | 60 | 58 |
| takeover | 86 | 82 |
| hardening | 86 | 74 |
| owasp | 50 | 41 |
| evidence | 2 | 2 |

Counts assume no additional project context or filters. Remote target support can further reduce selection. [Machine-readable memberships](membership.json).

## Restored coverage

- MB-0043 joins hardening/takeover, gated by `log_rotation_config`. It reads the existing supplied project candidate (`devops/logrotate.conf`); no file is generated or mandated by a default scan. It does not prove host installation or discover every system logrotate policy. An opted-in missing/unsupported candidate remains a collection gap.
- MB-0093 and MB-0806 are selected by the opt-in `evidence` profile only. MB-0806 leaves hardening/OWASP. These checks lint supplied records; they do not establish implemented controls or close a technical issue by themselves.
- MB-0731 remains a compatible historical selector; profiles select MB-0728 instead, including new prelaunch membership. Raw requested assessments remain separate; identical observed conditions share a canonical issue.
- MB-0733/0736 join development/prelaunch/takeover/hardening, retaining bounded template scope and canonical grouping.
- MB-0739/0740/0742 join prelaunch/takeover/hardening. Findings concern named ini/config declarations, not proof of worker runtime state. Missing declarations are unknown, not enabled settings.
- MB-0741 joins hardening and conditional prelaunch/takeover. It requires `cache_backend_policy`, selected by hardening by default. The rule compares an explicit stricter baseline; another backend is not inherently a vulnerability.
- MB-0744 joins hardening/prelaunch/takeover and optional development maintenance. `dependency_maintenance` is selected by the former three; development requires explicit opt-in. It remains the library subset of maintenance evidence, with exact overlap grouping retained.

## Context and migration

Profile `default_capabilities` select policy/assessment intent, not evidence that a condition works. Only Magebean profiles may declare them, and each must reference a capability of a member. Explicit project `false` overrides defaults; an explicit CLI capability enables it. Planner and rules:list use the same resolution. Agent manifests keep their explicit capability contract and do not inherit context from a profile label.

```sh
php magebean.phar audit --profile=development
php magebean.phar audit --profile=development --capabilities=dependency_maintenance
php magebean.phar audit --profile=takeover --capabilities=log_rotation_config,cache_backend_policy
php magebean.phar audit --profile=evidence
php magebean.phar rules:list --profile=prelaunch
```

Direct MB-0043/0741/0744 selectors also require the corresponding context. `evidence` itself is the explicit opt-in for record lint; no second capability flag is required. No mandatory advisory snapshot or evidence document is created. Local runtime URL resolution continues through shared Magento store configuration. Default findings still omit per-issue guidance/confidence and keep summary borders.

## Validation

- Full regression: 142 test files passed, no failures.
- Phase 5 profile regression: 62 assertions, including exact normative profile comparison, context false overrides, optional development maintenance, compatible MB-0731, and planner/listing agreement.
- Protected standard/archive baseline verification passed.
- Standard and one-time PHAR candidates run all Phase 1–5 gates and profile CLI fixtures before replacing local artifacts.

Phase 6 retains broader Console catalog import/re-import, representative performance measurements and release handoff. Fixtures are not live-store qualification.
