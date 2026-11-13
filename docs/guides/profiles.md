# Profiles and selection

Profiles choose related criteria; they do not change a predicate's meaning or certify the store. Membership is persisted in [internal-profiles.json](../../src/Rules/requirements/internal-profiles.json). The [baseline](../magebean-baseline-v1.md#profile-selection) is generated from that catalogue and records current counts.

| Profile | Inventory | Default LOCAL selection | Focus |
|---|---:|---:|---|
| basic | 37 | 37 | Routine technical security/readiness |
| hardening | 86 | 80 | Deeper deployment and strict coding policy |
| development | 31 | 29 | Offline source/modules/declarations |
| prelaunch | 60 | 58 | Source plus deployed candidate and HTTP evidence |
| takeover | 86 | 82 | Inherited technical risks and maintenance scope |
| owasp | 50 | 41 | Magebean checks organized by Top 10 taxonomy |
| module-integrity | 11 | 11 | Identity, REST and DI |
| module-source | 4 | 4 | PHP/contracts/request sinks |
| module-lifecycle | 3 | 3 | Schema/patch/handler declarations |
| module-reliability | 2 | 2 | Bounded review candidates |
| evidence | 2 | 2 | Supplied document/record lint only |
| asvs-l1 | 70 | 0 | ASVS 5.0.0 Level 1 |
| asvs-l2 | 253 | 0 | ASVS 5.0.0 Level 2 |
| asvs-l3 | 345 | 0 | ASVS 5.0.0 Level 3 |
| pci | 280 | 0 | PCI DSS 4.0.1 |

Counts assume no project overrides, extra capabilities or filters. ASVS/PCI retain human evidence obligations; include `--include-manual-review` to enter those workflows. Magebean profiles contain no required human checklist. Evidence lint is informational and does not prove implemented security controls.

## Defaults and optional context

Hardening includes all current Basic and Magebean OWASP members, and selects `strict_native_api_policy`, `cache_backend_policy` and `dependency_maintenance` by default. Six separately gated rules still require actual deployment targeting/expected inputs; see [production context](production-context.md).

Development selects template checks but stays offline. MB-0744 needs explicit `dependency_maintenance`; MB-0828 needs `local_advisory_snapshot` plus a supplied trusted snapshot. Prelaunch selects online library maintenance; MB-0828 and the strict cache baseline MB-0741 remain opt-in. Takeover selects maintenance; its worker, logrotate and strict-cache checks remain conditional.

`evidence` selects MB-0093 and MB-0806 with their lint context. MB-0093 inspects supplied document topics; MB-0806 validates supplied mitigation records against expected IDs. Neither belongs to core hardening/OWASP or the separate PCI profile. Selecting this profile does not create documents or records.

A profile default capability is assessment intent, not observed evidence. Explicit project false values override it; an explicit CLI capability enables it. Direct rule selection also respects capability gates. Context defaults are restricted to Magebean profiles and must reference a member's gate.

```sh
php magebean.phar audit --path=/var/www/magento --profile=hardening
php magebean.phar rules:list --profile=hardening
php magebean.phar audit --path=. --profile=development --capabilities=dependency_maintenance
php magebean.phar audit --path=/var/www/magento --profile=evidence
```

`production` and `production-hardening` alias hardening; `owasp` aliases owasp-top-10-2025; `pci` aliases pci-dss-v4.0.1. ASVS/PCI identities are separate from Magebean rules. MB-0731 remains a compatible password selector while built-in profiles select MB-0728. The [baseline](../magebean-baseline-v1.md) lists each current criterion's membership.

Console membership import currently does not persist CLI default capabilities or put them in agent manifests. Agent context remains explicit; do not assume CLI/agent selection parity.
