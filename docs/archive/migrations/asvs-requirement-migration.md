# ASVS L1/L2 requirement migration inventory

Mapping inventory for the [requirement model](../../reference/requirement-model.md). ASVS profiles now compile one canonical assessment definition per mapped requirement, including native partial implementations for the former gaps. The legacy IDs below identify evidence sources and compatibility aliases; see [runtime migration](requirement-migration.md).

## Scope and count reconciliation

| Scope | Unique standard requirements | Meaning |
|---|---:|---|
| L1 | 70 | One target definition per ASVS L1 requirement |
| L2 additions | 183 | Additional requirements, not a second copy of L1 |
| L1 + L2 | 253 | Cumulative target inventory including coverage gaps |

The raw profiles contain 29 legacy IDs mapped to multiple distinct ASVS L1/L2 requirements, 23 requirements supported by multiple legacy IDs, and 12 requirements without a mapped legacy definition. These categories overlap and must not be summed as a catalog size. They are mapping facts, not implementation effort estimates. Historical selection counts (32/60 L1 and 73/183 non-contextual L2) counted legacy definitions. Current runtime counts are 42/70 L1 and 90/198 non-contextual L2, with the 12 former gaps now implemented as native partial evidence checks.

## Reclassification work

- For fan-out mappings, define each requirement's actual predicate before assigning shared checks; the legacy rule's single result is not automatically sufficient for all mapped criteria.
- For fan-in mappings, preserve every evidence contribution and its applicability/manual obligations beneath one requirement definition; do not count the requirement multiple times.
- Unsupported requirements stay explicit gaps. A human/evidence plan or an absent detector is not an automated implementation.
- Keep standard version, level-specific conditions, capability, evidence lineage and migration aliases. Canonical IDs use OWASP-ASVS:5.0.0:<requirement>; command and flag names remain compatible.
- ASVS L3 is compiled by the same adapter to preserve inheritance. OWASP Top 10, PCI DSS and Magento baseline mappings still need review before a repository-wide catalog conversion. This inventory covers L1/L2 only; the one-requirement model applies to future definitions in each namespace.

## Legacy IDs that must be split at the requirement boundary

| Legacy ID | Target ASVS requirement IDs |
|---|---|

| MB-R011 | 2.4.1, 6.3.1, 6.6.3 |
| MB-R016 | 1.2.2, 1.3.6, 5.3.2 |
| MB-R020 | 1.2.2, 5.3.2 |
| MB-R021 | 5.2.1, 5.2.2, 5.2.3, 5.3.1, 5.3.2, 5.4.2 |
| MB-R024 | 14.2.4, 16.2.5 |
| MB-R025 | 11.2.1, 11.3.2, 11.4.2 |
| MB-R026 | 4.1.2, 12.2.1 |
| MB-R028 | 12.1.1, 12.1.2 |
| MB-R030 | 3.3.1, 3.3.2, 3.3.4 |
| MB-R031 | 13.4.2, 15.2.3 |
| MB-R032 | 13.4.2, 15.2.3 |
| MB-R036 | 13.4.2, 15.2.3 |
| MB-R044 | 13.4.2, 15.2.3 |
| MB-R045 | 14.2.4, 16.2.5 |
| MB-R049 | 3.7.1, 15.1.2, 15.2.1 |
| MB-R058 | 3.7.1, 15.1.2 |
| MB-R073 | 12.2.1, 12.3.1, 12.3.3 |
| MB-R076 | 12.3.1, 13.2.4, 13.2.5 |
| MB-R077 | 14.2.3, 14.2.4 |
| MB-R078 | 12.1.2, 12.3.1 |
| MB-R081 | 13.2.2, 13.3.2 |
| MB-R094 | 8.2.1, 8.2.3 |
| MB-R095 | 4.3.1, 4.3.2, 13.4.5 |
| MB-R096 | 3.2.1, 3.4.4, 3.4.6 |
| MB-R097 | 13.2.3, 13.3.1 |
| MB-R099 | 5.4.1, 5.4.2, 8.2.1, 8.2.3 |
| MB-R130 | 3.4.2, 3.5.2, 4.4.2 |
| MB-R132 | 11.2.3, 11.3.1, 11.3.2, 11.3.3, 11.6.1 |
| MB-R135 | 12.2.2, 12.3.2 |

## Complete target inventory

The legacy evidence column is a migration source, not an assertion of full conformance. The runtime composes existing evidence conservatively; stronger criterion-specific automated proof remains follow-up work. Coverage values are current profile metadata, not new target outcomes.

| Canonical requirement identity | Introduced level | Current coverage | Legacy evidence definitions | Capability | Migration action |
|---|---:|---|---|---|---|
| OWASP-ASVS:5.0.0:1.1.1 | 2 | MANUAL_REVIEW | MB-R136 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:1.1.2 | 2 | MANUAL_REVIEW | MB-R137 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:1.2.1 | 1 | PARTIALLY_AUTOMATED | MB-R013 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:1.2.2 | 1 | PARTIALLY_AUTOMATED | MB-R016, MB-R020 | — | Compose evidence in one definition; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:1.2.3 | 1 | AUTOMATED | MB-R022 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:1.2.4 | 1 | PARTIALLY_AUTOMATED | MB-R012 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:1.2.5 | 1 | PARTIALLY_AUTOMATED | MB-R018 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:1.2.6 | 2 | CONTEXT_REQUIRED | MB-R218 | ldap | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:1.2.7 | 2 | CONTEXT_REQUIRED | MB-R219 | xpath | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:1.2.8 | 2 | CONTEXT_REQUIRED | MB-R220 | latex_processing | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:1.2.9 | 2 | MANUAL_REVIEW | MB-R138 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:1.3.1 | 1 | PARTIALLY_AUTOMATED | Native ASVS-NATIVE:1.3.1 (no MB-R alias) | — | Collect scoped evidence; independent confirmation remains required |
| OWASP-ASVS:5.0.0:1.3.2 | 1 | AUTOMATED | MB-R019 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:1.3.3 | 2 | MANUAL_REVIEW | MB-R139 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:1.3.4 | 2 | CONTEXT_REQUIRED | MB-R221 | user_supplied_svg | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:1.3.5 | 2 | CONTEXT_REQUIRED | MB-R222 | scriptable_user_content | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:1.3.6 | 2 | PARTIALLY_AUTOMATED | MB-R016 | — | Review predicate/evidence contract; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:1.3.7 | 2 | MANUAL_REVIEW | MB-R140 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:1.3.8 | 2 | CONTEXT_REQUIRED | MB-R223 | jndi | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:1.3.9 | 2 | CONTEXT_REQUIRED | MB-R224 | memcache | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:1.3.10 | 2 | MANUAL_REVIEW | MB-R141 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:1.3.11 | 2 | MANUAL_REVIEW | MB-R142 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:1.4.1 | 2 | CONTEXT_REQUIRED | MB-R225 | native_code | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:1.4.2 | 2 | CONTEXT_REQUIRED | MB-R226 | native_code | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:1.4.3 | 2 | CONTEXT_REQUIRED | MB-R227 | native_code | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:1.5.1 | 1 | AUTOMATED | MB-R098 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:1.5.2 | 2 | PARTIALLY_AUTOMATED | MB-R017 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:2.1.1 | 1 | MANUAL_REVIEW | MB-R102 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:2.1.2 | 2 | MANUAL_REVIEW | MB-R143 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:2.1.3 | 2 | MANUAL_REVIEW | MB-R144 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:2.2.1 | 1 | PARTIALLY_AUTOMATED | Native ASVS-NATIVE:2.2.1 (no MB-R alias) | — | Collect scoped evidence; independent confirmation remains required |
| OWASP-ASVS:5.0.0:2.2.2 | 1 | PARTIALLY_AUTOMATED | MB-R014 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:2.2.3 | 2 | MANUAL_REVIEW | MB-R145 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:2.3.1 | 1 | MANUAL_REVIEW | MB-R103 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:2.3.2 | 2 | MANUAL_REVIEW | MB-R146 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:2.3.3 | 2 | MANUAL_REVIEW | MB-R147 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:2.3.4 | 2 | MANUAL_REVIEW | MB-R148 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:2.4.1 | 2 | PARTIALLY_AUTOMATED | MB-R011 | — | Review predicate/evidence contract; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:3.2.1 | 1 | PARTIALLY_AUTOMATED | MB-R096 | — | Review predicate/evidence contract; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:3.2.2 | 1 | PARTIALLY_AUTOMATED | Native ASVS-NATIVE:3.2.2 (no MB-R alias) | — | Collect scoped evidence; independent confirmation remains required |
| OWASP-ASVS:5.0.0:3.3.1 | 1 | PARTIALLY_AUTOMATED | MB-R030 | — | Review predicate/evidence contract; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:3.3.2 | 2 | PARTIALLY_AUTOMATED | MB-R030 | — | Review predicate/evidence contract; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:3.3.3 | 2 | MANUAL_REVIEW | MB-R149 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:3.3.4 | 2 | PARTIALLY_AUTOMATED | MB-R030 | — | Review predicate/evidence contract; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:3.4.1 | 1 | AUTOMATED | MB-R027 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:3.4.2 | 1 | AUTOMATED | MB-R130 | — | Review predicate/evidence contract; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:3.4.3 | 2 | PARTIALLY_AUTOMATED | MB-R089 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:3.4.4 | 2 | PARTIALLY_AUTOMATED | MB-R096 | — | Review predicate/evidence contract; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:3.4.5 | 2 | PARTIALLY_AUTOMATED | MB-R150, MB-R273 | — | Compose evidence in one definition |
| OWASP-ASVS:5.0.0:3.4.6 | 2 | PARTIALLY_AUTOMATED | MB-R096 | — | Review predicate/evidence contract; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:3.5.1 | 1 | PARTIALLY_AUTOMATED | MB-R015 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:3.5.2 | 1 | AUTOMATED | MB-R130 | — | Review predicate/evidence contract; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:3.5.3 | 1 | PARTIALLY_AUTOMATED | Native ASVS-NATIVE:3.5.3 (no MB-R alias) | — | Collect scoped evidence; independent confirmation remains required |
| OWASP-ASVS:5.0.0:3.5.4 | 2 | MANUAL_REVIEW | MB-R151 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:3.5.5 | 2 | MANUAL_REVIEW | MB-R152 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:3.7.1 | 2 | PARTIALLY_AUTOMATED | MB-R049, MB-R058, MB-R062 | — | Compose evidence in one definition; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:3.7.2 | 2 | MANUAL_REVIEW | MB-R153 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:4.1.1 | 1 | PARTIALLY_AUTOMATED | Native ASVS-NATIVE:4.1.1 (no MB-R alias) | — | Collect scoped evidence; independent confirmation remains required |
| OWASP-ASVS:5.0.0:4.1.2 | 2 | PARTIALLY_AUTOMATED | MB-R026 | — | Review predicate/evidence contract; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:4.1.3 | 2 | MANUAL_REVIEW | MB-R154 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:4.2.1 | 2 | MANUAL_REVIEW | MB-R155 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:4.3.1 | 2 | PARTIALLY_AUTOMATED | MB-R095 | — | Review predicate/evidence contract; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:4.3.2 | 2 | PARTIALLY_AUTOMATED | MB-R095, MB-R275 | graphql | Compose evidence in one definition; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:4.4.1 | 1 | AUTOMATED | MB-R131 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:4.4.2 | 2 | PARTIALLY_AUTOMATED | MB-R130 | — | Review predicate/evidence contract; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:4.4.3 | 2 | CONTEXT_REQUIRED | MB-R228 | websocket | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:4.4.4 | 2 | CONTEXT_REQUIRED | MB-R229 | websocket | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:5.1.1 | 2 | CONTEXT_REQUIRED | MB-R230 | file_handling | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:5.2.1 | 1 | PARTIALLY_AUTOMATED | MB-R021 | — | Review predicate/evidence contract; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:5.2.2 | 1 | PARTIALLY_AUTOMATED | MB-R021 | — | Review predicate/evidence contract; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:5.2.3 | 2 | PARTIALLY_AUTOMATED | MB-R021 | — | Review predicate/evidence contract; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:5.3.1 | 1 | AUTOMATED | MB-R021, MB-R091 | — | Compose evidence in one definition; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:5.3.2 | 1 | PARTIALLY_AUTOMATED | MB-R020, MB-R021, MB-R016 | — | Compose evidence in one definition; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:5.4.1 | 2 | PARTIALLY_AUTOMATED | MB-R099 | — | Review predicate/evidence contract; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:5.4.2 | 2 | PARTIALLY_AUTOMATED | MB-R021, MB-R099 | — | Compose evidence in one definition; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:5.4.3 | 2 | CONTEXT_REQUIRED | MB-R231 | file_handling | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:6.1.1 | 1 | MANUAL_REVIEW | MB-R104 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:6.1.2 | 2 | MANUAL_REVIEW | MB-R156 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:6.1.3 | 2 | MANUAL_REVIEW | MB-R157 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:6.2.1 | 1 | AUTOMATED | MB-R008 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:6.2.2 | 1 | MANUAL_REVIEW | MB-R105 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:6.2.3 | 1 | MANUAL_REVIEW | MB-R106 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:6.2.4 | 1 | PARTIALLY_AUTOMATED | Native ASVS-NATIVE:6.2.4 (no MB-R alias) | — | Collect scoped evidence; independent confirmation remains required |
| OWASP-ASVS:5.0.0:6.2.5 | 1 | MANUAL_REVIEW | MB-R107 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:6.2.6 | 1 | MANUAL_REVIEW | MB-R108 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:6.2.7 | 1 | MANUAL_REVIEW | MB-R109 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:6.2.8 | 1 | MANUAL_REVIEW | MB-R110 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:6.2.9 | 2 | MANUAL_REVIEW | MB-R158 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:6.2.10 | 2 | MANUAL_REVIEW | MB-R159 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:6.2.11 | 2 | MANUAL_REVIEW | MB-R160 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:6.2.12 | 2 | MANUAL_REVIEW | MB-R161 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:6.3.1 | 1 | PARTIALLY_AUTOMATED | MB-R011 | — | Review predicate/evidence contract; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:6.3.2 | 1 | PARTIALLY_AUTOMATED | Native ASVS-NATIVE:6.3.2 (no MB-R alias) | — | Collect scoped evidence; independent confirmation remains required |
| OWASP-ASVS:5.0.0:6.3.3 | 2 | PARTIALLY_AUTOMATED | MB-R007 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:6.3.4 | 2 | MANUAL_REVIEW | MB-R162 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:6.4.1 | 1 | MANUAL_REVIEW | MB-R111 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:6.4.2 | 1 | MANUAL_REVIEW | MB-R112 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:6.4.3 | 2 | MANUAL_REVIEW | MB-R163 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:6.4.4 | 2 | MANUAL_REVIEW | MB-R164 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:6.5.1 | 2 | MANUAL_REVIEW | MB-R165 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:6.5.2 | 2 | MANUAL_REVIEW | MB-R166 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:6.5.3 | 2 | MANUAL_REVIEW | MB-R167 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:6.5.4 | 2 | MANUAL_REVIEW | MB-R168 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:6.5.5 | 2 | MANUAL_REVIEW | MB-R169 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:6.6.1 | 2 | MANUAL_REVIEW | MB-R170 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:6.6.2 | 2 | MANUAL_REVIEW | MB-R171 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:6.6.3 | 2 | PARTIALLY_AUTOMATED | MB-R011 | — | Review predicate/evidence contract; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:6.8.1 | 2 | CONTEXT_REQUIRED | MB-R232 | federated_identity | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:6.8.2 | 2 | CONTEXT_REQUIRED | MB-R233 | federated_identity | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:6.8.3 | 2 | CONTEXT_REQUIRED | MB-R234 | federated_identity | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:6.8.4 | 2 | CONTEXT_REQUIRED | MB-R235 | federated_identity | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:7.1.1 | 2 | MANUAL_REVIEW | MB-R172 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:7.1.2 | 2 | MANUAL_REVIEW | MB-R173 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:7.1.3 | 2 | CONTEXT_REQUIRED | MB-R236 | federated_identity | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:7.2.1 | 1 | MANUAL_REVIEW | MB-R113 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:7.2.2 | 1 | MANUAL_REVIEW | MB-R114 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:7.2.3 | 1 | MANUAL_REVIEW | MB-R115 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:7.2.4 | 1 | MANUAL_REVIEW | MB-R116 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:7.3.1 | 2 | PARTIALLY_AUTOMATED | MB-R009 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:7.3.2 | 2 | MANUAL_REVIEW | MB-R174 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:7.4.1 | 1 | MANUAL_REVIEW | MB-R117 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:7.4.2 | 1 | MANUAL_REVIEW | MB-R118 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:7.4.3 | 2 | MANUAL_REVIEW | MB-R175 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:7.4.4 | 2 | MANUAL_REVIEW | MB-R176 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:7.4.5 | 2 | MANUAL_REVIEW | MB-R177 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:7.5.1 | 2 | MANUAL_REVIEW | MB-R178 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:7.5.2 | 2 | MANUAL_REVIEW | MB-R179 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:7.6.1 | 2 | CONTEXT_REQUIRED | MB-R237 | federated_identity | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:7.6.2 | 2 | MANUAL_REVIEW | MB-R180 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:8.1.1 | 1 | MANUAL_REVIEW | MB-R119 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:8.1.2 | 2 | MANUAL_REVIEW | MB-R181 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:8.2.1 | 1 | PARTIALLY_AUTOMATED | MB-R094, MB-R099 | — | Compose evidence in one definition; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:8.2.2 | 1 | MANUAL_REVIEW | MB-R120 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:8.2.3 | 2 | PARTIALLY_AUTOMATED | MB-R094, MB-R099, MB-R100, MB-R101 | — | Compose evidence in one definition; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:8.3.1 | 1 | MANUAL_REVIEW | MB-R121 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:8.4.1 | 2 | CONTEXT_REQUIRED | MB-R238 | multi_tenant | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:9.1.1 | 1 | PARTIALLY_AUTOMATED | Native ASVS-NATIVE:9.1.1 (no MB-R alias) | — | Collect scoped evidence; independent confirmation remains required |
| OWASP-ASVS:5.0.0:9.1.2 | 1 | PARTIALLY_AUTOMATED | Native ASVS-NATIVE:9.1.2 (no MB-R alias) | — | Collect scoped evidence; independent confirmation remains required |
| OWASP-ASVS:5.0.0:9.1.3 | 1 | PARTIALLY_AUTOMATED | Native ASVS-NATIVE:9.1.3 (no MB-R alias) | — | Collect scoped evidence; independent confirmation remains required |
| OWASP-ASVS:5.0.0:9.2.1 | 1 | PARTIALLY_AUTOMATED | Native ASVS-NATIVE:9.2.1 (no MB-R alias) | — | Collect scoped evidence; independent confirmation remains required |
| OWASP-ASVS:5.0.0:9.2.2 | 2 | CONTEXT_REQUIRED | MB-R239 | self_contained_tokens | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:9.2.3 | 2 | CONTEXT_REQUIRED | MB-R240 | self_contained_tokens | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:9.2.4 | 2 | CONTEXT_REQUIRED | MB-R241 | self_contained_tokens | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:10.1.1 | 2 | CONTEXT_REQUIRED | MB-R242 | oauth_oidc | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:10.1.2 | 2 | CONTEXT_REQUIRED | MB-R243 | oauth_oidc | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:10.2.1 | 2 | CONTEXT_REQUIRED | MB-R244 | oauth_oidc | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:10.2.2 | 2 | CONTEXT_REQUIRED | MB-R245 | oauth_oidc | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:10.3.1 | 2 | CONTEXT_REQUIRED | MB-R246 | oauth_oidc | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:10.3.2 | 2 | CONTEXT_REQUIRED | MB-R247 | oauth_oidc | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:10.3.3 | 2 | CONTEXT_REQUIRED | MB-R248 | oauth_oidc | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:10.3.4 | 2 | CONTEXT_REQUIRED | MB-R249 | oauth_oidc | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:10.4.1 | 1 | MANUAL_REVIEW | MB-R122 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:10.4.2 | 1 | MANUAL_REVIEW | MB-R123 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:10.4.3 | 1 | MANUAL_REVIEW | MB-R124 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:10.4.4 | 1 | MANUAL_REVIEW | MB-R125 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:10.4.5 | 1 | MANUAL_REVIEW | MB-R126 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:10.4.6 | 2 | CONTEXT_REQUIRED | MB-R250 | oauth_oidc | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:10.4.7 | 2 | CONTEXT_REQUIRED | MB-R251 | oauth_oidc | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:10.4.8 | 2 | CONTEXT_REQUIRED | MB-R252 | oauth_oidc | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:10.4.9 | 2 | CONTEXT_REQUIRED | MB-R253 | oauth_oidc | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:10.4.10 | 2 | CONTEXT_REQUIRED | MB-R254 | oauth_oidc | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:10.4.11 | 2 | CONTEXT_REQUIRED | MB-R255 | oauth_oidc | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:10.5.1 | 2 | CONTEXT_REQUIRED | MB-R256 | oauth_oidc | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:10.5.2 | 2 | CONTEXT_REQUIRED | MB-R257 | oauth_oidc | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:10.5.3 | 2 | CONTEXT_REQUIRED | MB-R258 | oauth_oidc | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:10.5.4 | 2 | CONTEXT_REQUIRED | MB-R259 | oauth_oidc | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:10.5.5 | 2 | CONTEXT_REQUIRED | MB-R260 | oauth_oidc | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:10.6.1 | 2 | CONTEXT_REQUIRED | MB-R261 | oauth_oidc | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:10.6.2 | 2 | CONTEXT_REQUIRED | MB-R262 | oauth_oidc | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:10.7.1 | 2 | CONTEXT_REQUIRED | MB-R263 | oauth_oidc | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:10.7.2 | 2 | CONTEXT_REQUIRED | MB-R264 | oauth_oidc | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:10.7.3 | 2 | CONTEXT_REQUIRED | MB-R265 | oauth_oidc | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:11.1.1 | 2 | MANUAL_REVIEW | MB-R182 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:11.1.2 | 2 | MANUAL_REVIEW | MB-R183 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:11.2.1 | 2 | PARTIALLY_AUTOMATED | MB-R025 | — | Review predicate/evidence contract; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:11.2.2 | 2 | MANUAL_REVIEW | MB-R184 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:11.2.3 | 2 | PARTIALLY_AUTOMATED | MB-R132 | — | Review predicate/evidence contract; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:11.3.1 | 1 | AUTOMATED | MB-R132 | — | Review predicate/evidence contract; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:11.3.2 | 1 | PARTIALLY_AUTOMATED | MB-R025, MB-R132 | — | Compose evidence in one definition; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:11.3.3 | 2 | PARTIALLY_AUTOMATED | MB-R132 | — | Review predicate/evidence contract; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:11.4.1 | 1 | PARTIALLY_AUTOMATED | Native ASVS-NATIVE:11.4.1 (no MB-R alias) | — | Collect scoped evidence; independent confirmation remains required |
| OWASP-ASVS:5.0.0:11.4.2 | 2 | PARTIALLY_AUTOMATED | MB-R025 | — | Review predicate/evidence contract; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:11.4.3 | 2 | MANUAL_REVIEW | MB-R185 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:11.4.4 | 2 | MANUAL_REVIEW | MB-R186 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:11.5.1 | 2 | PARTIALLY_AUTOMATED | MB-R023 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:11.6.1 | 2 | PARTIALLY_AUTOMATED | MB-R132 | — | Review predicate/evidence contract; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:12.1.1 | 1 | AUTOMATED | MB-R028 | — | Review predicate/evidence contract; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:12.1.2 | 2 | PARTIALLY_AUTOMATED | MB-R028, MB-R078 | — | Compose evidence in one definition; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:12.1.3 | 2 | MANUAL_REVIEW | MB-R187 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:12.2.1 | 1 | AUTOMATED | MB-R026, MB-R073 | — | Compose evidence in one definition; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:12.2.2 | 1 | AUTOMATED | MB-R135 | — | Review predicate/evidence contract; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:12.3.1 | 2 | PARTIALLY_AUTOMATED | MB-R073, MB-R076, MB-R078 | — | Compose evidence in one definition; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:12.3.2 | 2 | PARTIALLY_AUTOMATED | MB-R135 | — | Review predicate/evidence contract; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:12.3.3 | 2 | PARTIALLY_AUTOMATED | MB-R073 | — | Review predicate/evidence contract; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:12.3.4 | 2 | MANUAL_REVIEW | MB-R188 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:13.1.1 | 2 | MANUAL_REVIEW | MB-R189 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:13.2.1 | 2 | MANUAL_REVIEW | MB-R190 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:13.2.2 | 2 | PARTIALLY_AUTOMATED | MB-R081 | — | Review predicate/evidence contract; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:13.2.3 | 2 | PARTIALLY_AUTOMATED | MB-R097 | — | Review predicate/evidence contract; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:13.2.4 | 2 | PARTIALLY_AUTOMATED | MB-R076 | — | Review predicate/evidence contract; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:13.2.5 | 2 | PARTIALLY_AUTOMATED | MB-R076 | — | Review predicate/evidence contract; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:13.3.1 | 2 | PARTIALLY_AUTOMATED | MB-R072, MB-R079, MB-R097 | — | Compose evidence in one definition; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:13.3.2 | 2 | PARTIALLY_AUTOMATED | MB-R081 | — | Review predicate/evidence contract; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:13.4.1 | 1 | AUTOMATED | MB-R134 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:13.4.2 | 2 | PARTIALLY_AUTOMATED | MB-R031, MB-R032, MB-R036, MB-R044, MB-R074 | — | Compose evidence in one definition; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:13.4.3 | 2 | AUTOMATED | MB-R005 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:13.4.4 | 2 | PARTIALLY_AUTOMATED | MB-R191, MB-R274 | — | Compose evidence in one definition |
| OWASP-ASVS:5.0.0:13.4.5 | 2 | PARTIALLY_AUTOMATED | MB-R042, MB-R095 | — | Compose evidence in one definition; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:14.1.1 | 2 | MANUAL_REVIEW | MB-R192 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:14.1.2 | 2 | MANUAL_REVIEW | MB-R193 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:14.2.1 | 1 | PARTIALLY_AUTOMATED | MB-R133 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:14.2.2 | 2 | MANUAL_REVIEW | MB-R194 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:14.2.3 | 2 | PARTIALLY_AUTOMATED | MB-R077 | — | Review predicate/evidence contract; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:14.2.4 | 2 | PARTIALLY_AUTOMATED | MB-R024, MB-R045, MB-R077, MB-R083 | — | Compose evidence in one definition; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:14.3.1 | 1 | MANUAL_REVIEW | MB-R127 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:14.3.2 | 2 | MANUAL_REVIEW | MB-R195 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:14.3.3 | 2 | MANUAL_REVIEW | MB-R196 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:15.1.1 | 1 | MANUAL_REVIEW | MB-R128 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:15.1.2 | 2 | PARTIALLY_AUTOMATED | MB-R049, MB-R055, MB-R058, MB-R060, MB-R063, MB-R068, MB-R070 | — | Compose evidence in one definition; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:15.1.3 | 2 | MANUAL_REVIEW | MB-R197 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:15.2.1 | 1 | AUTOMATED | MB-R049, MB-R050, MB-R059 | — | Compose evidence in one definition; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:15.2.2 | 2 | MANUAL_REVIEW | MB-R198 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:15.2.3 | 2 | PARTIALLY_AUTOMATED | MB-R031, MB-R032, MB-R036, MB-R044 | — | Compose evidence in one definition; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:15.3.1 | 1 | MANUAL_REVIEW | MB-R129 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:15.3.2 | 2 | MANUAL_REVIEW | MB-R199 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:15.3.3 | 2 | MANUAL_REVIEW | MB-R200 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:15.3.4 | 2 | MANUAL_REVIEW | MB-R201 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:15.3.5 | 2 | MANUAL_REVIEW | MB-R202 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:15.3.6 | 2 | MANUAL_REVIEW | MB-R203 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:15.3.7 | 2 | MANUAL_REVIEW | MB-R204 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:16.1.1 | 2 | MANUAL_REVIEW | MB-R205 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:16.2.1 | 2 | MANUAL_REVIEW | MB-R206 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:16.2.2 | 2 | MANUAL_REVIEW | MB-R207 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:16.2.3 | 2 | MANUAL_REVIEW | MB-R208 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:16.2.4 | 2 | MANUAL_REVIEW | MB-R209 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:16.2.5 | 2 | PARTIALLY_AUTOMATED | MB-R024, MB-R045, MB-R080, MB-R084 | — | Compose evidence in one definition; Split legacy mapping; reuse check implementations |
| OWASP-ASVS:5.0.0:16.3.1 | 2 | MANUAL_REVIEW | MB-R210 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:16.3.2 | 2 | MANUAL_REVIEW | MB-R211 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:16.3.3 | 2 | MANUAL_REVIEW | MB-R212 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:16.3.4 | 2 | MANUAL_REVIEW | MB-R213 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:16.4.1 | 2 | MANUAL_REVIEW | MB-R214 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:16.4.2 | 2 | PARTIALLY_AUTOMATED | MB-R001, MB-R002, MB-R004, MB-R043 | — | Compose evidence in one definition |
| OWASP-ASVS:5.0.0:16.4.3 | 2 | MANUAL_REVIEW | MB-R215 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:16.5.1 | 2 | PARTIALLY_AUTOMATED | MB-R033 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:16.5.2 | 2 | MANUAL_REVIEW | MB-R216 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:16.5.3 | 2 | MANUAL_REVIEW | MB-R217 | — | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:17.1.1 | 2 | CONTEXT_REQUIRED | MB-R266 | webrtc | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:17.2.1 | 2 | CONTEXT_REQUIRED | MB-R267 | webrtc | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:17.2.2 | 2 | CONTEXT_REQUIRED | MB-R268 | webrtc | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:17.2.3 | 2 | CONTEXT_REQUIRED | MB-R269 | webrtc | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:17.2.4 | 2 | CONTEXT_REQUIRED | MB-R270 | webrtc | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:17.3.1 | 2 | CONTEXT_REQUIRED | MB-R271 | webrtc | Review predicate/evidence contract |
| OWASP-ASVS:5.0.0:17.3.2 | 2 | CONTEXT_REQUIRED | MB-R272 | webrtc | Review predicate/evidence contract |

## Acceptance before code migration

Exactly 253 unique L1/L2 identities, each with one target definition; no duplicate inherited identities; coverage gaps remain visible; each old mapping has an explicit successor/evidence link; every predicate has aggregation and scope gates; legacy selections, exclusions and dashboard mappings have an explicit compatibility plan. Profiles now reference native implementations for the former 12 gaps; the legacy MB-R loader adapter remains unchanged.

