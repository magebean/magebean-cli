# OWASP scan quality review — 2026-10-07

Reviewed all 33 reported rows. The profile retains 69 requirements: 31 default automated assessments and 38 assessments requiring explicit human evidence. No requirement or standard alignment was deleted.

Twelve criteria now have reviewed bounded predicates. Seventeen broad criteria are explicitly human-required; their checks remain supporting technical observations and are selected with `--include-manual-review` or a direct `--rules` selector. Two already-human requirements (debug-wide/PII) remain filtered by default. Git history stays available globally; the deployment OWASP profile uses the existing working-tree requirement MB-0730. Cookie collection retains its actual endpoint/TLS cause.

This avoids claiming security conformance from keyword proximity, inactive server configuration or deploy-owner permission bits. It also prevents partial API inventories, comments, malformed PHP, unreadable paths and incomplete package-status responses from producing clean results.

| Requirement | Review decision | Scope / required evidence |
|---|---|---|
| MB-0010 | human_evidence_required | Verify the effective admin route and active reverse-proxy/firewall allowlist; repository ACL hints do not prove access restriction. |
| MB-0015 | human_evidence_required | Verify server-side CSRF validation and exemptions for each state-changing route; token markup alone does not prove CSRF protection. |
| MB-0016 | human_evidence_required | Trace attacker-controlled URLs to outbound requests and verify scheme, destination and redirect validation; nearby keywords do not prove SSRF prevention. |
| MB-0019 | human_evidence_required | Review dynamic execution arguments and runtime PHP semantics; boolean assert and nearby request tokens do not prove code injection. |
| MB-0020 | human_evidence_required | Trace untrusted file paths and verify canonicalization and containment at the actual filesystem sink. |
| MB-0021 | human_evidence_required | Review effective upload validation, storage and execution restrictions including delegated framework validators. |
| MB-0023 | human_evidence_required | Determine which generated values are security-sensitive and verify their entropy source; ordinary rand usage is not a cryptographic vulnerability. |
| MB-0025 | human_evidence_required | Review cryptographic algorithms, parameters and session configuration; raw OpenSSL or sodium use is not automatically unsafe. |
| MB-0043 | human_evidence_required | Verify effective installed logrotate, journald or managed logging retention and activation; a project logrotate file is optional evidence, not the entire logging policy. |
| MB-0073 | human_evidence_required | Review actual runtime outbound endpoint configuration including dynamic URLs; literal source URL observations alone do not establish HTTPS-only communication. |
| MB-0078 | human_evidence_required | Verify active gateway TLS protocols and cipher negotiation; inactive repository web-server configuration is supporting evidence only. |
| MB-0079 | human_evidence_required | Review secret storage and database configuration with redacted evidence; static source scanning cannot establish absence of API keys in the database. |
| MB-0089 | human_evidence_required | Verify enforcing CSP headers on actual checkout responses and the effective Magento CSP mode; source declarations alone do not prove enforcement. |
| MB-0096 | human_evidence_required | Verify security headers emitted by successful application responses; source declarations alone do not prove runtime policy. |
| MB-0097 | human_evidence_required | Confirm whether flagged literals are actual credentials and inspect dynamic secret sources; secret-like constant names alone do not prove hardcoded secrets. |
| MB-0098 | human_evidence_required | Review XML parser version, entity options and actual untrusted input; a nearby LIBXML flag alone does not prove exploitable XXE. |
| MB-0004 | human_evidence_required | Verify code is not writable by the actual PHP/web-server process, including ACLs and mount policy. Deploy-owner write bits alone do not establish runtime write access; do not chmod a deployment recursively from this observation. |
| MB-0009 | reviewed_scoped_automation | The effective default-scope Magento admin/security/session_lifetime setting resolved from env.php, config.php, core_config_data or actual installed module defaults is a positive integer not exceeding 900 seconds. |
| MB-0014 | reviewed_scoped_automation | Valid PHP files in the configured app subtree contain no T_VARIABLE references to $_GET, $_POST, $_REQUEST, $_COOKIE, $_FILES or $_SERVER. Comments and literal strings are ignored. This is a source coding policy, not proof of input validation. |
| MB-0027 | reviewed_scoped_automation | A successful same-host HTTPS response at the configured runtime URL emits one unambiguous Strict-Transport-Security header with an exact integer max-age directive of at least 31536000 seconds. Repository web-server declarations are not runtime proof. |
| MB-0034 | reviewed_scoped_automation | At least one readable PHP artifact exists in each configured generated/metadata and generated/code directory. This assesses artifact presence, not DI compilation correctness or freshness. |
| MB-0042 | reviewed_scoped_automation | Within the collected pub tree, no configured var/log or var/report relative path, nor symlink to the corresponding project target, is present. This is filesystem placement, not a live HTTP exposure assertion. |
| MB-0055 | reviewed_scoped_automation | No transitive package version in the complete collected Composer lock inventory is identified as affected by applicable advisories returned by the configured OSV service. Coverage is limited to the queried inventory and service data. |
| MB-0056 | reviewed_scoped_automation | For returned applicable advisory findings with published fixed versions, the combined declared dependency constraints intersect versions at or above the published fixed version. This does not establish complete Composer solver feasibility, platform compatibility or every fixed branch. |
| MB-0057 | reviewed_scoped_automation | Every package version in the complete collected Composer lock inventory has an explicit non-yanked status from the configured package-status source. Missing per-package status cannot establish a clean result. |
| MB-0059 | reviewed_scoped_automation | No returned advisory affecting an installed Composer package version has a publication age greater than the configured 30-day threshold. This is publication age, not organizational discovery time or a measured remediation SLA. |
| MB-0061 | reviewed_scoped_automation | No dependency package in the complete assessed Composer inventory is marked abandoned by the configured package-maintenance source; a clean conclusion requires explicit known status for every assessed package. |
| MB-0069 | reviewed_scoped_automation | Collected direct Composer package versions are not older than the latest stable release reported by the configured package-status source. This is a maintenance policy, not proof of an exploitable vulnerability. |
| MB-0070 | reviewed_scoped_automation | composer.lock has a matching Composer content-hash, no duplicate or malformed package identities, and contains or provides/replaces each declared root package dependency. This does not prove the full dependency solver result or installed vendor file integrity. |
| MB-0072 | deployment_profile_uses_MB-0730 | History scope retained globally; deployments without .git use existing working-tree requirement, not false clean history. |
| MB-0030 | collection_diagnostics | Report actual endpoint and TLS/network cause; no clean conclusion without emitted sensitive cookies. |
| MB-0379 | human_filtered_by_default | Default configuration cannot establish debug-disabled for all production components. |
| MB-0077 | human_filtered_by_default | Static string matching cannot establish third-party PII minimization. |

Collection gaps keep UNKNOWN for transport compatibility and now carry `collection_guidance` with category, owner and action. Default console prints the cause and action. TLS trust failures require a correct URL and trusted CA/certificate chain; TLS verification is never disabled. Missing cookie emissions require a real reachable session-producing page. The tool does not claim an unreachable deployment is secure.

Validation results are recorded after the regression and PHAR checks.

Validation completed: 82/82 standalone regression scripts pass; the source/PHAR contract exercises 130 quality assertions, real token/config/artifact predicates, a policy violation, and incomplete execution with exit3. On `/var/www/magento`, the rebuilt PHAR selected31/69 requirements and returned15PASS,14FAIL and2execution errors. There were no binding-unvalidated, default-human or INCONCLUSIVE sections. The remaining errors were untrusted self-signed TLS for HSTS and HTTP instead of successful HTTPS cookie probes; the console identifies the cause and required operator action.

The real-target rerun also fixed discovery of Magento_Security session defaults, classified binary fonts before applying text size limits, and raised the bounded deployed-text limit to16MiB so ordinary Composer lock files and packaged JavaScript are inspected. Oversized eligible text above the bound and unreadable inputs remain explicit collection errors. Actual target checks are not an attestation that all69 criteria conform.

Compatibility snapshot review accepted only the scoped listing and legacy admin-session fixture delta: missing configuration now yields unknown rather than a falseFAIL. Transport schema and unrelated engine/agent/PCI contracts remain unchanged. No commit or deployment was performed; the existing repository magebean.phar was not overwritten.
