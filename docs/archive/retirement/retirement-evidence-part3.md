# Retirement evidence, part 3 — archived entries 40–59

This review concerns **20 archived criteria**, MB-0101, MB-0102 and MB-0731–MB-0748. The archive manual/review metadata is not used as evidence that a criterion cannot be automated. No catalog, retirement status or executable rule was changed by this review.

## Reproduction and interpretation

```bash
php tools/verify-retirements-part3.php > /tmp/retirement-part3.json
```

The checked-in [probe output](retirement-evidence-part3-probes.json) records **54 direct binding executions**. Every row below has executed fixtures. `PASS`/`FAIL`/`UNKNOWN` are handler return values, not a new requirement verdict. These executions use archived check bindings against the **current checkout implementations**, not a historical executable captured on the retirement date. For MB-0738/0739, the additional HTTP binding is explicitly untested in the direct fixture suite. API endpoint and policy overrides are recorded per case; they are not silently presented as the original arguments.

The package-status fixture starts a loopback PHP server and exercises the existing HTTPS-to-private-HTTP fallback with no token. It supplies synthetic maintained/abandoned/unknown statuses. It does not contact the public Magebean API or prove current real-package metadata. All source/log strings are inert fixtures; uploaded code is never executed.

## Per-criterion evidence

### MB-0101 — Global Admin ACL limited to approved roles

- Implementation inspected: `src/Engine/Checks/AdminAclCheck.php:213`.
- Verified active criterion(s): **MB-0801**.
- Verdict: **Replacement for an explicitly bounded policy; not evidence of an inherently manual control.**

The injected complete role/user/rule fixture with a direct global allow grant fails without approvals and passes when role/user 1 are explicitly approved. Business approval is an input, but comparison of collected grants to that input is executable. Active MB-0801 instead requires approved_role_ids, bounded nonempty role/rule inventories and rejects malformed/orphan/direct-user evidence. It does not compute inherited effective privileges. AdminAclCheckTest and ProductionRuntimeCheckTest passed; no live production ACL database was queried.

Direct observed cases: `global grant without approvals` → **FAIL**; `same grant explicitly approved` → **PASS**.

### MB-0102 — PCI vendor default account evidence assessment

- Implementation inspected: `src/Engine/Checks/PciEvidenceCheck.php:19`.
- Verified active criterion(s): **MB-0470 (PCI family)**.
- Verdict: **No retirement proof for the whole control; preserve evidence workflow and consider narrower machine observations.**

Missing and structurally empty JSON both return UNKNOWN. The handler parses supplied scope/account states and reasons about retained default accounts; it does not independently discover every vendor appliance or test default passwords. PciEvidenceCheckTest passed its structured pass/fail/manual/unknown cases. PCI 2.2.2 remains active as MB-0470 in its own source family. This is not an automated Magebean replacement, nor does the need for externally supplied inventory prove account observations cannot be automated for a supported component.

Direct observed cases: `missing account evidence` → **UNKNOWN**; `malformed account evidence` → **UNKNOWN**.

### MB-0731 — Admin passwords require at least 8 characters

- Implementation inspected: `src/Engine/Checks/MagentoCheck.php:450`.
- Verified active criterion(s): **MB-0728**.
- Verdict: **Replacement; direct evidence disproves a blanket cannot-automate justification.**

A supported min_password_length declaration of 4 fails and 12 passes in the archived handler. Active MB-0728 reads the configured minimum, falling back to the installed Magento User validator when applicable; its bounded claim excludes strength of existing passwords and custom IdP behavior. BasicAdminConfigurationTest passed 32 assertions. Distinguish de-duplication/re-scoping from impossibility: this configuration predicate already executes without a human verdict.

Direct observed cases: `configured minimum 4` → **FAIL**; `configured minimum 12` → **PASS**.

### MB-0732 — No raw SQL without abstraction

- Implementation inspected: `src/Engine/Checks/Families/InputSafetySourceChecks.php:9`.
- Verified active criterion(s): **MB-0786; MB-0822**.
- Verdict: **Automate a narrower predicate; existing replacements are not equivalent SQL-safety coverage.**

The direct rawQuery concatenation fails, but a parameter-bound query with literal SQL and a second bind array also fails in the current archived heuristic. Dynamic method invocation $db->$f($sql) passes without analysis. The implementation uses textual windows and named calls, not binding-aware SQL dataflow. MB-0786 precisely checks literal first arguments and UNKNOWN variables; MB-0822 flags supported request-to-query flows. Neither proves all SQL uses abstraction or is injection-safe. AutomatedSourcePolicyTest passed 64 assertions. The failing heuristic supports retiring its broad clean claim, not retiring useful binding-aware analysis.

Direct observed cases: `rawQuery` → **FAIL**; `bound query` → **FAIL**; `indirect sql` → **PASS**.

### MB-0733 — Template output is escaped

- Implementation inspected: `src/Engine/Checks/Families/TemplateRequestSourceChecks.php:9`.
- Verified active criterion(s): **None verified for full template escaping**.
- Verdict: **No retirement proof for deleting the audit capability; automate context-specific subsets.**

Raw <?= $value ?> fails and escapeHtml($value) passes. Critically, escapeHtml($value) inside a JavaScript string also passes this generic PHTML handler: an approved helper name does not prove the correct output context. This directly demonstrates an insufficient old implementation. No active Magebean catalog rule was verified as a replacement for contextual template escaping. MB-0736 is also archived. These fixtures do not show contextual escaping cannot be checked with PHP/template/JavaScript parsing.

Direct observed cases: `raw template` → **FAIL**; `html helper` → **PASS**; `wrong JS context helper` → **PASS**.

### MB-0734 — No unsafe deserialization

- Implementation inspected: `src/Engine/Checks/Families/InputSafetySourceChecks.php:147`.
- Verified active criterion(s): **MB-0789**.
- Verdict: **Automate narrower policy; replacement intentionally changes acceptance.**

Direct unserialize(request) fails; unserialize(payload, allowed_classes=false) passes; call_user_func("unserialize", request) also passes despite preserving an unsafe indirect call. Active MB-0789 bans direct global native unserialize regardless of options and reports unsupported indirect references as incomplete scope. This is a native-API policy, not equivalent verification of every deserialization pathway. AutomatedSourcePolicyTest passed. The evidence warrants honest narrower claims and improved indirect-call coverage, not a universal manual-only conclusion.

Direct observed cases: `native unsafe` → **FAIL**; `classes disabled` → **PASS**; `indirect unsafe` → **PASS**.

### MB-0735 — Command execution is guarded

- Implementation inspected: `src/Engine/Checks/Families/InputSafetySourceChecks.php:183`.
- Verified active criterion(s): **MB-0790; MB-0822**.
- Verdict: **Automate narrower policy and request-flow diagnostics.**

Direct exec(request) fails, constant exec("whoami") passes, and indirect $fn="exec"; $fn(request) passes the archived safety heuristic. MB-0790 intentionally bans enumerated direct native process APIs and backticks even when the command is constant; MB-0822 supports limited request-to-command dataflow. Neither proves all process execution is guarded. AutomatedSourcePolicyTest passed. The three concrete outcomes establish both automatable observations and the previous detector boundary.

Direct observed cases: `request command` → **FAIL**; `constant command` → **PASS**; `indirect command` → **PASS**.

### MB-0736 — Escaping for JS context

- Implementation inspected: `src/Engine/Checks/Families/TemplateRequestSourceChecks.php:110`.
- Verified active criterion(s): **None verified for full JavaScript escaping**.
- Verdict: **No retirement proof for dropping all JS-context coverage; retain as a detector backlog.**

Raw PHP output in a JavaScript string fails; escapeJs passes; escapeHtml in that JS context fails. These positive/negative fixtures are evidence that a supported context subset already executes automatically. They do not cover JSON serialization, script-element termination, event attributes, mixed template languages or every sink. No active equivalent contextual escaping rule was verified. A broad security guarantee should be replaced by exact supported context checks, not described as intrinsically unautomatable.

Direct observed cases: `raw JS` → **FAIL**; `JS helper` → **PASS**; `wrong HTML helper` → **FAIL**.

### MB-0737 — Sensitive data not logged

- Implementation inspected: `src/Engine/Checks/Families/DataProtectionSourceChecks.php:376`.
- Verified active criterion(s): **MB-0795; MB-0814 (partial syntax only)**.
- Verdict: **Automate narrower logging/dataflow observations; replacement is partial.**

A named password variable in a logger call fails; a neutral value passes. Adding an unrelated comment containing mask causes the same password logging to pass: hasRedactionSignal at line 1014 scans a surrounding text window instead of proving redaction of the logged argument. MB-0795 and MB-0814 check direct request superglobals in named logger calls, not arbitrary secrets, tainted aliases or emitted log values. These are useful exact policies but do not fully replace sensitive-data logging analysis.

Direct observed cases: `named password log` → **FAIL**; `neutral payload log` → **PASS**; `unrelated mask comment` → **PASS**.

### MB-0738 — Xdebug disabled in production

- Implementation inspected: `src/Engine/Checks/PhpConfigCheck.php:155`.
- Verified active criterion(s): **MB-0729; MB-0807 (worker capability)**.
- Verdict: **Replacement for scoped static/runtime observations, not full equivalence.**

An xdebug zend_extension declaration fails; xdebug.mode=off alone passes. Only the first archived binding php_xdebug_disabled was executed in the part-3 probe; http_no_xdebug_headers was deliberately not executed there. Active MB-0729 inspects project debug declarations and ini files, and MB-0807 assesses mapped worker Xdebug modules with required context. PrelaunchDeploymentQaRegressionTest passed 23 assertions, including repeated zend_extension declarations. Header absence would not prove worker module absence. These existing automations refute a blanket cannot-automate statement.

Direct observed cases: `enabled extension` → **FAIL**; `mode off only` → **PASS**.

### MB-0739 — display_errors is Off

- Implementation inspected: `src/Engine/Checks/PhpConfigCheck.php:217`.
- Verified active criterion(s): **MB-0729 (project declarations only)**.
- Verdict: **Replacement for the declared flag subset; runtime response exposure remains distinct.**

display_errors=On fails and Off passes automatically. Only php_display_errors_disabled ran in the direct probe; the second archived binding http_no_stacktrace was not run by that probe. Active MB-0729 includes display_errors/display_startup_errors in inspected project ini files but expressly excludes web-worker runtime and all-response behavior. PrelaunchDeploymentQaRegressionTest and BasicAdminConfigurationTest passed. No live web-worker ini or arbitrary application error response was exercised. Narrow static flag testing is executable and should not be labelled impossible.

Direct observed cases: `display_errors On` → **FAIL**; `display_errors Off` → **PASS**.

### MB-0740 — No dev debug configs on production (template hints off)

- Implementation inspected: `src/Engine/Checks/PhpConfigCheck.php:281`.
- Verified active criterion(s): **MB-0729**.
- Verdict: **Replacement/re-scope; no evidence this predicate requires a human decision.**

Supported template_hints=0 passes and =1 fails. The old handler treats missing paths as absent/disabled in the supplied file; it does not independently establish effective settings in every store or custom module. Active MB-0729 states the default project declaration scope explicitly and covers relevant native debug keys. The positive/negative config fixtures and passing BasicAdminConfigurationTest demonstrate an automatic declaration check, not a reason to delete the capability.

Direct observed cases: `template_hints 0` → **PASS**; `template_hints 1` → **FAIL**.

### MB-0741 — No dev cache backends (avoid file backend)

- Implementation inspected: `src/Engine/Checks/PhpConfigCheck.php:598`.
- Verified active criterion(s): **MB-0038**.
- Verdict: **Verified executable replacement/de-duplication; cannot justify retirement as unautomatable.**

The exact php_no_file_cache_backend name and archived args are reused as an MB-0038 check. File backend fails; Redis for default only fails because page_cache still falls back to file; Redis declared for both frontends passes. This is not a theoretical replacement: the same current handler and arguments were executed. MB-0038 also adds php_cache_backend_configured. Its claim is declared backend policy, not actual Redis/Varnish health. The direct three-case result is sufficient to demonstrate automatable parity of this component.

Direct observed cases: `backend Cm_Cache_Backend_File` → **FAIL**; `backend Cm_Cache_Backend_Redis` → **FAIL**; `both frontend Redis declarations` → **PASS**.

### MB-0742 — Debug template hints disabled in production

- Implementation inspected: `src/Engine/Checks/PhpConfigCheck.php:329`.
- Verified active criterion(s): **MB-0729**.
- Verdict: **Replacement/re-scope; support automated default-scope flag checks.**

Inline translation=0 passes and =1 fails. The archived handler reads the named project config paths and treats absence as no declared enabled value. Active MB-0729 covers the relevant default native debug/inline translation declarations, with explicit limits about worker runtime and custom integrations. These config fixtures establish a machine-checkable subset. They do not demonstrate every store-scope runtime state.

Direct observed cases: `inline translation 0` → **PASS**; `inline translation 1` → **FAIL**.

### MB-0743 — PII not logged in application logs

- Implementation inspected: `src/Engine/Checks/Families/DataProtectionSourceChecks.php:376`.
- Verified active criterion(s): **MB-0795; MB-0814 (partial syntax only)**.
- Verdict: **Automate narrower PII observations; no full replacement verified.**

This uses the same code_sensitive_logging binding as MB-0737 with max_results=50. A logger call with $email passes in the direct fixture: hasSensitiveLoggingSignal enumerates password/token/card-like terms, not general PII. A neutral value also passes. Therefore the old PII title is not established by its implementation. Direct-superglobal logger checks are partial replacements and miss non-request customer data. PII field/flow or redacted emitted-log checks can be defined narrowly; the test does not support saying PII checks cannot be automated.

Direct observed cases: `named email log` → **PASS**; `neutral payload log` → **PASS**.

### MB-0744 — No abandoned libraries allowed

- Implementation inspected: `src/Engine/Checks/Families/ComposerRepositoryChecks.php:147`.
- Verified active criterion(s): **MB-0061**.
- Verdict: **Verified executable replacement; no retirement proof based on manual labels.**

Both archived MB-0744 and active MB-0061 library-scoped check use composer_abandoned_api. A loopback status API fixture returns abandoned=true/false/status-unknown: archived args and strict_scope=true active variant each return FAIL/PASS/UNKNOWN respectively. The active library binding differs from archived args by strict_scope=true; its other metadata source/default inventory limitations remain. Missing lock and invalid endpoint also return UNKNOWN. These are actual parser/transport/decision executions, not assertions that a real public package feed was contacted or that abandonment always requires replacement.

Direct observed cases: `no lock data` → **UNKNOWN**; `valid library inventory unavailable status` → **UNKNOWN**; `loopback abandoned=true archived args` → **FAIL**; `loopback abandoned=true active MB-0061 strict scope` → **FAIL**; `loopback abandoned=false archived args` → **PASS**; `loopback abandoned=false active MB-0061 strict scope` → **PASS**; `loopback abandoned=null archived args` → **UNKNOWN**; `loopback abandoned=null active MB-0061 strict scope` → **UNKNOWN**.

### MB-0745 — Debug/verbose off for third-party integrations

- Implementation inspected: `src/Engine/Checks/PhpConfigCheck.php:377`.
- Verified active criterion(s): **MB-0804**.
- Verdict: **Replacement with named policy prerequisites; old wildcard heuristic is not complete.**

payment.fixture.debug=0 passes and =1 fails. The archived implementation guesses debug/verbose/logging keys from integration-related path names; absence of matches is not proof every third-party integration is quiet, and audit logging may legitimately remain enabled. Active MB-0804 requires explicitly configured integration setting paths and resolves recognized values in default scope. ProductionRuntimeCheckTest passed 35 assertions including missing policy UNKNOWN, explicit disabled debug PASS despite logging on, and malformed flag UNKNOWN. This is supported automation with stated inputs.

Direct observed cases: `payment debug 0` → **PASS**; `payment debug 1` → **FAIL**.

### MB-0746 — Third-party logging sanitized (mask/redact)

- Implementation inspected: `src/Engine/Checks/Families/DataProtectionSourceChecks.php:255`.
- Verified active criterion(s): **MB-0795; MB-0814 (partial syntax only)**.
- Verdict: **Automate narrower argument/redaction observations; no complete active replacement.**

Gateway-associated password logging fails; an unrelated comment saying redact makes the same logging pass. The handler uses integration/sensitive word signals and hasRedactionSignal on a surrounding window (lines 895, 997–1020), not proof that a sanitizer transformed the logged value. Active direct-superglobal log checks do not prove third-party middleware scrubs passwords, responses or payment data. The old broad clean claim is unsupported, but deletion of all redaction checking has no demonstrated technical necessity.

Direct observed cases: `gateway log` → **FAIL**; `unrelated redact comment` → **PASS**.

### MB-0747 — No cardholder data in application logs

- Implementation inspected: `src/Engine/Checks/Families/PaymentSourceChecks.php:130`.
- Verified active criterion(s): **None verified for actual cardholder-data log scanning**.
- Verdict: **No retirement proof for deleting supported pattern scanning; automate narrower, safely redacted findings.**

A synthetic standard test PAN in a JSON log fails. No log inventory passes with "No application log or report files found to scan". The latter is absence of examined files, not evidence every application/central log contains no cardholder data. No active Magebean rule was verified that scans actual logs for this predicate; source superglobal logging and working-tree secret checks are not equivalents. Pattern/Luhn-labelled observations with explicit files, retention scope and redaction can be automated; these probes do not establish full payment-data compliance.

Direct observed cases: `synthetic test PAN` → **FAIL**; `no log inventory` → **PASS**.

### MB-0748 — No executable code in media or upload paths

- Implementation inspected: `src/Engine/Checks/Families/AuthorizationSourceChecks.php:195`.
- Verified active criterion(s): **MB-0780; MB-0800**.
- Verdict: **Partial bounded replacement; document lost paths/signatures rather than claim full parity.**

PHP hidden in picture.jpg and a Python shebang in script.txt both fail the archived signature detector. Missing upload roots pass the legacy handler. MB-0780 checks PHP-like filenames in pub/media; MB-0800 checks configured PHP tags/handler signatures with bounded inventory and UNKNOWN for missing/unreadable scope. Defaults do not cover all archived pub/import, var/import, var/export roots; Python/shebang coverage is not equivalent. ProductionRuntimeCheckTest and BasicExposureCheckTest passed. These are strong existing automations, but neither proves absence of all executable code or server-side execution.

Direct observed cases: `PHP disguised as image` → **FAIL**; `non-PHP shebang signature` → **FAIL**; `no upload inventory` → **PASS**.

## Additional checks actually executed

Full commands and captured outputs are in [retirement-evidence-part3-tests.json](retirement-evidence-part3-tests.json). All ten commands exited 0:

- `php tests/PciEvidenceCheckTest.php` — PciEvidenceCheckTest: PASS.
- `php tests/AdminAclCheckTest.php` — AdminAclCheckTest: PASS.
- `php tests/BasicAdminConfigurationTest.php` — BasicAdminConfigurationTest: 32 assertions passed.
- `php tests/AutomatedSourcePolicyTest.php` — Automated source policy: 64 assertions passed.
- `php tests/ProductionRuntimeCheckTest.php` — ProductionRuntimeCheckTest: 35 assertions passed.
- `php tests/BasicExposureCheckTest.php` — BasicExposureCheckTest: 16 assertions passed.
- `php tests/PrelaunchDeploymentQaRegressionTest.php` — Prelaunch deployment QA: 23 assertions passed; representative tree 0.021s.
- `php tests/PrelaunchHttpQaRegressionTest.php` — Prelaunch HTTP QA regressions: 22 assertions passed.
- `php tests/OwaspScanQualityTest.php` — OwaspScanQualityTest: 151 assertions passed.
- `php tests/ComposerMaintenanceCoverageTest.php` — Composer maintenance coverage: 11 assertions passed.

These tests verify the predicates exercised in their fixtures. They do not certify live business approvals, actual deployed passwords, all template contexts, worker configuration, public package feeds, every store scope, centralized logs or server execution rules.

## Findings that change the retirement rationale

1. **MB-0741 and MB-0744 have executable active counterparts using the same handler.** Their retirement can be described as consolidation/re-scoping, not inability to automate.
2. **Password and debug configuration have direct positive/negative executions.** MB-0731/0738/0739/0740/0742/0745 similarly cannot be dismissed using a manual flag alone.
3. **Old clean results for source/logging rules have concrete counterexamples.** The parameter-bound SQL false positive, indirect-operation passes, context-insensitive template helper acceptance, unrelated redaction-comment passes and PII email miss identify detector defects or overbroad claims. They justify narrower criteria or fixes, not a universal assertion that analysis is impossible.
4. **Several broad capabilities lack a verified full replacement.** Template/JS escaping, general PII/redaction and actual cardholder-data log scanning need explicit backlog decisions; listing a different narrow source policy is not equivalent coverage.
5. **Missing inventory is not clean evidence.** Legacy log/media PASS with no collected files must not be used to justify coverage. Active bounded upload criteria improve this distinction but have narrower default roots/signatures.

