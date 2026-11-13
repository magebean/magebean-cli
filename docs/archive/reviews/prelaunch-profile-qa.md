# Prelaunch profile QA

Read-only review of the current prelaunch profile. Three QA reviewers covered local deployment rules, HTTP/TLS checks and profile integration. The review focused on the 24 deployment/runtime additions and integration of the 28-member development set, including its recent fixes. Full membership is 52, default selection is 51 because local snapshot advisory MB-0828 is opt-in. The initial review was read-only. Subsequent authorized remediation is recorded below; the original findings remain as the audit trail.

## Verdict

The profile fits release-candidate review in its broad selection, but several checks can return clean results for unsupported or incompletely interpreted evidence. Passing existing tests is not sufficient to qualify a launch audit. Missing or ambiguous evidence must remain unavailable in structured results; it must not become a security finding or a clean assessment. The requested quiet overview is retained.

## Confirmed findings

### P2 — MB-0030 accepts contradictory duplicate SameSite attributes

Source: src/Engine/Checks/HttpCheck.php:396–405. assessCookieFlags takes the first SameSite value then stops. Reproduced with PHPSESSID=x; Secure; HttpOnly; SameSite=Lax; SameSite=None: the cookie assessment returns ok=true. Reversing those values returns false. The rule cannot establish an unambiguous cookie policy by selecting the first contradictory attribute. Reject ambiguous input as incomplete coverage, retain the reported evidence, and add duplicate/order regression cases. This finding does not assert exploitation or prescribe a browser behavior model.

### P2 — MB-0026 accepts an ambiguous redirect with multiple Location fields

Source: src/Engine/Checks/HttpCheck.php:205 and hget():138–140. A loopback 302 response with an HTTP external Location followed by a same-host HTTPS Location returns PASS because the helper takes only the last header value. This does not establish one unambiguous direct same-host HTTPS redirect. Validate header cardinality before evaluating destination; malformed/contradictory fields should be incomplete evidence.

### P2 — MB-0005 silently ignores recognizable listing content beyond 8 KiB

Source: src/Engine/Checks/HttpCheck.php:558. A successful loopback response with normal directory-index markup returns FAIL when the markup is early. The same recognizable markup after 9,000 spaces returns PASS. The detector truncates its local body inspection to 8,192 bytes without recording incomplete detection scope. Assess the bounded collected response consistently or emit a coverage gap whenever relevant data is excluded; do not silently treat an inspected prefix as a complete negative.

### P1 — MB-0729 can miss repeated Xdebug extension declarations

Source: src/Engine/Checks/MagentoCheck.php:153. An assessed php.ini containing zend_extension=xdebug.so followed by zend_extension=opcache.so returns a clean debug declaration result. parse_ini_file collapses repeatable extension directives to the last value, hiding the earlier Xdebug declaration. Parse repeatable directives without losing entries, distinguish an observed declaration from effective worker state, and test both declaration orders.

### P2 — MB-0780 reports clean after resolving a symlink media root

Source: src/Engine/Checks/BasicExposureCheck.php:14. The media root is resolved with realpath before checking symlinks. A pub/media symlink to an empty directory returns PASS with zero entries despite the criterion treating symlink collection as unresolved. Either enforce the declared no-symlink observation boundary, or deliberately version a supported linked-root policy with complete path/source scope. Do not silently discard the original root type.

### P2 — Project capabilities can disappear when CLI capabilities are added

Source: src/Engine/ScanPlanner.php:52–53 and src/Engine/RequirementCatalog.php:46. Reproduced project config: {"capabilities":["local_advisory_snapshot"]}. Prelaunch selects 52 rules with config alone. Adding --capabilities=unrelated_context drops MB-0828 and selects 51. The merge creates a mixed list/map; enabled() switches to associative lookup and loses the original list entry. Normalize list and map capability forms before additive merging. This is a shared planner defect, not a reason to create a prelaunch-specific selector.

## Additional robustness concerns

These are code-review observations, not reproduced security defects:

- FilesystemCheck.php:847–851 (MB-0001), :273–276 (MB-0042), :710 (MB-0035) and :798 (MB-0034) traverse without shared entry/time budgets and cancellation checkpoints. Large trees can take unbounded work relative to the advertised bounded workflow.
- BasicExposureCheck.php:19–21 uses leaf-only iteration for media; max_entries does not count every visited directory, so many empty directories do not consume the intended traversal budget.
- The shared HTTP collector uses buffered RETURNTRANSFER without an explicit response-body byte cap (HttpCollector.php:26). This is distinct from the separate bounded production runtime collector and from MB-0005's detector-local 8 KiB cutoff.
- Cookie sensitivity inferred from names containing sess/admin can include preference cookies. This needs an explicit sensitivity contract or conservative confidence; no complete runtime authentication classification is established by a name alone.

## Behavior confirmed by integration review

- Prelaunch uses the shared LOCAL URL resolver. Magento store configuration is authoritative, and --url does not override a local installation.
- Report metadata keeps the local path and tested endpoint separately and explicitly records matching_build_verified=false. A local lock hash does not prove the endpoint deploys that build.
- Canonical explicit rule selections stay within the development/prelaunch membership; unsupported selectors are rejected.
- Default prelaunch has 51 selected rules, local snapshot capability enables all 52. Development remains 27/28.
- Collection details hidden by the default UI still exist in report metadata and retain incomplete-execution exit semantics. No recommendation is made to restore warning-heavy default output.
- Declared production mode, local compiled/static artifacts and scheduler configuration are scoped observations, not proof of full runtime readiness, successful jobs or business-flow correctness.

## Verification and limits

Ten relevant existing test files passed during this review: DevelopmentPrelaunchProfileTest, HttpUrlDiscoveryTest, BasicHttpScopeTest, HttpRuntimeCompletionTest, BasicDeploymentPoliciesTest, DeploymentCompletionTest, ProductionCheckPolicyTest, ProductionRuntimeCheckTest, BasicExposureCheckTest and FindingsFirstPresentationTest. Output: /tmp/magebean-prelaunch-qa-tests.log.

Additional agent verification passed HttpCollectorTest and BasicPracticeCheckTest. Independent adversarial fixtures reproduced the failures above despite the passing baseline. HTTP repros used loopback fixtures or the exact internal parsing helper; deployment repros used temporary local files. No customer Magento deployment, real staging endpoint or production database was audited. This is a code/fixture QA report, not launch approval.

## Suggested correction order

1. Fix false-clean HTTP interpretation: duplicate fields and incomplete listing inspection.
2. Fix local evidence loss: repeated extension directives and media-root symlink scope.
3. Normalize capability merging in the shared planner and introduce shared resource/cancellation budgets for unbounded collectors.
4. Add the adversarial cases to regressions, run the full CLI suite and qualify both PHAR variants. Preserve existing rule IDs, criterion history and external-standard definitions.

## Remediation

- MB-0030 detects duplicate SameSite attributes as ambiguous, preserves independently established cookie violations, and uses explicit configured sensitive cookie names rather than inferring authentication from admin/sess substrings. Criterion revision/history records the narrower name scope.
- MB-0026 requires an unambiguous single Location before confirming a direct HTTPS redirect.
- MB-0005 scans the entire bounded collected body instead of silently restricting detection to its first 8 KiB.
- MB-0729 inspects every repeated zend_extension declaration, respects explicit xdebug.mode=off, and reports malformed/oversized ini evidence as unavailable.
- MB-0780 checks the media root and pub ancestor before resolving paths. Root symlinks and broken links remain incomplete coverage, not clean inventories. Directories count toward traversal budgets.
- Shared planner capabilities normalize list/map forms before additive CLI merging; explicit false values remain false unless enabled on CLI.
- Strict filesystem traversals use entry/time budgets and shared cancellation checkpoints. Default budget is 200,000 entries / 10 seconds, configurable up to 1 million / 30 seconds. Proven findings survive partial inventory. Artifact presence remains an existential observation.
- Shared HTTP collection limits retained bodies to 1 MiB and rejects aggregate headers over 64 KiB. Body/header overflow cannot produce a clean result. cURL callbacks and stream reads honor cancellation, and stream reads have an absolute request deadline. PHP's native stream wrapper receives response headers before the application can inspect their aggregate size; this fallback is not a preallocation memory cap for native header parsing.

New regression files: PrelaunchHttpQaRegressionTest (22 assertions, including cURL/stream child checks), PrelaunchDeploymentQaRegressionTest (23), PrelaunchCapabilityMergeRegressionTest (11). A synthetic 1,500-file/30-directory traversal returns incomplete with a 1,000-entry budget and completes with 5,000 entries; the two checks took approximately 0.02 seconds locally. No live staging or customer deployment qualification is claimed.

Final verification: all 133 CLI test files passed. Both standard and one-time PHAR builds passed their release gates. Logs: /tmp/magebean-prelaunch-fixes-final-suite.log and /tmp/magebean-prelaunch-fixes-final-{standard,one-time}.log.
