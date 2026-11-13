# Magebean finding detail and remediation review

The review covers the actionability and interpretation of all **117 Magebean requirements**. Each now has individually written corrective guidance, verification instructions, interpretation, triage steps, scope limitations and references. Requirements, IDs, assessment policy and ASVS/PCI source definitions remain unchanged. Guidance has its own version, separate from the criterion revision.

## Root causes and changes

Many definitions had no `remediation`, so Console imported an empty remediation field. Console also rendered only each check's message even when its stored evidence contained file/line locations and collection scope. Remediation displayed as one paragraph, making multi-step instructions difficult to follow.

The catalog now contains a distinct change/validation/rerun recipe for every Magebean requirement, including the previously missing 13 Basic additions. Existing useful instructions are retained in remediation history. Catalog import preserves structured `finding_guidance` for new assessment snapshots. CLI/JSON/HTML carry the structured interpretation and remediation; detailed CLI/HTML output presents the next actions.

Console finding detail now selects bounded metadata from stored check evidence: affected file/path, line, observed symbol/type/permissions, selected numeric measurements and collection scope/gaps. It supports nested primary requirement evidence and legacy evidence. Raw response bodies, headers, credentials and source snippets are excluded; displayed text is escaped. Missing locations are not reconstructed or invented.

For older Magebean assessments without structured guidance, the page can show guidance from the active catalog for the exact same native ID, explicitly labelled **Current catalog guidance; original assessment evidence and snapshot are unchanged**. Snapshot guidance remains authoritative when it already exists. Original historical instructions remain available separately. No migration rewrites historical result, criterion or remediation snapshots. ASVS/PCI are excluded from this Magebean fallback.

## MB-0014 example

The earlier page showed only “Direct PHP superglobal references found” and no next action. The token detector already retained file, line and variable evidence, but the page omitted it.

The page now shows those collected locations and directs the developer to:

1. Open each `file:line`, identify the component and trace whether the input is client-controlled and runtime-reachable.
2. Use the supported injected request abstraction where appropriate for HTTP code, then validate expected types, lengths and allow-lists and enforce authorization.
3. Review the actual SQL, HTML/JavaScript, path, upload or outbound-request sink; handle `$_FILES` through upload abstractions and distinguish trusted server metadata from client-controlled headers.
4. Test missing/malformed/unauthorized input and the real affected workflow in staging, then rerun MB-0014.

Direct superglobal references are a scoped development-policy observation. They do **not** alone demonstrate injection or another exploitable vulnerability. Replacing `$_GET` with `getParam()` alone is not validation or authorization. Narrow CLI/bootstrap/server-metadata exceptions need a documented rationale, not blanket mechanical replacement. The detector now reports match count and whether its location list is truncated.

## Security boundaries

Instructions avoid blanket permission changes, manual database edits, deletion of backlog records to hide failure, disabling TLS verification and copying secrets/payment data into tickets. Dependency updates require supported versions and compatibility testing; maintenance age/latest-version signals are distinguished from confirmed vulnerabilities. Cache, static and scheduler observations retain their readiness scope. Enrollment, actual web-process access, payment scope and runtime enforcement need the corresponding evidence.

This is an evidence/actionability review, not a new independent validation of every detector against every Magento release or a penetration test.

## Rollout

Deploy the updated Console views/services and CLI catalog, then run `php artisan security:catalog:import /path/to/magebean-cli/src/Rules`. Existing findings can display already-stored locations and labelled supplemental guidance immediately. Rerun affected checks with the updated CLI/agent if evidence was absent or truncated; import cannot recover uncollected data. Production deployment and PHAR rebuild are separate from this local update.

## Validation

- CLI regression: **101 test files passed**. The targeted MB-0014/catalog/agent/export test adds 867 assertions, including source location preservation and the distinction between input access and validation.
- Directly related Console regression: **33 tests passed, 179 assertions**, including a real existing-finding page request, supplemental current guidance, snapshot preservation, escaped location rendering and exclusion of raw secrets/snippets.
- Local import and parity: **117/117 Magebean definitions** match Console remediation and structured guidance; seven profile memberships still match.
- Two failures remain in broader Console runs: `VerificationAndFindingTest` expects a Requirements table column absent from the current findings table; `JobAndScanTest` expects three projection rows but observes two. Those assertions occur before the new finding-detail behavior and do not establish that the whole Console suite passes. The table and scan projection implementation were not changed for this review.

## Sources

- [Adobe Commerce development security](https://developer.adobe.com/commerce/php/development/security/)
- [Technical guidelines](https://developer.adobe.com/commerce/php/coding-standards/technical-guidelines)
- [Extension security and performance](https://developer.adobe.com/commerce/php/best-practices/extensions/security)
- [File uploads](https://developer.adobe.com/commerce/php/development/security/file-uploads)
- [Context-specific XSS prevention](https://developer.adobe.com/commerce/php/development/security/cross-site-scripting)
- [CSP](https://developer.adobe.com/commerce/php/development/security/content-security-policies)
- [SSRF](https://developer.adobe.com/commerce/php/development/security/server-side-request-forgery)
- [Deployment security best practices](https://experienceleague.adobe.com/en/docs/commerce-operations/implementation-playbook/best-practices/launch/security-best-practices)
