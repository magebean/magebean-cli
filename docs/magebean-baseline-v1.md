# Magebean Security Baseline v1

**Author:** Son Cao  
**Baseline version:** 1  
**Documentation revision:** 2026-11-03

**Scope:** 100 Magebean requirements

## Scope and authority

This baseline contains only Magebean's Magento security and production-readiness requirements. The authoritative inventory is the `magebean` family in [magebean-catalog.json](../src/Rules/requirements/magebean-catalog.json). The catalog owns identity, revision, criterion, applicability, evidence obligations and implementation guidance; this document mirrors its criteria for review.

PCI DSS and OWASP ASVS requirements are outside this baseline. Use their official documents for standard clauses; Magebean does not reproduce or maintain those standards here. See [source families](requirement-source-families.md) for the CLI catalog boundary.

## Reading the rules

One requirement is one assessable Magebean criterion with a stable MB identity. Each entry records its revision, criterion, severity, catalog coverage, target modes and native profile membership. Checks and evidence obligations remain defined in the authoritative catalog. Historical MB-R identifiers are compatibility definitions, not baseline inventory.

Profile membership selects rules without redefining them. Human-required criteria are archived in [magebean-retirements.json](../src/Rules/requirements/magebean-retirements.json). Their IDs remain reserved. Coverage describes implementation capability, not a scan outcome or complete verification of the criterion.

For profile selection and execution, use the [automated-only profile contract](magebean-automated-only-profiles.md) and [CLI reference](cli-reference.md). For evidence obligations and outcomes, use the [requirement model](requirement-model.md).

## Rule groups

| Control | Rules |
|---|---:|
| MB-C01 — File & Folder Permissions | 9 |
| MB-C02 — Admin & Auth Hardening | 11 |
| MB-C03 — Secure Coding Practices | 15 |
| MB-C04 — HTTPS & TLS Enforcement | 10 |
| MB-C05 — Production Mode & Deployment Hygiene | 6 |
| MB-C06 — Cache & Indexing Health | 4 |
| MB-C07 — Logging & Monitoring | 3 |
| MB-C08 — Cron Job Reliability | 3 |
| MB-C09 — Extension Vulnerability Management | 8 |
| MB-C10 — Abandoned Extensions Removal | 4 |
| MB-C11 — Composer Dependency Hygiene | 5 |
| MB-C12 — Third-party Config Security | 4 |
| MB-C20 — Module Structure and Integration | 16 |
| MB-C21 — Module Reliability and Performance | 2 |
| **Total Magebean rules** | **100** |

## Magebean requirement inventory

Entries mirror the Magebean catalog, grouped by control. Profile membership is persisted membership before capability and target-mode filtering. Entries without native profile membership are retained criteria outside executable profiles. Coverage labels are copied verbatim; consult catalog obligations and limitations to interpret them.

### MB-C01 — File & Folder Permissions

#### MB-0001 — No world-writable files or directories

- **Revision:** 2
- **Criterion:** No world-writable files or directories; assess only the collected Magento deployment scope.
- **Severity:** high
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** basic, hardening, owasp

#### MB-0002 — env.php satisfies configured mode and ownership policy

- **Revision:** 3
- **Criterion:** The collected app/etc/env.php Unix permission bits are a subset of configured mode 0640, and its owner and group match the configured reference paths (the project root by default). This is an explicit deployment ownership policy, not proof of effective ACL or web-process access restrictions.
- **Severity:** high
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** basic, hardening, owasp

#### MB-0003 — Webroot hygiene (no .git/.env/backups in pub/)

- **Revision:** 3
- **Criterion:** Webroot hygiene (no .git/.env/backups in pub/); assess only the collected Magento deployment scope.
- **Severity:** high
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** basic, hardening, owasp

#### MB-0005 — Directory listing absent on probed Magento paths

- **Revision:** 3
- **Criterion:** Successful responses from the configured runtime endpoint on /media/, /static/, /errors/ and /var/ must not expose recognizable directory-index markup. Scope is these paths at scan time; transport or unsupported responses are inconclusive.
- **Severity:** medium
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL, REMOTE
- **Native profiles:** basic, hardening, owasp

#### MB-0780 — Media inventory has no executable PHP-like filenames

- **Revision:** 1
- **Criterion:** The bounded readable pub/media filename inventory contains no PHP-like executable extension, including double extensions. Symlinks, unreadable subtrees and budget gaps remain unresolved. Web-server execution policy is separate evidence.
- **Severity:** high
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** basic, hardening

#### MB-0781 — Named sensitive HTTP paths are denied or absent

- **Revision:** 1
- **Criterion:** Six named deployment artifact paths are denied or absent over HTTP. A bounded prefix containing a recognizable artifact signature is a violation; ambiguous 200 pages, redirects and transport gaps remain unresolved. No response contents are retained.
- **Severity:** high
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL, REMOTE
- **Native profiles:** basic, hardening

#### MB-0782 — Sensitive deployment configuration excluded from Git index

- **Revision:** 1
- **Criterion:** The readable current deployment Git index does not track app/etc/env.php. Historical commits, remote repositories and deployments without a readable Git index require separate evidence.
- **Severity:** high
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** basic, hardening

#### MB-0799 — Application worker code paths are read-only

- **Revision:** 1
- **Criterion:** For every explicitly supplied PHP-FPM worker PID, the scanner and worker have identical effective UID/GID/groups, zero effective/permitted/ambient capabilities, matching project tree, mount namespace and Linux security context. Kernel access observations find no writable object or replaceable code root in the complete bounded configured app/vendor/lib inventory. Unsupported identity, seccomp, links or inventory gaps remain UNKNOWN.
- **Severity:** medium
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** hardening, owasp

#### MB-0800 — Upload inventory has no configured PHP or handler signatures

- **Revision:** 1
- **Criterion:** Within the complete bounded configured upload path inventory, readable files contain no explicit long PHP opening tags or configured htaccess script-handler signatures and no PHP-like executable filename extension. Missing/unreadable/oversized eligible files, unfollowed links and traversal-budget gaps remain UNKNOWN. This is a signature policy, not absence of arbitrary executable content or prevention of server execution.
- **Severity:** medium
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** hardening, owasp


### MB-C02 — Admin & Auth Hardening

#### MB-0006 — Declared Admin route avoids common names

- **Revision:** 4
- **Criterion:** The collected backend.frontName is a valid nonempty route other than admin or backend. Route obscurity is not authentication or access control.
- **Severity:** high
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** basic, hardening, owasp

#### MB-0007 — Native Admin MFA provider configuration declared

- **Revision:** 4
- **Criterion:** For a native Admin authentication deployment, Magento_TwoFactorAuth is declared enabled and resolved twofactorauth/general/force_providers names recognized native engines. Possible Adobe IMS mode, unforced providers or an unsupported provider require additional evidence. An empty force_providers setting does not prove MFA is disabled. This predicate does not prove enrollment, enforcement or absence of bypass.
- **Severity:** critical
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** basic, hardening, owasp

#### MB-0009 — Configured admin session lifetime is at most 900 seconds

- **Revision:** 3
- **Criterion:** The effective default-scope Magento admin/security/session_lifetime setting resolved from env.php, config.php, core_config_data or actual installed module defaults is a positive integer not exceeding 900 seconds.
- **Severity:** medium
- **Catalog coverage:** DIRECT
- **Target modes:** LOCAL
- **Native profiles:** basic, hardening, owasp

#### MB-0011 — Configured admin login CAPTCHA or bounded lockout

- **Revision:** 3
- **Criterion:** Default-scope Magento admin login configuration enables native CAPTCHA for backend_login, recognized backend_login reCAPTCHA, or a positive lockout failure limit at most 10 with a positive lockout threshold. Locked env.php/config.php settings precede core_config_data. Custom authentication enforcement and runtime effectiveness require separate evidence.
- **Severity:** medium
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** basic, hardening, owasp

#### MB-0100 — Recorded Admin role assignments have relational integrity

- **Revision:** 3
- **Criterion:** Collected admin_user, authorization_role and authorization_rule rows have valid user/group parent relationships, no cyclic group ancestry or orphan rules, and each active admin has one assigned group with ACL rules. This checks relational assignment integrity, not business approval, least privilege or effective authorization policy.
- **Severity:** high
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** basic, hardening

#### MB-0728 — Configured admin password minimum is at least eight

- **Revision:** 1
- **Criterion:** The collected admin password minimum declaration, or the installed Magento User validator minimum when no declaration overrides it, is at least eight characters. This checks the observed admin policy, not every user password or ASVS conformance.
- **Severity:** high
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** basic, hardening

#### MB-0773 — Admin secret URL keys enabled

- **Revision:** 1
- **Criterion:** The resolved default-scope native Admin admin/security/use_form_key configuration is enabled. Authenticated route enforcement requires separate verification.
- **Severity:** medium
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** basic, hardening

#### MB-0774 — Admin login names are case sensitive

- **Revision:** 1
- **Criterion:** The resolved default-scope native Admin admin/security/use_case_sensitive_login configuration is enabled; this is a configuration observation, not an authentication flow test.
- **Severity:** medium
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** basic, hardening

#### MB-0775 — Admin account sharing disabled

- **Revision:** 1
- **Criterion:** The resolved default-scope native Admin admin/security/admin_account_sharing configuration is disabled. This does not establish that each person has a unique approved account.
- **Severity:** medium
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** basic, hardening

#### MB-0776 — Admin password reset protection configured

- **Revision:** 1
- **Criterion:** Resolved native Admin reset protection is enabled with bounded hourly requests and a positive cooldown meeting Magebean policy (at most 5 requests/hour and at least 1 minute). This does not exercise reset tokens or email delivery.
- **Severity:** medium
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** basic, hardening

#### MB-0801 — Direct global Admin ACL grants match the approved role policy

- **Revision:** 1
- **Criterion:** In a nonempty bounded deployed authorization_role inventory and complete bounded authorization_rule inventory, every direct allow rule for Magento_Backend::all or Magento_Adminhtml::all assigned to a group role has a role ID in the explicitly configured approved_role_ids policy. Missing policy, malformed/orphan rows, direct user grants or incomplete tables remain UNKNOWN. This checks direct stored grants, not inherited effective privileges or business least privilege.
- **Severity:** medium
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** hardening


### MB-C03 — Secure Coding Practices

#### MB-0014 — No direct PHP superglobal references in inspected application files

- **Revision:** 3
- **Criterion:** Valid PHP files in the configured app subtree contain no T_VARIABLE references to $_GET, $_POST, $_REQUEST, $_COOKIE, $_FILES or $_SERVER. Comments and literal strings are ignored. This is a source coding policy, not proof of input validation.
- **Severity:** high
- **Catalog coverage:** DIRECT
- **Target modes:** LOCAL
- **Native profiles:** hardening, owasp

#### MB-0786 — Direct named query methods use a literal first argument

- **Revision:** 1
- **Criterion:** Every syntactically named query/rawQuery/exec/executeQuery method call in collected custom PHP/PHTML uses one static string first argument, without direct concatenation or interpolation. Unresolved variables yield UNKNOWN. This does not prove parameter binding or SQL injection safety. Scope is completely collected app/code PHP/PHTML; missing, unreadable, oversized, linked, malformed or truncated eligible input prevents a clean PASS.
- **Severity:** low
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** hardening, owasp

#### MB-0787 — No unconditional validateForCsrf acceptance override

- **Revision:** 1
- **Criterion:** Collected custom PHP/PHTML contains no validateForCsrf method whose complete body is an unconditional return true. This exact bypass ban does not establish form tokens or server-side CSRF effectiveness. Scope is completely collected app/code PHP/PHTML; missing, unreadable, oversized, linked, malformed or truncated eligible input prevents a clean PASS.
- **Severity:** medium
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** hardening, owasp

#### MB-0788 — Custom source avoids enumerated native network primitives

- **Revision:** 1
- **Criterion:** Collected custom PHP/PHTML has no direct global calls to curl_exec, curl_multi_exec, fsockopen, pfsockopen, stream_socket_client or file_get_contents. Dynamic callable/alias ambiguity yields UNKNOWN. This explicit API restriction does not establish SSRF safety of framework adapters. Scope is completely collected app/code PHP/PHTML; missing, unreadable, oversized, linked, malformed or truncated eligible input prevents a clean PASS.
- **Severity:** low
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** hardening, owasp

#### MB-0789 — Custom source avoids native unserialize calls

- **Revision:** 1
- **Criterion:** Collected custom PHP/PHTML contains no direct unqualified or fully-qualified global unserialize call, irrespective of allowed_classes options. Indirect calls and function aliases yield UNKNOWN. Other serializers remain outside this syntax policy. Scope is completely collected app/code PHP/PHTML; missing, unreadable, oversized, linked, malformed or truncated eligible input prevents a clean PASS.
- **Severity:** medium
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** hardening, owasp

#### MB-0790 — Custom source avoids enumerated shell/process primitives

- **Revision:** 1
- **Criterion:** Collected custom PHP/PHTML contains no direct global exec/system/passthru/shell_exec/popen/proc_open/pcntl_exec invocation or shell backtick expression. Indirect calls and function aliases yield UNKNOWN; framework process adapters are outside this API ban. Scope is completely collected app/code PHP/PHTML; missing, unreadable, oversized, linked, malformed or truncated eligible input prevents a clean PASS.
- **Severity:** medium
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** hardening, owasp

#### MB-0791 — Custom source avoids eval and create_function constructs

- **Revision:** 1
- **Criterion:** Collected custom PHP/PHTML contains no eval construct or direct global create_function call. Dynamic include targets, indirect calls, function aliases and unresolved assertion semantics yield UNKNOWN. This is a construct policy, not general runtime execution assurance. Scope is completely collected app/code PHP/PHTML; missing, unreadable, oversized, linked, malformed or truncated eligible input prevents a clean PASS.
- **Severity:** medium
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** hardening, owasp

#### MB-0792 — Custom source avoids enumerated raw filesystem primitives

- **Revision:** 1
- **Criterion:** Collected custom PHP/PHTML contains no direct global file_get_contents/file_put_contents/fopen/readfile/unlink/rename/copy/scandir/glob call. Indirect calls and aliases yield UNKNOWN. This explicit API restriction does not establish path safety of framework adapters. Scope is completely collected app/code PHP/PHTML; missing, unreadable, oversized, linked, malformed or truncated eligible input prevents a clean PASS.
- **Severity:** low
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** hardening, owasp

#### MB-0793 — Custom source avoids native upload move calls

- **Revision:** 1
- **Criterion:** Collected custom PHP/PHTML contains no direct global move_uploaded_file invocation. Indirect calls and aliases yield UNKNOWN. This is an explicit native API restriction, not proof that other upload handlers validate content or authorization. Scope is completely collected app/code PHP/PHTML; missing, unreadable, oversized, linked, malformed or truncated eligible input prevents a clean PASS.
- **Severity:** medium
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** hardening, owasp

#### MB-0794 — Custom source avoids enumerated weak randomness APIs

- **Revision:** 1
- **Criterion:** Collected custom PHP/PHTML contains no direct global rand/mt_rand/lcg_value/uniqid/srand/mt_srand call. Indirect calls and aliases yield UNKNOWN. This deliberately strict coding policy includes non-security uses; it does not establish entropy or token lifetime. Scope is completely collected app/code PHP/PHTML; missing, unreadable, oversized, linked, malformed or truncated eligible input prevents a clean PASS.
- **Severity:** low
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** hardening, owasp

#### MB-0795 — No direct request superglobals in named log method arguments

- **Revision:** 1
- **Criterion:** Collected custom PHP/PHTML contains no $_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER/$_FILES token inside arguments of syntactically named log/debug/info/notice/warning/error/critical/alert/emergency method calls. This exact syntax rule does not prove absence of sensitive data in arbitrary logs. Scope is completely collected app/code PHP/PHTML; missing, unreadable, oversized, linked, malformed or truncated eligible input prevents a clean PASS.
- **Severity:** medium
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** hardening, owasp

#### MB-0796 — Custom source avoids enumerated raw crypto and session APIs

- **Revision:** 1
- **Criterion:** Collected custom PHP/PHTML contains no direct global session_start/session_id/session_regenerate_id/session_set_save_handler/mcrypt_encrypt/mcrypt_decrypt/md5/sha1/crypt/openssl_encrypt/openssl_decrypt call. This explicit coding restriction also bans legitimate non-security hash uses; it does not prove framework cryptography/session semantics. Scope is completely collected app/code PHP/PHTML; missing, unreadable, oversized, linked, malformed or truncated eligible input prevents a clean PASS.
- **Severity:** low
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** hardening, owasp

#### MB-0797 — No enumerated XML external feature constructs in custom source

- **Revision:** 1
- **Criterion:** Collected custom PHP/PHTML contains no token reference to LIBXML_NOENT/LIBXML_DTDLOAD/LIBXML_DTDATTR, no resolveExternals/substituteEntities/validateOnParse assignment except literal false, and no syntactically named xinclude or xml_set_external_entity_ref_handler invocation. This exact construct ban does not establish every parser default or runtime configuration. Scope is completely collected app/code PHP/PHTML; missing, unreadable, oversized, linked, malformed or truncated eligible input prevents a clean PASS.
- **Severity:** medium
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** hardening, owasp


#### MB-0814 — Avoid direct request superglobals in module log calls

- **Revision:** 1
- **Criterion:** Selected PHP and PHTML module source avoids direct request superglobal references in arguments to enumerated log-like methods.
- **Severity:** medium
- **Catalog coverage:** PARTIAL
- **Target modes:** LOCAL
- **Native profiles:** module-integrity


#### MB-0822 — Review request data reaching command and query calls

- **Revision:** 1
- **Criterion:** Flag supported direct and single assignment flows from request superglobals into shell calls or named query text arguments.
- **Severity:** high
- **Catalog coverage:** PARTIAL
- **Target modes:** LOCAL
- **Native profiles:** module-source

### MB-C04 — HTTPS & TLS Enforcement

#### MB-0026 — Observed storefront entrypoint redirects to HTTPS

- **Revision:** 4
- **Criterion:** The observed HTTP storefront root redirects directly with 301/302/303/307/308 to same-host HTTPS. Admin and other store entrypoints are assessed separately.
- **Severity:** high
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL, REMOTE
- **Native profiles:** basic, hardening, owasp

#### MB-0027 — Observed HTTPS response has HSTS max-age of at least one year

- **Revision:** 4
- **Criterion:** A successful same-host HTTPS response at the configured runtime URL emits one unambiguous Strict-Transport-Security header with an exact integer max-age directive of at least 31536000 seconds. Repository web-server declarations are not runtime proof.
- **Severity:** medium
- **Catalog coverage:** DIRECT
- **Target modes:** LOCAL, REMOTE
- **Native profiles:** basic, hardening, owasp

#### MB-0028 — Runtime endpoint rejects legacy TLS

- **Revision:** 3
- **Criterion:** The assessed runtime host and port must accept TLS 1.2 or 1.3 and reject TLS 1.0 and 1.1. Rejection requires peer protocol-version alerts or successful active protocol enumeration; client-side protocol restrictions and connection failures are not proof.
- **Severity:** high
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL, REMOTE
- **Native profiles:** basic, hardening, owasp

#### MB-0029 — Literal HTTP asset references absent in assessed markup/CSS

- **Revision:** 3
- **Criterion:** In LOCAL mode, readable markup/CSS files under app must contain no literal HTTP subresource or form-action references. In REMOTE mode, successful HTTPS pages at configured paths must contain no literal HTTP subresource/form references. Dynamic code-generated URLs, external stylesheets and unvisited routes require separate assessment.
- **Severity:** medium
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL, REMOTE
- **Native profiles:** basic, hardening, owasp

#### MB-0030 — Sensitive cookies use Secure, HttpOnly, and SameSite

- **Revision:** 3
- **Criterion:** Sensitive session/admin cookies actually emitted by successful same-host HTTPS responses on the configured probe paths have exact Secure and HttpOnly attributes and SameSite=Lax or Strict. This assesses observed cookie emissions, not unobserved authenticated sessions.
- **Severity:** high
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL, REMOTE
- **Native profiles:** basic, hardening, owasp

#### MB-0777 — Observed Admin entrypoint redirects to HTTPS

- **Revision:** 1
- **Criterion:** The explicitly supplied or locally resolved Admin HTTP entrypoint redirects directly to same-host HTTPS. Missing Admin route evidence remains unresolved without preventing the separate storefront probe.
- **Severity:** high
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** basic, hardening

#### MB-0778 — Observed TLS certificate has trusted hostname and renewal margin

- **Revision:** 1
- **Criterion:** The configured endpoint completes a peer-verified TLS connection for its hostname with a currently valid certificate and at least 15 days remaining under Magebean renewal policy. Uncollectable trust or network evidence is unresolved.
- **Severity:** medium
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL, REMOTE
- **Native profiles:** basic, hardening

#### MB-0779 — Observed page restricts framing

- **Revision:** 1
- **Criterion:** A successful same-host application response emits an unambiguous enforced restrictive CSP frame-ancestors policy, or valid X-Frame-Options DENY/SAMEORIGIN when no enforced frame-ancestors overrides it. This scopes the observation to the requested page.
- **Severity:** medium
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL, REMOTE
- **Native profiles:** basic, hardening

#### MB-0802 — Named checkout response emits the explicit enforced CSP baseline

- **Revision:** 1
- **Criterion:** The supplied checkout path returns a successful same-origin no-redirect HTTPS GET with one unambiguous enforced Content-Security-Policy. The emitted policy explicitly defines script-src, connect-src, frame-src, form-action, object-src and base-uri; assessed sources contain no wildcard, unsafe-inline, unsafe-eval or broad scheme-only source. object-src is exactly none, base-uri is exactly none or self, and reporting is present when configured. Report-only alone fails; redirect/inaccessible checkout, multiple policies, unsupported syntax or incomplete collection remain UNKNOWN.
- **Severity:** medium
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL, REMOTE
- **Native profiles:** hardening, owasp

#### MB-0803 — Observed application response emits nosniff

- **Revision:** 1
- **Criterion:** One successful same-origin no-redirect HTTPS GET at the configured path emits exactly one X-Content-Type-Options header whose trimmed value is nosniff. Missing or invalid header on an observed successful response fails; duplicate headers, redirects, transport failures and incomplete collection remain UNKNOWN. HSTS and frame protection are assessed separately.
- **Severity:** medium
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL, REMOTE
- **Native profiles:** hardening, owasp


### MB-C05 — Production Mode & Deployment Hygiene

#### MB-0031 — Declared Magento deployment mode is production

- **Revision:** 1
- **Criterion:** The collected app/etc/env.php MAGE_MODE declaration equals production. Runtime environment overrides and actual web process state require separate evidence.
- **Severity:** high
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** basic, hardening, owasp

#### MB-0034 — Generated DI PHP artifacts are present

- **Revision:** 3
- **Criterion:** At least one readable PHP artifact exists in each configured generated/metadata and generated/code directory. This assesses artifact presence, not DI compilation correctness or freshness.
- **Severity:** low
- **Catalog coverage:** DIRECT
- **Target modes:** LOCAL
- **Native profiles:** hardening, owasp

#### MB-0035 — Published static artifacts present in assessed deployment

- **Revision:** 3
- **Criterion:** In LOCAL mode, pub/static/frontend or pub/static/adminhtml must contain at least one readable, nonempty published CSS/JS/font/image artifact. In REMOTE mode, same-origin Magento static CSS/JS assets referenced by the retrieved storefront must return nonempty non-HTML content with HTTP 200. This verifies observed deployment artifacts, not completeness of every theme, locale or route.
- **Severity:** low
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL, REMOTE
- **Native profiles:** basic, hardening, owasp

#### MB-0729 — Declared project debug settings are disabled

- **Revision:** 1
- **Criterion:** Inspected default-scope project Magento debug/inline-translation declarations and project PHP ini display_errors/display_startup_errors and Xdebug declarations must not enable debug output. Absent declarations are not enabled declarations in this scope; web-worker runtime, custom integrations and all-component ASVS conformance are outside this predicate.
- **Severity:** high
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** basic, hardening

#### MB-0784 — Published theme and locale static scopes have representative assets

- **Revision:** 1
- **Criterion:** The bounded observed published frontend theme/locale scopes contain representative readable nonempty CSS and JavaScript artifacts. Explicit intended scopes may refine this observation. Active-store coverage, asset freshness and headless deployment applicability require separate evidence.
- **Severity:** low
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** basic, hardening

#### MB-0807 — Configured PHP-FPM workers have no mapped Xdebug binary module

- **Revision:** 1
- **Criterion:** Every explicitly inventoried Linux PHP-FPM worker is bound to its pool, executable identity and exact process start_ticks before and after a complete bounded nonempty /proc process-map observation. No Xdebug-named shared module is mapped in these verified workers. Missing or changed identity, empty/unreadable/truncated maps or malformed inventory remain UNKNOWN. This observes configured process mappings at scan time, not every deployment worker, Xdebug feature mode, statically linked code or complete PHP runtime settings.
- **Severity:** medium
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** hardening, owasp


### MB-C06 — Cache & Indexing Health

#### MB-0037 — Declared Full Page Cache type enabled

- **Revision:** 4
- **Criterion:** The collected deployment app/etc/env.php declares cache_types.full_page enabled. This verifies the persisted Magento cache type state; Varnish selection and actual cache hit rates are separate observations.
- **Severity:** high
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** basic, hardening

#### MB-0038 — Declared cache backends use Redis or Varnish

- **Revision:** 5
- **Criterion:** Declared default and page-cache frontend backends use supported Redis configuration; an explicit Varnish page-cache setting may replace an absent page-cache backend declaration. No assessed declared backend is file-based. This checks deployed configuration declarations, not live cache service health.
- **Severity:** medium
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** hardening

#### MB-0039 — Recorded Magento indexers have valid state

- **Revision:** 3
- **Criterion:** Every recorded row in the deployed Magento indexer_state table has status valid. Working or invalid indexers fail this readiness policy; empty, malformed or unreadable table evidence is a collection error. This does not assert mview queue state or coverage of unregistered indexers.
- **Severity:** medium
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** hardening

#### MB-0040 — Declared Redis session storage has authentication configured

- **Revision:** 3
- **Criterion:** The deployed configuration declares session.save as redis and session.redis.password as a nonempty string. This checks the configured authentication declaration; it does not prove server ACL, network isolation or credential validity.
- **Severity:** high
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** hardening

### MB-C07 — Logging & Monitoring

#### MB-0042 — Log/report paths are absent from the collected webroot

- **Revision:** 3
- **Criterion:** Within the collected pub tree, no configured var/log or var/report relative path, nor symlink to the corresponding project target, is present. This is filesystem placement, not a live HTTP exposure assertion.
- **Severity:** high
- **Catalog coverage:** DIRECT
- **Target modes:** LOCAL
- **Native profiles:** basic, hardening, owasp

#### MB-0783 — Installed Magento cron has every-minute cadence

- **Revision:** 1
- **Criterion:** The observed installed cron:run schedule has every-minute cadence for the assessed project. External/cloud/container scheduling without a matching installed entry requires separate scheduler evidence; presence alone is insufficient.
- **Severity:** low
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** basic, hardening

#### MB-0785 — Magento cron execution has recent success and bounded backlog

- **Revision:** 1
- **Criterion:** The read-only bounded cron_schedule observation contains recent successful execution within 24 hours and no overdue pending jobs beyond 15 minutes under Magebean readiness policy. The reported collection window is explicit; job-group completeness and external schedulers require separate evidence.
- **Severity:** low
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** basic, hardening


### MB-C08 — Cron Job Reliability

#### MB-0046 — Installed Magento scheduler observed

- **Revision:** 4
- **Criterion:** A collected installed cron:run entry targets this deployment. Missing installed entries remain unresolved when an external/cloud/container scheduler may apply; cadence and execution health are separate observations.
- **Severity:** medium
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** basic, hardening

#### MB-0047 — Recorded cron execution is recent (<= 900s)

- **Revision:** 3
- **Criterion:** The latest recorded cron_schedule.executed_at among success, running or error jobs in the deployment database is no older than 900 seconds. No execution or a stale execution fails this policy; unreadable or malformed table evidence and future timestamps indicating clock skew are collection errors. Job success and scheduler retention are outside this criterion.
- **Severity:** high
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** hardening

#### MB-0048 — Due pending cron backlog is below 1000

- **Revision:** 3
- **Criterion:** The deployment cron_schedule table contains fewer than 1000 pending jobs whose scheduled_at is at or before scanner UTC time. Future scheduled jobs are excluded. This counts due pending scheduler jobs, not arbitrary application queues.
- **Severity:** medium
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** hardening


### MB-C09 — Extension Vulnerability Management

#### MB-0049 — Composer dependency OSV advisory matches

- **Revision:** 3
- **Criterion:** Collected versioned Composer lock dependencies have no applicable OSV advisory matches in the successfully queried dataset, accounting for locally verified advisory-specific hotfix evidence. This does not certify absence of unknown vulnerabilities or uncollected runtime dependencies.
- **Severity:** critical
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** basic, hardening, owasp

#### MB-0050 — Adobe security release patch assessment

- **Revision:** 3
- **Criterion:** The collected Composer-locked Magento product version is current for its Adobe security release branch according to the successfully queried patch dataset, or each required advisory patch is satisfied by verified local alternative evidence. Unsupported branches and missing required patches fail; this does not certify runtime patch deployment outside collected files.
- **Severity:** critical
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** basic, hardening, owasp

#### MB-0055 — Collected transitive versions have no returned applicable advisories

- **Revision:** 3
- **Criterion:** No transitive package version in the complete collected Composer lock inventory is identified as affected by applicable advisories returned by the configured OSV service. Coverage is limited to the queried inventory and service data.
- **Severity:** critical
- **Catalog coverage:** DIRECT
- **Target modes:** LOCAL
- **Native profiles:** hardening, owasp

#### MB-0056 — Declared constraints permit returned advisory fixed versions

- **Revision:** 3
- **Criterion:** For returned applicable advisory findings with published fixed versions, the combined declared dependency constraints intersect versions at or above the published fixed version. This does not establish complete Composer solver feasibility, platform compatibility or every fixed branch.
- **Severity:** high
- **Catalog coverage:** DIRECT
- **Target modes:** LOCAL
- **Native profiles:** hardening, owasp

#### MB-0057 — Collected package versions are not reported withdrawn

- **Revision:** 3
- **Criterion:** Every package version in the complete collected Composer lock inventory has an explicit non-yanked status from the configured package-status source. Missing per-package status cannot establish a clean result.
- **Severity:** high
- **Catalog coverage:** DIRECT
- **Target modes:** LOCAL
- **Native profiles:** hardening, owasp

#### MB-0059 — Affected advisory publication age is within 30 days

- **Revision:** 3
- **Criterion:** No returned advisory affecting an installed Composer package version has a publication age greater than the configured 30-day threshold. This is publication age, not organizational discovery time or a measured remediation SLA.
- **Severity:** low
- **Catalog coverage:** DIRECT
- **Target modes:** LOCAL
- **Native profiles:** hardening, owasp

#### MB-0806 — Declared mitigation records satisfy structure and expiry policy

- **Revision:** 1
- **Criterion:** The bounded readable schema-version-1 mitigation record inventory has a valid generated_at timestamp within configured max_age_days and covers each identity in the supplied nonempty expected_ids policy with a unique record containing nonempty advisory, package, version, owner, action, rollback and a valid future expires_at. This checks declared record structure and expiry only, not whether all deployed mitigations are declared, effective or approved.
- **Severity:** low
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** hardening, owasp



#### MB-0828 — Composer dependency matches in local OSV snapshot

- **Revision:** 1
- **Criterion:** Collected Composer lock versions have no applicable active advisory in the required local OSV snapshot.
- **Severity:** high
- **Catalog coverage:** PARTIAL
- **Target modes:** LOCAL
- **Native profiles:** development, prelaunch

### MB-C10 — Abandoned Extensions Removal

#### MB-0061 — Collected dependencies are not reported abandoned

- **Revision:** 5
- **Criterion:** No dependency package in the complete assessed Composer inventory is marked abandoned by the configured package-maintenance source; a clean conclusion requires explicit known status for every assessed package.
- **Severity:** high
- **Catalog coverage:** DIRECT
- **Target modes:** LOCAL
- **Native profiles:** hardening, owasp

#### MB-0062 — Reported latest package releases are within 24 months

- **Revision:** 3
- **Criterion:** For every versioned package in the complete collected Composer lock inventory, the configured package-status source reports known latest release history with a valid nonfuture latest release timestamp within the configured 24 calendar-month threshold. This is a maintenance policy, not proof of exploitability; unknown release history cannot establish a clean conclusion.
- **Severity:** medium
- **Catalog coverage:** PARTIALLY_AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** hardening

#### MB-0063 — Reported source repositories remain available and active

- **Revision:** 3
- **Criterion:** For every applicable source repository reported for packages in the complete collected Composer lock inventory, the configured package-status source explicitly reports that the repository is neither archived, disabled nor missing. Explicit repository-not-applicable classifications are outside scope; unsupported or unassessed providers cannot establish a clean conclusion. This is a maintenance policy, not proof of exploitability.
- **Severity:** medium
- **Catalog coverage:** PARTIALLY_AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** hardening

#### MB-0805 — Collected Composer dependency sources match explicit policy

- **Revision:** 1
- **Criterion:** Every package in the readable bounded collected composer.lock inventory has source and/or dist URL and nonempty reference matching the supplied exact per-package source policy; replacement declarations and root composer.json repository declarations also match the supplied policy. Explicit metadata-only metapackages may have no source/dist. Missing package policies or incomplete source identity are unresolved. This compares collected declarations and does not verify installed bytes, canonical upstream truth or absence of malicious approved revisions.
- **Severity:** medium
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** hardening


### MB-C11 — Composer Dependency Hygiene

#### MB-0065 — No wildcard constraints in composer.json

- **Revision:** 2
- **Criterion:** No wildcard constraints in composer.json; assess only the collected Magento deployment scope.
- **Severity:** high
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** hardening, owasp

#### MB-0066 — No dev branches in composer.json

- **Revision:** 2
- **Criterion:** No dev branches in composer.json; assess only the collected Magento deployment scope.
- **Severity:** high
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** hardening, owasp

#### MB-0067 — prefer-stable=true in composer.json

- **Revision:** 2
- **Criterion:** prefer-stable=true in composer.json; assess only the collected Magento deployment scope.
- **Severity:** high
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** hardening, owasp

#### MB-0069 — Direct locked versions match the reported latest stable release

- **Revision:** 3
- **Criterion:** Collected direct Composer package versions are not older than the latest stable release reported by the configured package-status source. This is a maintenance policy, not proof of an exploitable vulnerability.
- **Severity:** low
- **Catalog coverage:** DIRECT
- **Target modes:** LOCAL
- **Native profiles:** hardening, owasp

#### MB-0070 — Composer lock hash and dependency identities are consistent

- **Revision:** 3
- **Criterion:** composer.lock has a matching Composer content-hash, no duplicate or malformed package identities, and contains or provides/replaces each declared root package dependency. This does not prove the full dependency solver result or installed vendor file integrity.
- **Severity:** medium
- **Catalog coverage:** DIRECT
- **Target modes:** LOCAL
- **Native profiles:** hardening, owasp

### MB-C12 — Third-party Config Security

#### MB-0072 — No configured secret-pattern matches in collected VCS scope

- **Revision:** 4
- **Criterion:** No configured PCRE secret-pattern matches occur in eligible nonbinary working-tree files up to max_file_bytes and in individual file lines across available local Git ref history, within configured paths and exclusions. Git metadata and Git PCRE support are required for a clean history conclusion. This does not certify absence of every secret format, multiline historical matches, excluded files, remote refs or unavailable history.
- **Severity:** critical
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** hardening

#### MB-0730 — No configured secret patterns in deployed application files

- **Revision:** 2
- **Criterion:** Eligible deployed working-tree text files within configured paths and exclusions contain no configured secret-pattern matches. Git history is outside this basic deployment check. Runtime credential configuration app/etc/env.php is excluded; unreadable or oversized eligible files are collection errors.
- **Severity:** critical
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** basic, hardening, owasp

#### MB-0798 — No plain HTTP standalone PHP string literals in custom source

- **Revision:** 1
- **Criterion:** Collected custom PHP/PHTML contains no standalone constant string literal beginning http://. Comments are excluded. This deliberately strict literal policy includes non-endpoint examples and does not establish effective endpoint inventory, TLS verification or runtime interpolation. Scope is completely collected app/code PHP/PHTML; missing, unreadable, oversized, linked, malformed or truncated eligible input prevents a clean PASS.
- **Severity:** low
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** hardening, owasp

#### MB-0804 — Named integration debug settings resolve disabled in default scope

- **Revision:** 1
- **Criterion:** Every explicitly configured integration debug/verbose setting path resolves through deployed env.php/config.php/default core_config_data or supported installed-module defaults to a recognized disabled value in default scope. Any recognized enabled value fails; omitted paths, missing values or unsupported flag representations remain UNKNOWN. This verifies named settings, not every third-party integration or store scope.
- **Severity:** medium
- **Catalog coverage:** AUTOMATED
- **Target modes:** LOCAL
- **Native profiles:** hardening, owasp

### MB-C20 — Module Structure and Integration

#### MB-0808 — Consistent static Magento module identity

- **Revision:** 1
- **Criterion:** Literal module registrations and module.xml names agree for selected module roots, and a literal registration name has a unique installed root.
- **Severity:** medium
- **Catalog coverage:** PARTIAL
- **Target modes:** LOCAL
- **Native profiles:** module-integrity

#### MB-0809 — Supported module XML satisfies its local schema

- **Revision:** 1
- **Criterion:** Collected module, routes, webapi and ACL XML declarations satisfy their resolvable project-local declared Magento XSD.
- **Severity:** medium
- **Catalog coverage:** PARTIAL
- **Target modes:** LOCAL
- **Native profiles:** module-integrity

#### MB-0810 — Declared Composer package names are available

- **Revision:** 1
- **Criterion:** Package names in selected modules’ Composer require metadata appear in the installed package inventory or a collected provide or replace declaration.
- **Severity:** medium
- **Catalog coverage:** PARTIAL
- **Target modes:** LOCAL
- **Native profiles:** module-integrity

#### MB-0811 — REST declaration references a public service method

- **Revision:** 1
- **Criterion:** Selected global webapi.xml entries reference a public method on a uniquely indexed service class or interface within supported resolution scope.
- **Severity:** medium
- **Catalog coverage:** PARTIAL
- **Target modes:** LOCAL
- **Native profiles:** module-integrity

#### MB-0812 — REST ACL references are declared in collected context

- **Revision:** 1
- **Criterion:** Selected enabled modules’ global webapi.xml resource references resolve to an enabled static global ACL declaration or the special anonymous or self resource.
- **Severity:** medium
- **Catalog coverage:** PARTIAL
- **Target modes:** LOCAL
- **Native profiles:** module-integrity

#### MB-0813 — Review sensitive anonymous REST declarations

- **Revision:** 1
- **Criterion:** Flag selected enabled modules’ global webapi.xml routes that declare anonymous access and have an export, download, credentials, permissions, roles, or secrets path segment.
- **Severity:** medium
- **Catalog coverage:** PARTIAL
- **Target modes:** LOCAL
- **Native profiles:** module-integrity


#### MB-0815 — DI preferences resolve to compatible concrete targets

- **Revision:** 1
- **Criterion:** Effective preferences in supported DI stages resolve to compatible concrete PHP classes within the indexed symbol scope.
- **Severity:** medium
- **Catalog coverage:** PARTIAL
- **Target modes:** LOCAL
- **Native profiles:** module-integrity

#### MB-0816 — DI virtual types resolve to concrete classes

- **Revision:** 1
- **Criterion:** Effective virtual type chains in supported DI stages are acyclic and resolve to concrete classes within the indexed symbol scope.
- **Severity:** medium
- **Catalog coverage:** PARTIAL
- **Target modes:** LOCAL
- **Native profiles:** module-integrity

#### MB-0817 — DI constructor arguments match supported signatures

- **Revision:** 1
- **Criterion:** Named DI arguments match indexed constructor parameters. Array arguments match the supported parameter types.
- **Severity:** medium
- **Catalog coverage:** PARTIAL
- **Target modes:** LOCAL
- **Native profiles:** module-integrity

#### MB-0818 — DI plugins target interceptable declarations

- **Revision:** 1
- **Criterion:** Enabled directly configured plugins use concrete plugin classes and supported hooks on interceptable target methods.
- **Severity:** medium
- **Catalog coverage:** PARTIAL
- **Target modes:** LOCAL
- **Native profiles:** module-integrity

#### MB-0819 — Module PHP syntax matches the configured target

- **Revision:** 1
- **Criterion:** Selected PHP files avoid enumerated language features introduced after Composer config.platform.php.
- **Severity:** medium
- **Catalog coverage:** PARTIAL
- **Target modes:** LOCAL
- **Native profiles:** module-source

#### MB-0820 — Indexed public method declarations preserve their contracts

- **Revision:** 1
- **Criterion:** Directly redeclared methods retain public visibility and staticness from their uniquely indexed public parent or interface declaration.
- **Severity:** medium
- **Catalog coverage:** PARTIAL
- **Target modes:** LOCAL
- **Native profiles:** module-source

#### MB-0821 — Declared Magento Framework constraints match the installed version

- **Revision:** 1
- **Criterion:** Selected modules declaring a magento/framework dependency accept the installed framework version under Composer constraint semantics.
- **Severity:** medium
- **Catalog coverage:** PARTIAL
- **Target modes:** LOCAL
- **Native profiles:** module-source

#### MB-0823 — Declarative schema XML satisfies its installed schema

- **Revision:** 1
- **Criterion:** Selected global db_schema.xml documents have supported XML syntax and satisfy their declared installed XSD.
- **Severity:** medium
- **Catalog coverage:** PARTIAL
- **Target modes:** LOCAL
- **Native profiles:** module-lifecycle

#### MB-0824 — Setup patch declarations and dependencies are compatible

- **Revision:** 1
- **Criterion:** Indexed setup patch classes implement the interface for their directory and supported static dependencies resolve to compatible concrete patches without cycles.
- **Severity:** medium
- **Catalog coverage:** PARTIAL
- **Target modes:** LOCAL
- **Native profiles:** module-lifecycle

#### MB-0825 — Cron and queue declarations reference public handlers

- **Revision:** 1
- **Criterion:** Supported global cron and queue declarations refer to public methods on uniquely indexed handler symbols.
- **Severity:** medium
- **Catalog coverage:** PARTIAL
- **Target modes:** LOCAL
- **Native profiles:** module-lifecycle

### MB-C21 — Module Reliability and Performance

#### MB-0826 — Review empty exception handlers

- **Revision:** 1
- **Criterion:** Flag empty catch bodies in selected module PHP as suspected reliability issues.
- **Severity:** low
- **Catalog coverage:** PARTIAL
- **Target modes:** LOCAL
- **Native profiles:** module-reliability

#### MB-0827 — Review query-like calls in loops

- **Revision:** 1
- **Criterion:** Record query-like method calls directly inside loops in selected module PHP for performance review.
- **Severity:** low
- **Catalog coverage:** PARTIAL
- **Target modes:** LOCAL
- **Native profiles:** module-reliability
