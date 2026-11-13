# Native evidence for former ASVS gaps

The 12 previously NOT_YET_COVERED ASVS 5.0.0 L1 requirements now have executable native evidence checks, inherited into L2/L3. All 12 are PARTIALLY_AUTOMATED. This fills implementation/discovery gaps; it does not remove human assurance obligations or establish full conformance.

The native catalog is `src/Rules/requirements/asvs-v5.0.0.json`. Profiles bind the implementation identity explicitly. RequirementCatalog compiles these checks under the existing canonical requirement IDs; there are no new MB-R aliases, duplicate findings or agent result fields. Existing MB-R manifests remain compatible. The legacy ProfileLoader::apply adapter selects old evidence rules; use applyRequirements or the ASVS CLI profiles to execute native requirement definitions.

| Requirement | Collected evidence | Essential unresolved evidence |
|---|---|---|
| 1.3.1 | Sanitizer references and HTML rendering sinks | Actual untrusted HTML paths, library policy and bypass tests |
| 2.2.1 | Server validation calls and request-input access | Positive business constraints before decisions; L2/L3 covers all input |
| 3.2.2 | Text rendering functions and HTML sinks | Text/HTML intent and all dynamic browser paths |
| 3.5.3 | Controller method interfaces, mutation calls, Sec-Fetch guard references | Effective route enforcement or strict header validation |
| 4.1.1 | One successful response media type, charset and supported body classification | All response/endpoint types, authenticated paths and errors |
| 6.2.4 | Password denylist controls and password flow references | At least top 3000 policy-matching passwords; registration/change enforcement |
| 6.3.2 | Fresh supplied inventory and enabled default-name candidates | Live state, identity provenance and complete application/provider scope |
| 9.1.1 | Token-context signature/verification and decoding references | Verification before acceptance and invalid-signature tests |
| 9.1.2 | Token-context algorithm policy and None candidates | Effective allowlist and key-confusion rejection |
| 9.1.3 | Token-context key references and jku/x5u/jwk usage | Issuer binding and preconfigured trusted sources/allowlists |
| 9.2.1 | Token-context time validators and nbf/exp references | Boundary acceptance/rejection and clock skew |
| 11.4.1 | Weak/modern hash calls | Cryptographic purpose and approved algorithm policy |

## Outcome and collection boundaries

Relevant observations return MANUAL_REVIEW, never an unsupported requirement PASS or confirmed FAIL. Missing or incomplete necessary evidence returns UNKNOWN. No matches do not prove absence or non-applicability. Candidates are unverified observations; a method/class name or library reference is not proof of control effectiveness. An MD5 checksum alone does not establish a cryptographic violation. A default-looking account name alone does not prove the identity was provisioned as a default.

Source scope is app and lib/web, extensions php/phtml/js/ts. Comments and quoted code examples are excluded; no raw source snippets or secrets are retained. Collection is bounded to files up to 1 MiB, 2000 files and 10 MiB read, with at most 50 recorded observations and explicit limitations/truncation. Missing PHP tokenizer or incomplete reads return UNKNOWN. Dependency/generated/runtime scope and full data-flow analysis remain outside these checks. Local source/account evidence is not reused for REMOTE targets.

The response check performs GET only against the supplied store URL, without following redirects. It does not probe sensitive routes or submit passwords/tokens. Redirects, unsuccessful/empty responses, transport failures and unsupported body classifications return UNKNOWN. HTML/JSON/XML sniffing only supports partial consistency evidence; unsupported charsets are marked unverified, not automatically unsafe. Raw response bodies/headers are omitted. The HTTP stream fallback now honors the follow flag consistently with curl.

## Account inventory input

Place a read-only export at `.magebean/evidence/asvs-default-accounts.json` inside the assessed project. Maximum size is 1 MiB. The artifact must resolve inside the project and supply schema 1.0, application scope, complete=true, a timezone-qualified RFC3339 generation time and a list of nonempty usernames with actual boolean enabled states. Exports older than 24 hours or more than 60 seconds in the future are rejected. `complete` is an assertion by the exporter and still requires independent confirmation.

Illustrative export; replace the timestamp with the actual current export time:

```json
{
  "schema_version": "1.0",
  "scope": "application",
  "complete": true,
  "generated_at": "2026-10-06T00:00:00Z",
  "accounts": [
    {"username": "admin", "enabled": false},
    {"username": "operator", "enabled": true}
  ]
}
```

Default-name candidates include root, admin, administrator, sa, guest, demo and test. Disabled names are not flagged. Custom defaults, deleted accounts, provider state and inventory provenance need reviewer verification. Output retains counts and candidate names only; extra password/secret fields are not emitted. No database login, account mutation or credential test is performed.

## Selection and coverage

```sh
php bin/magebean scan --path=/var/www/store --profile=asvs-l2 --rules=OWASP-ASVS:5.0.0:6.2.4
php bin/magebean scan --url=https://store.example --profile=asvs-l1 --rules=OWASP-ASVS:5.0.0:4.1.1
```

L1 coverage is 15 AUTOMATED, 27 PARTIALLY_AUTOMATED, 28 MANUAL_REVIEW and zero NOT_YET_COVERED. Cumulative L2/L3 partial counts are 74/82 and their implementation-gap counts are also zero. Scan selection counts remain 42/90/98 default and 70/198/268 with human review before capabilities. A zero implementation-gap count does not mean zero UNKNOWN outcomes or complete automation.

55 test scripts pass. The dedicated native suite covers 159 assertions on both curl and stream fallback, including no-evidence outcomes, source comments/strings, scope boundaries, token context, artifact freshness/shape, header/body consistency, redirects and deadlines. Compatibility review accepted only four output changes for this follow-up: scan/rules:list help and two control-filtered ASVS listings.
