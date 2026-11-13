# Magebean API Reference

Current primary runtime: one internal `MB-…` requirement identity with reusable check functions and requirement-owned obligations. Profiles select identities; standards references are alignment metadata. Historical MB-R APIs/selectors/manifests remain compatibility adapters. Older examples and legacy API sections below must be read with that boundary. See [requirement model](requirement-model.md) and [migration contract](../archive/migrations/requirement-migration.md).

Magebean CLI performs most checks locally. Some dependency, package-lifecycle,
and Adobe security-patch rules call `https://api.magebean.com`.

## Data disclosure

API-backed checks send endpoint-specific data from the selected dependency inventory: installed Composer metadata when available, with locked-only/dev/build scope preserved separately. Root Composer declarations and lock metadata supply the relevant declared context. The exact request depends on the endpoint and selected rule.
Adobe package and patch alternatives are evaluated locally.

### `POST /v1/osv/advisories`

The CLI sends:

- request schema and the `Packagist` ecosystem;
- Composer package names and installed versions, possibly limited by the
  selected rule's package scope;
- client name and CLI version.

Example:

```json
{
  "schema_version": "magebean-osv-request-v1",
  "ecosystem": "Packagist",
  "packages": [
    {
      "name": "vendor/package",
      "version": "1.2.3"
    }
  ],
  "client": {
    "name": "magebean-cli",
    "version": "1.0.0"
  }
}
```

### `POST /v1/packages/status`

The CLI sends:

- request schema;
- Composer package names and installed versions.

The package list is the selected observed scope, such as installed dependencies, direct dependencies, Magento modules or an explicitly selected maintenance subset. A lock entry is not automatically labeled an installed runtime component.

Example:

```json
{
  "schema_version": "magebean-package-status-request-v1",
  "packages": [
    {
      "name": "vendor/package",
      "version": "1.2.3"
    }
  ]
}
```

### `POST /v1/adobe/security-patches`

The CLI sends:

- the detected Magento product (`adobe-commerce` or
  `magento-open-source`) and installed Magento version;
- empty `evidence.packages` and `evidence.patch_artifacts` containers required
  by the v1 API schema;
- client name and CLI version.

Example:

```json
{
  "schema_version": "magebean-adobe-patch-request-v1",
  "product": "magento-open-source",
  "installed_version": "2.4.8-p1",
  "evidence": {
    "packages": {},
    "patch_artifacts": []
  },
  "client": {
    "name": "magebean-cli",
    "version": "1.0.0"
  }
}
```

After the API returns `alternative_rules`, the CLI evaluates installed package
constraints, applied patch identifiers, relative paths, and file fingerprints locally. These observations qualify only the supported alternative; they do not prove arbitrary patch effectiveness.

The request body fields are listed above. HTTPS infrastructure also receives
standard connection and HTTP metadata, plus authorization headers when a token
is configured.

To prevent these API disclosures, block outbound access to
`api.magebean.com` or do not select rules that use these endpoints. Such rules
may return `UNKNOWN` when their remote dataset is unavailable.

## Canonical ASVS agent manifests

The submission envelope remains schema 1.0 with `manifest_hash`, `summary` and `results`; existing result fields and status mapping are unchanged. Only manifest-selected assessment items are returned. Legacy MB-R manifests retain their execution path.

For canonical `rule_key` values such as `OWASP-ASVS:5.0.0:6.2.1`, the manifest must supply top-level `profile` equal to `asvs-l1`, `asvs-l2` or `asvs-l3`; optional `capabilities` selects conditional requirements. The agent uses bundled profiles, preventing project files from redefining dashboard assessment scope. Missing profile, inactive/unavailable canonical requirements and duplicate canonical identities are rejected or reported unsupported, rather than producing a false PASS.

The dashboard must register the new requirement keys and matching assessment_item_id values before issuing canonical manifests. This code change verifies serialization and mapper compatibility locally; it does not migrate or verify a deployed dashboard. UNKNOWN and human review still map to wire status `error`. See [runtime migration](../archive/migrations/requirement-migration.md).
