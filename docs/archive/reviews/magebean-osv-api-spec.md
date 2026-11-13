# Magebean OSV Advisory API Spec

This document describes the API contract for replacing the local OSV bundle
(`VULNS/*.json`) with a remote API hosted at `https://api.magebean.com`.

## Endpoint

```http
POST /v1/osv/advisories
Host: api.magebean.com
Content-Type: application/json
Accept: application/json
```

## Purpose

The CLI sends installed Composer packages from `composer.lock`. The API returns
OSV-compatible advisories that affect those packages. The CLI can then evaluate
the installed versions locally and report vulnerable packages.

## Request

```json
{
  "schema_version": "magebean-osv-request-v1",
  "ecosystem": "Packagist",
  "packages": [
    {
      "name": "vendor/package",
      "version": "1.0.0"
    },
    {
      "name": "magento/module-catalog",
      "version": "103.0.6"
    }
  ],
  "client": {
    "name": "magebean-cli",
    "version": "1.0.0"
  }
}
```

### Request Fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `schema_version` | string | yes | Must be `magebean-osv-request-v1`. |
| `ecosystem` | string | yes | Composer ecosystem. Use `Packagist`. |
| `packages` | array | yes | Installed Composer packages from `composer.lock`. |
| `packages[].name` | string | yes | Composer package name, for example `vendor/package`. |
| `packages[].version` | string | yes | Installed version from `composer.lock`, without a leading `v` if possible. |
| `client` | object | no | Client metadata for API observability. |
| `client.name` | string | no | Client name, for example `magebean-cli`. |
| `client.version` | string | no | CLI version. |

## Successful Response

Return HTTP `200`.

```json
{
  "schema_version": "magebean-osv-response-v1",
  "generated_at": "2026-05-27T00:00:00Z",
  "ecosystem": "Packagist",
  "advisories": [
    {
      "id": "GHSA-xxxx-yyyy-zzzz",
      "aliases": ["CVE-2025-12345"],
      "summary": "Example vulnerable package advisory",
      "published": "2025-01-10T00:00:00Z",
      "modified": "2025-02-01T00:00:00Z",
      "severity": [
        {
          "type": "CVSS_V3",
          "score": "9.8"
        }
      ],
      "affected": [
        {
          "package": {
            "ecosystem": "Packagist",
            "name": "vendor/package"
          },
          "ranges": [
            {
              "type": "ECOSYSTEM",
              "events": [
                {
                  "introduced": "0"
                },
                {
                  "fixed": "1.2.3"
                }
              ]
            }
          ],
          "versions": ["1.0.0", "1.1.0"],
          "database_specific": {
            "fixed": "1.2.3"
          }
        }
      ],
      "references": [
        {
          "type": "ADVISORY",
          "url": "https://example.com/advisory"
        }
      ]
    }
  ],
  "meta": {
    "requested_packages": 2,
    "matched_packages": 1,
    "advisories_returned": 1,
    "dataset_revision": "2026-05-27.1"
  }
}
```

### Response Fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `schema_version` | string | yes | Must be `magebean-osv-response-v1`. |
| `generated_at` | string | yes | ISO-8601 timestamp for this response. |
| `ecosystem` | string | yes | Usually `Packagist`. |
| `advisories` | array | yes | OSV-compatible advisory objects. Empty array means no matching advisories. |
| `meta` | object | no | Diagnostics for logging/debugging. |

## Advisory Object Requirements

Each item in `advisories` should be compatible with the OSV schema.

Minimum required shape:

```json
{
  "id": "OSV-or-GHSA-or-CVE-id",
  "affected": [
    {
      "package": {
        "ecosystem": "Packagist",
        "name": "vendor/package"
      },
      "ranges": [
        {
          "type": "ECOSYSTEM",
          "events": [
            {
              "introduced": "0"
            },
            {
              "fixed": "1.2.3"
            }
          ]
        }
      ]
    }
  ]
}
```

Alternative exact-version shape:

```json
{
  "id": "CVE-2025-12345",
  "affected": [
    {
      "package": {
        "ecosystem": "Packagist",
        "name": "vendor/package"
      },
      "versions": ["1.0.0", "1.0.1", "1.0.2"]
    }
  ]
}
```

### Advisory Fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `id` | string | yes | Primary advisory id. Prefer GHSA/OSV id, with CVE in `aliases`. |
| `aliases` | array | no | Related CVE/GHSA ids. |
| `summary` | string | no | Human-readable summary. |
| `published` | string | no | ISO-8601 publication timestamp. |
| `modified` | string | no | ISO-8601 last-modified timestamp. |
| `severity` | array | no | OSV severity entries. `score` can be a CVSS numeric string, for example `9.8`. |
| `affected` | array | yes | Affected package/version definitions. |
| `affected[].package.ecosystem` | string | yes | Must be `Packagist` or `Composer`. |
| `affected[].package.name` | string | yes | Composer package name. Must match `composer.lock`. |
| `affected[].ranges` | array | conditional | Use when vulnerability is described by introduced/fixed ranges. |
| `affected[].versions` | array | conditional | Use when vulnerability is described by exact vulnerable versions. |
| `affected[].database_specific.fixed` | string | no | Optional fixed version hint. |
| `references` | array | no | Advisory, patch, article, or vendor URLs. |

At least one of `affected[].ranges` or `affected[].versions` should be present.

## Error Responses

Use JSON error responses for non-2xx status codes.

```json
{
  "schema_version": "magebean-error-v1",
  "error": {
    "code": "invalid_request",
    "message": "packages must be a non-empty array"
  }
}
```

Recommended status codes:

| Status | Code | Meaning |
| --- | --- | --- |
| `400` | `invalid_request` | Request body is malformed or missing required fields. |
| `401` | `unauthorized` | API key is missing or invalid, if auth is enabled. |
| `413` | `payload_too_large` | Too many packages in one request. |
| `429` | `rate_limited` | Rate limit exceeded. |
| `500` | `server_error` | Unexpected API error. |
| `503` | `dataset_unavailable` | Advisory dataset is temporarily unavailable. |

## Headers

Recommended response headers:

```http
Content-Type: application/json
Cache-Control: public, max-age=3600
ETag: "dataset-revision-or-response-hash"
X-Magebean-Dataset-Revision: 2026-05-27.1
```

If authentication is added later:

```http
Authorization: Bearer <token>
```

## Magebean CLI Integration

Rule `MB-R049` uses the `composer_audit_api` check with these defaults:

```json
{
  "endpoint": "https://api.magebean.com/v1/osv/advisories",
  "timeout_ms": 10000,
  "batch_size": 500,
  "allow_private_http_fallback": true
}
```

The CLI splits large `composer.lock` package lists into batches and combines
advisories by advisory id before evaluating installed versions.

When `allow_private_http_fallback` is enabled, the CLI retries with HTTP only
if the HTTPS request fails and the endpoint hostname resolves to a private or
loopback IPv4 address. Public API addresses are never downgraded to HTTP. The
fallback is also disabled when a bearer token is configured, so credentials
are never sent over plaintext HTTP.

An optional bearer token can be supplied with:

```shell
export MAGEBEAN_OSV_API_TOKEN="<token>"
```

Transport failures, non-`200` responses, invalid JSON, unsupported response
schemas, or a missing `advisories` array produce an `UNKNOWN` rule result.

## Matching Rules

The API may return only advisories matching the requested package names, or a
larger set of Packagist advisories. The CLI should still evaluate affected
versions locally.

Version semantics:

- `introduced` is inclusive.
- `fixed` is exclusive.
- `versions` entries are exact vulnerable versions.
- Package names should be lowercase Composer names from `composer.lock`.

## Empty Dataset vs No Matches

If the API is healthy and no requested packages have advisories, return:

```json
{
  "schema_version": "magebean-osv-response-v1",
  "generated_at": "2026-05-27T00:00:00Z",
  "ecosystem": "Packagist",
  "advisories": [],
  "meta": {
    "requested_packages": 2,
    "matched_packages": 0,
    "advisories_returned": 0,
    "dataset_revision": "2026-05-27.1"
  }
}
```

If the dataset cannot be loaded, return HTTP `503` with `dataset_unavailable`
instead of returning an empty `advisories` array.
