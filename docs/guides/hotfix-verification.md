# Hotfix verification

The API reads the published hotfix_catalog inside data/adobe-security-patches.json.
config/hotfixes.json is the curated seed and the fallback before the first
hotfix-enabled collection. OSV responses attach
matching rules to affected[].database_specific.magebean_hotfixes, using the
advisory ID or CVE alias and the affected Composer package. Existing response
schemas and clients remain compatible.

The CLI checks the installed version against the rule's explicit versions,
then hashes the installed files under the Magento root. Every file in one
variant must match. Variants are alternatives; files inside a variant are all
required. A verified fix removes only that package/advisory finding from
unresolved results and retains it in remediated_findings. Other CVEs and
packages remain findings. Derived OSV rules consume the reconciled findings.

Absent rules preserve existing version-based behavior. Missing files, partial
patches, reverted code, custom modifications, unknown hashes, unsafe paths, and
unsupported versions cannot prove a fix. The version-based finding remains,
with hotfix_verification.status = unverified when rules were supplied.
This is not proof that a patch is absent. Verified fixes do not prove that a
previous compromise has been cleaned up.

## Collect with adobe:collect

No extra command is required:

~~~sh
php bin/bundler adobe:collect
# Or run the existing full pipeline, which includes adobe:collect:
php bin/bundler data:refresh
~~~

The collector discovers candidates from Adobe's Commerce security index, release
notes and linked Adobe hotfix pages (bounded to 80 pages and depth 2). An extra
official page can be supplied when an emergency advisory is not yet linked:

~~~sh
php bin/bundler adobe:collect --hotfix-source=https://helpx.adobe.com/security/products/magento/apsb26-146.html
~~~

Discovery records patch links and possible CVEs as pending. Co-occurrence on a
page is NOT proof that a patch remediates every CVE on that page. A local manifest
must explicitly declare the CVE/package/version mapping.

Place each source/patch fixture in a folder under hotfixes/inbox:

~~~text
hotfixes/inbox/VULN-39341-framework-version/
  metadata.json
  fix.patch
  source/
    composer.lock
    vendor/
      magento/
        framework/
          ... pristine files targeted by the patch ...
~~~

Copy hotfixes/metadata.example.json to metadata.json and replace the package,
version and checksum with verified values. The example is not an active rule.
The version is the Composer PACKAGE version, which may differ from the Magento
product version. Include every patch and every source file needed for the
specified CVE. Source paths must match the a/... and b/... paths in the patch,
relative to a Magento root. All target files must be present.

Compute the official patch checksum with:

~~~sh
sha256sum hotfixes/inbox/VULN-39341-framework-version/fix.patch
~~~

For a public Adobe-hosted raw patch, a patches entry can use url instead of file,
with a pinned sha256. Allowed download hosts are helpx.adobe.com,
experienceleague.adobe.com and repo.magento.com over HTTPS. Downloads are bounded
to 8 MiB and redirects are not followed. If downloading requires authentication,
provide the local patch. ZIPs must be unpacked locally: the importer accepts
text unified diffs that modify existing files with a/ and b/ prefixes. Binary,
rename, mode, create/delete and unsupported patch formats remain pending.

Source is provided locally; the collector does not download a Magento
installation or run Composer scripts. It verifies the package version in
source/composer.lock, copies only patch target files into a temporary directory,
runs git apply --check and git apply, and hashes every resulting target.
It records original-file and patch hashes as provenance. Source fixtures and
patches in the inbox remain unchanged. PHP code from the source is never run.

Options on adobe:collect:
- --hotfixes-inbox: defaults to ./hotfixes/inbox.
- --hotfixes-seed: defaults to ./config/hotfixes.json.
- --hotfix-source: repeatable extra official discovery URLs.

The command merges previously published verified rules with the curated seed
and successful imports. Separate exact package versions can share a hotfix ID.
Failed imports become pending and do not remove previously verified rules.
Deleting an inbox folder does not revoke a published fingerprint. Source
failures are recorded under hotfix_catalog.collection.errors. Missing metadata,
source, incorrect checksums and patches that fail to apply cannot create a rule.
Discovery candidates may remain pending for broader coverage even after one
package/version is imported.

The combined release/hotfix document is written atomically to --out. During
data:refresh it is written only into staging and published with the CVE dataset.
--skip-adobe-patches skips both release and hotfix collection, retaining seeded
published data. Refresh manifest statistics include verified and pending counts.
The API exposes only hotfix_catalog.hotfixes for verification; pending items
never suppress CVE findings.

## Curated seed catalog

The seed is independent of regenerated CVE feeds. Review and version it as
security data. Only add fingerprints obtained from authentic package contents
and the official patch. A fingerprint is evidence of a particular file set, not
independent proof of the correctness or completeness of a local CVE mapping.

Example structure (illustrative; replace hashes with verified 64-digit values):

~~~json
{
  "schema_version": "magebean-hotfix-catalog-v1",
  "revision": "2",
  "hotfixes": [{
    "id": "VENDOR-HOTFIX-ID",
    "advisories": ["CVE-YYYY-NNNN", "GHSA-example"],
    "package": "vendor/package",
    "versions": ["1.0.0"],
    "source_url": "https://vendor.example/security/advisory",
    "variants": [{
      "id": "official-patch-1.0.0",
      "files": [
        {"path": "vendor/vendor/package/A.php", "sha256": "<verified SHA-256>"},
        {"path": "vendor/vendor/package/B.php", "sha256": "<verified SHA-256>"}
      ]
    }]
  }]
}
~~~

No production fingerprint for StyleSmuggler/VULN-39341 is included: the official
patch and tested package contents must be obtained and verified first. The
initial catalog is empty. This implementation alone does not enable coverage
for that CVE. Do not substitute a patch filename, an Applied label, or an
invented fingerprint.

## Server-side verification

POST /v1/hotfixes/verify accepts:

~~~json
{
  "schema_version": "magebean-hotfix-request-v1",
  "observations": [{
    "advisory": "CVE-YYYY-NNNN",
    "package": "vendor/package",
    "version": "1.0.0",
    "hotfix_id": "VENDOR-HOTFIX-ID",
    "files": {"vendor/vendor/package/A.php": "<observed SHA-256>"}
  }]
}
~~~

The server looks up expected hashes in its own catalog, never in the request,
and returns magebean-hotfix-response-v1, catalog_revision, and per-observation
verified_fixed or unverified. Results explicitly identify their evidence as
client_reported_file_sha256. They are not independent server attestation of a
remote filesystem. Send only file paths and hashes, not source code.

The CLI currently performs the equivalent match locally from the API-provided
catalog; it does not call this optional verification endpoint or upload hashes.
Re-run the scan after files change. No persistent suppression is stored.

The existing Adobe R050 release-patch alternatives are separate. This mechanism
reconciles OSV CVE findings; it does not replace R050's release lifecycle checks
or its existing alternative-evidence behavior.

## Verification

API: php tests/HotfixCatalogTest.php

Collector: php tests/AdobeHotfixCollectTest.php

Refresh: php tests/AdobeHotfixRefreshTest.php

CLI: php tests/HotfixVerificationTest.php
