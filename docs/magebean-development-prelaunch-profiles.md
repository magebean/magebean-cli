# Magebean Development and Prelaunch Profiles

Both profiles are opt-in and automated. Development has 28 criteria. Prelaunch has 52. The authoritative selection lives in internal-profiles.json. Use rules:list with the profile name to inspect it.

    php magebean.phar scan --profile=development --path=. --no-interaction --no-ansi
    php magebean.phar scan --profile=prelaunch --path=/var/www/magento --url=https://staging.example.com
    php magebean.phar rules:list --profile=development
    php magebean.phar rules:list --profile=prelaunch

Development resolves a local source checkout from its Composer Magento dependency. Deployment config, environment credentials and a storefront are unnecessary to start. Module source defaults to app/code. Use --modules=Vendor_Module to choose exact module roots, including Composer packages, for the module-aware checks. Other rules keep their catalog scopes, such as app for the markup check and the working tree for secrets. Missing installed metadata and deployment-dependent enablement or DI order remain coverage gaps. PHP compatibility uses config.platform.php from composer.json.

Both profiles read an explicit local OSV JSON array at .magebean/osv-db.json. Supply a nonempty trusted snapshot with applicable Packagist coverage. The reader is bounded to 32 MiB. Invalid or missing snapshot data produces a collection gap. A usable snapshot without matches completes the advisory check. The advisory rule does not contact a feed during the scan and does not verify snapshot freshness or coverage beyond the supplied data.

Prelaunch adds deployment and HTTP checks. Specify the staging endpoint explicitly. HTTP checks use that URL, and selected HTTP collectors do not follow redirects to another destination. The redirect predicate observes the first HTTP response. Reports print the local root, endpoint and local composer.lock SHA-256 when available. The local path and HTTP endpoint are separate evidence scopes until the operator establishes that they refer to the same build. Without an explicit URL the scan preserves local results and reports incomplete runtime coverage. HTTPS is required for a meaningful TLS and cookie assessment. Probes use existing per-check bounds.

Canonical --rules selections can narrow either profile to its listed IDs. To execute other criteria, select them without either profile. Existing project policy can filter or override presentation as usual. The automation exit contract is 0 for completed execution without actionable observations, 1 for actionable observations, 2 for critical observations, and 3 for incomplete execution. Incomplete execution takes precedence and retains findings already collected.

| Membership | Canonical rule IDs | Scope and prerequisites |
|---|---|---|
| Development module integrity, REST, DI | MB-0808–MB-0818 | Installed module metadata, selected source, local XSDs and the enabled-module order where needed |
| Development source and compatibility | MB-0819–MB-0822 | Selected PHP source, explicit PHP target and installed Framework version where applicable |
| Development lifecycle declarations | MB-0823–MB-0825 | Local schema, patch and handler source and supported static references |
| Development source policy and working tree | MB-0029, MB-0730, MB-0787, MB-0789, MB-0790, MB-0791, MB-0793, MB-0797 | Existing scoped markup, PHP and working-tree predicates |
| Development dependency evidence | MB-0070, MB-0828 | Composer metadata and the local OSV snapshot |
| Prelaunch source | All 28 Development IDs | Same source and advisory prerequisites |
| Prelaunch local readiness | MB-0001, MB-0002, MB-0003, MB-0031, MB-0729, MB-0034, MB-0035, MB-0037, MB-0042, MB-0046, MB-0780, MB-0782, MB-0783, MB-0784, MB-0800 | Installed candidate and supported local configuration, filesystem, cache and scheduler observations |
| Prelaunch HTTP and TLS | MB-0005, MB-0026, MB-0027, MB-0028, MB-0030, MB-0778, MB-0779, MB-0781, MB-0803 | Explicit staging URL and reachable endpoints, with TLS support where required |

The source predicates cover specific patterns and declarations. JavaScript parsing, full contextual escaping, SSRF and authorization dataflow remain gaps. Availability of a local scheduler declaration does not establish healthy production dispatch. This profile documents the CLI workflow. Dashboard scheduling and build correlation are separate work.

## Verification

The full CLI suite passed 126 test files under PHP 8.4.27 on WSL. Both PHAR build gates ran the same development and prelaunch fixture, including a checkout without deployment configuration, a loopback endpoint, an unavailable endpoint, source-only prelaunch and local snapshot validation. The standard PHAR fixture took 3.25 seconds end to end with maximum process RSS of 67,468 KiB, measured with GNU time. The figure covers the whole small synthetic fixture and its multiple CLI invocations.

An isolated Console SQLite catalog import and repeat import passed 19 assertions for 725 rules and 13 profiles, including exact counts for the two new profiles and unchanged protected ASVS/PCI records. The CLI workflow has not been exercised against a live Magento staging store.
