# Magebean Development and Prelaunch Profiles

Both profiles are opt-in and automated. Development has 31 criteria. Prelaunch has 60. The authoritative selection lives in internal-profiles.json. Use rules:list with the profile name to inspect it.

    php magebean.phar scan --profile=development --path=. --no-interaction --no-ansi
    php magebean.phar scan --profile=prelaunch --path=/var/www/magento
    php magebean.phar rules:list --profile=development
    php magebean.phar rules:list --profile=prelaunch

Development resolves a local source checkout from its Composer Magento dependency. Deployment config, environment credentials and a storefront are unnecessary to start. Module source defaults to app/code. Use --modules=Vendor_Module to choose exact module roots, including Composer packages, for the module-aware checks. Other rules keep their catalog scopes, such as app for the markup check and the working tree for secrets. Missing installed metadata remains a coverage gap. Without deployment module order, DI checks evaluate independent source files and do not claim effective merged configuration. Development REST checks inspect source declarations even when activation is unknown or disabled; these findings do not establish live exposure. Referenced installed framework/vendor symbols are collected passively as bounded analysis context, not as additional audit subjects. PHP compatibility uses config.platform.php from composer.json.

Local snapshot advisory checking (MB-0828) is opt-in. Development selects 29 rules by default and Prelaunch selects 58; their full memberships are 31 and 60. Enable `--capabilities=local_advisory_snapshot` only when you have supplied a trusted OSV JSON array at `.magebean/osv-db.json` under the target project. Magebean does not create or distribute this file. Without that capability the rule is listed as not evaluated rather than a missing-file finding. Explicit MB-0828 selection also requires the capability. The reader is bounded to 32 MiB; missing, invalid or unsupported evidence after opting in is a collection gap. Malformed Composer lock entries cannot be silently discarded. A usable snapshot without matches completes only the supplied-data check; snapshot freshness and completeness are not certified. Core source analysis remains offline.

    php magebean.phar audit --profile=development --path=.
    php magebean.phar audit --profile=development --path=. --capabilities=local_advisory_snapshot
    php magebean.phar rules:list --profile=development --capabilities=local_advisory_snapshot

Prelaunch adds deployment and HTTP checks. By default, the runtime endpoint is discovered from Magento store configuration. LOCAL URL selection uses the same shared resolver as other profiles: the configured store URL is authoritative and --url does not override it. HTTP checks use the resolved URL, and selected HTTP collectors do not follow redirects to another destination. The redirect predicate observes the first HTTP response. Reports print the local root, endpoint and local composer.lock SHA-256 when available. The local path and HTTP endpoint are separate evidence scopes until the operator establishes that they refer to the same build. If store configuration does not supply a valid URL, the scan preserves local results and reports incomplete runtime coverage. HTTPS is required for a meaningful TLS and cookie assessment. Probes use existing per-check bounds.

Canonical --rules selections can narrow either profile to its listed IDs. To execute other criteria, select them without either profile. Existing project policy can filter or override presentation as usual. The automation exit contract is 0 for completed execution without actionable observations, 1 for actionable observations, 2 for critical observations, and 3 for incomplete execution. Incomplete execution takes precedence and retains findings already collected.

| Membership | Canonical rule IDs | Scope and prerequisites |
|---|---|---|
| Development module integrity, REST, DI | MB-0808–MB-0818 | Installed module metadata, selected source, local XSDs and the enabled-module order where needed |
| Development source and compatibility | MB-0819–MB-0822 | Selected PHP source, explicit PHP target and installed Framework version where applicable |
| Development lifecycle declarations | MB-0823–MB-0825 | Local schema, patch and handler source and supported static references |
| Development source policy and working tree | MB-0029, MB-0730, MB-0787, MB-0789, MB-0790, MB-0791, MB-0793, MB-0797 | Existing scoped markup, PHP and working-tree predicates |
| Development dependency evidence | MB-0070, MB-0828 | Composer metadata and the local OSV snapshot |
| Prelaunch source | All 31 Development IDs | Same source and advisory prerequisites |
| Prelaunch local readiness | MB-0001, MB-0002, MB-0003, MB-0031, MB-0729, MB-0034, MB-0035, MB-0037, MB-0042, MB-0046, MB-0780, MB-0782, MB-0783, MB-0784, MB-0800 | Installed candidate and supported local configuration, filesystem, cache and scheduler observations |
| Prelaunch HTTP and TLS | MB-0005, MB-0026, MB-0027, MB-0028, MB-0030, MB-0778, MB-0779, MB-0781, MB-0803 | Configured store URL and reachable endpoints, with TLS support where required |

The source predicates cover specific patterns and declarations. JavaScript parsing, full contextual escaping, SSRF and authorization dataflow remain gaps. Availability of a local scheduler declaration does not establish healthy production dispatch. This profile documents the CLI workflow. Dashboard scheduling and build correlation are separate work.

## Additional current coverage

MB-0733/0736 cover supported template contexts. Prelaunch also selects canonical MB-0728 and declared-config MB-0739/0740/0742. MB-0744 library maintenance is online: default in prelaunch, opt-in with dependency_maintenance in development. MB-0741 needs explicit cache_backend_policy in prelaunch. Missing declarations are unknown, not enabled settings. See [profiles](profiles.md) and [criteria](../magebean-baseline-v1.md).
