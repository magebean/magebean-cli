# CLI reference

Use `php magebean.phar <command>` or `php bin/magebean <command>` in a source checkout. `audit` and `scan` are aliases. Run a command with `--help` for its exact current options; `list` and `--version` describe the executable being used.

## Audit and scan

```sh
php magebean.phar audit --path=/var/www/magento
php magebean.phar scan --path=/var/www/magento --profile=hardening
php magebean.phar audit --path=. --profile=development --modules=Vendor_Module
php magebean.phar audit --url=https://store.example
```

| Option | Meaning |
|---|---|
| --path | Local Magento/project root; otherwise autodetect from the working directory. An explicitly empty/invalid path is an input error. |
| --url | Remote endpoint without --path. Local scans use the shared Magento store-config resolver; this flag does not override local store configuration. |
| --profile | Built-in name or custom JSON profile; basic is default. See [profiles](profiles.md). |
| --rules | Comma-separated internal IDs for explicit assessment/detail. Family, context and development/prelaunch member constraints still apply. |
| --exclude-rules | Remove IDs after selection/project policy. |
| --controls | Comma-separated control IDs for scan selection. rules:list uses the singular --control. |
| --modules | Exact Magento module names for module-aware criteria. Other checks retain their catalogue scope. |
| --capabilities | Comma-separated context gates. Flags select intent, not evidence. |
| --config | Explicit project policy file; JSON is portable, YAML needs the PHP YAML extension. |
| --include-manual-review | Include required human assessment entries for separate ASVS/PCI workflows; does not restore inactive Magebean criteria. |
| --pci-context | PCI applicability context JSON. |
| --pci-evidence | PCI structured external evidence JSON. |
| --pci-report | Write PCI evidence-readiness JSON. |
| --standard | Legacy report selector; prefer --profile for criterion selection. |

The ordinary command renders text findings. There is no exposed --format/--output/--detail option for standalone HTML/SARIF export. Those report implementations are engine APIs. `--rules` enables detailed evidence/remediation for the selected IDs. [Output contract](findings-and-output.md).

```sh
php magebean.phar audit --path=/var/www/magento --profile=hardening --rules=MB-0049
```

Local and HTTP evidence are separate scopes until deployed-build identity is established. Source parsing and declaration observations do not prove runtime activation. See [URL discovery](runtime-url-discovery.md).

## Rule listing

```sh
php magebean.phar rules:list --profile=hardening
php magebean.phar rules:list --profile=hardening --control=MB-C03
php magebean.phar rules:list --profile=owasp --severity=critical
php magebean.phar rules:list --profile=asvs-l1 --include-manual-review
```

Supported filters are --profile, --include-manual-review, --capabilities, --control and --severity. Control and severity filters intersect. Listing reports selected rules, profile inventory and contextual omissions; counts are not proof of completed assessment. The [baseline](../magebean-baseline-v1.md) lists all 110 active Magebean criteria.

## Project configuration

`.magebean.json` in the project root can set capabilities, control inclusion, exclusions and overrides. Explicit false capabilities override profile defaults; an explicit CLI capability enables them.

```json
{"capabilities":{"strict_native_api_policy":false}}
```

Hardening selects strict_native_api_policy, cache_backend_policy and dependency_maintenance by default, producing 80 default LOCAL selections from 86 members. Six remaining checks need [production context](production-context.md). Development stays offline; enable dependency_maintenance only when online library maintenance is wanted. A local advisory snapshot is a separate opt-in, never a generated prerequisite.

## Exit codes

For native automated scans:

| Code | Meaning |
|---|---|
| 0 | No actionable findings collected; interpret completeness and actual selected scope. |
| 1 | Actionable findings without critical priority. Command/input failures may also be nonzero; inspect diagnostics. |
| 2 | At least one critical finding. |
| 3 | Incomplete execution; takes precedence over finding severity and retains collected evidence. |

A selected rule can remain UNKNOWN. Missing/excluded package lists stay out of ordinary issue messages. Diagnostics, raw per-rule assessment outcomes and canonical issues remain inspectable. [Troubleshooting](troubleshooting.md).

## ASVS and PCI

ASVS profiles contain 70/253/345 identities and PCI contains 280. Their human obligations remain; --include-manual-review includes those assessment entries. Technical checks alone do not certify the standard. Magebean owasp is a Top 10 taxonomy profile, not ASVS.

```sh
php magebean.phar audit --path=/var/www/magento --profile=asvs-l1 --include-manual-review
php magebean.phar audit --path=/var/www/magento --profile=pci --include-manual-review \
  --pci-context=/path/to/context.json --pci-evidence=/path/to/evidence.json --pci-report=/path/to/readiness.json
```

See [standards](../standards/README.md) and [examples](../examples/README.md). Template IDs/values must be replaced with project evidence.

## Security Dashboard agent

```sh
php magebean.phar agent:connect --code=YOUR_PAIRING_CODE --magento-path=/var/www/magento
php magebean.phar agent:doctor
php magebean.phar agent:status
php magebean.phar agent:tick
php magebean.phar agent:cron
php magebean.phar agent:disconnect
```

Agent HTTP transport requires PHP cURL. State, private token, queue/outbox, cache and logs live under MAGEBEAN_HOME or ~/.magebean. Do not commit credentials. Status/doctor/tick/cron/disconnect accept --config-dir; use MAGEBEAN_HOME to choose the initial connect directory.

`agent:cron` prints a recommended line; --install modifies the crontab after interactive confirmation and avoids duplicate entries. A polling cycle executes only authorized jobs and preserves redaction, result correspondence and outbox delivery. Use command-specific --help for supported configuration flags. Development API mode is not a production connection setting.

Console catalogue import does not persist CLI default_capabilities or add them to queued manifests. Agent checks remain explicitly gated by manifest context; CLI profile defaults do not establish agent parity. Raw per-request results and additive canonical references retain assessment history. [Reporting contract](findings-and-output.md).

The separate `assessment:run` command accepts --magento-path, --console-url, --assessment and a short-lived --token for authorized one-time work; use its --help and the Dashboard-provided invocation. Never place real tokens in documentation or committed shell scripts.

## Further reference

[Profiles](profiles.md), [production context](production-context.md), [API/data disclosure](../reference/api-reference.md), [architecture](../reference/architecture.md), [baseline](../magebean-baseline-v1.md).
