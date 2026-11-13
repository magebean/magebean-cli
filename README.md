# Magebean CLI

Magebean audits the current technical state of a Magento store: dependencies, configuration, source/modules, files and permissions, deployment state, and consistency between components. Findings identify observable evidence and explain how to investigate, fix and verify it. A snapshot does not certify every checkout flow or overall store safety.

## Quick start

Use the supplied `magebean.phar` with PHP 8.1 or newer:

```sh
php magebean.phar audit --path=/var/www/magento
php magebean.phar audit --path=/var/www/magento --profile=hardening
php magebean.phar rules:list --profile=hardening
```

`audit` and `scan` are aliases. The default profile is `basic`. Local source checks need readable project files; deployed checks may need Magento configuration, database/process access or a reachable store URL. Development can start from a source checkout without deployment credentials.

For a development checkout, install Composer dependencies and use `php bin/magebean` instead of the PHAR:

```sh
composer install
php bin/magebean audit --path=/path/to/project --profile=development
```

## Choose a profile

The catalogue contains **735 requirements: 110 Magebean, 345 ASVS and 280 PCI**, across **15 built-in profiles**. Profiles reuse identities; their counts must not be added together.

| Profile | Purpose | Inventory | Default LOCAL selection |
|---|---|---:|---:|
| `basic` | Routine Magento security/readiness observations | 37 | 37 |
| `hardening` | Deeper deployment and strict coding policies | 86 | 80 |
| `development` | Offline source, module and declaration audit | 31 | 29 |
| `prelaunch` | Source plus deployed candidate/configuration and HTTP evidence | 60 | 58 |
| `takeover` | Current technical risks and maintenance scope for handover | 86 | 82 |
| `owasp` | Magebean checks organized by OWASP Top 10 taxonomy | 50 | 41 |
| `module-integrity` | Module identity, REST and DI declarations | 11 | 11 |
| `module-source` | PHP compatibility, contracts and supported request-to-sink analysis | 4 | 4 |
| `module-lifecycle` | Schema, patches, cron and queue declarations | 3 | 3 |
| `module-reliability` | Supported exception/query review candidates | 2 | 2 |
| `evidence` | Opt-in supplied document/mitigation-record lint | 2 | 2 |
| `asvs-l1` | Separate OWASP ASVS 5.0.0 Level 1 assessment | 70 | 0 |
| `asvs-l2` | Separate OWASP ASVS 5.0.0 Level 2 assessment | 253 | 0 |
| `asvs-l3` | Separate OWASP ASVS 5.0.0 Level 3 assessment | 345 | 0 |
| `pci` | Separate PCI DSS 4.0.1 evidence assessment | 280 | 0 |

Default selection assumes no project overrides or extra filters. ASVS/PCI retain human evidence obligations; use `--include-manual-review` for their assessment workflow. Zero default selection does not mean the standards contain no technical criteria. Magebean profiles contain automated predicates; `evidence` checks records, not implemented security controls.

Hardening enables all six `strict_native_api_policy` checks by default. Its remaining six contextual rules need deployment-specific inputs. Development stays offline; online library maintenance and a supplied advisory snapshot are separate opt-ins. See [profiles](docs/guides/profiles.md) and [production context](docs/guides/production-context.md).

## Read the result

```text
Rules  80 selected · 6 require additional context
```

This reports selection, not completed verification. A selected rule can still lack evidence. Findings distinguish security, correctness, explicit policy and informational observations. A confirmed code pattern is not confirmed exploitation.

Default output shows observed issues, keeps the summary borders and omits repetitive per-issue remediation/confidence text. Missing API data and excluded package lists stay in structured diagnostics/evidence. Exact duplicate evidence is grouped into one canonical issue without removing raw assessment results.

```sh
# Inspect evidence, remediation and verification for selected rule IDs
php magebean.phar audit --path=/var/www/magento --profile=hardening --rules=MB-0049
```

A dependency match is reported plainly:

```text
Known vulnerability found in symfony/filesystem 8.0.11
Advisory: PKSA-G499-CM4Q-V35Y
```

Available advisory title, published fix and references appear in detailed output. See [findings and output](docs/guides/findings-and-output.md).

## Target and project context

Local HTTP checks use the URL resolved from Magento store configuration through the shared resolver. `--url` does not override that local configuration. A local checkout and an HTTP response remain separate evidence scopes unless their deployed build identity is established. To audit an accessible storefront without source, use `--url` without `--path`; target-mode filtering limits available rules.

Project policy is loaded from `.magebean.json` (or YAML when the PHP YAML extension is available). Explicit false capabilities override profile defaults:

```json
{"capabilities":{"strict_native_api_policy":false}}
```

Flags select context; they do not manufacture evidence. No `.magebean/osv-db.json`, production policy or logrotate file is created automatically. Only opt into supplied inputs that apply to the project. See [CLI reference](docs/guides/cli-reference.md) and [runtime URL discovery](docs/guides/runtime-url-discovery.md).

For native automated scans, exit codes are `0` for no actionable findings, `1` for findings, `2` for a critical finding, and `3` for incomplete execution. Incomplete execution takes precedence and retains collected findings. A zero finding count alone does not establish complete coverage. Command/input errors may also return nonzero; inspect diagnostics.

## Security Dashboard agent

PHP cURL is required for agent transport. Pair using a one-time code from the Dashboard:

```sh
php magebean.phar agent:connect --code=YOUR_PAIRING_CODE --magento-path=/var/www/magento
php magebean.phar agent:doctor
php magebean.phar agent:status
php magebean.phar agent:tick
```

Use `agent:cron` to print the polling schedule and `agent:cron --install` to install it interactively. Agent state and private credentials live under `$MAGEBEAN_HOME` or `~/.magebean`. Do not commit that directory.

Agent manifests use explicit capabilities and preserve per-request assessment results. The current Console importer synchronizes membership but does not propagate CLI profile default capabilities into queued manifests. CLI default selection and agent execution are therefore not identical. See [agent commands](docs/guides/cli-reference.md#security-dashboard-agent) and [report compatibility](docs/guides/findings-and-output.md).

## Development and packaging

```sh
php tests/run.php
php tools/update-baseline-doc.php --check
python3 tools/check-docs.py
php tools/build-phar.php
php tools/build-phar.php --one-time
```

Builds validate a runtime-only candidate before replacing either local PHAR. They do not deploy to a store or import a production Console database. See [release packaging](docs/reference/release-packaging.md) and [contributing](CONTRIBUTING.md).

## Documentation

- [Documentation index](docs/README.md)
- [Magebean Security Baseline v1 — all 110 current criteria](docs/magebean-baseline-v1.md)
- [Profile selection and defaults](docs/guides/profiles.md)
- [Required production context](docs/guides/production-context.md)
- [API calls and data disclosure](docs/reference/api-reference.md)
- [Architecture and contracts](docs/reference/architecture.md)
- [ASVS/PCI workflows](docs/standards/README.md)
- [Archived plans, QA and migration evidence](docs/archive/README.md)

The repository is licensed under [MIT](LICENSE). Report security issues following [SECURITY.md](SECURITY.md).
