# Magebean CLI Reference

See the [documentation index](README.md), [Magebean Baseline v1](magebean-baseline-v1.md) and [source-family boundaries](requirement-source-families.md). The baseline contains Magebean criteria only; ASVS and PCI use their own official documents and separate catalogs.

Current primary runtime: one internal `MB-…` requirement identity with reusable check functions and requirement-owned obligations. Profiles select identities; standards references are alignment metadata. Historical MB-R APIs/selectors/manifests remain compatibility adapters. Older examples and legacy API sections below must be read with that boundary. See [requirement model](requirement-model.md) and [migration contract](requirement-migration.md).

The primary listing uses internal requirement identities. Legacy `RulePackLoader` still exposes 371 historical MB-R definitions for compatibility; those are not extra primary requirements. Obtain current primary and selected-profile totals through `rules:list`, with manual/capability filters labeled explicitly.

Current CLI version:

```text
Magebean CLI — Magento 2 Security Audit 1.0.0
```

## Invocation

Run the source checkout:

```bash
php bin/magebean <command> [options]
```

Run the packaged executable:

```bash
php magebean.phar <command> [options]
```

Show the version or command list:

```bash
php magebean.phar --version
php magebean.phar list
```

## Commands

| Command | Purpose |
|---|---|
| `scan` | Audit a Magento installation or storefront. |
| `rules:list` | List internal requirements after applying profile and filters. |
| `agent:connect` | Pair a Magento host with Magebean Security Dashboard. |
| `agent:status` | Show local and remote agent status. |
| `agent:doctor` | Validate agent, PHP, Magento, storage, and disk prerequisites. |
| `agent:tick` | Run one bounded dashboard polling cycle. |
| `agent:cron` | Print or install the current-user polling cron entry. |
| `agent:disconnect` | Revoke the remote agent and remove its local token. |
| `completion` | Generate Bash, Fish, or Zsh completion. |
| `help` | Display help for a command. |
| `list` | List available commands. |

## `scan`

### Synopsis

```bash
php magebean.phar scan [--path=PATH] [--url=URL] [options]
```

### Target modes

| Mode | Options | Coverage |
|---|---|---|
| Local | `--path=PATH`, or omit both target options | Reads the Magento filesystem and local configuration. |
| Remote | `--url=URL` | Runs externally observable checks after confirming the target is Magento. |
| Hybrid | `--path=PATH --url=URL` | Combines local and HTTP evidence. |

When neither `--path` nor `--url` is supplied, Magebean searches for a Magento root from the current directory. A local Magento root must contain at least:

- `composer.json`
- `bin/magento`
- `app/etc/config.php` or `app/etc/env.php`

### Profiles

| Profile | Requirement selection |
|---|---|
| `basic` | Default production-readiness predicates. |
| `asvs-l1` | 70 ASVS-aligned identities at Level 1. |
| `asvs-l2` | 253 ASVS-aligned identities cumulatively, before context filters. |
| `asvs-l3` | 345 ASVS-aligned identities cumulatively, before context filters. |
| `owasp` | Application predicates tagged with Top 10 categories; categories are not requirement IDs. |
| `pci` | 280 PCI DSS 4.0.1-aligned identities with applicable human/evidence obligations. |
| `hardening` | Production hardening predicates. |
| `module-integrity` | Opt-in local module structure and AppSec checks. |
| `module-source` | Opt-in PHP target, method contract, framework constraint and request flow checks. |
| `module-lifecycle` | Opt-in declarative schema, setup patch and cron/queue handler checks. |
| `module-reliability` | Opt-in reliability and performance observations. |
| `development` | Offline checkout and module source audit. |
| `prelaunch` | Local release candidate and explicit staging endpoint. |
| `FILE` | Custom profile selecting internal identities. |

`rules:list` reports actual selected counts. Human and capability filters reduce execution selection and do not increase the underlying unique inventory.

The `asvs-l1` mapping covers all 70 Level 1 requirements: 15 automated, 27 partially automated and 28 manual-review. This is an evidence-oriented scan profile, not an ASVS certification.

The cumulative `asvs-l3` mapping covers all 345 ASVS 5.0 requirements: 70 Level 1, 183 Level 2, and 92 Level 3 additions. It selects 98 requirement definitions by default and 268 non-contextual definitions with `--include-manual-review`. Level 3 human-assessment results use the `HUMAN VERIFICATION REQUIRED` status and provide the specific assessment scope for each requirement.

The cumulative `asvs-l2` mapping covers 253 requirements. By default it selects 90 requirement definitions including 12 native partial evidence implementations. Add `--include-manual-review` to select 198 non-contextual requirement definitions. Set capabilities explicitly to activate relevant conditional reviews:

```json
{
  "capabilities": {
    "graphql": true,
    "oauth_oidc": false,
    "webrtc": false
  }
}
```

Manual reviews can be enabled with `--include-manual-review`. The same capabilities can be supplied for one scan with `--capabilities=graphql,oauth_oidc`. Unspecified or false capabilities do not activate contextual rules.

Every scan summary shows both the number of rules selected to run and the complete rule count for the current profile selection. When human-verification rules are hidden, the summary reports how many are hidden and instructs the user to add `--include-manual-review`. The same count and guidance are shown by `rules:list`.

If `--profile` is omitted, Magebean uses `basic`.

The former `standard` profile name is no longer supported:

```bash
php magebean.phar scan --profile=basic
```

### Command options

| Option | Description |
|---|---|
| `--path=PATH` | Magento root. Omit to auto-detect it from the current directory. |
| `--url=URL` | Absolute storefront URL. Selects Remote or Hybrid mode. |
| `--profile=PROFILE\|FILE` | Built-in or custom profile. Default: `basic`. |
| `--include-manual-review` | Include human manual-review rules; excluded by default. |
| `--modules=Vendor_Module,...` | Replace the module audit source scope with exact installed module names. |
| `--capabilities=NAME,...` | Enable capability-dependent profile rules for this scan. |
| `--controls=MB-Cxx,...` | Restrict the loaded rule pack to control IDs. |
| `--rules=MB-xxxx,...` | Select internal requirements explicitly; historical MB-R selectors remain compatibility requests. |
| `--exclude-rules=MB-xxxx,...` | Exclude internal requirements after profile/project policy; legacy aliases resolve at the adapter boundary. |
| `--config=FILE` | Project policy file. Local scans auto-detect `.magebean.json` or `.magebean.yml`. |
| `--pci-context=FILE` | PCI DSS entity, scope, payment architecture, overlays, and requirement overrides. |
| `--pci-evidence=FILE` | Credential-free structured external evidence package. |
| `--pci-report=FILE` | Write a PCI DSS evidence-readiness JSON report; never a compliance attestation. |
| `--standard=NAME` | Legacy report selector: `magebean`, `owasp`, `pci`, or `cwe`. Prefer `--profile`. |

An explicit `--profile` takes precedence over the legacy `--standard` selector.

### Global options

| Option | Description |
|---|---|
| `-h`, `--help` | Display command help. |
| `-V`, `--version` | Display the Magebean version. |
| `-q`, `--quiet` | Display errors only. |
| `--silent` | Suppress all output. |
| `--ansi`, `--no-ansi` | Force or disable ANSI formatting. |
| `-n`, `--no-interaction` | Disable interactive questions. |
| `-v`, `-vv`, `-vvv` | Increase verbosity. |

### Selection order

Magebean applies selection in this order:

```text
Target rule pack
→ project policy
→ explicit `--rules` selection or profile selection
→ --exclude-rules
```

When `--rules` is provided, Magebean bypasses profile selection and resolves the requested IDs directly from the available catalog. A separate `--profile` value is ignored for that scan:

With `--rules`, the summary renders every selected rule, including PASS, FAIL, and INCONCLUSIVE. Each rule includes a `Detail` block with the underlying check name, status, and full multiline message. Without `--rules`, the summary remains compact.

```bash
php magebean.phar scan \
  --path=/var/www/magento \
  --rules=MB-R100,MB-R101
```

### Examples

Default Basic scan:

```bash
cd /var/www/magento
php /var/www/magebean-cli/magebean.phar scan
```

Explicit local scan:

```bash
php magebean.phar scan --path=/var/www/magento
```

Remote and Hybrid scans:

```bash
php magebean.phar scan --url=https://store.example.com
php magebean.phar scan \
  --path=/var/www/magento \
  --url=https://store.example.com
```

Select a profile:

```bash
php magebean.phar scan --path=/var/www/magento --profile=basic
php magebean.phar scan --path=/var/www/magento --profile=owasp
php magebean.phar scan --path=/var/www/magento --profile=pci
php magebean.phar scan --path=/var/www/magento --profile=pci --pci-context=.magebean/pci-context.json --pci-evidence=.magebean/pci-evidence.json --include-manual-review --pci-report=var/report/magebean-pci.json
php magebean.phar scan --path=/var/www/magento --profile=hardening
```

Filter controls or rules:

```bash
php magebean.phar scan \
  --path=/var/www/magento \
  --profile=hardening \
  --controls=MB-C01,MB-C05

php magebean.phar scan \
  --path=/var/www/magento \
  --profile=hardening \
  --rules=MB-R049,MB-R050

php magebean.phar scan \
  --path=/var/www/magento \
  --exclude-rules=MB-R032
```

Use a project policy:

```bash
php magebean.phar scan \
  --path=/var/www/magento \
  --config=.magebean.yml
```

### Exit behavior

- Exit `0`: scan completed without confirmed findings. `UNKNOWN` results are reported as inconclusive.
- Exit `1`: invalid input, target/configuration error, or one or more confirmed findings.

## `rules:list`

### Synopsis

```bash
php magebean.phar rules:list [options]
```

### Options

| Option | Description |
|---|---|
| `--profile=PROFILE\|FILE` | Select a built-in or custom profile. Default: `basic`. |
| `--control=MB-Cxx,...` | Keep only listed controls. |
| `--severity=LEVEL` | Keep `low`, `medium`, `high`, or `critical` rules. |

`--control` and `--severity` are intersected with the selected profile; they do not add rules.

### Examples

```bash
php magebean.phar rules:list
php magebean.phar rules:list --profile=hardening
php magebean.phar rules:list --profile=hardening --control=MB-C03
php magebean.phar rules:list --profile=owasp --severity=critical
php magebean.phar rules:list --profile=.magebean/profiles/acme.json
```

## Security Dashboard agent

The agent commands pair a Magento installation with Magebean Security Dashboard and poll for assessment work. Dashboard communication uses `https://console.magebean.com/api`; scan APIs remain separate at `https://api.magebean.com`.

Agent data is stored under `$MAGEBEAN_HOME` when that environment variable is set. Otherwise it is stored in `~/.magebean`:

| File or directory | Purpose |
|---|---|
| `config.json` | Dashboard URL, Magento path, agent identity, and development-mode setting. |
| `credentials.json` | Agent bearer token. Created with private permissions and never printed. |
| `state.json` | Connection and polling timestamps. |
| `queue/pending-uploads` | Uploads waiting to be retried. |
| `cache/manifests` | Cached assessment manifests. |
| `logs` | Agent logs. |

After a successful connection, the CLI prints the resolved paths to `config.json` and `credentials.json`:

```text
Agent connected. Token stored locally and not displayed.
Config saved to: /home/user/.magebean/config.json
Credentials saved to: /home/user/.magebean/credentials.json
```

### `agent:connect`

Pair the current host using a one-time code generated by Security Dashboard:

```bash
php magebean.phar agent:connect \
  --code=MB-N77V-XKNF \
  --magento-path=/var/www/magento
```

| Option | Description |
|---|---|
| `--code=CODE` | Required one-time pairing code. |
| `--magento-path=PATH` | Required readable Magento root. |
| `--dev` | Use `https://console.magebean.local/api` and allow its self-signed development certificate. |

The CLI detects the storefront URL from Magento configuration, detects Magento version and edition from the installation, and uses the machine hostname as the agent name. These values are not accepted as command-line options.

For local Dashboard development:

```bash
php magebean.phar agent:connect \
  --code=MB-N77V-XKNF \
  --magento-path=/var/www/magento \
  --dev
```

Keep a space between the Magento path and `--dev`. For example, `--magento-path=/var/www/magento--dev` is interpreted as one invalid path.

If an agent is already connected, run `agent:disconnect` before pairing again. A replacement pairing code must also permit replacement on Security Dashboard.

### `agent:status`

Show the local connection, Dashboard endpoint, Magento path, remote status, and last polling time:

```bash
php magebean.phar agent:status
```

### `agent:doctor`

Check the PHP version, cURL extension, connection state, credential permissions, Magento files, writable queue, and available disk space:

```bash
php magebean.phar agent:doctor
```

The command exits non-zero when any prerequisite fails.

### `agent:tick`

Run one bounded polling cycle. This is normally invoked by cron:

```bash
php magebean.phar agent:tick
```

### `agent:cron`

Print the recommended once-per-minute cron entry without changing the crontab:

```bash
php magebean.phar agent:cron
```

Install it for the current user after interactive confirmation:

```bash
php magebean.phar agent:cron --install
```

`--install` fails in non-interactive mode and does not add a duplicate entry.

### `agent:disconnect`

Notify Security Dashboard, revoke the remote agent, and remove the local token:

```bash
php magebean.phar agent:disconnect
```

If Dashboard cannot be reached, the CLI reports a warning and still removes the local token.

### Alternate agent data directory

`agent:status`, `agent:doctor`, `agent:tick`, `agent:cron`, and `agent:disconnect` accept:

```bash
php magebean.phar agent:status --config-dir=/srv/magebean-agent
```

`agent:connect` intentionally exposes only `--code`, `--magento-path`, and `--dev`. To choose its initial data directory, set `MAGEBEAN_HOME`:

```bash
MAGEBEAN_HOME=/srv/magebean-agent php magebean.phar agent:connect \
  --code=MB-N77V-XKNF \
  --magento-path=/var/www/magento
```

## Custom profiles

A custom profile is a JSON file containing an ID and a list of rule IDs:

```json
{
  "id": "acme",
  "title": "ACME Magento Policy",
  "description": "Rules required by ACME production policy.",
  "rules": [
    "MB-R001",
    "MB-R031",
    "MB-R049",
    "MB-R050"
  ]
}
```

Load it by path:

```bash
php magebean.phar scan \
  --path=/var/www/magento \
  --profile=.magebean/profiles/acme.json
```

Unknown rule IDs fail validation.

## Shell completion

Generate completion for Bash, Fish, or Zsh:

```bash
php magebean.phar completion bash
php magebean.phar completion fish
php magebean.phar completion zsh
```

Example Bash installation:

```bash
php magebean.phar completion bash > completion.sh
source completion.sh
```

## Troubleshooting

Show detailed help:

```bash
php magebean.phar scan --help
php magebean.phar rules:list --help
```

Disable colors for logs and CI:

```bash
php magebean.phar scan \
  --path=/var/www/magento \
  --no-ansi \
  --no-interaction
```

Increase diagnostic output:

```bash
php magebean.phar scan --path=/var/www/magento -vvv
```

If Magento root detection fails, pass the installation root explicitly:

```bash
php magebean.phar scan --path=/var/www/magento
```

Inspect agent configuration and prerequisites:

```bash
php magebean.phar agent:status
php magebean.phar agent:doctor
```

For local Dashboard development, confirm that `console.magebean.local` resolves from the environment running the CLI, then connect with `--dev`.

## Internal requirement selectors and compatibility

Normal profile findings use internal `MB-…` IDs, with singular requirement identity and standard alignment metadata. Use the ID returned by `rules:list` with `--rules=ID --profile=PROFILE`. Rerun guidance retains the selected profile, enabled capabilities and supplied hybrid target context when those are recorded in result metadata.

Historical MB-R and former `OWASP-ASVS:5.0.0:…` selectors are compatibility requests, not additional inventory entries. Their exact expansion/result behavior belongs to the compatibility adapter. Do not infer equality from shared source checks or remove a source definition to hide it from primary inventory.

Project selection/exclusion uses primary identities. Requirement identity, criterion, obligations and proof classifications are immutable through presentation overrides. A changing title or severity does not promote heuristic evidence into complete automation.

Missing source/runtime/artifact evidence remains UNKNOWN. Partial technical observations need confirmation rather than automatically proving the entire criterion. Native implementation of the former 12 ASVS gaps remains partial. See [runtime migration](requirement-migration.md) and [native evidence](asvs-native-evidence.md).

### Basic automation execution contract

`scan --path=/path/to/magento --profile=basic` selects 37 automated deployment requirements before target-mode filtering. It can discover the configured runtime URL; use `--url` when the configured endpoint is inaccessible from the scanning host. Run with permission to read deployment configuration and installed scheduler sources. Missing runtime/configuration/permission evidence causes a separate execution error and process exit3. It is never counted as a confirmed vulnerability. Complete scans retain exits0=clean,1=noncritical findings,2=critical findings.
`--include-manual-review` includes requirements that declare mandatory human evidence, including those with automated technical checks. Without the flag, profile scans and listings exclude them. Explicit `--rules` selection remains an intentional opt-in.

## OWASP scan quality review — 2026-10-07

The OWASP deployment profile has 31 automated requirements by default and 38 requiring explicit human evidence. Broad heuristic checks require `--include-manual-review`; reviewed bounded criteria can conclude PASS/FAIL. Git history is replaced in this deployment profile by existing MB-0730, with MB-0072 retained globally. Missing runtime/API evidence includes concrete collection guidance rather than instructions to fix a tool implementation gate. See [the 33-item security review](owasp-scan-quality-review.md).


`audit` is an alias of `scan`. Both commands accept the same options and return the same exit codes. For example, `php magebean.phar audit --profile development` is equivalent to `php magebean.phar scan --profile development`.
