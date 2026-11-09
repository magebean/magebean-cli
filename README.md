# Magebean CLI — Magento 2 Security & Compliance Auditing

Magebean CLI audits Magento 2 installations and public storefronts against versioned security profiles. Run it locally, remotely, or in hybrid mode to turn filesystem, configuration, dependency, and HTTP evidence into actionable findings.

Use the fast production-readiness profile for routine checks, map an assessment to OWASP ASVS, OWASP Top 10, or PCI DSS. The CLI supports both automated checks and structured human verification, works in CI, and can connect a Magento host to Magebean Security Dashboard for managed assessments.

> **Goal**: “Audit in minutes. Know exactly what to fix and why.”

---

## Assessment terminology

We use **requirement** for the unit assessed and reported. The accepted model is **one requirement = one assessment definition (legacy name: rule)**, containing one or more reusable checks. ASVS profiles compile one definition per versioned requirement. The underlying MB-R catalog remains a compatibility/evidence catalog; all thirteen customer profiles use persisted source-family definitions. Exact command names such as `rules:list`, options such as `--rules`, and JSON `rules` keys remain supported as implemented today.

Start with the [documentation index](docs/README.md) and the [Magebean Baseline v1](docs/magebean-baseline-v1.md), which contains only Magebean requirements. ASVS and PCI DSS clauses remain in their separate official source documents and CLI catalogs.

Read the [requirement model](docs/requirement-model.md) and [ASVS L1/L2 migration inventory](docs/asvs-requirement-migration.md) for the mapping and implementation boundary. A technical check PASS does not resolve an unverified human obligation.


## ✨ Features

- **Target-aware scanning**: audit a Magento filesystem in LOCAL mode, a public storefront in REMOTE mode, or combine both evidence sources in HYBRID mode.
- **Security profiles**: choose `basic`, ASVS Level 1–3, OWASP Top 10 2025, PCI DSS v4.0.1, `hardening`, or a custom profile.
- **Automated and human checks**: selected profiles combine technical observations with structured human verification when independent evidence is required.
- **Actionable results**: Basic, Hardening and Magebean OWASP prioritize findings requiring attention, including informational UNKNOWN/collection findings in the same workflow. Inspect evidence, remediation and verification guidance; standards profiles retain their assessment outcomes. See [findings-first reporting](docs/magebean-findings-first.md).
- **PCI DSS workflow**: compile applicability context, import structured external evidence, and generate an evidence-readiness JSON report.
- **Project policy**: customize capabilities, controls, exclusions, rule overrides, project-specific rules, and additional rule packs with `.magebean.json` or YAML.
- **CI-friendly behavior**: use deterministic exit codes based on confirmed finding severity while keeping inconclusive checks separate.
- **Security Dashboard agent**: pair a Magento host, validate prerequisites, install bounded polling, and run managed assessment work with the `agent:*` commands.
- **Local-first data handling**: filesystem checks stay on the host; API-backed checks disclose only endpoint-specific data described in [API data disclosure](docs/api-reference.md#data-disclosure).

---

## 📦 Requirements

- PHP **8.1+**
- For LOCAL or HYBRID scans: a readable Magento **2.4+** installation
- For REMOTE scans: an accessible HTTP/HTTPS Magento storefront; source access is not required
- For Security Dashboard agent commands: PHP cURL extension
- Optional: PHP YAML extension when using `.magebean.yml` or `.yaml` policy files
- Optional for scheduled agent polling: cron and `flock`

---

## 🚀 Install

### Option 1: Use the packaged PHAR
```bash
# Download magebean.phar (example path)
curl -L -o magebean.phar https://magebean.com/files/magebean.phar
chmod +x magebean.phar
```

### Option 2: Local development (composer)
```bash
composer install
php bin/magebean rules:list
```

### Build a release PHAR

```bash
php tools/build-phar.php
# Alternate artifact path:
php tools/build-phar.php --one-time
```

The build uses only application runtime files and production Composer packages, regenerates the production autoloader, and rejects nested PHARs, artifacts, tests/docs and dev packages. A candidate must pass manifest and runtime smoke checks before replacing the release; the previous binary is saved under ignored `build/`. Keep Composer and `box.phar` available as build tools; they are not bundled. See [release packaging](docs/release-packaging.md).

---

## 🧪 Quick Start

```bash
./magebean.phar scan \
  --path=/var/www/magento
```

The primary catalog contains **725 requirements** in three separate families: **100 Magebean, 345 ASVS and 280 PCI**. Historical legacy rule counts describe the deprecated compatibility library, not current profile coverage.

Use `development` for a source checkout and `prelaunch` for an installed candidate plus staging URL. See the [Development and Prelaunch guide](docs/magebean-development-prelaunch-profiles.md).

For an opt-in local module audit, run `magebean scan --path=/path/to/magento --profile=module-integrity`. Add `--modules=Vendor_Module` to select an installed Composer module or narrow the scope.

`scan` and `rules:list` use the 37-requirement `basic` profile by default. Basic includes 30 security and 7 readiness criteria informed by Adobe guidance. Basic, Hardening and Magebean OWASP are automated-only profiles, without human-evidence requirements or manual checklists. Unavailable technical evidence remains an execution error, never an implicit PASS. Numeric thresholds are Magebean policy. ASVS and PCI retain their independent document clauses and evidence workflows; use `--include-manual-review` for those assessments. PCI supports `--pci-context`, `--pci-evidence` and `--pci-report`.

See [CLI Reference](docs/cli-reference.md) for all commands, options, profiles, target modes, and examples.

---

## Commands

| Command | Purpose |
|---|---|
| `scan` | Audit a local Magento installation, a public storefront, or both. |
| `rules:list` | List rules after applying profile, control, severity, capability, and manual-review filters. |
| `agent:connect` | Pair this host with Magebean Security Dashboard. |
| `agent:status` | Show local and remote agent status. |
| `agent:doctor` | Validate PHP, Magento, agent storage, credentials, and disk prerequisites. |
| `agent:tick` | Run one bounded Dashboard polling cycle. |
| `agent:cron` | Print or install the current-user polling cron entry. |
| `agent:disconnect` | Disconnect the host and remove its local token. |
| `completion` | Generate shell completion. |
| `list` / `help` | Discover commands and command-specific help. |

Use command help as the authoritative option summary for the installed build:

```bash
php magebean.phar list
php magebean.phar scan --help
php magebean.phar rules:list --help
php magebean.phar agent:connect --help
```

---

## Results and exit codes

Basic, Hardening and Magebean OWASP prioritize findings requiring attention. Inspect a requirement using its current identity:

```bash
php magebean.phar scan --path=/var/www/magento --rules=MB-0001
```

Evidence, remediation and collection guidance depend on the selected requirement and profile. ASVS and PCI retain their independent evidence workflows. See [findings-first reporting](docs/magebean-findings-first.md) and the [CLI reference](docs/cli-reference.md).

| Exit | Meaning |
|---|---|
| `0` | Completed scan with no confirmed findings |
| `1` | Confirmed high, medium or low findings |
| `2` | Confirmed critical findings |
| `3` | Incomplete execution in native Magebean automated profiles |

Missing evidence does not establish PASS or a confirmed vulnerability. Resolve execution errors before treating a native profile scan as complete.

---
## ⚙️ Scan Options

Target mode is selected from the explicitly provided options:

- `--url` without `--path`: **REMOTE**; confirm Magento 2 first, then run the selected profile's externally observable requirements (`basic` by default).
- `--path` without `--url`: **LOCAL**.
- `--path` with `--url`: **HYBRID**, combining local and HTTP evidence.
- No target options: auto-detect a Magento root and run **LOCAL**.

| Option | Description | Default |
|---|---|---|
| `--profile` | Built-in profile or custom JSON profile path | `basic` |
| `--standard` | Legacy report selector: `magebean`, `owasp`, `pci`, or `cwe`; prefer `--profile` | `magebean` |
| `--path` | Magento root to audit | auto-detect in LOCAL mode |
| `--url` | Absolute HTTP/HTTPS store base URL | none |
| `--rules` | Run only selected rule IDs | all |
| `--controls` | Restrict the loaded pack to selected control IDs | none |
| `--exclude-rules` | Exclude selected rule IDs | none |
| `--config` | Project policy file (`.magebean.json` auto-detected in Magento root) | auto |
| `--include-manual-review` | Include human-review rules | off |
| `--capabilities` | Enable contextual profile rules, such as `graphql` or `oauth_oidc` | none |
| `--pci-context` | PCI DSS applicability context JSON | none |
| `--pci-evidence` | PCI DSS structured external evidence JSON | none |
| `--pci-report` | Write a PCI evidence-readiness report as JSON | none |

Selection order is: target pack → project policy → (`--rules` or profile) → `--exclude-rules`. An explicit `--rules` list selects IDs within one source family; an explicit profile must match that family.

### Profiles

| Profile | Source family | Inventory | Default LOCAL selection |
|---|---|---:|---:|
| `basic` | Magebean | 37 | 37 |
| `hardening` | Magebean | 100 | 67 |
| `owasp` | Magebean | 51 | 41 |
| `asvs-l1` | ASVS 5.0.0 | 70 | 0 |
| `asvs-l2` | ASVS 5.0.0 | 253 | 0 |
| `asvs-l3` | ASVS 5.0.0 | 345 | 0 |
| `pci` | PCI DSS 4.0.1 | 280 | 0 |

ASVS/PCI inventories include contextual and human requirements. Their `--include-manual-review` flag enables human-required entries; capabilities and target mode can further limit execution. Zero default selection describes their evidence gate, not absence of reusable technical checks. Magebean native profiles contain only automated requirements. See [requirement source families](docs/requirement-source-families.md).
Hardening includes every automated Basic and Magebean OWASP requirement plus deeper production checks. Fifty previous human-dependent members are tracked in `magebean-automation-backlog.json` outside executable profiles, preserving their original criteria for automation engineering. `--include-manual-review` does not restore them into Magebean profiles. This preserves honest coverage; it does not establish complete production protection.
The automation review adds 22 fresh scoped requirements, MB-0786–MB-0807; it does not relabel the original 50 backlog criteria as automated. Strict native-API coding policies and checks requiring explicit machine targeting/expected-state policy are capability gated. Missing capabilities are listed as omitted requirements; enabled checks with missing or malformed machine input remain UNKNOWN. See [production machine policy](docs/automation-feasibility/production-policy.md) for typed inputs and capability names.
Custom profile files can be passed to `--profile`, including profiles stored under `.magebean/profiles`.

### List and filter rules

```bash
php magebean.phar rules:list
php magebean.phar rules:list --profile=asvs-l2 --include-manual-review
php magebean.phar rules:list --profile=hardening --control=MB-C03
php magebean.phar rules:list --profile=owasp --severity=critical
```

`rules:list` supports `--profile`, `--include-manual-review`, `--capabilities`, `--control`, and `--severity`. Its filters are intersected.

### Project-specific policy

Create `.magebean.json` in the Magento root to tune assessment policy per project without changing the CLI:

```json
{
  "capabilities": {
    "graphql": true,
    "oauth_oidc": false,
    "webrtc": false
  },
  "include_controls": ["MB-C01", "MB-C02", "MB-C03"],
  "exclude_rules": ["MB-R005"],
  "override_rules": {
    "MB-R002": {
      "severity": "critical",
      "checks": [
        {
          "name": "file_mode_max",
          "args": {
            "file": "app/etc/env.php",
            "max_octal": "0600"
          }
        },
        {
          "name": "file_owner_group_matches",
          "args": {
            "file": "app/etc/env.php",
            "owner_reference": ".",
            "group_reference": "."
          }
        }
      ]
    }
  },
  "rules": [
    {
      "id": "PROJECT-R001",
      "title": "No project debug module references",
      "control": "PROJECT",
      "severity": "high",
      "op": "all",
      "checks": [
        {
          "name": "code_grep",
          "args": {
            "paths": ["app/code"],
            "must_not_match": ["DebugToolbar"]
          }
        }
      ],
      "messages": {
        "pass": "No debug module references detected.",
        "fail": "Debug module reference detected in project code."
      }
    }
  ]
}
```

For MB-R101, explicitly document approved global Admin ACL exceptions by overriding its check arguments. Both the role and every active user inheriting that role must be approved:

```json
{
  "override_rules": {
    "MB-R101": {
      "checks": [
        {
          "name": "magento_admin_global_acl_restricted",
          "args": {
            "env_file": "app/etc/env.php",
            "approved_global_role_names": ["Emergency Administrators"],
            "approved_global_usernames": ["breakglass.admin"]
          }
        }
      ]
    }
  }
}
```

You can also attach external JSON rule packs:

```json
{
  "rule_packs": ["security-rules"]
}
```

YAML configs are accepted when the PHP `yaml` extension is installed; JSON is the portable PHAR-safe format.

---

## Security Dashboard Agent

Pair the host using a one-time code from Magebean Security Dashboard, check it, and install the polling schedule:

```bash
php magebean.phar agent:connect \
  --code=MB-N77V-XKNF \
  --magento-path=/var/www/magento

php magebean.phar agent:doctor
php magebean.phar agent:status
php magebean.phar agent:cron --install
```

The agent stores its configuration, private token, state, queue, cache, and logs in `$MAGEBEAN_HOME`, or `~/.magebean` when the variable is unset. The token is stored locally and is never printed.

Run one polling cycle manually with `agent:tick`. To print the recommended cron line without modifying the crontab, run `agent:cron` without `--install`. Cron installation requires interactive confirmation and avoids duplicate agent entries.

```bash
php magebean.phar agent:tick
php magebean.phar agent:cron
php magebean.phar agent:disconnect
```

`agent:status`, `agent:doctor`, `agent:tick`, `agent:cron`, and `agent:disconnect` accept `--config-dir`. For the initial connection, use `MAGEBEAN_HOME` to select a non-default data directory. `agent:connect --dev` targets the local development Dashboard API and disables TLS verification; do not use it in production.

See [Security Dashboard agent](docs/cli-reference.md#security-dashboard-agent) for storage layout, command behavior, and troubleshooting.

---

## 🧩 Development

```bash
# run locally
php bin/magebean scan --path=/path/to/magento

# scan a public store without filesystem access
php bin/magebean scan --url=https://magento-store.com

# inspect available rules
php bin/magebean rules:list

# inspect every registered command
php bin/magebean list
```

See the [documentation index](docs/README.md) for operational guides, standards workflows and historical engineering reviews.

---

## 🔐 Security

Responsible disclosure: please email **support@magebean.com**.

---

## 🗺️ Roadmap

- Live CVE updates via Magebean Cloud API
- Additional controls & rule packs
- PDF export
- GitHub Action wrapper

---

## 📬 Contact

- Email: **support@magebean.com**
- Website: **https://magebean.com**

---

## License

MageBean CLI is open-sourced software licensed under the [MIT license](./LICENSE).

- **Core CLI** → MIT licensed, free to use and extend.
- **Audit-as-a-Service** → Commercial offering.

The CLI is free to use and extend under MIT; professional audit services are offered separately.

ASVS counts above are requirement findings, including 12 native partial evidence implementations (missing evidence still returns UNKNOWN). Canonical selectors require a profile, for example `scan --profile=asvs-l2 --rules=OWASP-ASVS:5.0.0:6.2.1`. Explicit MB-R selections retain legacy execution. See [runtime migration and dashboard compatibility](docs/requirement-migration.md).

The former ASVS L1 implementation gaps now have native checks; see [ASVS native evidence](docs/asvs-native-evidence.md) for scope, required account artifacts and human confirmation.
