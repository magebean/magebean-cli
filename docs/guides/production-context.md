# Production context and optional checks

Hardening selects **80 of 86** local rules by default, including all six `strict_native_api_policy` checks. The other six need project-specific targeting or expected-state inputs. They are optional selection context, not six confirmed defects or mandatory files every Magento project must create.

| Rule | Capability | Actual input required |
|---|---|---|
| MB-0799 | runtime_worker_access | Current PHP-FPM worker PIDs in `.magebean/production-checks.json`; scanner runs as the matching runtime user to observe actual write permissions. |
| MB-0801 | admin_role_policy | Explicit approved direct global Admin group-role IDs in production-checks.json, plus readable Magento database/configuration. `[]` means none are permitted. |
| MB-0804 | integration_debug_policy | Known debug/verbose setting paths for the installed integration versions in production-checks.json. The predicate observes declared default-scope values, not every runtime/store override. |
| MB-0805 | dependency_source_policy | `.magebean/dependency-source-policy.json` with schema_version 1, approved root_repositories and per-package source/dist identities, references and replacement declarations. |
| MB-0807 | runtime_worker_inventory | `.magebean/php-fpm-workers.json` with schema_version 1 and explicit pool, pid and start_ticks worker identities; access to corresponding Linux process information. |
| MB-0043 | log_rotation_config | An existing supplied `devops/logrotate.conf` candidate. This checks the declaration; it does not prove host installation or complete rotation coverage. |

Enable only applicable inputs:

```sh
php magebean.phar audit --path=/var/www/magento --profile=hardening \
  --capabilities=runtime_worker_access,admin_role_policy,integration_debug_policy,dependency_source_policy,runtime_worker_inventory,log_rotation_config
```

This selects all 86 local members, subject to project filters. It does not ensure every selected check has sufficient evidence. Missing or invalid input remains UNKNOWN/incomplete, never PASS. No policy, snapshot, logrotate file or credentials are generated automatically.

## Typed production policy

Use a regular project-local `.magebean/production-checks.json` only when the corresponding check applies. It requires integer schema_version 1 and a checks object. The [example](../examples/production-checks.example.json) contains placeholders; replace them with actual deployment values. Do not copy its sample PIDs, role IDs, vendor paths or mitigation IDs as approved policy.

| Check key | Only accepted policy input |
|---|---|
| production_bound_worker_code_readonly | worker_pids: nonempty list of current pool worker PIDs |
| production_direct_global_roles_approved | approved_role_ids: explicit group-role allow-list |
| production_integration_debug_defaults_disabled | paths: nonempty known Magento setting paths |
| dependency_mitigation_records | expected_ids: nonempty mitigation ID list; used by opt-in evidence lint |

The wrapper accepts only these keys/inputs, rejects malformed types, duplicate/unknown keys, symbolic links and files over 32 KiB, then executes real collectors. Inputs cannot supply observed results, arbitrary commands/PHP or claims that a control works. Worker identities must be refreshed after restarts; another user/root cannot substitute its permissions for a bound worker observation. Omit non-applicable entries.

## Strict source policy

Hardening automatically selects MB-0786/0788/0792/0794/0796/0798: literal query argument policy, native network/filesystem API policies, weak-random API policy, raw crypto/session API policy, and plain-HTTP string policy. These require readable source, not an additional policy file. A matching API occurrence is a coding-policy observation, not proof of injection, exposure or exploitation.

To disable the group in `.magebean.json`:

```json
{"capabilities":{"strict_native_api_policy":false}}
```

Other profiles keep their own defaults. `cache_backend_policy` is selected by hardening and conditional in prelaunch/takeover. `dependency_maintenance` is selected by hardening/prelaunch/takeover and opt-in in development. A supplied local advisory snapshot is a separate opt-in; Magebean does not distribute or create `.magebean/osv-db.json`.

## Agent boundary

These defaults describe direct CLI profile selection. Console membership import currently does not persist CLI default_capabilities or propagate them into queued manifests. Agent capability context remains explicit and fail-closed. Importing a profile alone does not enable these observations on an agent.
