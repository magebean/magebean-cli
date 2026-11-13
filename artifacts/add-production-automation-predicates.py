"""Allocate exact production observations without restoring or weakening historical IDs."""
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
base = root / 'src/Rules/requirements'
read = lambda path: json.loads(path.read_text(encoding='utf-8-sig'))
write = lambda path, value: path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
catalog = read(base / 'magebean-catalog.json')
allocation = read(base / 'allocation-manifest.json')
ledger = read(base / 'reconciliation-ledger.json')
profiles = read(base / 'internal-profiles.json')
backlog = {r['id']: r for r in read(base / 'magebean-automation-backlog.json')['requirements']}
runtime_rows = read(root / 'docs/archive/automation-feasibility/runtime-implementation.json')
runtime = {r['id']: r for r in runtime_rows}
dependency_doc = read(root / 'docs/archive/automation-feasibility/dependencies-implementation.json')
dependencies = {r['id']: r for r in dependency_doc['rows']}
known = {r['id']: r for r in catalog['requirements']}

specs = [
    ('MB-0004', 'production_bound_worker_code_readonly', 'runtime_worker_access', 'LOCAL', runtime['MB-0004']),
    ('MB-0748', 'production_upload_signatures_absent', None, 'LOCAL', runtime['MB-0748']),
    ('MB-0101', 'production_direct_global_roles_approved', 'admin_role_policy', 'LOCAL', runtime['MB-0101']),
    ('MB-0089', 'production_checkout_csp_response', None, 'BOTH', runtime['MB-0089']),
    ('MB-0096', 'production_runtime_nosniff', None, 'BOTH', runtime['MB-0096']),
    ('MB-0745', 'production_integration_debug_defaults_disabled', 'integration_debug_policy', 'LOCAL', runtime['MB-0745']),
    ('MB-0064', 'dependency_source_policy', 'dependency_source_policy', 'LOCAL', dependencies['MB-0064']),
    ('MB-0053', 'dependency_mitigation_records', 'dependency_mitigation_policy', 'LOCAL', dependencies['MB-0053']),
    ('MB-0738', 'production_worker_xdebug_absent', 'runtime_worker_inventory', 'LOCAL', {
        'new_title': 'Configured PHP-FPM workers have no mapped Xdebug binary module',
        'criterion': 'Every explicitly inventoried Linux PHP-FPM worker is bound to its pool, executable identity and exact process start_ticks before and after a complete bounded nonempty /proc process-map observation. No Xdebug-named shared module is mapped in these verified workers. Missing or changed identity, empty/unreadable/truncated maps or malformed inventory remain UNKNOWN. This observes configured process mappings at scan time, not every deployment worker, Xdebug feature mode, statically linked code or complete PHP runtime settings.',
        'args': {'policy_file': '.magebean/php-fpm-workers.json'},
        'limitations': ['Explicit process inventory is machine targeting configuration; it cannot assert a clean result. Process mappings are collected directly without reading environ or executing target PHP.'],
    }),
]
guidance = {
    'MB-0004': (
        'Identify the exact reported writable code path and whether access comes from file ownership, runtime group, ACL or writable parent. Separate deployment ownership from the PHP-FPM runtime identity; restrict that runtime identity from writing app/vendor/lib and their replaceable parents while preserving required writable var/generated/pub paths for the deployment architecture. Do not recursively remove write permissions from every Magento path.',
        'Configure current worker_pids in .magebean/production-checks.json, run the scanner as their exact unprivileged identity and namespace, and rerun the kernel access check. Confirm deployment/upgrade procedures still work under their separate deployment identity.'),
    'MB-0748': (
        'Quarantine the reported upload object outside the served tree for investigation; do not execute it. Determine how the PHP tag, PHP-like filename or script-handler override entered the upload path. Fix the real upload pipeline using server-derived type/extension policy, generated names, size limits and authorization; configure the delivery server so media cannot execute scripts.',
        'Test harmless accepted and rejected upload fixtures in isolation, verify no unintended handler overrides, and rerun the complete configured upload inventory. Resolve symlinks, unreadable or oversized eligible files before interpreting a clean result.'),
    'MB-0101': (
        'Compare reported group role IDs with the intended administrator policy in the same deployed database. Remove the unnecessary direct All resource grant or replace it with the specific resources the role needs through Magento Admin role management; do not remove the last required administrative recovery path without testing access.',
        'Maintain approved_role_ids in .magebean/production-checks.json as explicit deployment policy, then re-query real authorization tables through this check. Verify ordinary and restricted Admin functions separately because direct-row policy does not prove effective least privilege.'),
    'MB-0089': (
        'Inspect the actual enforced CSP response on the named checkout URL. Configure the installed Magento CSP modules and applicable edge/server response rules to emit the stated explicit directive baseline; replace broad script origins and inline/eval dependencies with supported nonce/hash or external script integration after compatibility testing. Report-only does not satisfy this rule.',
        'Exercise each applicable payment provider and checkout flow in staging before enforcement. Retrieve the same named checkout page without a login/cart redirect and rerun. Multiple policies or unavailable checkout context must be resolved rather than merged optimistically.'),
    'MB-0096': (
        'Set X-Content-Type-Options: nosniff in the response-producing Magento/web-server/edge layer that serves the reported application path. Remove conflicting duplicate declarations and ensure JavaScript, CSS and downloads use correct Content-Type values; avoid applying changes only to an unused sample configuration.',
        'Retrieve the same successful HTTPS application page through the actual production ingress and rerun. Test asset loading and intended downloads in staging; assess HSTS and frame protection using their separate checks.'),
    'MB-0745': (
        'For each reported named integration setting, confirm its path and semantics against the installed integration version, then disable debug/verbose output through its supported configuration mechanism in the assessed default scope. Preserve ordinary audit logging and never assume every logging setting is debug. If sensitive data was emitted, review sink exposure and rotate affected credentials as appropriate.',
        'List the applicable explicit configuration paths in .magebean/production-checks.json, rerun resolved-value collection and test integration behavior in isolation. Assess store-specific overrides and custom runtime logging separately; an absent/unresolved path is not disabled.'),
    'MB-0064': (
        'Compare the reported package, source/dist URL, revision, replacement and root repository declarations against the approved exact source policy. Investigate unexpected forks/replacements before updating either lockfile or allow-list; restore the intended package/revision through normal Composer dependency resolution and deploy a reviewed build.',
        'Maintain .magebean/dependency-source-policy.json for the complete collected package inventory and rerun against composer.lock plus composer.json. Independently verify installed artifact integrity and trusted upstream provenance; merely approving the observed source does not perform that verification.'),
    'MB-0053': (
        'Update the declared mitigation record inventory for the expected IDs with the real advisory/package/version, accountable owner, concrete action, rollback and future expiry. Replace or remove expired temporary measures through the normal release process; never fabricate a record to make the check pass.',
        'Configure the authoritative expected_ids list in .magebean/production-checks.json and rerun record structure/expiry validation against .magebean/mitigations.json. Independently test mitigation effectiveness and completeness; this finding is about declared record hygiene only.'),
    'MB-0738': (
        'Identify the PHP-FPM pool and mapped Xdebug module reported by the verified worker observation. Remove the production pool extension-loading declaration through its real deployment configuration and restart/reload the applicable pool through normal operations after staging verification. Do not expose phpinfo or a public diagnostic endpoint.',
        'Refresh .magebean/php-fpm-workers.json with current actual pool names, PIDs and start_ticks after restart, then rerun direct process-map collection. Verify every intended worker is inventoried separately; a clean CLI extension list does not establish a clean web-worker result.'),
}

added = []
for old_id, check, capability, mode, row in specs:
    key = 'magebean/production-observation-v1/' + check
    prior = next((r for r in allocation['allocations'] if r['allocation_key'] == key), None)
    if prior:
        new_id = prior['id']
    else:
        new_id = f"MB-{allocation['next_id']:04d}"
        if new_id in known:
            raise RuntimeError('Allocation collision ' + new_id)
        allocation['next_id'] += 1
        allocation['allocations'].append({'id': new_id, 'allocation_key': key, 'revision': 1, 'verdict': 'accepted_scoped_criterion'})
    title = row['new_title']
    criterion = row.get('criterion') or row.get('new_criterion')
    args = dict(row.get('args', row.get('checkargs', {})))
    args.pop('expected_ids', None)  # This must come from validated machine policy, not an empty built-in default.
    checks = [{'name': check, 'args': args}]
    repair, verify = guidance[old_id]
    limitations = row.get('limitations', [])
    if isinstance(limitations, str): limitations = [limitations]
    limitations = ' '.join(limitations) + ' Original historical criterion and ID remain in the engineering backlog; this new ID records only its exact supported observation.'
    requirement = {
        'id': new_id, 'revision': 1, 'title': title, 'criterion': criterion,
        'control': known[old_id]['control'], 'severity': 'low' if old_id == 'MB-0053' else 'medium', 'alignments': [],
        'obligations': [{'id': 'O001', 'op': 'all', 'role': 'mandatory', 'proof': 'verified_predicate', 'checks': checks}],
        'coverage': 'AUTOMATED', 'verification': 'automated', 'review_state': 'accepted_scoped_criterion',
        'human_evidence': {'required': False, 'instructions': '', 'evidence_types': ['scoped_observation']},
        'target_modes': ['LOCAL', 'REMOTE'] if mode == 'BOTH' else ['LOCAL'], 'checks': checks, 'op': 'all', 'family': 'magebean',
        'source': {'document': 'Magebean security requirements', 'version': '1', 'reference': key},
        'lane': 'readiness' if old_id == 'MB-0053' else 'security',
        'policy_source': {'owner': 'Magebean', 'version': 'production-observation-1', 'note': 'Exact automated predicate with explicit runtime or typed machine-policy scope; not certification of the broader historical criterion.'},
        'automation_backlog_ids': [old_id],
        'remediation': [repair, verify, f'Rerun {new_id} on the same deployment and release; retain the new observation and resolve collection gaps before treating the predicate as satisfied.'],
        'finding_guidance': {'version': 1, 'interpretation': criterion, 'risk': 'The observed state violates this explicit Magebean scoped production policy. Assess actual exposure and business impact using the concrete evidence; a clean observation does not establish the broader historical control.', 'triage': ['Confirm the reported target identity, response path or collected artifact belongs to the assessed release.', 'Distinguish an observed violation from missing policy or unavailable collection; do not convert UNKNOWN to satisfied.'], 'verification': [verify, f'Rerun {new_id}; configuration edits or ticket closure alone do not establish a new passing result.'], 'limitations': limitations, 'references': []},
    }
    if capability: requirement['applicability'] = {'capability': capability}
    if new_id not in known:
        catalog['requirements'].append(requirement); known[new_id] = requirement
        ledger['identities'].append({'id': new_id, 'allocation_key': key, 'revision': 1, 'criterion': criterion, 'verdict': 'accepted_scoped_criterion', 'reviewer': 'production-automation-implementation', 'limitations': limitations, 'obligation_count': 1, 'alignments': [], 'family': 'magebean'})
    membership = ['hardening']
    if 'owasp-top-10-2025' in backlog[old_id]['previous_profiles']: membership.append('owasp-top-10-2025')
    for profile_id in membership:
        if new_id not in profiles['profiles'][profile_id]['requirement_ids']: profiles['profiles'][profile_id]['requirement_ids'].append(new_id)
    row['new_id'] = new_id
    row['new_id_required'] = True
    row['original_criterion_ready'] = False
    added.append({'id': new_id, 'source_backlog_ids': [old_id], 'check': check, 'capability': capability, 'profiles': membership, 'criterion': criterion})
    if old_id == 'MB-0738':
        runtime[old_id].update({'ready': True, 'new_id': new_id, 'new_id_required': True, 'original_criterion_ready': False, 'check': check, 'method': 'LinuxWorkerObservationCheck::xdebugModulesAbsent', 'args': args, 'new_title': title, 'criterion': criterion, 'limitations': [limitations]})

aggregate = read(base / 'internal-catalog.json')
aggregate['requirements'] = catalog['requirements'] + read(base / 'asvs-catalog.json')['requirements'] + read(base / 'pci-catalog.json')['requirements']
counts = ledger['counts']
counts['active_internal_requirements'] = len(aggregate['requirements'])
counts['historical_allocations'] = len(allocation['allocations'])
counts['families']['magebean'] = len(catalog['requirements'])
counts['accepted_scoped_criteria'] = sum(r.get('review_state') == 'accepted_scoped_criterion' for r in aggregate['requirements'])
counts['human_evidence_required'] = sum(bool(r.get('human_evidence', {}).get('required')) for r in aggregate['requirements'])
for name, value in [('magebean-catalog.json', catalog), ('internal-catalog.json', aggregate), ('allocation-manifest.json', allocation), ('reconciliation-ledger.json', ledger), ('internal-profiles.json', profiles)]: write(base / name, value)
write(root / 'docs/archive/automation-feasibility/runtime-implementation.json', runtime_rows)
write(root / 'docs/archive/automation-feasibility/dependencies-implementation.json', dependency_doc)
write(root / 'docs/archive/automation-feasibility/runtime-catalog-integration.json', {'added': added, 'catalog_counts': counts, 'profile_counts': {key: len(value['requirement_ids']) for key, value in profiles['profiles'].items()}})
print(json.dumps({'added_ids': [r['id'] for r in added], 'profile_counts': {key: len(value['requirement_ids']) for key, value in profiles['profiles'].items()}, 'next_id': allocation['next_id']}, indent=2))
