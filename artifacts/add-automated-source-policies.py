"""Allocate narrower source policies without changing any historical backlog criterion."""
import json
from pathlib import Path

root=Path(__file__).resolve().parents[1]
base=root/'src/Rules/requirements'
read=lambda p:json.loads(p.read_text(encoding='utf-8-sig'))
write=lambda p,v:p.write_text(json.dumps(v,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
catalog=read(base/'magebean-catalog.json')
aggregate=read(base/'internal-catalog.json')
allocation=read(base/'allocation-manifest.json')
ledger=read(base/'reconciliation-ledger.json')
profiles=read(base/'internal-profiles.json')
backlog=read(base/'magebean-automation-backlog.json')
rows=read(root/'docs/archive/automation-feasibility/source-implementation.json')
groups={}
for row in rows:
    if row['ready'] and row['new_id_required']:
        groups.setdefault(row['reuse_group'],[]).append(row)
strict={'weak_prng','raw_crypto_session','native_network','native_filesystem','literal_https','sql_literal_query'}
fixes={
 'native_unserialize':('Replace native unserialize at the reported location with a supported JSON or typed serializer whose input contract is explicit. Do not treat allowed_classes=false as permission to deserialize untrusted input; migrate stored values through a tested compatibility path.','Verify old stored records and malformed JSON handling in isolated integration tests; confirm the forbidden native call is removed.'),
 'shell_execution':('Remove direct shell/process invocation and backticks. Where a subprocess is required, use an approved process adapter with a fixed executable and separate argument vector; review option injection and least-privilege execution independently. An unrelated escapeshellarg call does not satisfy this policy.','Test paths with spaces, shell metacharacters and argument-like values against the approved adapter in isolation; ensure ordinary workflows still work.'),
 'dynamic_execution':('Replace eval/create_function with ordinary callable objects, closures or an explicit action map. Resolve dynamic include targets through a fixed installed-file map; do not execute data as PHP. Resolve function aliases and indirect calls when they prevent complete analysis.','Exercise each supported action and include target, verify unexpected targets are rejected, and rerun the syntax policy.'),
 'weak_prng':('Replace security-token randomness with random_bytes or random_int at the required entropy and preserve hard failure on entropy-source errors. For non-security random selection or identifiers, determine whether this deliberately strict API policy should apply before changing behavior; do not label every mt_rand call exploitable.','Test token length/encoding, uniqueness expectations and entropy-source failure; confirm weak generators and fallbacks are absent from the opted-in source scope.'),
 'raw_crypto_session':('Move session operations into the installed Magento session services. Use an approved Magento encryption or password-hashing service for its intended purpose. Review md5/sha1 checksum uses separately: this strict policy also prohibits legitimate non-security hashes, so preserve compatibility and verify policy applicability.','Test session continuity and login/logout plus encryption round trips or password verification in isolation; verify existing persisted data remains readable before deployment.'),
 'native_network':('Move native outbound network calls to the approved HTTP client adapter; this strict policy also bans file_get_contents for local reads, so use the approved filesystem abstraction for local files. Configure allowed destinations, timeouts, TLS validation and redirect behavior in the actual adapter.','Run the adapter integration tests against approved and forbidden controlled destinations, then rerun the native API ban; passing this ban alone does not prove SSRF prevention.'),
 'native_filesystem':('Move direct native file operations to an approved filesystem service with an explicit root and operation contract. Preserve required encoding and atomicity; independently enforce canonical path containment and symlink handling where paths can be influenced externally.','Test ordinary files, missing files, encoded traversal and symlink escapes in isolated fixtures; rerun the API ban without claiming that adapter path safety follows automatically.'),
 'native_upload':('Replace direct move_uploaded_file with the approved upload pipeline and preserve its ownership/error behavior. Configure extension and server-derived MIME allowlists, size limits, generated names, authorization and non-executable delivery in the real pipeline.','Test approved content and harmless rejected extension/MIME/size cases plus unauthorized upload in isolation; rerun this native-call restriction separately from upload-security tests.'),
 'sql_literal_query':('At the reported named query method, use a static query string with separately bound values through the installed Magento adapter, or move query composition to the approved query builder. Do not replace interpolation with manual escaping or interpolate request data into identifiers. Resolve variable-built queries when the checker returns UNKNOWN.','Test special characters and identifier choices through the real adapter in isolation; confirm query results and bindings remain correct and no first-argument concatenation/interpolation remains.'),
 'xml_external_features':('Remove prohibited entity/DTD constants, external entity callbacks and XInclude calls, and set external resolution/substitution properties explicitly false where supported. Use the approved parser wrapper for the installed PHP/libxml version; migrating parser flags requires compatibility tests.','Use harmless isolated external-entity and DTD fixtures with a controlled destination, verify no external fetch or expansion, and retest legitimate XML documents; the syntax ban alone does not establish parser defaults.'),
 'literal_https':('Identify whether the literal is an actual production endpoint, a local development address, an XML namespace or documentation. For actual endpoints, configure HTTPS and verified peer/hostname behavior through the client. For intentional non-endpoint HTTP strings, review the strict policy scope instead of blindly replacing namespace identifiers.','Test real endpoint TLS peer/hostname checks and normal integration behavior; rerun the literal rule only in the agreed strict source scope.'),
 'csrf_unconditional_bypass':('Remove the unconditional true validateForCsrf override. Delegate to Magento validation where appropriate, or implement and test the provider-specific alternate request authentication before accepting a deliberately exempt callback. Do not merely rename the method or add an unused form-key helper.','In isolation, verify missing, invalid and foreign-session tokens cannot perform the protected state change; check valid requests and any authenticated webhook exception still work.'),
 'direct_request_logging':('Replace direct request-superglobal logging with an explicit allowlist of necessary non-sensitive fields and supported redaction before every configured sink. Avoid dumping complete request/cookie/server arrays; if a secret was logged, assess sink access/retention and rotate the affected credential as appropriate.','Send synthetic nested secret/PII canaries through the real logging pipeline and check every configured sink; rerun this syntax rule while retaining separate tests for data logged through variables or SDKs.'),
}
known={r['id']:r for r in catalog['requirements']}
back={r['id']:r for r in backlog['requirements']}
added=[]
for kind,source_rows in groups.items():
    key='magebean/source-policy-v1/'+kind
    prior=next((a for a in allocation['allocations'] if a['allocation_key']==key),None)
    if prior:
        new_id=prior['id']
    else:
        new_id=f"MB-{allocation['next_id']:04d}"
        if new_id in known:raise RuntimeError('Identity collision '+new_id)
        allocation['next_id']+=1
        allocation['allocations'].append({'id':new_id,'allocation_key':key,'revision':1,'verdict':'accepted_scoped_criterion'})
    exemplar=source_rows[0]
    args=exemplar['check_args']
    checks=[{'name':'automated_source_policy','args':args}]
    criterion=exemplar['criterion']+' Scope is completely collected app/code PHP/PHTML; missing, unreadable, oversized, linked, malformed or truncated eligible input prevents a clean PASS.'
    references=['https://www.php.net/manual/en/function.unserialize.php'] if kind=='native_unserialize' else []
    change,verify=fixes[kind]
    limitations='Exact opt-in coding policy, not a finding of confirmed exploitability or proof of the broader historical requirement. Runtime adapters, dependencies, generated code and files outside app/code remain outside this predicate.'
    requirement={
        'id':new_id,'revision':1,'title':exemplar['title'],'criterion':criterion,
        'control':known[exemplar['backlog_id']]['control'],'severity':'low' if kind in strict else 'medium','alignments':[],
        'obligations':[{'id':'O001','op':'all','role':'mandatory','proof':'verified_predicate','checks':checks}],
        'coverage':'AUTOMATED','verification':'automated','review_state':'accepted_scoped_criterion',
        'human_evidence':{'required':False,'instructions':'','evidence_types':['scoped_observation']},
        'target_modes':['LOCAL'],'checks':checks,'op':'all','family':'magebean',
        'source':{'document':'Magebean security requirements','version':'1','reference':key},
        'lane':'security','policy_source':{'owner':'Magebean','version':'source-policy-1','note':'Explicit syntactic coding restriction; no original backlog criterion is promoted or rewritten.'},
        'automation_backlog_ids':[r['backlog_id'] for r in source_rows],
        'remediation':[change,verify,f'Rerun {new_id} against the same release and complete source scope; retain file/line evidence and investigate collection gaps rather than treating UNKNOWN as satisfied.'],
        'finding_guidance':{'version':1,'interpretation':criterion,'risk':'The observed construct violates the configured Magebean coding policy. Determine actual data flow, reachability and runtime exposure before assigning incident or exploit severity.','triage':['Locate the reported file and line in the assessed release; evidence intentionally omits source snippets and secrets.','Determine whether this exact policy is enabled and applicable to the implementation; identify framework adapters and dependencies outside its scope.'],'verification':[verify,f'Rerun {new_id}; a ticket or source edit alone does not establish a new passing observation.'],'limitations':limitations,'references':references},
    }
    if kind in strict:requirement['applicability']={'capability':'strict_native_api_policy'}
    if new_id not in known:
        catalog['requirements'].append(requirement);known[new_id]=requirement
        ledger['identities'].append({'id':new_id,'allocation_key':key,'revision':1,'criterion':criterion,'verdict':'accepted_scoped_criterion','reviewer':'source-automation-implementation','limitations':limitations,'obligation_count':1,'alignments':[],'family':'magebean'})
    profile_ids=['hardening']
    if any('owasp-top-10-2025' in back[r['backlog_id']]['previous_profiles'] for r in source_rows):profile_ids.append('owasp-top-10-2025')
    for profile_id in profile_ids:
        profile=profiles['profiles'][profile_id]
        if new_id not in profile['requirement_ids']:profile['requirement_ids'].append(new_id)
    for row in source_rows:row['new_id']=new_id
    added.append({'id':new_id,'kind':kind,'strict_policy_gate':kind in strict,'source_backlog_ids':[r['backlog_id'] for r in source_rows],'profiles':profile_ids})
aggregate['requirements']=catalog['requirements']+read(base/'asvs-catalog.json')['requirements']+read(base/'pci-catalog.json')['requirements']
counts=ledger['counts'];counts['active_internal_requirements']=len(aggregate['requirements']);counts['historical_allocations']=len(allocation['allocations']);counts['families']['magebean']=len(catalog['requirements']);counts['accepted_scoped_criteria']=sum(r.get('review_state')=='accepted_scoped_criterion' for r in aggregate['requirements']);counts['human_evidence_required']=sum(bool(r.get('human_evidence',{}).get('required')) for r in aggregate['requirements'])
for name,value in [('magebean-catalog.json',catalog),('internal-catalog.json',aggregate),('allocation-manifest.json',allocation),('reconciliation-ledger.json',ledger),('internal-profiles.json',profiles)]:write(base/name,value)
write(root/'docs/archive/automation-feasibility/source-implementation.json',rows)
write(root/'docs/archive/automation-feasibility/source-catalog-integration.json',{'added':added,'catalog_counts':counts,'profile_counts':{k:len(v['requirement_ids']) for k,v in profiles['profiles'].items()}})
print(json.dumps({'added':added,'profile_counts':{k:len(v['requirement_ids']) for k,v in profiles['profiles'].items()},'next_id':allocation['next_id']},indent=2))
