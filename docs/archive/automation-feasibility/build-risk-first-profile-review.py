"""Inventory-level review of every current Magebean profile member, not detector correctness certification."""
import json,csv,collections
from pathlib import Path
root=Path(__file__).resolve().parents[3]
base=Path(__file__).parent
catalog=json.loads((root/'src/Rules/requirements/magebean-catalog.json').read_text())['requirements']
profiles=json.loads((root/'src/Rules/requirements/internal-profiles.json').read_text())['profiles']
names=['basic','hardening','owasp-top-10-2025']
index={r['id']:r for r in catalog}
ids=sorted(set().union(*(set(profiles[n]['requirement_ids']) for n in names)))
assert len(ids)==79 and set(ids)==set(profiles['hardening']['requirement_ids'])
signals={'MB-0014','MB-0029','MB-0072','MB-0730',*[f'MB-{n:04}' for n in range(786,799)]}
metadata={'MB-0057','MB-0059','MB-0061','MB-0062','MB-0063','MB-0069'}
policies={'MB-0006','MB-0065','MB-0066','MB-0067','MB-0070','MB-0805','MB-0806'}
notes={
'MB-0006':'Common Admin route is an exposure/hygiene signal; high severity alone must not imply an authorization bypass. Pair with observed protection context.',
'MB-0007':'Native MFA declaration is useful configuration evidence. Critical severity needs exposure/provider/enforcement context; do not claim all login paths enforce MFA.',
'MB-0014':'Direct superglobal access is a coding signal, not proof of injection. Match only real tokens, identify file/line and distinguish legitimate SERVER/context reads.',
'MB-0029':'Literal HTTP assets are mixed-content candidates; output/use and actual page context determine impact.',
'MB-0049':'Advisory match is actionable; severity should follow the matched advisory and affected version, not only static critical requirement severity. Lock metadata is not installed-byte attestation.',
'MB-0050':'Security patch gap is actionable when product/version/release coverage is complete. Prioritize using the relevant bulletin rather than blanket critical.',
'MB-0055':'Overlaps MB-0049; correlate by package/version/advisory to avoid duplicate tickets while retaining requirement mappings.',
'MB-0056':'Constraint incompatibility explains remediation difficulty; correlate with the original advisory instead of generating an unrelated exploit finding.',
'MB-0059':'Advisory age is prioritization metadata; a recent vulnerability must not look safe merely because it is younger than 30 days. Avoid an independent vulnerability ticket for age alone.',
'MB-0062':'Latest-release recency is a maintenance signal; old stable releases may still be supported. Explain provider freshness and avoid a proven-vulnerability claim.',
'MB-0063':'Repository availability/activity is a supply-chain signal, not proof of installed code exploitability or vendor support.',
'MB-0065':'Wildcard constraints concern future dependency resolution policy; deployed lockfile risk needs separate advisory/version evidence. Review high severity.',
'MB-0066':'Dev constraints are risk indicators; pinned commit/package context matters. Review blanket high severity.',
'MB-0067':'prefer-stable is dependency-resolution policy, not a production vulnerability by itself. Review blanket high severity.',
'MB-0069':'Not latest is a maintenance signal, not automatically vulnerable. Include compatible security fix/version context.',
'MB-0072':'Secret-pattern matches need redacted location/type evidence, confidence and historical-versus-deployed distinction; a regex match does not establish a live credential. Correlate MB-0730.',
'MB-0730':'Working-tree secret patterns are valuable candidates; never retain matched values. Correlate VCS duplicates and distinguish example/test/disabled values.',
'MB-0780':'Executable filename is useful risk evidence but not proof server executes it. Correlate file/path with MB-0800.',
'MB-0781':'Successful sensitive-path responses need content/type fingerprint and endpoint context; a generic HTTP200 error page is not confirmed data exposure.',
'MB-0786':'Named query/exec receiver may not be a database; literal arguments do not prove binding or absence of SQL injection. Keep strict policy optional; report observed construct as candidate.',
'MB-0787':'Unconditional validateForCsrf acceptance is useful review evidence; bind to actual controller/interface/route before claiming a request can bypass protection.',
'MB-0788':'Native network primitives include file_get_contents local reads. It is an optional coding policy signal, not proof of SSRF.',
'MB-0789':'Native unserialize call is a useful sink signal; impact depends on input control, options and reachable classes. Do not demand replacement solely to silence a safe use.',
'MB-0790':'Shell/process calls need input/reachability context; they are not automatically command injection. Retain file/line and safe remediation.',
'MB-0791':'eval/create_function constructs are useful dynamic execution candidates; reachability and argument control determine risk.',
'MB-0792':'Filesystem API use is normal in Magento. Keep optional policy; distinguish path control and scope before suggesting a traversal vulnerability.',
'MB-0793':'move_uploaded_file does not itself bypass upload validation; show the sink and ask to inspect validation/filename/storage/execution policy.',
'MB-0794':'Weak PRNG calls matter in security-sensitive use. Nonsecurity randomization must not be described as a token vulnerability.',
'MB-0795':'Direct request logging is useful disclosure-risk evidence. Do not delete required audit events; redact/minimize relevant fields. Correlate broad superglobal findings.',
'MB-0796':'Raw hash/crypto/session API calls can be legitimate. Keep optional policy; identify security purpose and options before changing them.',
'MB-0797':'XML external-feature syntax is useful candidate evidence; input trust, resolver and runtime parser settings determine exploitability.',
'MB-0798':'Standalone HTTP strings include documentation/local references; keep optional policy and establish actual endpoint use before claiming insecure transport.',
'MB-0799':'Matched worker effective-access observation is useful; report unsupported identity as collection gap, not security suspicion. Does not inventory all workers automatically.',
'MB-0800':'PHP/handler signatures are useful suspicious-file candidates. False positives and execution configuration need triage; correlate MB-0780.',
'MB-0801':'Unexpected direct global ACL grant is an observed policy violation; full business least privilege is not proven.',
'MB-0802':'Strict checkout CSP baseline may reject deliberately used sources. Distinguish observed header policy deviation from demonstrated XSS; correlate MB-0779 without hiding distinct directives.',
'MB-0804':'Integration debug flag default-scope observation is useful but not every store/worker runtime. Missing input is a collection gap.',
'MB-0805':'Source/revision mismatch is a supply-chain policy deviation, not proof of malicious package. Missing baseline is collection context.',
'MB-0806':'Record structure/expiry belongs to operational readiness, not proof a mitigation is applied or ineffective. Consider readiness lane or supplement the original vulnerability.',
'MB-0807':'Loaded Xdebug binary is useful production-risk evidence; it does not prove remote debugging is enabled or exploitable.',
}
rows=[]
for rid in ids:
 r=index[rid]
 kind='RUNTIME_OR_CONFIGURATION_RISK'
 if r.get('lane')=='readiness':kind='OPERATIONAL_READINESS'
 elif rid in signals:kind='SOURCE_RISK_CANDIDATE'
 elif rid in metadata:kind='MAINTENANCE_OR_PRIORITY_SIGNAL'
 elif rid in policies:kind='POLICY_OR_RECORD_DEVIATION'
 note=notes.get(rid,'Useful scoped production observation. Keep concrete target/config/path evidence and requirement-specific remediation; distinguish the exact observed deviation from exploitability.')
 if kind=='OPERATIONAL_READINESS':note='Keep as operational readiness; '+note+' Do not label availability/performance symptoms as confirmed security vulnerabilities.'
 checks=[dict(name=c['name'],args=c.get('args',{})) for c in r['checks']]
 rows.append(dict(id=rid,title=r['title'],profiles=[n for n in names if rid in profiles[n]['requirement_ids']],current_severity=r['severity'],current_lane=r.get('lane'),proposed_triage_kind=kind,check_bindings=checks,capability=r.get('applicability',{}).get('capability'),human_required=r.get('human_evidence',{}).get('required',False),has_remediation=len(r.get('remediation',[]))>=3,has_triage_guidance=bool(r.get('finding_guidance',{}).get('triage')),has_verification_guidance=bool(r.get('finding_guidance',{}).get('verification')),current_proof_types=sorted({o.get('proof','') for o in r.get('obligations',[])}),review_note=note,implementation_changed=False))
assert len(rows)==len({r['id'] for r in rows})==79
assert all(not r['human_required'] and r['has_remediation'] and r['has_triage_guidance'] and r['has_verification_guidance'] for r in rows)
summary={n:dict(inventory=len(profiles[n]['requirement_ids']),classification_counts=dict(collections.Counter(r['proposed_triage_kind'] for r in rows if n in r['profiles'])),capability_bound=sum(bool(r['capability']) for r in rows if n in r['profiles'])) for n in names}
out=dict(date='2026-10-18',scope='All current Magebean profile requirement definitions, check bindings, guidance presence and shared result pipeline; no production assessment or exhaustive detector correctness test',unique_requirements=79,profile_summary=summary,unique_classification_counts=dict(collections.Counter(r['proposed_triage_kind'] for r in rows)),all_guidance_present=True,result_pipeline_supports_separate_risk_signal=False,requirements=rows)
(base/'risk-first-profile-review.json').write_text(json.dumps(out,indent=2,ensure_ascii=False)+'\n')
with (base/'risk-first-profile-review.csv').open('w',newline='') as f:
 w=csv.writer(f);w.writerow(['id','profiles','title','severity','lane','proposed_triage_kind','capability','review_note'])
 for r in rows:w.writerow([r['id'],','.join(r['profiles']),r['title'],r['current_severity'],r['current_lane'],r['proposed_triage_kind'],r['capability'],r['review_note']])
print(json.dumps(dict(unique_requirements=79,profiles=summary,categories=out['unique_classification_counts']),indent=2))
