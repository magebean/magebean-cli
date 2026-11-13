"""Merge specialist reviews with exhaustive identity/criterion validation."""
import collections,csv,hashlib,json,re
from pathlib import Path
root=Path(__file__).resolve().parents[3]
out=Path(__file__).resolve().parent
catalog_path=root/'src/Rules/requirements/magebean-catalog.json'
catalog={r['id']:r for r in json.loads(catalog_path.read_text())['requirements']}
backlog=json.loads((root/'src/Rules/requirements/magebean-automation-backlog.json').read_text())['requirements']
verdicts=['FULL_AUTOMATION','SCOPED_AUTOMATION','SIGNAL_ONLY','NOT_AUTOMATABLE']
rows=[]
for file,expected in [('runtime.json',17),('source.json',23),('dependencies.json',10)]:
    data=json.loads((out/file).read_text())
    if isinstance(data,dict):data=data.get('requirements',data.get('reviews',data.get('items',data.get('rows'))))
    assert isinstance(data,list) and len(data)==expected,(file,'partition count')
    for r in data:
        assert r['id'] in catalog and r['criterion']==catalog[r['id']]['criterion'],(file,r['id'],'criterion drift')
        assert r['verdict'] in verdicts,(r['id'],'invalid verdict')
        for field in ['rationale','implementation_evidence','required_inputs','proposed_check','tests','effort','limitations']:
            assert r.get(field),(r['id'],'missing '+field)
        assert isinstance(r['current_ready'],bool),(r['id'],'readiness must be explicit')
        for pointer in r['implementation_evidence']:
            if not isinstance(pointer,str) or pointer.startswith('http'):continue
            if (root/pointer).is_file():continue
            match=re.match(r'(.+?):(?:L)?(\d+)',pointer)
            assert match,(r['id'],'unparseable evidence pointer',pointer)
            file_path=root/match.group(1)
            assert file_path.is_file(),(r['id'],'missing source file',pointer)
            assert 1<=int(match.group(2))<=len(file_path.read_text(errors='replace').splitlines()),(r['id'],'invalid source line',pointer)
        r['review_partition']=file.removesuffix('.json')
        rows.append(r)
assert len(rows)==50 and len({r['id'] for r in rows})==50,'No duplicate identities'
assert {r['id'] for r in rows}=={r['id'] for r in backlog},'Every backlog requirement reviewed'
rows.sort(key=lambda r:int(r['id'][3:]))
counts={v:sum(r['verdict']==v for r in rows) for v in verdicts}
hashes={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [catalog_path,root/'src/Rules/requirements/internal-profiles.json',root/'src/Rules/requirements/magebean-automation-backlog.json',out/'root-probes.json']}
summary={'review_date':'2026-10-17','scope':'All50 Magebean automation backlog requirements; feasibility review, not implemented automation or certification.','counts':counts,'candidate_requirements':counts['FULL_AUTOMATION']+counts['SCOPED_AUTOMATION'],'current_ready':sum(r['current_ready'] for r in rows),'with_related_active_check':sum(bool(r.get('covered_by_active_ids')) for r in rows),'input_sha256':hashes}
(out/'review.json').write_text(json.dumps({'summary':summary,'requirements':rows},indent=2,ensure_ascii=False)+'\n')
with (out/'review.csv').open('w',newline='',encoding='utf-8-sig') as f:
    fields=['id','verdict','current_ready','effort','covered_by_active_ids','proposed_check','required_inputs','rationale','limitations','implementation_evidence']
    writer=csv.DictWriter(f,fieldnames=fields);writer.writeheader()
    for r in rows:writer.writerow({k:json.dumps(r.get(k),ensure_ascii=False) if isinstance(r.get(k),(list,dict)) else r.get(k) for k in fields})
print(json.dumps(summary,indent=2))
