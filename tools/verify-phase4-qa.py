#!/usr/bin/env python3
"""Re-run original synthetic QA fixtures, adding captured risk envelopes without changing archived evidence."""
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'docs/archive/current-state/phase4'
BUILD = ROOT / 'build'
OUT.mkdir(exist_ok=True)
BUILD.mkdir(exist_ok=True)
probes = {}
for name, source in [('overlap', 'tools/qa-current-state-overlaps.php'), ('middle', 'tools/probe-current-state-middle38.php')]:
    code = (ROOT / source).read_text()
    if name == 'overlap':
        marker = "'collection_complete'=>$risk['collection_complete']"
    else:
        marker = "'needs_attention'=>$risk['needs_attention']"
    assert marker in code
    code = code.replace(marker, marker + ", 'risk_observation'=>$risk, 'title'=>$r['title'], 'severity'=>$r['severity']")
    path = BUILD / ('phase4-' + name + '-probe.php')
    path.write_text(code)
    run = subprocess.run(['php', str(path)], cwd=ROOT, capture_output=True, text=True, check=True)
    data = json.loads(run.stdout)
    (OUT / (name + '-probes.json')).write_text(json.dumps(data, indent=2) + '\n')
    probes[name] = data['results']

grouper = BUILD / 'phase4-group.php'
grouper.write_text("<?php require __DIR__.'/../vendor/autoload.php'; $rows=json_decode(stream_get_contents(STDIN),true,512,JSON_THROW_ON_ERROR); echo json_encode(\\Magebean\\Engine\\MagebeanIssueCorrelation::group($rows),JSON_THROW_ON_ERROR);".replace('\\\\', '\\'))
acceptance = json.loads((ROOT / 'docs/archive/current-state/phase0/acceptance.json').read_text())['cases']
cases = {c['id']: c for c in acceptance if c['phase'] == 4}
pairs = [('CS-033', 'CS-034', 'template-output-encoding'), ('CS-035', 'CS-036', 'admin-password-minimum'),
         ('CS-044', 'CS-045', 'upload-script-artifact'), ('CS-046', 'CS-047', 'source-command-call'),
         ('CS-048', 'CS-049', 'source-request-logging')]
results = []
for first, second, family in pairs:
    entries = []
    for key in [first, second]:
        case = cases[key]
        name = 'overlap' if 'overlap' in case['source_file'] else 'middle'
        entries.append(probes[name][case['source_index']])
    run = subprocess.run(['php', str(grouper)], input=json.dumps(entries), cwd=ROOT, capture_output=True, text=True, check=True)
    issues = json.loads(run.stdout)
    assert len(issues) == 1 and issues[0]['issue_family'] == family, (first, second)
    assert issues[0]['correlation_status'] == 'evidence_identity'
    assert set(issues[0]['rule_ids']) == {row['id'] for row in entries}
    results.append({'acceptance_ids': [first, second], 'rules': issues[0]['rule_ids'], 'raw_assessment_count': 2,
                    'canonical_issue_count': 1, 'issue_family': family, 'issue_id': issues[0]['issue_id'],
                    'contributor_count': len(issues[0]['contributors']), 'passed': True})
(OUT / 'acceptance-results.json').write_text(json.dumps({'phase': 4, 'scope': 'Fresh original synthetic QA fixtures; inert sample PHP is parsed, never executed.',
    'qa_observations': len(cases), 'pairs': results}, indent=2) + '\n')
assert len(cases) == 10
print('Phase 4 QA acceptance: 10 original observations -> 5 evidence-correlated issues; per-rule assessments preserved.')
