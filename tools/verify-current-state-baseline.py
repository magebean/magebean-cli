#!/usr/bin/env python3
"""Validate the QA migration contract; --check-current freezes runtime only in Phase 0."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'docs/archive/current-state/phase0'
def read(path):
    return json.loads(path.read_text())
def check(condition, message):
    if not condition:
        raise SystemExit('FAIL: ' + message)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-current', action='store_true')
    args = parser.parse_args()
    baseline = read(BASE / 'baseline.json')
    acceptance = read(BASE / 'acceptance.json')
    contract = read(BASE / 'finding-contract.json')
    decisions = read(BASE / 'profile-decisions.json')
    ids = [r['id'] for r in baseline['rules']]
    check(len(ids) == len(set(ids)) == 110, '110 distinct reviewed rules')
    check(len(baseline['profiles']) == 14, '14 baseline profiles')
    inactive = {r['id'] for r in baseline['inactive_archive_decisions']}
    check(len(inactive) == 50 and not inactive.intersection(ids), '50 distinct inactive references')
    for path, digest in baseline['protected_files'].items():
        check(hashlib.sha256((ROOT / path).read_bytes()).hexdigest() == digest,
              'Protected standard/archive changed: ' + path)
    cases = acceptance['cases']
    check(len(cases) == acceptance['qa_observation_count'] == 49, '49 QA observations')
    check(len({c['id'] for c in cases}) == 49, 'Unique acceptance IDs')
    coverage = set()
    sources = {}
    for case in cases:
        source = case['source_file']
        data = sources.setdefault(source, read(ROOT / source))
        rows = data.get('observations', data.get('results'))
        key = (source, case['source_index'])
        check(key not in coverage, 'Duplicate QA observation: ' + str(key))
        coverage.add(key)
        original = rows[case['source_index']]
        check(original['case'] == case['case'], 'QA case traceability: ' + case['id'])
        check(set(original.get('rules', [original.get('id')])) == set(case['rules']),
              'QA rule traceability: ' + case['id'])
        check(1 <= case['phase'] <= 6 and bool(case['expected_behavior'].strip()),
              'Actionable phase acceptance: ' + case['id'])
        check(case['status'] == 'planned', 'Baseline must not claim fixes passed')
    check(len(coverage) == sum(len(d.get('observations', d.get('results'))) for d in sources.values()),
          'Every raw QA observation has acceptance coverage')
    extra = acceptance['additional_regressions']
    check(len(extra) == len({c['id'] for c in extra}) == 8, 'Eight distinct additional regression gates')
    restored = {'MB-0043','MB-0093','MB-0731','MB-0733','MB-0736','MB-0739','MB-0740','MB-0741','MB-0742','MB-0744'}
    rows = decisions['decisions']
    check(len(rows) == 10 and {r['id'] for r in rows} == restored, 'All restored rules have profile decisions')
    for row in rows:
        check(row['condition'] and row['profiles'], 'Conditional profile decision: ' + row['id'])
        check(set(row['profiles']) <= set(baseline['profiles']) | {'evidence'}, 'Known or proposed profiles')
    check(decisions['status'] == 'phase5_target_not_current_membership', 'Profile plan is not runtime membership')
    check(contract['phase0_runtime_changes'] is False, 'No Phase 0 runtime migration')
    check(set(contract['categories']) == {'security','correctness','policy','informational'}, 'Category compatibility')
    check(set(contract['confidence']) == {'confirmed','suspected','informational'}, 'Confidence compatibility')
    check(len(contract['finding_quality']) == 6, 'Six finding quality requirements')
    check({'rule_id','collection_timestamp'} <= set(contract['correlation']['excluded_identity_fields']),
          'Stable correlation excludes scanner identity and time')
    if args.check_current:
        current = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                   for p in (ROOT / 'src').rglob('*') if p.is_file()}
        check(current == baseline['source_hashes'], 'Phase 0 production sources unchanged')
    print('PASS: 110-rule baseline; 49/49 QA observations; 8 regression gates; 10 profile decisions; protected definitions' +
          ('; production sources unchanged' if args.check_current else ''))

if __name__ == '__main__':
    main()
