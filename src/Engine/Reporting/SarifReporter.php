<?php

declare(strict_types=1);

namespace Magebean\Engine\Reporting;

final class SarifReporter implements Reporter
{
    public function write(array $result, string $outFile): void
    {
        $runs = [];
        $detectorRuns = []; $diagnostics=[];
        foreach ($result['findings'] ?? [] as $f) {
            if (is_array($f['risk_observation'] ?? null)) {
                if (!isset($result['canonical_issues'])) array_push($runs, ...self::observations($f));
                else { $information=$f;$information['risk_observation']['findings']=[];array_push($runs,...self::observations($information)); }
                $risk = $f['risk_observation'];
                foreach ($risk['collection_gaps'] as $gap) $diagnostics[]=['level'=>'note','message'=>['text'=>$gap['message']],
                    'descriptor'=>['id'=>$gap['reason_code']??'COLLECTION_INCOMPLETE'],
                    'properties'=>['requirement_id'=>$f['id'],'check'=>$gap['check']??'', 'collection_guidance'=>$gap['collection_guidance']??[]]];
                if (!empty($risk['detector_runs']) || !empty($risk['findings_truncated']) || !empty($risk['collection_gaps_truncated'])) {
                    $detectorRuns[] = ['requirement_id' => $f['id']] + array_intersect_key($risk, array_flip([
                        'detector_runs', 'findings_truncated', 'collection_gaps_truncated', 'collection_complete',
                    ]));
                }
                continue;
            }
            $status = strtoupper((string)($f['status'] ?? 'UNKNOWN'));
            if ($status === 'PASS') continue;
            $properties = ['magebean_status' => $status];
            if (isset($f['requirement'])) {
                $properties['requirement'] = $f['requirement'];
                $properties['alignment'] = $f['alignment'] ?? [];
                $properties['coverage'] = $f['coverage'] ?? null;
                $properties['applicability'] = $f['applicability'] ?? null;
            }
            $runs[] = [
                'ruleId' => (string)$f['id'],
                'level' => $status === 'FAIL' ? 'error' : 'note',
                'message' => ['text' => (string)($f['message'] ?? $f['title'] ?? '')],
                'properties' => $properties,
            ];
        }
        if (isset($result['canonical_issues'])) foreach ($result['canonical_issues'] as $issue) {
            foreach (self::observations($issue) as $observation) {
                $observation['level']=match($issue['severity']) {'critical','high'=>'error','medium','low'=>'warning',default=>'note'};
                $observation['properties']['severity']=$issue['severity'];
                $observation['properties']['canonical_issue_id']=$issue['issue_id'];
                $observation['properties']['related_rule_ids']=$issue['rule_ids'];
                $observation['properties']['assessment_outcomes']=$issue['assessment_outcomes'];
                $observation['properties']['contributors']=$issue['contributors'];
                $observation['partialFingerprints']['magebean/canonical-v1']=$issue['issue_id'];
                $runs[]=$observation;
            }
        }
        $sarif = ['version' => '2.1.0', 'runs' => [['tool' => ['driver' => ['name' => 'magebean-cli']], 'results' => $runs]]];
        if ($diagnostics!==[]) $sarif['runs'][0]['invocations']=[['executionSuccessful'=>false,'toolExecutionNotifications'=>$diagnostics]];
        if ($detectorRuns !== []) $sarif['runs'][0]['properties']['magebean_detector_runs'] = $detectorRuns;
        file_put_contents($outFile, json_encode($sarif, JSON_PRETTY_PRINT));
    }

    private static function observations(array $finding): array
    {
        $risk = $finding['risk_observation'];
        $results = [];
        $observations = array_merge($risk['findings'], $risk['observations'] ?? []);
        foreach ($observations as $row) {
            $kind = $row['kind'];
            $severity = $kind === 'collection_issue' ? 'info' : ($row['severity'] ?? $finding['severity'] ?? 'info');
            $properties = array_intersect_key($row, array_flip(['kind', 'category', 'confidence', 'detector', 'detector_version', 'issue_key', 'evidence', 'collection_guidance', 'claim_type', 'confidence_basis', 'exploitability', 'guidance']));
            $result = [
                'ruleId' => $finding['id'],
                'level' => match ($severity) {
                    'high', 'critical' => 'error',
                    'medium', 'low' => 'warning',
                    default => 'note',
                },
                'message' => ['text' => $row['message']],
                'properties' => $properties + [
                    'severity' => $severity,
                    'magebean_status' => $risk['assessment_outcome'],
                    'collection_complete' => $risk['collection_complete'],
                ],
            ];
            foreach ($row['evidence']['locations'] ?? $row['evidence']['violations'] ?? $row['evidence']['matches'] ?? [] as $location) {
                if (!is_array($location) || !is_string($location['file']??null) || $location['file']===''
                    || str_starts_with($location['file'],'/') || str_contains($location['file'],':')
                    || in_array('..',explode('/',$location['file']),true)) continue;
                $uri = implode('/', array_map('rawurlencode', explode('/', $location['file'])));
                $physical = ['artifactLocation' => ['uri' => $uri]];
                if (!empty($location['line'])) $physical['region'] = ['startLine' => (int) $location['line']];
                $result['locations'][] = ['physicalLocation' => $physical];
            }
            if (isset($row['fingerprint'])) $result['partialFingerprints'] = ['magebean/v1' => $row['fingerprint']];
            $results[] = $result;
        }
        return $results;
    }
}
