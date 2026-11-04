<?php

declare(strict_types=1);

namespace Magebean\Engine\Reporting;

final class SarifReporter implements Reporter
{
    public function write(array $result, string $outFile): void
    {
        $runs = [];
        $detectorRuns = [];
        foreach ($result['findings'] ?? [] as $f) {
            if (is_array($f['risk_observation'] ?? null)) {
                array_push($runs, ...self::observations($f));
                $risk = $f['risk_observation'];
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
        $sarif = ['version' => '2.1.0', 'runs' => [['tool' => ['driver' => ['name' => 'magebean-cli']], 'results' => $runs]]];
        if ($detectorRuns !== []) $sarif['runs'][0]['properties']['magebean_detector_runs'] = $detectorRuns;
        file_put_contents($outFile, json_encode($sarif, JSON_PRETTY_PRINT));
    }

    private static function observations(array $finding): array
    {
        $risk = $finding['risk_observation'];
        $results = [];
        $observations = array_merge($risk['findings'], $risk['observations'] ?? []);
        foreach ($risk['collection_gaps'] as $gap) {
            $represented = array_filter($observations, static fn(array $row): bool =>
                ($row['kind'] ?? '') === 'collection_issue' && $row['check'] === $gap['check']);
            if ($represented === []) $observations[] = $gap + ['kind' => 'collection_issue'];
        }
        foreach ($observations as $row) {
            $kind = $row['kind'];
            $severity = $kind === 'collection_issue' ? 'info' : ($row['severity'] ?? $finding['severity'] ?? 'info');
            $properties = array_intersect_key($row, array_flip(['kind', 'category', 'confidence', 'detector', 'detector_version', 'issue_key', 'evidence', 'collection_guidance']));
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
            foreach ($row['evidence']['locations'] ?? [] as $location) {
                if (empty($location['file'])) continue;
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
