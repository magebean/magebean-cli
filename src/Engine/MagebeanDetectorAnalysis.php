<?php
declare(strict_types=1);

namespace Magebean\Engine;

/** A bounded detector result that makes no requirement conformance claim. */
final class MagebeanDetectorAnalysis
{
    public const EVIDENCE_KEY = 'magebean_detector_analysis';
    public const MAX_ROWS = 100;

    /**
     * Detector authors must supply redacted summaries, relative paths and no raw source.
     * Suppression is visible separately and does not change execution completeness.
     */
    public static function result(
        string $detector,
        string $version,
        array $findings = [],
        array $gaps = [],
        array $suppressed = [],
    ): CheckResult {
        if (!preg_match('/^[a-zA-Z0-9_.:-]{1,128}$/D', $detector)
            || !preg_match('/^[a-zA-Z0-9_.+-]{1,64}$/D', $version)) {
            throw new \InvalidArgumentException('Detector identity and version must be stable identifiers.');
        }

        $issues = [];
        foreach (array_slice($findings, 0, self::MAX_ROWS) as $finding) {
            if (!in_array($finding['confidence'] ?? null, ['confirmed', 'suspected', 'informational'], true)
                || !in_array($finding['category'] ?? null, ['security', 'correctness', 'policy', 'informational'], true)
                || !in_array($finding['severity'] ?? null, ['info', 'low', 'medium', 'high', 'critical'], true)) {
                throw new \InvalidArgumentException('Detector findings require valid confidence, category and severity.');
            }
            $key = $finding['key'] ?? '';
            if (!is_string($key) || !preg_match('/^[a-zA-Z0-9_.:-]{1,128}$/D', $key)
                || trim($finding['message'] ?? '') === '' || trim($finding['reasoning'] ?? '') === '') {
                throw new \InvalidArgumentException('Detector findings require a stable issue key, message and reasoning.');
            }
            $locations = [];
            foreach (array_slice($finding['locations'] ?? [], 0, 20) as $location) {
                $file = str_replace('\\', '/', $location['file'] ?? '');
                if ($file === '' || str_starts_with($file, '/') || str_contains($file, ':')
                    || in_array('..', explode('/', $file), true) || preg_match('/[\x00-\x1f]/', $file)) {
                    throw new \InvalidArgumentException('Detector locations must be project-relative.');
                }
                $locations[] = ['file' => self::text($file)] + (isset($location['line']) ? ['line' => max(1, (int) $location['line'])] : [])
                    + (isset($location['byte_offset']) && is_int($location['byte_offset']) && $location['byte_offset']>=0 ? ['byte_offset'=>$location['byte_offset']] : [])
                    + (is_string($location['source_sha256']??null) && preg_match('/^[a-f0-9]{64}$/D',$location['source_sha256']) ? ['source_sha256'=>$location['source_sha256']] : []);
            }
            $subject = [];
            foreach (['module', 'package', 'version', 'area', 'symbol'] as $field) {
                if (isset($finding['subject'][$field])) $subject[$field] = self::text($finding['subject'][$field]);
            }
            $issues[] = [
                'issue_key' => $key,
                'message' => self::text($finding['message'] ?? ''),
                'confidence' => $finding['confidence'],
                'category' => $finding['category'],
                'severity' => $finding['severity'],
                'evidence' => [
                    'subject' => $subject,
                    'locations' => $locations,
                    'reasoning' => self::text($finding['reasoning'] ?? ''),
                    'remediation' => self::text($finding['remediation'] ?? ''),
                    'assumptions' => array_map(self::text(...), array_slice($finding['assumptions'] ?? [], 0, 10)),
                ],
            ];
        }
        $diagnostics = [];
        foreach (array_slice($gaps, 0, self::MAX_ROWS) as $gap) {
            $diagnostics[] = [
                'message' => self::text($gap['message'] ?? ''),
                'reason_code' => 'DETECTOR_COLLECTION_INCOMPLETE',
                'collection_guidance' => ['action' => self::text($gap['action'] ?? '')],
            ];
        }
        $analysis = [
            'detector' => $detector,
            'detector_version' => $version,
            'complete' => $gaps === [],
            'findings' => $issues,
            'gaps' => $diagnostics,
            'suppressed_count' => count($suppressed),
            'suppressions' => array_map(self::text(...), array_slice($suppressed, 0, 20)),
            'findings_truncated' => count($findings) > count($issues),
            'collection_gaps_truncated' => count($gaps) > count($diagnostics),
        ];

        return CheckResult::of(
            CheckOutcome::Unknown,
            $analysis['complete'] ? 'Detector completed its declared analysis.' : 'Detector analysis was incomplete.',
            [self::EVIDENCE_KEY => $analysis],
            $analysis['complete'] ? 'DETECTOR_ANALYSIS_COMPLETE' : 'DETECTOR_COLLECTION_INCOMPLETE',
        );
    }

    private static function text(string $value): string
    {
        $value = preg_replace('/\b(password|token|secret|authorization|cookie)\s*[:=]\s*(?:"[^"]*"|\'[^\']*\'|[^\s,;]+)/i', '$1=[REDACTED]', trim($value)) ?? '';
        if (preg_match('/^.{0,1000}/us', $value, $match) !== 1) {
            throw new \InvalidArgumentException('Detector summaries must be valid UTF-8.');
        }
        return $match[0];
    }
}
