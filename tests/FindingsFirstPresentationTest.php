<?php
declare(strict_types=1);
require __DIR__ . '/../vendor/autoload.php';
use Magebean\Engine\Checks\AutomatedSourcePolicyCheck;
use Magebean\Engine\Context;
use Magebean\Console\ScanConsoleRenderer;
use Magebean\Engine\Reporting\HtmlReporter;
use Symfony\Component\Console\Output\BufferedOutput;
$root = sys_get_temp_dir() . '/magebean-risk-presentation-' . bin2hex(random_bytes(6)); mkdir($root . '/app/code', 0777, true);
$n = 0; $assert = static function(bool $v, string $m) use (&$n): void { $n++; if (!$v) throw new RuntimeException($m); };
$observation = static function(bool $attention, array $findings = [], array $gaps = []): array { return ['schema_version' => 1, 'needs_attention' => $attention, 'findings' => $findings, 'collection_gaps' => $gaps, 'collection_complete' => $gaps === [], 'assessment_outcome' => $attention ? 'FAIL' : ($gaps ? 'UNKNOWN' : 'PASS')]; };
try {
    file_put_contents($root . '/app/code/unsafe.php', '<?php unserialize($input);');
    $actual = (new AutomatedSourcePolicyCheck(new Context($root, '')))->run(['kind' => 'native_unserialize', 'paths' => ['app/code']])->toLegacy();
    $assert($actual[0] === false, 'Fixture supplies a real observed source-policy candidate');
    $risk = ['id' => 'MB-risk', 'title' => 'Source candidate <script>alert(1)</script>', 'severity' => 'high', 'passed' => false, 'status' => 'UNKNOWN', 'risk_observation' => $observation(true, [['check' => 'automated_source_policy', 'message' => 'Native unserialize reference requires attention', 'reason_code' => 'source_candidate', 'evidence' => $actual[2]]], [['check' => 'inventory', 'message' => 'Another subtree unavailable']]), 'remediation' => ['Use the supported serializer after validating the data contract.'], 'requirement' => ['lane' => 'security', 'finding_guidance' => ['interpretation' => 'A reference is a candidate; runtime exploitability is not established.', 'verification' => ['Run isolated serializer regression tests.']]]];
    $gap = ['id' => 'MB-gap', 'title' => 'Unavailable source subtree', 'status' => 'ERROR', 'passed' => false, 'risk_observation' => $observation(false, [], [['check' => 'inventory', 'message' => 'Source file unreadable']])];
    $clean = ['id' => 'MB-clean', 'title' => 'Clean check must remain hidden', 'status' => 'PASS', 'passed' => true, 'risk_observation' => $observation(false)];
    $result = ['meta' => ['findings_first' => true, 'automation_only' => true, 'rules_filter' => ['MB-clean'], 'profile' => ['title' => 'Hardening']], 'summary' => ['total' => 3, 'passed' => 1, 'failed' => 0, 'needs_attention' => 1, 'path' => $root], 'findings' => [$risk, $gap, $clean], 'risk_findings' => [$risk, $clean], 'collection_issues' => [$gap], 'coverage_summary' => ['inventory' => 4, 'executed' => 3, 'not_evaluated' => 1, 'unresolved' => 2, 'assessment_complete' => false], 'not_evaluated_requirements' => [['id' => 'MB-omitted', 'title' => 'Omitted contextual observation', 'reason_code' => 'capability_not_declared']]];
    $render = static function(array $data) use ($root): array {
        $out = new BufferedOutput(); (new ScanConsoleRenderer())->renderPrettySummary($out, $data, $root);
        $file = $root . '/report.html'; (new HtmlReporter(__DIR__ . '/../resources/report-template.html', true))->write($data, $file);
        return [$out->fetch(), (string)file_get_contents($file)];
    };
    [$text, $html] = $render($result);
    foreach ([$text, $html] as $format) {
        $assert((str_contains($format, 'need attention') || str_contains($format, 'Needs attention')) && str_contains($format, 'Scan collection issues'), 'Risk work and collection gaps have separate summary labels');
        $assert(str_contains($format, 'MB-risk') && str_contains($format, 'Native unserialize reference'), 'Candidate observation is shown despite wire UNKNOWN');
        $assert(!str_contains($format, 'MB-clean') && !str_contains($format, 'Clean check must remain hidden'), 'Clean rows never become findings even with explicit rules filter');
        $assert(str_contains($format, 'Source file unreadable'), 'Pure collection gap is separately actionable');
        $assert(str_contains($format, 'Remediation guidance') && str_contains($format, 'supported serializer'), 'Actionable remediation is retained');
        $assert(!str_contains($format, 'Confirmed findings') && !str_contains($format, 'INCONCLUSIVE') && !str_contains($format, '[FAIL]'), 'No assertion-style wire badges in findings-first report');
        $assert(str_contains($format, 'MB-omitted') === ($format === $html), 'Omitted IDs remain in HTML but are hidden from CLI output');
    }
    $collectionResult = $result;
    $collectionResult['risk_findings'][0]['risk_observation']['findings'][0]['kind'] = 'collection_issue';
    $collectionResult['risk_findings'][0]['risk_observation']['findings'][0]['evidence']['collection_guidance']['action'] = 'Repair certificate trust from an approved source.';
    $collectionResult['collection_issues'][0]['collection_guidance']['action'] = 'Restore readable source permissions.';
    [$collectionDetails] = $render($collectionResult);
    $assert(str_contains($collectionDetails, 'Repair certificate trust') && str_contains($collectionDetails, 'Restore readable source permissions'), 'Explicit rules retain both kinds of collection guidance');
    $collectionResult['meta']['rules_filter'] = [];
    [$collectionOverview] = $render($collectionResult);
    $assert(!str_contains($collectionOverview, 'How to resolve') && !str_contains($collectionOverview, 'Repair certificate trust') && !str_contains($collectionOverview, 'Restore readable source permissions'), 'Overview hides collection remediation in findings and separate issues');
    $confidenceResult = $result;
    $confidenceResult['risk_findings'][0]['risk_observation']['findings'][0]['confidence'] = 'confirmed';
    [$confidenceDetails] = $render($confidenceResult);
    $assert(str_contains($confidenceDetails, 'Confirmed'), 'Explicit rules show observation confidence');
    $confidenceResult['meta']['rules_filter'] = [];
    [$confidenceOverview] = $render($confidenceResult);
    $assert(!str_contains($confidenceOverview, 'Confirmed'), 'Overview hides observation confidence');
    $overview = $result; $overview['meta']['rules_filter'] = [];
    [$overviewText, $overviewHtml] = $render($overview);
    $assert(!str_contains($overviewText, 'Remediation guidance') && !str_contains($overviewText, 'supported serializer'), 'Overview hides remediation until --rules selects details');
    $assert(str_contains($overviewText, 'Native unserialize reference') && str_contains($overviewText, '--rules=MB-risk'), 'Overview retains issues and the details command');
    $anotherRisk = $risk; $anotherRisk['id'] = 'MB-second';
    $overview['risk_findings'][] = $anotherRisk;
    [$multipleText] = $render($overview);
    $assert(substr_count($multipleText, 'scan --profile=') === 1 && !str_contains($multipleText, 'Details:'), 'One shared details command replaces repeated per-issue hints');
    $assert(strpos($multipleText, '--rules=MB-risk') > strpos($multipleText, 'Source file unreadable'), 'Shared details guidance follows findings and collection issues');
    $assert(!str_contains($text, 'For issue details and remediation'), 'Explicit rule details omit the overview hint');
    $assert(str_contains($overviewHtml, 'Remediation guidance'), 'HTML export keeps remediation independently of CLI detail selection');
    $assert(str_contains($html, '&lt;script&gt;alert(1)&lt;/script&gt;') && !str_contains($html, '<script>alert(1)</script>'), 'HTML escapes finding data');
    $cleanResult = $result; $cleanResult['risk_findings'] = []; $cleanResult['collection_issues'] = []; $cleanResult['summary']['needs_attention'] = 0;
    [$cleanText, $cleanHtml] = $render($cleanResult);
    foreach ([$cleanText, $cleanHtml] as $format) $assert(str_contains($format, 'No risk observations requiring attention were collected.') && !str_contains($format, 'MB-risk'), 'Empty risk list is honestly reported without clean findings');
    $legacy = $result; $legacy['meta']['findings_first'] = false; $legacy['meta']['rules_filter'] = []; $legacy['meta']['automation_only'] = false; $legacy['findings'] = [$clean];
    [$legacyText, $legacyHtml] = $render($legacy);
    $assert(str_contains($legacyText, 'Passed') && str_contains($legacyText, 'Confirmed findings'), 'Legacy and standards console presentation remains unchanged');
    $assert(str_contains($legacyHtml, 'MB-clean') && str_contains($legacyHtml, 'PASS'), 'Legacy HTML preserves check result rows');
    echo "Findings-first presentation: $n assertions passed\n";
} finally { foreach (glob($root . '/app/code/*') ?: [] as $file) unlink($file); if (is_file($root . '/report.html')) unlink($root . '/report.html'); rmdir($root . '/app/code'); rmdir($root . '/app'); rmdir($root); }

