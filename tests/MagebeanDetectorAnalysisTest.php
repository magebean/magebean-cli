<?php
declare(strict_types=1);

require __DIR__.'/../vendor/autoload.php';

use Magebean\Agent\AgentResultMapper;
use Magebean\Console\FindingsConsoleRenderer;
use Magebean\Engine\Checks\CheckRegistry;
use Magebean\Engine\MagebeanDetectorAnalysis;
use Magebean\Engine\Reporting\JsonReporter;
use Magebean\Engine\Reporting\SarifReporter;
use Magebean\Engine\{ScanContext, ScanExitPolicy, ScanPlan, ScanPlanner, ScanReportAssembler, ScanRequest, ScanService};
use Symfony\Component\Console\Output\BufferedOutput;

function assertDetector(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

$context = new ScanContext(sys_get_temp_dir(), '');
$base = (new ScanPlanner())->planCli(new ScanRequest($context, ['rules' => 'MB-0014']), CheckRegistry::fromContext($context->toLegacy()));
$rule = $base->pack['rules'][0];
$rule['checks'] = [['name' => 'fixture_detector', 'args' => []]];
$rule['obligations'] = [['id' => 'O001', 'proof' => 'heuristic', 'role' => 'mandatory', 'op' => 'all', 'checks' => $rule['checks']]];
$plan = new ScanPlan($base->request, array_replace($base->pack, ['rules' => [$rule]]), $base->metadata);
$sample = [
    'key' => 'request-sink', 'message' => 'Request value reaches a sensitive operation',
    'confidence' => 'suspected', 'category' => 'security', 'severity' => 'high',
    'reasoning' => 'The configured guard was not recognized.',
    'remediation' => 'Verify the guard before reading the record.',
    'locations' => [['file' => 'app/code/Vendor/Module/Controller.php', 'line' => 7]],
    'subject' => ['module' => 'Vendor_Module', 'area' => 'frontend', 'package' => 'vendor/module'],
    'assumptions' => ['Custom guards may apply.', 'token="fixture secret value"'],
    'source' => 'unrestricted source should never be carried',
];
$confirmed = array_replace($sample, ['key' => 'invalid-reference', 'confidence' => 'confirmed', 'category' => 'correctness', 'severity' => 'medium']);
$info = array_replace($sample, ['key' => 'route-discovered', 'message' => 'Route discovered', 'category' => 'informational', 'confidence' => 'informational', 'severity' => 'info']);
$gap = ['message' => 'Could not parse a required file', 'action' => 'Inspect the parser diagnostics.'];
$many = [];
for ($line = 1; $line <= 101; $line++) $many[] = array_replace($sample, ['locations' => [['file' => 'Example.php', 'line' => $line]]]);

foreach ([
    'clean' => [[], [], 0, 0],
    'suspected' => [[$sample, $sample], [], 1, 1],
    'partial' => [[$sample, $confirmed], [$gap], 3, 2],
    'informational' => [[$info], [], 0, 0],
    'truncated' => [$many, [], 1, 100],
] as $case => [$findings, $gaps, $exit, $expected]) {
    $registry = new CheckRegistry();
    $registry->register('fixture_detector', fn() => MagebeanDetectorAnalysis::result('fixture-flow', '1.0', $findings, $gaps, ['Explicit fixture suppression']));
    $raw = (new ScanService())->run($plan, null, $registry);
    $result = (new ScanReportAssembler())->assemble($raw, $plan)->toLegacy();
    $risk = $result['findings'][0]['risk_observation'];
    assertDetector($result['findings'][0]['status'] === 'UNKNOWN', 'Detector analysis does not claim conformance');
    assertDetector(count($risk['findings']) === $expected, 'Observations are scoped, deduplicated and bounded: '.$case);
    assertDetector($risk['collection_complete'] === ($gaps === []), 'Completeness is independent of finding count and truncation');
    assertDetector((new ScanExitPolicy())->code($result) === $exit, 'Exit code distinguishes collection gaps from successful detection');
    assertDetector($risk['detector_runs'][0]['suppressed_count'] === 1, 'Suppression metadata is visible');
    $output = new BufferedOutput();
    (new FindingsConsoleRenderer())->render($output, $result, $context->path);
    $cli = $output->fetch();
    assertDetector(str_contains($cli, '1 suppressed'), 'CLI shows suppressions even without a finding');
    if ($case === 'partial') {
        assertDetector(str_contains($cli, 'Suspected') && str_contains($cli, 'Confirmed') && str_contains($cli, $gap['message']), 'CLI shows confidence and gaps');
        assertDetector($result['summary']['detector_findings_by_category'] === ['security' => 1, 'correctness' => 1], 'Category totals remain independent');
    }
    $wire = (new AgentResultMapper())->map($raw->toLegacy(), [], ['MB-0014' => ['assessment_item_id' => 'fixture']], [], $context->path);
    $transmitted = $wire['results'][0]['evidence']['risk_observation'];
    assertDetector($transmitted == $risk, 'Agent keeps the full additive envelope, including the 51–100 row range');
    $file = tempnam(sys_get_temp_dir(), 'mb-detector-');
    try {
        (new JsonReporter())->write($result, $file);
        $json = file_get_contents($file);
        assertDetector(!str_contains($json, 'fixture secret value') && !str_contains($json, $sample['source']), 'Unrestricted source and named credentials are excluded');
        assertDetector(json_decode($json, true, 512, JSON_THROW_ON_ERROR)['findings'][0]['risk_observation'] === $risk, 'JSON preserves the envelope');
        (new SarifReporter())->write($result, $file);
        $sarif = json_decode(file_get_contents($file), true, 512, JSON_THROW_ON_ERROR)['runs'][0];
        assertDetector(count($sarif['results']) === $expected + ($case === 'informational' ? 1 : 0), 'SARIF results contain findings and information only');
        assertDetector(count($sarif['invocations'][0]['toolExecutionNotifications']??[])===count($gaps),'SARIF keeps independent collection notifications');
        assertDetector($sarif['properties']['magebean_detector_runs'][0]['detector_runs'][0]['suppressed_count'] === 1, 'SARIF retains suppression metadata');
        if ($case === 'partial') {
            assertDetector($sarif['results'][0]['locations'][0]['physicalLocation']['region']['startLine'] === 7, 'SARIF carries source location');
            assertDetector(array_column(array_column($sarif['results'], 'properties'), 'confidence') === ['suspected', 'confirmed'], 'SARIF retains both confidence levels');
        }
    } finally {
        unlink($file);
    }
}
echo "Magebean detector analysis pipeline passed\n";
