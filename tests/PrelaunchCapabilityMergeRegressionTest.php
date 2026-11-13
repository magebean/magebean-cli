<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';

use Magebean\Engine\{ScanContext, ScanRequest, ScanPlanner, ScanPlan};
use Magebean\Engine\Checks\CheckRegistry;

$root = sys_get_temp_dir().'/mb-prelaunch-capability-'.bin2hex(random_bytes(6));
mkdir($root, 0700);
$n = 0;
$assert = static function (bool $ok, string $message) use (&$n): void {
    ++$n;
    if (!$ok) throw new RuntimeException($message);
};
$plan = static function (array $caps, string $cli = '', string $profile = 'prelaunch') use ($root): ScanPlan {
    file_put_contents($root.'/.magebean.json', json_encode(['capabilities'=>$caps], JSON_THROW_ON_ERROR));
    $context = new ScanContext($root, '', '', ['meta'=>['target_mode'=>'LOCAL', 'launch_profile'=>$profile]]);
    $options = ['profile'=>$profile];
    if ($cli !== '') $options['capabilities'] = $cli;
    $result = (new ScanPlanner())->planCli(new ScanRequest($context, $options), CheckRegistry::fromContext($context->toLegacy()));
    if ($result === null) throw new RuntimeException('Capability fixture did not produce a plan.');
    return $result;
};
try {
    foreach (['prelaunch'=>59, 'development'=>30] as $profile=>$count) {
        $baseline = $plan(['local_advisory_snapshot'], '', $profile);
        $merged = $plan(['local_advisory_snapshot'], 'unrelated_context', $profile);
        $assert(count($baseline->pack['rules']) === $count && count($merged->pack['rules']) === $count, 'CLI additions retain list-form configured advisory capability for '.$profile);
        $assert($merged->metadata['capabilities'] === ($profile==='prelaunch' ? ['dependency_maintenance'=>true, 'local_advisory_snapshot'=>true, 'unrelated_context'=>true] : ['local_advisory_snapshot'=>true, 'unrelated_context'=>true]), 'List and CLI capabilities merge into a canonical map');
        $assert(in_array('MB-0828', array_column($merged->pack['rules'], 'id'), true), 'Advisory membership is not silently removed');
    }
    $disabled = $plan(['LOCAL_ADVISORY_SNAPSHOT'=>false, 'other_context'=>true], 'unrelated_context');
    $assert(count($disabled->pack['rules']) === 58 && $disabled->metadata['capabilities']['local_advisory_snapshot'] === false, 'Unrelated CLI additions preserve explicit false map values');
    $enabled = $plan(['LOCAL_ADVISORY_SNAPSHOT'=>false], 'LOCAL_ADVISORY_SNAPSHOT');
    $assert(count($enabled->pack['rules']) === 59 && $enabled->metadata['capabilities'] === ['dependency_maintenance'=>true, 'local_advisory_snapshot'=>true], 'CLI explicitly enables a configured false capability with canonical lowercase identity');
    $canonical = $plan([' Local_Advisory_Snapshot ', 'LOCAL_ADVISORY_SNAPSHOT'], ' local_ADVISORY_snapshot , OTHER_context ');
    $assert(count($canonical->pack['rules']) === 59 && $canonical->metadata['capabilities'] === ['dependency_maintenance'=>true, 'local_advisory_snapshot'=>true, 'other_context'=>true], 'Whitespace, casing and duplicates cannot change capability identity');
    $map = $plan(['local_advisory_snapshot'=>'off', 'other_context'=>'yes']);
    $assert(count($map->pack['rules']) === 58 && $map->metadata['capabilities'] === ['dependency_maintenance'=>true, 'local_advisory_snapshot'=>false, 'other_context'=>true], 'Map boolean strings retain existing filter-var semantics');
    $defaults = $plan([]);
    $assert(count($defaults->pack['rules']) === 58 && $defaults->metadata['capabilities'] === ['dependency_maintenance'=>true], 'Prelaunch maintenance context is selected by its profile');
    echo "Prelaunch capability merge regression: $n assertions passed\n";
} finally {
    if (is_file($root.'/.magebean.json')) unlink($root.'/.magebean.json');
    rmdir($root);
}
