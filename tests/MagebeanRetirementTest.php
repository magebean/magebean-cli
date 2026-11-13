<?php
declare(strict_types=1);

require __DIR__.'/../vendor/autoload.php';

use Magebean\Engine\Checks\CheckRegistry;
use Magebean\Engine\MagebeanRetirement;
use Magebean\Engine\RequirementCatalog;
use Magebean\Engine\RequirementDefinitionValidator;
use Magebean\Engine\RequirementPolicy;
use Magebean\Engine\ScanContext;
use Magebean\Engine\ScanPlanner;
use Magebean\Engine\ScanRequest;

function retirementAssert(bool $ok, string $message): void
{
    if (!$ok) throw new RuntimeException($message);
}

function expectRetirement(callable $select): void
{
    try {
        $select();
    } catch (RuntimeException $exception) {
        retirementAssert(str_contains($exception->getMessage(), 'was retired'), 'Expected actionable retirement error');
        return;
    }
    throw new RuntimeException('Retired selector was accepted');
}

$archive = RequirementCatalog::read('magebean-retirements')['requirements'];
$active = array_column(RequirementCatalog::loadAll()['rules'], null, 'id');
$allocations = array_column(RequirementCatalog::read('allocation-manifest')['allocations'], null, 'id');
retirementAssert(count($archive) === 60, 'All retired definitions are archived');
foreach ($archive as $definition) {
    $id = $definition['id'];
    retirementAssert($definition['family'] === 'magebean' && RequirementPolicy::requiresHuman($definition), 'Only human-required Magebean definitions retire');
    retirementAssert(isset($allocations[$id]), 'Archive preserves allocation');
    $review = array_column(RequirementCatalog::read('magebean-retirement-review')['requirements'], null, 'id');
    retirementAssert(isset($review[$id]), 'Every archived ID has an evidence-based classification');
    if ($review[$id]['active']) {
        retirementAssert(isset($active[$id]) && $active[$id]['revision'] > $definition['revision'] && !RequirementPolicy::requiresHuman($active[$id]), 'Restored revision is scoped automation');
        retirementAssert(MagebeanRetirement::diagnostic($id) === null, 'Restored selector is executable');
    } else retirementAssert(!isset($active[$id]) && MagebeanRetirement::diagnostic($id) !== null, 'Unqualified broad criterion remains blocked');
}
foreach ($active as $definition) {
    retirementAssert($definition['family'] !== 'magebean' || !RequirementPolicy::requiresHuman($definition), 'Active Magebean catalog is automation-only');
}

$context = new ScanContext(sys_get_temp_dir(), '');
$registry = CheckRegistry::fromContext($context->toLegacy());
$planner = new ScanPlanner();
expectRetirement(fn() => $planner->planCli(new ScanRequest($context, [
    'rules' => 'MB-0001,MB-0004', 'include-manual-review' => true,
]), $registry));
expectRetirement(fn() => RequirementPolicy::resolveIds(['MB-R004']));
retirementAssert(MagebeanRetirement::diagnostic('MB-0103') === null, 'ASVS IDs do not retire based on prefix');
retirementAssert(RequirementDefinitionValidator::validate($archive[0], $registry) !== [], 'An archived criterion cannot be added to an active Magebean pack');

$profile = tempnam(sys_get_temp_dir(), 'mb-retirement-');
try {
    file_put_contents($profile, json_encode(['family' => 'magebean', 'requirement_ids' => ['MB-0004']]));
    expectRetirement(fn() => RequirementCatalog::forProfile($profile));
} finally {
    unlink($profile);
}

echo "Magebean retirement contract passed\n";
