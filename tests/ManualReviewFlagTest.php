<?php

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use Magebean\Application;
use Magebean\Engine\RequirementCatalog;
use Symfony\Component\Console\Tester\CommandTester;

function assertManualFlag(bool $condition, string $message): void
{
    if (!$condition) {
        fwrite(STDERR, $message . "\n");
        exit(1);
    }
}

$asvsManualId = RequirementCatalog::resolveAlias('OWASP-ASVS:5.0.0:1.1.1')[0];
$pciHuman = array_values(array_filter(RequirementCatalog::forProfile('pci')['rules'], static fn(array $r): bool => ($r['verification'] ?? '') === 'manual'))[0]['id'];
$app = new Application();
$command = $app->find('rules:list');

$default = new CommandTester($command);
$default->execute(['--profile' => 'asvs-l2', '--no-ansi' => true]);
$defaultOutput = $default->getDisplay();
assertManualFlag(str_contains($defaultOutput, 'Total Rules Listed: 0'), 'ASVS L2 must list 89 requirements by default');
assertManualFlag(!str_contains($defaultOutput, $asvsManualId), 'Manual rule leaked into default L2 list');

$withManual = new CommandTester($command);
$withManual->execute(['--profile' => 'asvs-l2', '--include-manual-review' => true, '--no-ansi' => true]);
$manualOutput = $withManual->getDisplay();
assertManualFlag(str_contains($manualOutput, 'Total Rules Listed: ' . count(RequirementCatalog::forProfile('asvs-l2')['rules'])), 'ASVS L2 manual flag must list 197 requirements');
assertManualFlag(str_contains($manualOutput, $asvsManualId), 'Manual rule missing when flag is enabled');

$baseline = new CommandTester($command);
$baseline->execute(['--profile' => 'hardening', '--no-ansi' => true]);
assertManualFlag(str_contains($baseline->getDisplay(), 'Total Rules Listed: ' . count(array_filter(RequirementCatalog::forProfile('hardening')['rules'], static fn(array $r):bool => !\Magebean\Engine\RequirementPolicy::requiresHuman($r)))), 'Hardening must exclude manual rules by default');

$baselineManual = new CommandTester($command);
$baselineManual->execute(['--profile' => 'hardening', '--include-manual-review' => true, '--no-ansi' => true]);
assertManualFlag(str_contains($baselineManual->getDisplay(), 'Total Rules Listed: 80'), 'Manual flag cannot enable machine-context-gated requirements or restore human backlog');

$pci = new CommandTester($command);
$pci->execute(['--profile' => 'pci', '--no-ansi' => true]);
assertManualFlag(str_contains($pci->getDisplay(), 'Total Rules Listed: 0'), 'PCI must list32criteria with runnable technical evidence by default');
assertManualFlag(!str_contains($pci->getDisplay(), $pciHuman), 'PCI manual rule leaked without the flag');

$pciManual = new CommandTester($command);
$pciManual->execute(['--profile' => 'pci', '--include-manual-review' => true, '--no-ansi' => true]);
assertManualFlag(str_contains($pciManual->getDisplay(), 'Total Rules Listed: 280'), 'PCI manual flag must list all280independent PCI clauses');
assertManualFlag(str_contains($pciManual->getDisplay(), $pciHuman), 'PCI manual rule is missing with the flag');

echo "ManualReviewFlagTest: PASS\n";
