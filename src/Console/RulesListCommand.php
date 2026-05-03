<?php

declare(strict_types=1);

namespace Magebean\Console;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\{InputInterface, InputOption};
use Symfony\Component\Console\Output\OutputInterface;
use Magebean\Engine\RulePackLoader;
use Magebean\Engine\ProfileLoader;

final class RulesListCommand extends Command
{
    protected static $defaultName = 'rules:list';

    protected function configure(): void
    {
        $this->setName('rules:list')
            ->addOption('control', null, InputOption::VALUE_OPTIONAL, 'Comma list of controls (e.g. MB-C01,MB-C02)')
            ->addOption('profile', null, InputOption::VALUE_OPTIONAL, 'Built-in profile alias (owasp|pci) or custom profile JSON path')
            ->addOption('severity', null, InputOption::VALUE_OPTIONAL, 'low|medium|high|critical');
    }
    protected function execute(InputInterface $in, OutputInterface $out): int
    {
        $controlsOpt = (string)($in->getOption('control') ?? '');
        $profileOpt = trim((string)($in->getOption('profile') ?? ''));
        $controls = $controlsOpt ? array_map('trim', explode(',', $controlsOpt)) : [];
        $pack = RulePackLoader::loadAll($controls);
        if ($profileOpt !== '' && !in_array(strtolower($profileOpt), ['baseline', 'all', 'magebean'], true)) {
            $profile = ProfileLoader::load($profileOpt, getcwd() ?: '');
            $pack = ProfileLoader::apply($pack, $profile);
            $out->writeln(sprintf(
                '<info>Profile:</info> %s (%s)',
                (string)($profile['id'] ?? $profileOpt),
                (string)($profile['title'] ?? '')
            ));
        }
        $sev = $in->getOption('severity');
        $count = 0;
        foreach ($pack['rules'] as $r) {
            if ($sev && strcasecmp($r['severity'], (string)$sev) !== 0) continue;
            $mapping = '';
            if (isset($r['profile']['mapping']) && is_array($r['profile']['mapping'])) {
                $m = $r['profile']['mapping'];
                $refs = $m['requirements'] ?? $m['categories'] ?? $m['map'] ?? [];
                if (is_array($refs) && $refs) {
                    $mapping = ' (' . implode(', ', array_map('strval', $refs)) . ')';
                }
            }
            $out->writeln("{$r['id']} [{$r['control']}] {$r['severity']} — {$r['title']}{$mapping}");
            $count++;
        }
        $out->writeln("<info>Total Rules Listed: {$count}</info>");
        return Command::SUCCESS;
    }
}
