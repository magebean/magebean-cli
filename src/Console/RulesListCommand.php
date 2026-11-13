<?php

declare(strict_types=1);

namespace Magebean\Console;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\{InputInterface, InputOption};
use Symfony\Component\Console\Output\OutputInterface;
use Magebean\Engine\RequirementCatalog;

final class RulesListCommand extends Command
{
    protected static $defaultName = 'rules:list';

    private const HELP = <<<'HELP'
List Magebean requirements after applying a profile and optional control/severity filters.

PROFILES
  basic      Default production-readiness requirements.
  asvs-l1    ASVS level 1 requirements.
  asvs-l2    ASVS levels 1 and 2 requirements.
  asvs-l3    ASVS levels 1, 2, and 3 requirements.
  owasp      Application requirements tagged with OWASP Top 10 categories.
  pci        PCI DSS requirement evidence and human verification obligations.
  hardening  Production hardening requirements.
  development Offline source/config checks; online maintenance is opt-in.
  prelaunch  Source/deployment checks including online library maintenance.
  takeover   Current technical risks and maintenance scope for handover.
  evidence   Opt-in document/record lint, not technical security assurance.
  FILE       Custom profile JSON selecting requirement IDs.

Context: log_rotation_config enables supplied logrotate checks.
cache_backend_policy selects a strict backend baseline (default in hardening).
Explicit false project capabilities override profile defaults.

Counts are calculated from the selected catalog and capability context.

OPTIONS
  --profile=PROFILE|FILE       Select the profile. Default: basic.
  --include-manual-review    Include human-review rules; excluded by default.
  --capabilities=NAME,NAME    Include contextual rules for enabled application capabilities.
  --control=MB-Cxx,MB-Cxx     Keep only the listed controls.
  --severity=LEVEL             Keep low, medium, high, or critical rules.
  -h, --help                   Show this help.
  -V, --version                Show the Magebean version.
  -q, --quiet                  Show errors only.
  --silent                     Suppress all output.
  --ansi|--no-ansi             Force or disable ANSI formatting.
  -n, --no-interaction         Disable interactive questions.
  -v|vv|vvv                    Increase verbosity.

EXAMPLES
  php magebean.phar rules:list
  php magebean.phar rules:list --profile=asvs-l1
  php magebean.phar rules:list --profile=asvs-l2 --include-manual-review --capabilities=oauth_oidc
  php magebean.phar rules:list --profile=asvs-l3 --include-manual-review
  php magebean.phar rules:list --profile=hardening
  php magebean.phar rules:list --profile=hardening --control=MB-C03
  php magebean.phar rules:list --profile=owasp --severity=critical
  php magebean.phar rules:list --profile=.magebean/profiles/acme.json

Filters are intersected: --control and --severity only reduce the selected profile.
HELP;

    protected function configure(): void
    {
        $this->setName('rules:list')
            ->setDescription('List and filter Magebean rules by profile, control, and severity.')
            ->addUsage('--profile=hardening')
            ->addUsage('--profile=hardening --control=MB-C03')
            ->addUsage('--profile=owasp --severity=critical')
            ->setHelp(self::HELP)
            ->addOption('include-manual-review', null, InputOption::VALUE_NONE, 'Include human manual-review rules (excluded by default)')
            ->addOption('capabilities', null, InputOption::VALUE_OPTIONAL, 'Comma list of application capabilities for contextual rules')
            ->addOption('control', null, InputOption::VALUE_OPTIONAL, 'Comma list of controls (e.g. MB-C01,MB-C02)')
            ->addOption('profile', null, InputOption::VALUE_OPTIONAL, 'Profile: basic (default) | asvs-l1 | asvs-l2 | asvs-l3 | owasp | pci | hardening | development | prelaunch | takeover | evidence | custom JSON')
            ->addOption('severity', null, InputOption::VALUE_OPTIONAL, 'low|medium|high|critical');
    }
    protected function execute(InputInterface $in, OutputInterface $out): int
    {
        $controlsOpt = (string)($in->getOption('control') ?? '');
        $capabilitiesOpt = trim((string)($in->getOption('capabilities') ?? ''));
        $includeManualReview = (bool)$in->getOption('include-manual-review');
        $capabilities = $capabilitiesOpt === '' ? [] : array_fill_keys(array_filter(array_map('trim', explode(',', strtolower($capabilitiesOpt)))), true);
        $profileOpt = trim((string)($in->getOption('profile') ?? ''));
        if ($profileOpt === '') {
            $profileOpt = 'basic';
        }
        $controls = $controlsOpt ? array_map('trim', explode(',', $controlsOpt)) : [];
        $pack = RequirementCatalog::forProfile($profileOpt, $capabilities);
        if ($controls !== []) {
            $pack['rules'] = array_values(array_filter($pack['rules'] ?? [], static fn(array $rule): bool => RequirementCatalog::matchesControls($rule,$controls)));
            $pack['controls'] = RequirementCatalog::controlIds($pack['rules']);
        }
        $profile = $pack['profile'] ?? [];
        if ($profile !== []) {
            $out->writeln(sprintf('<info>Profile:</info> %s (%s)', (string)($profile['id'] ?? $profileOpt), (string)($profile['title'] ?? '')));
            if(isset($profile['family']))$out->writeln('<info>Requirement source:</info> '.match($profile['family']){'magebean'=>'Magebean','asvs'=>'OWASP ASVS','pci'=>'PCI DSS',default=>(string)$profile['family']});
        }
        $profileRulesTotal = count($pack['rules'] ?? []);
        $profileManualRulesTotal = count(array_filter($pack['rules'] ?? [], static fn(array $rule): bool => \Magebean\Engine\RequirementPolicy::requiresHuman($rule)));
        if (!$includeManualReview) {
            $pack['rules'] = array_values(array_filter(
                $pack['rules'] ?? [],
                static fn(array $rule): bool => !\Magebean\Engine\RequirementPolicy::requiresHuman($rule)
            ));
        }
        $sev = $in->getOption('severity');
        $count = 0;
        foreach ($pack['rules'] as $r) {
            if ($sev && strcasecmp($r['severity'], (string)$sev) !== 0) continue;
            $out->writeln("{$r['id']} [{$r['control']}] {$r['severity']} — {$r['title']}");
            $count++;
        }
        $out->writeln("<info>Total Rules Listed: {$count}</info>");
        $automationOnly=($pack['profile']['automation_only']??false)===true;
        if (!$includeManualReview && $profileManualRulesTotal > 0) {
            $out->writeln(sprintf('<comment>Human verification rules hidden: %d. Use --include-manual-review to show them.</comment>', $profileManualRulesTotal));
        } elseif ($includeManualReview && $profileManualRulesTotal > 0) {
            $out->writeln(sprintf('<info>Human verification rules included: %d.</info>', $profileManualRulesTotal));
        } elseif (!$automationOnly) {
            $out->writeln('<comment>Human verification rules: none in this profile. Use --include-manual-review when the selected profile provides them.</comment>');
        }        return Command::SUCCESS;
    }
}
