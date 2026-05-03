<?php

declare(strict_types=1);

namespace Magebean\Console;

use Magebean\Engine\Context;
use Magebean\Engine\ScanRunner;
use Magebean\Engine\RulePackLoader;
use Magebean\Engine\ProfileLoader;
use Magebean\Engine\ProjectConfigLoader;
use Magebean\Engine\RulePackMerger;
use Magebean\Engine\RuleValidator;
use Magebean\Engine\Checks\CheckRegistry;
use Magebean\Engine\Reporting\{HtmlReporter, JsonReporter, SarifReporter};
use Magebean\Bundle\BundleManager;
use Magebean\Engine\Cve\CveAuditor;

use Symfony\Component\Console\Helper\ProgressBar;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

final class ScanCommand extends Command
{
    protected static $defaultName = 'scan';

    /** Keep help text in one place */
    private const HELP = <<<'HELP'
<fg=cyan;options=bold>Execute a comprehensive audit</> for a Magento 2 project using <fg=green;options=bold>12 controls</> and <fg=green;options=bold>81 rules</>.
Doc: <href=https://magebean.com/documentation>magebean.com/documentation</>

<options=bold>What it checks</>
  • <fg=red;options=bold>Security Auditing</> — unsafe code patterns, permissions, world-writable files, XSS, SQLi, SSRF
  • <fg=yellow;options=bold>Configuration Auditing</> — production mode, cache, Elasticsearch, cron jobs, logging/monitoring
  • <fg=blue;options=bold>Performance Insights</> — runtime hotspots, cache effectiveness, DB indexing, static assets
  • <fg=magenta;options=bold>Extension Auditing</> — parse composer.lock, match against known CVEs, flag abandoned modules

<options=bold>USAGE</>
  <fg=green>php magebean.phar scan --path=/var/www/html</>
  <fg=green>php magebean.phar scan --path=/var/www/html --url=https://magento.local</>

<options=bold>COMMON OPTIONS</>
  <fg=yellow>--path=PATH</>                     Path to the Magento 2 root to scan (default: current directory)
  <fg=yellow>--url=URL</>                       Optional store base URL override for HTTP checks
  <fg=yellow>--format=html|json|sarif</>        Output format for results (default: html)
  <fg=yellow>--output=FILE</>                   Save results to a file (auto default based on format)
  <fg=yellow>--cve-data=PATH</>                 Path to CVE data (JSON/NDJSON or ZIP bundle)
  <fg=yellow>--profile=owasp|pci|FILE</>        Select a built-in or custom profile (default: baseline/all rules)
  <fg=yellow>--controls=MB-Cxx,MB-Cxx</>       Only load selected controls (e.g., MB-C01,MB-C05)
  <fg=yellow>--rules=MB-Rxx,MB-Rxx</>           Only run a list of specified rules (e.g., MB-R036,MB-R020)
  <fg=yellow>--exclude-rules=MB-Rxx,MB-Rxx</>   Exclude specific rules after loading the pack
  <fg=yellow>--config=FILE</>                   Project policy file (.magebean.json auto-detected)

<options=bold>EXAMPLES</>
  # Scan current directory and print a quick summary
  <fg=green>php magebean.phar scan --path=.</>

  # Generate a shareable HTML report
  <fg=green>php magebean.phar scan --path=/var/www/html --url=https://magento.local --format=html --output=report.html</>

  # Use a known CVE data when auditing installed extensions.
  # Download: <href=https://magebean.com/download>magebean.com/download</>
  <fg=green>php magebean.phar scan --path=. --cve-data=/downloads/magebean-known-cve-bundle-202509.zip</>

<options=bold>SEE ALSO</>
  <fg=cyan>rules:list</>           List all baseline rules

<options=bold>NOTES</>
  • Ensure <fg=yellow>--path</> points to the Magento root that contains app/etc and vendor.
  • <fg=blue>HTML reports</> are convenient for stakeholders; <fg=yellow>JSON</> can be archived in CI.

CONTACT: <href=mailto:support@magebean.com>support@magebean.com</>

HELP;


    public function __construct()
    {
        parent::__construct('scan');
    }

    protected function configure(): void
    {
        $this
            ->setDescription('Execute a comprehensive audit for a Magento 2 project using 12 controls and 81 rules.')
            ->addUsage('--path=/var/www/html')
            ->addUsage('--path=. --format=html --output=report.html')
            ->addUsage('--path=. --cve-data=./cve/magebean-known-cve-bundle-' . date('Ym') . '.zip')
            ->addOption('format', null, InputOption::VALUE_REQUIRED, 'Output format: html|json|sarif', 'html')
            ->addOption('output', null, InputOption::VALUE_OPTIONAL, 'Output file (auto default by format)')
            ->addOption('detail', null, InputOption::VALUE_NONE, 'Include Details column in HTML report')
            ->addOption('cve-data', null, InputOption::VALUE_OPTIONAL, 'Path to CVE data (JSON/NDJSON or ZIP bundle)')
            ->addOption('standard', null, InputOption::VALUE_OPTIONAL, 'Report standard: magebean (default) | owasp | pci | cwe', 'magebean')
            ->addOption('profile', null, InputOption::VALUE_OPTIONAL, 'Built-in profile alias (owasp|pci) or custom profile JSON path')
            ->addOption('controls', null, InputOption::VALUE_OPTIONAL, 'Comma-separated control IDs to load (e.g., MB-C01,MB-C05 or MB-01,MB-05)')
            ->addOption('rules', null, InputOption::VALUE_OPTIONAL, 'Comma-separated rule IDs to run (e.g., MB-R036,MB-R020)')
            ->addOption('exclude-rules', null, InputOption::VALUE_OPTIONAL, 'Comma-separated rule IDs to exclude after loading')
            ->addOption('config', null, InputOption::VALUE_OPTIONAL, 'Project policy file (.magebean.json or .magebean.yml)')
            ->addOption('url', null, InputOption::VALUE_OPTIONAL, 'Optional base URL override for HTTP checks')
            ->addOption('path', null, InputOption::VALUE_OPTIONAL, 'Magento root path (omit to auto-detect from current working directory)', '');
    }

    public function getHelp(): string
    {
        return self::HELP;
    }

    protected function execute(InputInterface $in, OutputInterface $out): int
    {
        $io = new SymfonyStyle($in, $out);
        $this->writePhase($out, 1, 6, 'Resolving Magento root and input options');

        $pathOpt = (string)($in->getOption('path') ?? '');
        $requestedPath = $pathOpt !== '' ? $pathOpt : getcwd();
        $requestedPath = self::normalize($requestedPath);
        $urlOpt = trim((string)($in->getOption('url') ?? ''));
        if ($urlOpt === '') {
            $urlOpt = (string)$this->autoDetectBaseUrl($requestedPath);
        }
        $requestedUrl = $urlOpt !== '' ? $urlOpt : '';

        // Nếu path không trỏ tới Magento root, thử leo lên tối đa 4 cấp
        if (!self::isMagentoRoot($requestedPath)) {
            $detected = self::detectMagentoRoot($requestedPath, 4);
            if ($detected !== null) {
                $out->writeln(sprintf('<info>Detected Magento root:</info> %s', $detected));
                $requestedPath = $detected;
            } else {
                $out->writeln("<error>Cannot locate Magento root from: {$requestedPath}</error>");
                $out->writeln('Hint: run from your Magento root or pass --path=/absolute/path/to/magento');
                return Command::FAILURE;
            }
        }

        try {
            // Cho phép tự dò lên trên tối đa 2 cấp nếu user chỉ định nhầm subfolder
            $magentoRoot = $this->findMagentoRoot($requestedPath, 2);

            if ($magentoRoot === null) {
                throw new \RuntimeException(
                    "Not a valid Magento 2 installation.\n" .
                        "- Expected files: bin/magento, composer.json, app/etc/config.php\n" .
                        "- Checked: {$requestedPath} (and up to 2 parents)"
                );
            }

            // Xác minh chi tiết (composer.json có magento/framework, bin/magento executable, v.v.)
            $this->assertMagento2Root($magentoRoot);

            // ✅ OK -> bắt đầu scan
            $projectPath = (string)$magentoRoot;
            $projectUrl = (string)$requestedUrl;
            $format      = strtolower((string)$in->getOption('format'));
            $outFile     = (string)($in->getOption('output') ?? '');
            $cveDataFile = (string)($in->getOption('cve-data') ?? '');
            $standard    = strtolower((string)($in->getOption('standard') ?? 'magebean'));
            $profileOpt  = trim((string)($in->getOption('profile') ?? ''));
            $rulesOpt    = (string)($in->getOption('rules') ?? '');
            $excludeRulesOpt = (string)($in->getOption('exclude-rules') ?? '');
            $controlsOpt = (string)($in->getOption('controls') ?? '');
            $configOpt = trim((string)($in->getOption('config') ?? ''));

            // validate standard
            $allowed = ['magebean', 'owasp', 'pci', 'cwe'];
            if (!in_array($standard, $allowed, true)) {
                $out->writeln('<error>Invalid --standard. Allowed: magebean | owasp | pci | cwe</error>');
                return Command::FAILURE;
            }
            if (!in_array($format, ['html', 'json', 'sarif'], true)) {
                $out->writeln('<error>Invalid --format. Allowed: html | json | sarif</error>');
                return Command::FAILURE;
            }

            if ($outFile === '') {
                $outFile = match ($format) {
                    'json'  => 'magebean-report.json',
                    'sarif' => 'magebean-report.sarif',
                    default => 'magebean-report.html',
                };
            }

            $bundleMeta = [];
            if ($cveDataFile !== '') {
                $this->writePhase($out, 2, 6, 'Preparing CVE bundle metadata');
                $isZip = (bool)preg_match('/\.zip$/i', $cveDataFile);
                if ($isZip) {
                    $bundleMeta = [];
                    if ($cveDataFile !== '') {
                        $isZip = (bool)preg_match('/\.zip$/i', (string)($in->getOption('cve-data') ?? ''));
                        if ($isZip && class_exists(\ZipArchive::class)) {
                            $origZip = (string)$in->getOption('cve-data');
                            $tmpRoot = sys_get_temp_dir() . '/mbbundle_' . bin2hex(random_bytes(4));
                            @mkdir($tmpRoot, 0777, true);
                            $zip2 = new \ZipArchive();
                            if ($zip2->open($origZip) === true) {
                                $zip2->extractTo($tmpRoot);
                                $zip2->close();
                                $bundleMeta = $this->collectBundleMeta($tmpRoot);
                            }
                        }
                    }

                    $bm = new BundleManager();
                    $extracted = $bm->extractOsvFileFromZip($cveDataFile);
                    if ($extracted && is_file($extracted)) {
                        $cveDataFile = $extracted;
                    } else {
                        $out->writeln('<comment>Warning:</comment> Could not extract JSON/NDJSON from zip (cve-data).');
                        if (class_exists(\ZipArchive::class)) {
                            $zip = new \ZipArchive();
                            if ($zip->open($cveDataFile) === true) {
                                $out->writeln('  Entries in ZIP:');
                                $listed = 0;
                                for ($i = 0; $i < $zip->numFiles && $listed < 50; $i++) {
                                    $st = $zip->statIndex($i);
                                    if (!$st) continue;
                                    $out->writeln('   - ' . $st['name'] . ' (' . $st['size'] . ' bytes)');
                                    $listed++;
                                }
                                $zip->close();
                            }
                        }
                    }
                }
            } else {
                $this->writePhase($out, 2, 6, 'Skipping CVE bundle preparation');
            }

            $ctx  = new Context($projectPath, $projectUrl, $cveDataFile, [
                'path' => $projectPath,
                'url' => $projectUrl,
                'meta' => $bundleMeta,
            ]);
            $registry = CheckRegistry::fromContext($ctx);

            $this->writePhase($out, 3, 6, 'Loading rule pack');
            $configFile = $configOpt !== ''
                ? self::normalize($this->resolveProjectConfigPath($configOpt, $projectPath))
                : ProjectConfigLoader::discover($projectPath);
            $projectConfig = ProjectConfigLoader::load($configFile);
            if ($configFile !== null) {
                $out->writeln(sprintf('<info>Loaded Magebean project config:</info> %s', $configFile));
            }

            // normalize controls filter
            $controlsFilter = $this->normalizeControlList($projectConfig['include_controls'] ?? []);
            if ($controlsOpt !== '') {
                $controlsFilter = $this->normalizeControlList($controlsOpt);
            }

            $pack = RulePackLoader::loadAll($controlsFilter);

            if ($controlsFilter) {
                $loaded = $pack['controls'] ?? [];
                $missing = array_values(array_diff($controlsFilter, $loaded));
                if ($missing) {
                    $out->writeln('<error>Control file(s) not found: ' . implode(', ', $missing) . '</error>');
                    return Command::FAILURE;
                }
            }

            $pack = RulePackMerger::applyProjectConfig($pack, $projectConfig);

            $activeProfile = [
                'id' => 'baseline',
                'title' => 'Magebean Baseline',
                'description' => 'All enabled rules from the Magebean rule catalog.',
                'report_template' => 'standard',
                '_source' => 'builtin:baseline',
            ];
            if ($profileOpt === '' && in_array($standard, ['owasp', 'pci'], true)) {
                $profileOpt = $standard;
            }
            if ($profileOpt !== '' && !in_array(strtolower($profileOpt), ['baseline', 'all', 'magebean'], true)) {
                $profile = ProfileLoader::load($profileOpt, $projectPath);
                $pack = ProfileLoader::apply($pack, $profile);
                $activeProfile = ProfileLoader::publicMetadata($profile);
                $standard = (string)($activeProfile['id'] ?? $standard);
                $out->writeln(sprintf(
                    '<info>Loaded profile:</info> %s (%d rules)',
                    (string)($activeProfile['id'] ?? $profileOpt),
                    count($pack['rules'] ?? [])
                ));
            }

            // filter by --rules (comma-separated IDs)
            $requestedIds = [];
            if ($rulesOpt !== '') {
                $requestedIds = array_values(array_unique(array_filter(array_map('trim', explode(',', $rulesOpt)))));
                if ($requestedIds) {
                    $byId = [];
                    foreach ($pack['rules'] as $r) {
                        $byId[strtoupper((string)($r['id'] ?? ''))] = $r;
                    }
                    $selected = [];
                    $unknown  = [];
                    foreach ($requestedIds as $id) {
                        $key = strtoupper($id);
                        if (isset($byId[$key])) $selected[] = $byId[$key];
                        else $unknown[] = $id;
                    }
                    foreach ($unknown as $id) {
                        $out->writeln(sprintf('<comment>Unknown rule id:</comment> %s', $id));
                    }
                    if ($selected) {
                        // giữ nguyên controls pack để render/summary, nhưng thay tập rules đã chọn
                        $pack['rules'] = $selected;
                    } else {
                        $out->writeln('<error>No valid rules matched the --rules filter.</error>');
                        return Command::FAILURE;
                    }
                }
            }

            if ($excludeRulesOpt !== '') {
                $excludedIds = array_values(array_unique(array_filter(array_map(
                    static fn(string $id): string => strtoupper(trim($id)),
                    explode(',', $excludeRulesOpt)
                ))));
                if ($excludedIds) {
                    $pack['rules'] = array_values(array_filter(
                        $pack['rules'],
                        static fn(array $rule): bool => !in_array(strtoupper((string)($rule['id'] ?? '')), $excludedIds, true)
                    ));
                }
            }

            $validationErrors = RuleValidator::validatePack($pack, $registry);
            if ($validationErrors) {
                $out->writeln('<error>Invalid rule pack:</error>');
                foreach (array_slice($validationErrors, 0, 20) as $error) {
                    $out->writeln('  - ' . $error);
                }
                if (count($validationErrors) > 20) {
                    $out->writeln(sprintf('  - ... and %d more', count($validationErrors) - 20));
                }
                return Command::FAILURE;
            }

            if (empty($pack['rules'])) {
                $out->writeln('<error>No rules found. Check rules directory or control filter.</error>');
                return Command::FAILURE;
            }

            $this->writePhase($out, 4, 6, sprintf('Running %d audit rules', count($pack['rules'])));
            $ruleProgress = $this->createRuleProgressBar($out, count($pack['rules']));
            // 1) Scan rules
            $runner = new ScanRunner($ctx, $pack, function (array $event) use ($ruleProgress): void {
                $type = (string)($event['type'] ?? '');
                if ($type === 'rule_start') {
                    $ruleProgress->setMessage($this->formatRuleProgressMessage($event));
                    $ruleProgress->display();
                    return;
                }
                if ($type === 'rule_done') {
                    $ruleProgress->setMessage($this->formatRuleProgressMessage($event));
                    $ruleProgress->advance();
                }
            }, $registry);
            $result = $runner->run();
            $ruleProgress->finish();
            $out->writeln('');
            // attach meta
            $result['meta']['standard']    = $standard;
            $result['meta']['profile']     = $activeProfile;
            $result['meta']['rules_filter'] = $requestedIds;
            $result['meta']['controls_filter'] = $controlsFilter;
            $result['meta']['project_config'] = $configFile;
            $result['summary']['path'] = $projectPath;

            // 2) CVE audit (nếu có data)
            if ($cveDataFile !== '' && is_file($cveDataFile)) {
                $this->writePhase($out, 5, 6, 'Running CVE audit against installed packages');
                $aud = new CveAuditor($ctx);
                $result['cve_audit'] = $aud->run($cveDataFile);
            } else {
                $this->writePhase($out, 5, 6, 'Skipping CVE audit because no dataset was provided');
                $result['cve_audit'] = null;
            }

            // 3) Render export
            $this->writePhase($out, 6, 6, sprintf('Writing %s report to %s', strtoupper($format), $outFile));
            switch ($format) {
                case 'json':
                    (new JsonReporter())->write($result, $outFile);
                    break;
                case 'sarif':
                    (new SarifReporter())->write($result, $outFile);
                    break;
                default:
                    $tpl = $this->resolveTemplatePath((string)($activeProfile['report_template'] ?? 'standard'));
                    $rep = new HtmlReporter($tpl, (bool)$in->getOption('detail'));
                    $rep->write($result, $outFile);
                    break;
            }

            // ---------- Pretty console output (mimic sample) ----------
            $this->renderPrettySummary($out, $result, $projectPath, $outFile);

            return $this->determineExitCode($result);

            // TODO: gọi engine scan của bạn, truyền $magentoRoot vào context
            // $result = $this->scanner->run($magentoRoot, ...);

            // Demo:
            // $io->success('Scan completed.');
            return Command::SUCCESS;
        } catch (\RuntimeException $e) {
            $io->error($e->getMessage());
            return Command::FAILURE;
        } catch (\Throwable $e) {
            // Bắt mọi lỗi không lường trước, tránh stacktrace lộ ra ngoài
            $io->error('Unexpected error: ' . $e->getMessage());
            return Command::FAILURE;
        }
    }

    private function renderPrettySummary(OutputInterface $out, array $result, string $path, string $outFile): void
    {
        $sum    = $result['summary'] ?? [];
        $total  = (int)($sum['total']  ?? 0);
        $passed = (int)($sum['passed'] ?? 0);

        $env      = strtoupper($this->detectMageMode($path));
        $isExternal = str_starts_with($path, 'URL:');
        $env        = $isExternal ? 'EXTERNAL' : strtoupper($this->detectMageMode($path));
        $phpShort = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;

        // Helpers
        $sevBadge = function (string $sev): string {
            $sev = strtoupper($sev);
            return match ($sev) {
                'CRITICAL' => '<fg=white;bg=red;options=bold>[CRITICAL]</>',
                'HIGH'     => '<fg=red;options=bold>[HIGH]</>',
                'MEDIUM'   => '<fg=yellow;options=bold>[MEDIUM]</>',
                'LOW'      => '<fg=blue;options=bold>[LOW]</>',
                default    => sprintf('[%s]', $sev),
            };
        };
        $envTag = function (string $env) {
            return match ($env) {
                'PRODUCTION' => '<fg=white;bg=green;options=bold>PRODUCTION</>',
                'DEVELOPER'  => '<fg=yellow;options=bold>DEVELOPER</>',
                'DEFAULT'    => '<fg=cyan>DEFAULT</>',
                'EXTERNAL'   => '<fg=blue;options=bold>EXTERNAL</>',
                default      => sprintf('<fg=magenta>%s</>', $env),
            };
        };

        // Header
        $out->writeln('');
        $out->writeln(sprintf('<fg=cyan;options=bold>Magebean Security Audit v1.0</>        Target: <fg=green>%s</>', $path));
        $standard = (string)($result['meta']['standard'] ?? 'magebean');
        $profile = (array)($result['meta']['profile'] ?? []);
        $profileTitle = (string)($profile['title'] ?? $profile['id'] ?? 'Magebean Baseline');
        $out->writeln(sprintf('Standard: <info>%s</info>', strtoupper($standard)));
        $out->writeln(sprintf('Profile: <info>%s</info>', $profileTitle));
        $out->writeln(sprintf('Time: <comment>%s</comment>   PHP: <info>%s</info>   Env: %s', date('Y-m-d H:i'), $phpShort, $envTag($env)));
        if ($isExternal) {
            $det = $result['meta']['detected'] ?? [];
            $detConf = (int)($det['confidence'] ?? 0);
            $signals = (array)($det['signals'] ?? []);
            $overall = (int)($result['meta']['overall_confidence'] ?? 0);
            $tPct    = (int)($result['meta']['transport_success_percent'] ?? 0);
            $cPct    = (int)($result['meta']['coverage_percent'] ?? 0);
            $planned = (int)($result['meta']['planned_rules'] ?? 0);
            $execd   = (int)($result['meta']['executed_rules'] ?? 0);
            $out->writeln(sprintf('Detected: <info>Magento 2</info> (confidence <comment>%d%%</comment>)', $detConf));
            $out->writeln(sprintf('Scan confidence: <info>%d%%</info> (detect %d, transport %d, coverage %d)', $overall, $detConf, $tPct, $cPct));
            if ($planned > 0) {
                $out->writeln(sprintf('Coverage: <info>%d/%d</info> rules (%d%%)', $execd, $planned, $cPct));
            }
            if (!empty($signals)) {
                $out->writeln('Signals:');
                foreach (array_slice($signals, 0, 6) as $s) {
                    $out->writeln('  - ' . $s);
                }
                if (count($signals) > 6) $out->writeln('  - …');
            }
            $out->writeln('');
        }
        $out->writeln('');

        // Findings
        $failedFindings = array_values(array_filter(($result['findings'] ?? []), fn($f) => empty($f['passed']) === true));
        usort($failedFindings, fn($a, $b) => $this->sevOrder($a['severity'] ?? 'Low') <=> $this->sevOrder($b['severity'] ?? 'Low'));
        $top = array_slice($failedFindings, 0, 10);

        $out->writeln(sprintf('<options=bold>Findings</> (<fg=red>%d</>)', count($failedFindings)));
        foreach ($top as $f) {
            $sev   = strtoupper((string)($f['severity'] ?? 'LOW'));
            $title = (string)($f['title'] ?? '');
            $msg   = (string)($f['message'] ?? '');
            $line  = sprintf('%s %s', $sevBadge($sev), $msg !== '' ? $msg : $title);
            $out->writeln('  ' . $line);
        }
        if (count($failedFindings) > count($top)) {
            $out->writeln(sprintf('  <comment>… and %d more</comment>', count($failedFindings) - count($top)));
        }
        $out->writeln('');

        // Severity counts
        $sevCounts = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0];
        foreach ($failedFindings as $f) {
            $k = strtolower((string)($f['severity'] ?? 'low'));
            if (!isset($sevCounts[$k])) $k = 'low';
            $sevCounts[$k]++;
        }

        // Summary (colored)
        $out->writeln('<options=bold>Summary</>');
        $out->writeln(sprintf('Passed Rules: <info>%d</info> / <info>%d</info>', $passed, $total));
        $out->writeln(sprintf(
            'Issues: %s %d Critical</> | %s %d High</> | %s %d Medium</> | %s %d Low</>',
            '<fg=white;bg=red;options=bold>',
            $sevCounts['critical'],
            '<fg=red;options=bold>',
            $sevCounts['high'],
            '<fg=yellow;options=bold>',
            $sevCounts['medium'],
            '<fg=blue;options=bold>',
            $sevCounts['low'],
        ));

        // CVE console:
        if (!$isExternal) {
            if (!empty($result['cve_audit']) && is_array($result['cve_audit'])) {
                $cs = $result['cve_audit']['summary'] ?? [];
                $out->writeln(sprintf(
                    "\n<info>✓ CVE Checks</info>: %d packages against %d known CVEs | Affected: <fg=red;options=bold>%d</>",
                    (int)($cs['packages_total'] ?? 0),
                    (int)($cs['dataset_total'] ?? 0),
                    (int)($cs['packages_affected'] ?? 0)
                ));
            } else {
                $out->writeln('');
                $out->writeln('<comment>⚠ CVE checks skipped</comment>');
                $out->writeln('  → Requires CVE Bundle (<comment>--cve-data=magebean-cve-bundle-YYYYMM.zip</comment>)');
                $out->writeln('  → Visit <href=https://magebean.com/download>magebean.com/download</>');
            }
        }

        // Footer
        $out->writeln('');
        $out->writeln(sprintf('→ <info>Report saved to</info> <href=file://%1$s>%1$s</>', $outFile));
        $out->writeln('Contact: <href=mailto:support@magebean.com>support@magebean.com</>');
        $out->writeln('');
    }

    private function normalizeControlId(string $raw): string
    {
        $id = strtoupper(trim($raw));
        if ($id === '') return '';
        if (preg_match('/^MB-C(\d{2})$/', $id, $m)) return 'MB-C' . $m[1];
        if (preg_match('/^MB-(\d{2})$/', $id, $m)) return 'MB-C' . $m[1];
        if (preg_match('/^C(\d{2})$/', $id, $m)) return 'MB-C' . $m[1];
        if (preg_match('/^(\d{2})$/', $id, $m)) return 'MB-C' . $m[1];
        return '';
    }

    private function normalizeControlList(mixed $raw): array
    {
        if (is_string($raw)) {
            $parts = array_map('trim', explode(',', $raw));
        } elseif (is_array($raw)) {
            $parts = $raw;
        } else {
            return [];
        }

        $normalized = [];
        $invalid = [];
        foreach ($parts as $control) {
            if (!is_scalar($control)) {
                $invalid[] = '[non-scalar]';
                continue;
            }
            $control = trim((string)$control);
            if ($control === '') {
                continue;
            }
            $nc = $this->normalizeControlId($control);
            if ($nc === '') {
                $invalid[] = $control;
            } else {
                $normalized[] = $nc;
            }
        }

        if ($invalid) {
            throw new \RuntimeException(
                'Invalid control id(s): ' . implode(', ', $invalid) . "\nExpected format: MB-C01 or MB-01"
            );
        }

        return array_values(array_unique($normalized));
    }

    private function resolveProjectConfigPath(string $config, string $projectPath): string
    {
        if ($config === '') {
            return $config;
        }
        if ($config[0] === '/' || (bool)preg_match('/^[A-Za-z]:[\\\\\\/]/', $config)) {
            return $config;
        }

        $cwdCandidate = getcwd() . DIRECTORY_SEPARATOR . $config;
        if (is_file($cwdCandidate)) {
            return $cwdCandidate;
        }

        return rtrim($projectPath, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $config;
    }

    private function sevOrder(string $sev): int
    {
        return match (strtolower($sev)) {
            'critical' => 0,
            'high'     => 1,
            'medium'   => 2,
            default    => 3
        };
    }

    private function detectMageMode(string $path): string
    {
        $envFile = rtrim($path, '/') . '/app/etc/env.php';
        if (!is_file($envFile)) return 'UNKNOWN';
        $arr = @include $envFile;
        if (is_array($arr)) {
            if (isset($arr['MAGE_MODE'])) return (string)$arr['MAGE_MODE'];
            // thử key kiểu nested
            $m = $arr['system']['default']['dev']['debug']['environment'] ?? null;
            if (is_string($m) && $m !== '') return $m;
        }
        return 'UNKNOWN';
    }
    private function resolveTemplatePath(string $template = 'standard'): string
    {
        $template = preg_match('/^[a-z0-9_-]+$/i', $template) ? $template : 'standard';
        $candidates = [
            __DIR__ . '/../../resources/report-template-' . $template . '.html',
            __DIR__ . '/../../resources/report-template.html',
            __DIR__ . '/../resources/report-template-' . $template . '.html',
            __DIR__ . '/../resources/report-template.html',
            getcwd() . '/resources/report-template-' . $template . '.html',
            getcwd() . '/resources/report-template.html',
        ];
        foreach ($candidates as $p) {
            if (is_file($p)) return $p;
        }
        $tmp = sys_get_temp_dir() . '/magebean-report-template.html';
        $html = <<<HTML
<!doctype html><html><head><meta charset="utf-8"><title>Magebean Report</title>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;padding:16px;}
table{width:100%;border-collapse:collapse;margin-top:12px}
td,th{border:1px solid #eee;padding:8px;vertical-align:top}
.status-pass{color:#0a0;background:#e9fbe9;font-weight:600;text-align:center}
.status-fail{color:#a00;background:#fdeaea;font-weight:600;text-align:center}
summary{cursor:pointer}
</style>
</head><body>
<h2>Magebean Scan</h2>
<div>Completed: {{scan_completed}}</div>
<div>Path: {{path_audited}}</div>
<div>Profile: {{profile_title}} ({{profile_id}})</div>
<div>Rules: {{rules_passed}} / {{rules_total}} ({{rules_passed_percent}}%) — Failed: {{rules_failed}}</div>
<div>Findings (Critical: {{findings_critical}}, High: {{findings_high}}, Medium: {{findings_medium}}, Low: {{findings_low}})</div>
<table>
<thead><tr><th>ID</th><th>Severity</th><th>Status</th><th>Title / Message / Details</th></tr></thead>
<tbody>
{{table}}
</tbody>
</table>
</body></html>
HTML;
        file_put_contents($tmp, $html);
        return $tmp;
    }
    /**
     * Tìm root Magento 2, thử chính path và tối đa $maxParents cấp cha.
     * Trả về path hợp lệ hoặc null nếu không tìm thấy.
     */
    private function findMagentoRoot(string $path, int $maxParents = 0): ?string
    {
        $probe = function (string $p): bool {
            return is_dir($p)
                && is_file($p . '/composer.json')
                && is_file($p . '/bin/magento')
                && (is_file($p . '/app/etc/config.php') || is_file($p . '/app/etc/env.php'));
        };

        $current = $path;
        for ($i = 0; $i <= $maxParents; $i++) {
            if ($probe($current)) {
                return realpath($current) ?: $current;
            }
            $parent = dirname($current);
            if ($parent === $current) {
                break;
            }
            $current = $parent;
        }
        return null;
    }

    /**
     * Xác minh chi tiết cài đặt Magento 2.
     * Ném RuntimeException nếu thiếu thành phần quan trọng.
     */
    private function assertMagento2Root(string $root): void
    {
        // 1) Thư mục tồn tại & đọc được
        if (!is_dir($root) || !is_readable($root)) {
            throw new \RuntimeException("Path '{$root}' is not readable.");
        }

        // 2) Các file/binary quan trọng
        $required = [
            'composer.json',
            'bin/magento',
        ];
        foreach ($required as $rel) {
            $abs = $root . DIRECTORY_SEPARATOR . $rel;
            if (!file_exists($abs)) {
                throw new \RuntimeException("Missing required file: {$rel} at {$root}");
            }
        }

        // 3) Ít nhất phải có một trong hai: app/etc/config.php hoặc app/etc/env.php
        $hasConfig = is_file($root . '/app/etc/config.php') || is_file($root . '/app/etc/env.php');
        if (!$hasConfig) {
            throw new \RuntimeException("Missing app/etc/config.php or app/etc/env.php at {$root}");
        }

        // 4) bin/magento nên executable (không bắt buộc trên mọi OS, nhưng kiểm tra giúp debug)
        $binMagento = $root . '/bin/magento';
        if (!is_readable($binMagento)) {
            throw new \RuntimeException("bin/magento is not readable at {$root}");
        }
        // if (strncasecmp(PHP_OS, 'WIN', 3) !== 0 && !is_executable($binMagento)) {
        //     throw new \RuntimeException("bin/magento is not executable at {$root}");
        // }

        // 5) composer.json phải có "require": { "magento/framework": ... } hoặc name magento/*
        $composer = @file_get_contents($root . '/composer.json');
        if ($composer === false) {
            throw new \RuntimeException("Unable to read composer.json at {$root}");
        }

        $json = json_decode($composer, true);
        if (!is_array($json)) {
            throw new \RuntimeException("Invalid composer.json at {$root}");
        }

        $hasFramework =
            isset($json['require']['magento/framework']) ||
            (isset($json['name']) && is_string($json['name']) && str_starts_with($json['name'], 'magento/'));

        if (!$hasFramework) {
            throw new \RuntimeException(
                "composer.json does not look like a Magento 2 project (missing require: magento/framework)."
            );
        }
    }

    private static function normalize(string $p): string
    {
        $rp = realpath($p);
        return $rp !== false ? rtrim($rp, DIRECTORY_SEPARATOR) : rtrim($p, DIRECTORY_SEPARATOR);
    }

    private static function isMagentoRoot(string $dir): bool
    {
        // Tiêu chí an toàn: có cả env.php và bin/magento
        return is_file($dir . '/app/etc/env.php') && is_file($dir . '/bin/magento');
    }

    private static function detectMagentoRoot(string $startDir, int $maxUp = 4): ?string
    {
        $dir = self::normalize($startDir);
        for ($i = 0; $i <= $maxUp; $i++) {
            if (self::isMagentoRoot($dir)) {
                return $dir;
            }
            $parent = dirname($dir);
            if ($parent === $dir) break; // đến root FS
            $dir = $parent;
        }
        return null;
    }

    /**
     * HTTP fetch đơn giản (curl nếu có, fallback streams).
     * @return array{0:bool,1:string,2:array{status:int,headers:array,body:string,final_url:string}}
     */
    private function httpFetch(string $url, int $timeoutMs = 6000): array
    {
        $ua = 'Magebean-CLI/1.0';
        if (function_exists('curl_init')) {
            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL => $url,
                CURLOPT_CUSTOMREQUEST => 'GET',
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HEADER => true,
                CURLOPT_TIMEOUT_MS => $timeoutMs,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_MAXREDIRS => 3,
                CURLOPT_USERAGENT => $ua,
            ]);
            $resp = curl_exec($ch);
            if ($resp === false) {
                $err = curl_error($ch);
                curl_close($ch);
                return [false, $err, ['status' => 0, 'headers' => [], 'body' => '', 'final_url' => $url]];
            }
            $status  = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            $hdrSize = (int)curl_getinfo($ch, CURLINFO_HEADER_SIZE);
            $hdrRaw  = substr((string)$resp, 0, $hdrSize);
            $body    = substr((string)$resp, $hdrSize);
            $final   = (string)curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
            curl_close($ch);
            return [true, '', ['status' => $status, 'headers' => $this->parseHeadersAssoc($hdrRaw), 'body' => $body, 'final_url' => $final]];
        }
        // streams fallback
        $opts = ['http' => [
            'method' => 'GET',
            'header' => "User-Agent: {$ua}\r\n",
            'ignore_errors' => true,
            'timeout' => max(1, (int)ceil($timeoutMs / 1000)),
        ]];
        $ctx = stream_context_create($opts);
        $body = @file_get_contents($url, false, $ctx);
        $rawHeaders = is_array($http_response_header ?? null) ? implode("\r\n", $http_response_header) : '';
        $status = 0;
        if (preg_match('~HTTP/\S+\s+(\d{3})~', $rawHeaders, $m)) $status = (int)$m[1];
        if ($body === false) return [false, 'HTTP error (stream)', ['status' => 0, 'headers' => [], 'body' => '', 'final_url' => $url]];
        return [true, '', ['status' => $status, 'headers' => $this->parseHeadersAssoc($rawHeaders), 'body' => $body, 'final_url' => $url]];
    }

    /** Parse header raw thành assoc lowercase */
    private function parseHeadersAssoc(string $raw): array
    {
        $out = [];
        foreach (preg_split("~\r?\n~", $raw) as $line) {
            if (strpos($line, ':') !== false) {
                [$k, $v] = array_map('trim', explode(':', $line, 2));
                $k = strtolower($k);
                // gộp header trùng (vd: Set-Cookie)
                if (isset($out[$k])) {
                    if (is_array($out[$k])) $out[$k][] = $v;
                    else $out[$k] = [$out[$k], $v];
                } else {
                    $out[$k] = $v;
                }
            }
        }
        return $out;
    }

        private function collectBundleMeta(string $root): array
    {
        $map = [];
        $root = rtrim($root, '/\\');

        // Support both legacy layout (data/, rules/) and new flat layout (files at bundle root)
        foreach (['', 'data', 'DATA', 'rules', 'RULES'] as $dir) {
            $base = $root;
            if ($dir !== '') {
                $base .= DIRECTORY_SEPARATOR . $dir;
            }
            if (!is_dir($base)) continue;

            $candidates = [
                'abandoned'       => 'packagist-abandoned.json',
                'yanked'          => 'packagist-yanked.json',
                'release_history' => 'release-history.json',
                'repo_status'     => 'repo-status.json',
                'vendor_support'  => 'vendor-support.json',
                // advisories split by source (new bundle layout)
                'osv'             => 'osv-advisories.json',
                'ghsa'            => 'ghsa-advisories.json',
                'friendsofphp'    => 'friendsofphp-advisories.json',
                'snyk'            => 'snyk-advisories.json',
                // other meta
                'kev'             => 'cisa-kev.json',
                'high_risk'       => 'high-risk-modules.json',
                'osv_db'          => 'osv-db.json',                   // CVE DB (JSON/NDJSON flattened)
                'list'            => 'match-list.json',               // allow/deny list
                'tags'            => 'risk-surface.json',             // risk tags
                'market'          => 'marketplace-versions.json',     // marketplace versions
            ];
            foreach ($candidates as $key => $file) {
                $p = $base . DIRECTORY_SEPARATOR . $file;
                if (is_file($p) && !isset($map[$key])) {
                    // First match wins so bundles can ship duplicates in data/, rules/, or root.
                    $map[$key] = $p;
                }
            }
        }
        return $map;
    }

    private function autoDetectBaseUrl(string $projectPath): string
    {
        $root    = rtrim($projectPath, DIRECTORY_SEPARATOR);
        $envFile = $root . '/app/etc/env.php';
        if (!is_file($envFile)) {
            return '';
        }

        $env = @include $envFile;
        if (!is_array($env) || empty($env['db']['connection']['default'])) {
            return '';
        }

        $db     = $env['db']['connection']['default'];
        $prefix = $env['db']['table_prefix'] ?? '';
        $table  = ($prefix ? $prefix : '') . 'core_config_data';

        $host     = $db['host'] ?? 'localhost';
        $dbname   = $db['dbname'] ?? '';
        $username = $db['username'] ?? '';
        $password = $db['password'] ?? '';
        $port     = null;

        if (strpos($host, ':') !== false) {
            [$host, $port] = explode(':', $host, 2);
        }
        if ($dbname === '' || $username === '') {
            return '';
        }

        $dsn = "mysql:host={$host};dbname={$dbname};charset=utf8mb4";
        if (!empty($port)) {
            $dsn .= ";port={$port}";
        }

        try {
            $pdo = new \PDO($dsn, $username, $password, [
                \PDO::ATTR_ERRMODE            => \PDO::ERRMODE_EXCEPTION,
                \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC,
            ]);
        } catch (\PDOException $e) {
            return '';
        }

        $paths = ['web/secure/base_url', 'web/unsecure/base_url'];
        $in    = implode(',', array_fill(0, count($paths), '?'));
        $sql   = "SELECT scope, scope_id, path, value FROM {$table} WHERE path IN ($in)";

        try {
            $stmt = $pdo->prepare($sql);
            $stmt->execute($paths);
            $rows = $stmt->fetchAll();
        } catch (\PDOException $e) {
            return '';
        }
        if (!$rows) {
            return '';
        }

        $bucket = [
            'web/secure/base_url'   => ['stores' => [], 'websites' => [], 'default' => []],
            'web/unsecure/base_url' => ['stores' => [], 'websites' => [], 'default' => []],
        ];
        foreach ($rows as $r) {
            $path    = (string)($r['path'] ?? '');
            $scope   = strtolower((string)($r['scope'] ?? 'default'));
            if (!isset($bucket[$path][$scope])) $scope = 'default';
            $scopeId = (int)($r['scope_id'] ?? 0);
            $val     = trim((string)($r['value'] ?? ''));
            if ($val !== '' && isset($bucket[$path])) {
                $bucket[$path][$scope][$scopeId] = $val;
            }
        }

        $pick = function (array $b): ?string {
            if (!empty($b['stores'])) {
                $https = array_filter($b['stores'], fn($v) => stripos($v, 'https://') === 0);
                $cand  = reset($https);
                if ($cand) return $cand;
                return reset($b['stores']);
            }
            if (!empty($b['websites'])) {
                $https = array_filter($b['websites'], fn($v) => stripos($v, 'https://') === 0);
                $cand  = reset($https);
                if ($cand) return $cand;
                return reset($b['websites']);
            }
            if (!empty($b['default'])) {
                $https = array_filter($b['default'], fn($v) => stripos($v, 'https://') === 0);
                $cand  = reset($https);
                if ($cand) return $cand;
                return reset($b['default']);
            }
            return null;
        };

        $secure = $pick($bucket['web/secure/base_url']);
        $unsec  = $pick($bucket['web/unsecure/base_url']);

        $base = $secure ?: $unsec;
        if (!$base) return '';

        // Normalize: strip trailing index.php and ensure trailing slash
        $base = preg_replace('~/index\.php/?$~i', '/', $base);
        if (substr($base, -1) !== '/') {
            $base .= '/';
        }

        return $base;
    }

    private function determineExitCode(array $result): int
    {
        $failedFindings = array_filter(
            $result['findings'] ?? [],
            static fn(array $finding): bool => strtoupper((string)($finding['status'] ?? '')) === 'FAIL'
        );
        if ($failedFindings === []) {
            return Command::SUCCESS;
        }

        foreach ($failedFindings as $finding) {
            if (strtolower((string)($finding['severity'] ?? '')) === 'critical') {
                return 2;
            }
        }

        return Command::FAILURE;
    }

    private function writePhase(OutputInterface $out, int $current, int $total, string $message): void
    {
        if ($out->isQuiet()) {
            return;
        }

        $out->writeln(sprintf('<fg=cyan>[%d/%d]</> %s', $current, $total, $message));
    }

    private function createRuleProgressBar(OutputInterface $out, int $totalRules): ProgressBar
    {
        $progress = new ProgressBar($out, max(1, $totalRules));
        $progress->setFormat(' %current%/%max% [%bar%] %percent:3s%%  %message%');
        $progress->setMessage('Starting rule scan');
        $progress->start();

        return $progress;
    }

    private function formatRuleProgressMessage(array $event): string
    {
        $ruleId = (string)($event['rule_id'] ?? '');
        $control = (string)($event['control'] ?? '');
        $title = trim((string)($event['title'] ?? ''));
        $status = strtoupper((string)($event['status'] ?? ''));

        $parts = array_values(array_filter([$ruleId, $control]));
        $label = implode(' ', $parts);
        if ($title !== '') {
            $label .= ($label !== '' ? ' - ' : '') . $this->truncateProgressTitle($title, 70);
        }
        if ($status !== '') {
            $label .= ' [' . $status . ']';
        }

        return $label !== '' ? $label : 'Scanning rules';
    }

    private function truncateProgressTitle(string $title, int $maxLength): string
    {
        if (strlen($title) <= $maxLength) {
            return $title;
        }

        return rtrim(substr($title, 0, $maxLength - 3)) . '...';
    }
}
