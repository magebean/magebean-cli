<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use Magebean\Application;
use Magebean\Agent\AgentScanner;
use Magebean\Engine\{Context, ProfileLoader, RulePackLoader, ScanRunner};
use Magebean\Engine\Checks\{CheckRegistry, ComposerCheck};
use Symfony\Component\Console\Tester\CommandTester;

function compatibilityAssert(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

function compatibilityNormalize(mixed $value, string $root, string $url): mixed
{
    if (is_array($value)) {
        foreach ($value as $key => $item) {
            if (in_array($key, ['checked_at', 'generated_at', 'observed_at'], true)) {
                compatibilityAssert(is_string($item) && strtotime($item) !== false, 'Invalid timestamp: ' . $key);
                $value[$key] = '<TIMESTAMP>';
            } else $value[$key] = compatibilityNormalize($item, $root, $url);
        }
        return $value;
    }
    if (!is_string($value)) return $value;
    $value = str_replace([$root, $url, dirname(__DIR__)], ['<ROOT>', '<URL>', '<REPO>'], $value);
    $value = str_replace("\r\n", "\n", $value);
    $value = preg_replace('/PHP\s+\d+\.\d+(?:\.\d+)?/', 'PHP <VERSION>', $value) ?? $value;
    $value = preg_replace('/^(Environment[^\n]* · )\d{4}-\d{2}-\d{2} \d{2}:\d{2}$/m', '$1<TIMESTAMP>', $value) ?? $value;
    // Only volatile progress-bar lines are omitted; phase labels and summaries remain.
    $lines = explode("\n", $value);
    $lines = array_values(array_filter($lines, static fn(string $line): bool => preg_match('/^\s*\d+\/\d+\s+\[/', $line) !== 1));
    return implode("\n", array_map('rtrim', $lines));
}

function compatibilityCommand(string $name, array $input): array
{
    $tester = new CommandTester((new Application())->find($name));
    $exit = $tester->execute($input + ['--no-ansi' => true], ['decorated' => false, 'interactive' => false]);
    return ['exit' => $exit, 'output' => $tester->getDisplay(true)];
}

function compatibilityRule(string $id, string $check, array $args = [], string $severity = 'low'): array
{
    return ['id' => $id, 'title' => 'Compatibility ' . $id, 'control' => 'QA', 'severity' => $severity, 'checks' => [['name' => $check, 'args' => $args]]];
}

function compatibilityFirstDifference(mixed $expected, mixed $actual, string $path = '$'): ?string
{
    if (gettype($expected) !== gettype($actual)) return $path . ' (type changed)';
    if (!is_array($expected)) {
        if ($expected === $actual) return null;
        if (is_string($expected) && is_string($actual)) {
            $offset = 0; $limit = min(strlen($expected), strlen($actual));
            while ($offset < $limit && $expected[$offset] === $actual[$offset]) $offset++;
            return $path . ' (value changed at byte ' . $offset . '; expected ' . json_encode(substr($expected, max(0, $offset - 30), 130)) . '; actual ' . json_encode(substr($actual, max(0, $offset - 30), 130)) . ')';
        }
        return $path . ' (value changed)';
    }
    if (array_keys($expected) !== array_keys($actual)) return $path . ' (keys/order changed)';
    foreach ($expected as $key => $value) {
        $difference = compatibilityFirstDifference($value, $actual[$key], $path . '.' . $key);
        if ($difference !== null) return $difference;
    }
    return null;
}

$record = ($argv[1] ?? '') === '--record-baseline';
compatibilityAssert(count($argv) === 1 || ($record && count($argv) === 2), 'Usage: php tests/CompatibilityBaselineTest.php [--record-baseline]');
compatibilityAssert(function_exists('proc_open'), 'Compatibility suite needs proc_open for a loopback PHP fixture.');
putenv('COLUMNS=120');
putenv('LINES=40');
$root = sys_get_temp_dir() . '/magebean-compatibility-' . bin2hex(random_bytes(6));
$process = null;
$previousCwd = getcwd();
$socket = null;
try {
    foreach (['app/etc', 'bin', 'vendor', 'pub/media'] as $directory) mkdir($root . '/' . $directory, 0700, true);
    file_put_contents($root . '/composer.json', '{"name":"magento/fixture","require":{"magento/framework":"103.0.7"}}');
    file_put_contents($root . '/composer.lock', json_encode(['packages' => [['name' => 'qa/example', 'version' => '1.0.0']], 'packages-dev' => []], JSON_THROW_ON_ERROR));
    file_put_contents($root . '/bin/magento', "#!/usr/bin/env php\n<?php // Fixture, never bootstrapped.\n");
    file_put_contents($root . '/app/etc/env.php', "<?php return ['MAGE_MODE'=>'production','backend'=>['frontName'=>'fixtureadmin']];\n");
    file_put_contents($root . '/app/etc/config.php', "<?php return ['modules'=>[]];\n");
    file_put_contents($root . '/present.txt', 'fixture');
    chdir($root);

    $socket = stream_socket_server('tcp://127.0.0.1:0', $errno, $error);
    compatibilityAssert(is_resource($socket), 'Cannot reserve loopback port: ' . $error);
    $address = stream_socket_get_name($socket, false);
    fclose($socket); $socket = null;
    $url = 'http://' . $address;
    $process = proc_open([PHP_BINARY, '-S', $address, __DIR__ . '/support/CompatibilityHttpRouter.php'],
        [0 => ['file', PHP_OS_FAMILY === 'Windows' ? 'NUL' : '/dev/null', 'r'], 1 => ['file', $root . '/http.log', 'a'], 2 => ['file', $root . '/http.log', 'a']], $pipes, $root);
    compatibilityAssert(is_resource($process), 'Cannot start loopback fixture.');
    $ready = false;
    for ($attempt = 0; $attempt < 100; $attempt++) {
        $connection = @stream_socket_client('tcp://' . $address, $errno, $error, 0.05);
        if (is_resource($connection)) { fclose($connection); $ready = true; break; }
        if (!proc_get_status($process)['running']) break;
        usleep(20000);
    }
    compatibilityAssert($ready, 'Loopback fixture failed to start.');

    $actual = ['baseline_schema' => 1, 'application' => ['version' => Application::VERSION, 'baseline_version' => Application::BASELINE_VERSION]];
    $app = new Application();
    foreach (['scan', 'rules:list', 'agent:connect', 'agent:status', 'agent:doctor', 'agent:disconnect', 'agent:tick', 'agent:cron'] as $name) {
        $command = $app->find($name); $definition = $command->getDefinition();
        $options = [];
        foreach ($definition->getOptions() as $option) $options[$option->getName()] = [
            'shortcut' => $option->getShortcut(), 'required' => $option->isValueRequired(), 'optional' => $option->isValueOptional(),
            'array' => $option->isArray(), 'default' => $option->getDefault(), 'description' => $option->getDescription(),
        ];
        $actual['commands'][$name] = ['aliases' => $command->getAliases(), 'description' => $command->getDescription(), 'options' => $options, 'help' => $command->getHelp()];
    }
    $pack = RulePackLoader::loadAll();
    foreach ($pack['rules'] as $rule) $actual['catalog'][$rule['id']] = [
        'control' => $rule['control'], 'severity' => $rule['severity'], 'verification' => $rule['verification'] ?? 'automated',
        'definition_sha256' => hash('sha256', json_encode($rule, JSON_THROW_ON_ERROR)),
    ];
    foreach (['basic', 'asvs-l1', 'asvs-l2', 'asvs-l3', 'owasp', 'pci', 'hardening'] as $profile) {
        $selected = ProfileLoader::apply($pack, ProfileLoader::load($profile, $root));
        $actual['profiles'][$profile] = [
            'all_ids' => array_column($selected['rules'], 'id'),
            'automated_ids' => array_values(array_column(array_filter($selected['rules'], static fn(array $r): bool => ($r['verification'] ?? 'automated') !== 'manual'), 'id')),
        ];
    }
    foreach ([[], ['--profile' => 'hardening', '--control' => 'MB-C03', '--severity' => 'high'], ['--profile' => 'asvs-l1', '--include-manual-review' => true, '--control' => 'MB-C02'], ['--profile' => 'asvs-l3', '--capabilities' => 'graphql,oauth_oidc', '--control' => 'MB-C03']] as $i => $input)
        $actual['rule_listing'][$i] = compatibilityCommand('rules:list', $input);

    $fixtureRules = [compatibilityRule('QA-PASS', 'fs_exists', ['path' => 'present.txt']), compatibilityRule('QA-FAIL', 'fs_exists', ['path' => 'missing.txt'], 'high'), compatibilityRule('QA-CRITICAL', 'fs_exists', ['path' => 'missing.txt'], 'critical')];
    $fixtureRules[] = compatibilityRule('QA-MANUAL', 'human_manual_review_required', ['review' => 'Fixture human review']);
    $fixtureRules[3]['verification'] = 'manual';
    file_put_contents($root . '/rules.json', json_encode(['rules' => $fixtureRules], JSON_THROW_ON_ERROR));
    file_put_contents($root . '/policy.json', json_encode(['rule_files' => ['rules.json']], JSON_THROW_ON_ERROR));
    foreach (['pass' => 'QA-PASS', 'fail' => 'QA-FAIL', 'critical' => 'QA-CRITICAL', 'manual' => 'QA-MANUAL', 'mixed' => 'QA-PASS,QA-FAIL,QA-MANUAL'] as $name => $ids) {
        $actual['local_scans'][$name] = compatibilityCommand('scan', ['--path' => $root, '--config' => 'policy.json', '--rules' => $ids]);
    }
    compatibilityAssert($actual['local_scans']['pass']['exit'] === 0 && $actual['local_scans']['fail']['exit'] === 1 && $actual['local_scans']['critical']['exit'] === 2, 'Exit-code fixture did not exercise 0/1/2.');
    $actual['local_scans']['exclude'] = compatibilityCommand('scan', ['--path' => $root, '--config' => 'policy.json', '--rules' => 'QA-PASS,QA-FAIL', '--exclude-rules' => 'QA-FAIL']);
    $actual['local_scans']['autodetect'] = compatibilityCommand('scan', ['--config' => 'policy.json', '--rules' => 'QA-PASS']);
    $actual['hybrid_scan'] = compatibilityCommand('scan', ['--path' => $root, '--url' => $url, '--rules' => 'MB-R032']);
    $actual['remote_scan'] = compatibilityCommand('scan', ['--url' => $url, '--rules' => 'MB-R032']);
    $actual['remote_inconclusive'] = compatibilityCommand('scan', ['--url' => $url . '/not-magento', '--rules' => 'MB-R032']);
    foreach (['LOCAL' => $actual['hybrid_scan'], 'REMOTE' => $actual['remote_scan']] as $mode => $case) compatibilityAssert($case['exit'] === 0 && str_contains($case['output'], 'Target mode: ' . $mode), 'Mode fixture failed: ' . $mode);
    foreach ([['--path' => ''], ['--path' => $root, '--rules' => 'DOES-NOT-EXIST'], ['--path' => $root, '--profile' => 'basic', '--pci-context' => 'missing.json']] as $i => $input)
        $actual['invalid_inputs'][$i] = compatibilityCommand('scan', $input);

    $registry = new CheckRegistry();
    foreach (['pass' => true, 'fail' => false, 'unknown' => null] as $name => $ok) $registry->register($name, static fn(array $args): array => [$ok, $name . ' fixture', ['source' => $name]]);
    $registry->register('manual', static fn(array $args): array => [null, '[MANUAL_REVIEW] Fixture review', ['manual_review' => true]]);
    $rules = [];
    foreach (['all', 'any'] as $op) foreach (['pass', 'fail', 'unknown', 'manual'] as $left) foreach (['pass', 'fail', 'unknown', 'manual'] as $right) {
        $rule = compatibilityRule('QA-' . $op . '-' . $left . '-' . $right, $left); $rule['op'] = $op; $rule['checks'][] = ['name' => $right]; $rules[] = $rule;
    }
    $actual['engine_truth_table'] = (new ScanRunner(new Context($root, ''), ['rules' => $rules], null, $registry))->run();

    $advisory = ['id' => 'QA-CVE', 'affected' => [['package' => ['name' => 'qa/example', 'ecosystem' => 'Packagist'], 'ranges' => [['type' => 'ECOSYSTEM', 'events' => [['introduced' => '0'], ['fixed' => '1.1.0']]]]]]];
    file_put_contents($root . '/cve.json', json_encode([$advisory], JSON_THROW_ON_ERROR));
    $actual['offline_cve'] = (new ComposerCheck(new Context($root, '', $root . '/cve.json')))->auditOffline([]);
    compatibilityAssert($actual['offline_cve'][0] === false, 'Offline CVE fixture did not detect advisory.');

    foreach (['manual_hidden' => false, 'manual_included' => true] as $name => $manual) {
        file_put_contents($root . '/pci-policy.json', json_encode(['include_rules' => ['MB-R009', 'MB-R371']], JSON_THROW_ON_ERROR));
        $input = ['--path' => $root, '--profile' => 'pci', '--config' => 'pci-policy.json', '--pci-context' => 'pci-context.json', '--pci-evidence' => 'pci-evidence.json', '--pci-report' => 'pci-report.json'];
        copy(__DIR__ . '/../docs/examples/pci-dss-context.example.json', $root . '/pci-context.json');
        copy(__DIR__ . '/../docs/examples/pci-dss-external-evidence.example.json', $root . '/pci-evidence.json');
        if ($manual) $input['--include-manual-review'] = true;
        $actual['pci'][$name]['command'] = compatibilityCommand('scan', $input);
        compatibilityAssert(is_file($root . '/pci-report.json'), 'PCI report not written: ' . $actual['pci'][$name]['command']['output']);
        $actual['pci'][$name]['report'] = json_decode((string)file_get_contents($root . '/pci-report.json'), true, 512, JSON_THROW_ON_ERROR);
        unlink($root . '/pci-report.json');
    }
    $scanner = new AgentScanner();
    $manifest = ['schema_version' => '1.0', 'manifest_hash' => 'sha256:fixture', 'rules' => [['assessment_item_id' => 'item-media', 'rule_key' => 'MB-R091'], ['assessment_item_id' => 'item-unknown', 'rule_key' => 'NOT-BUNDLED']]];
    $actual['agent']['pass'] = $scanner->run($root, $manifest);
    file_put_contents($root . '/pub/media/unexpected.php', '<?php echo 1;');
    $actual['agent']['fail'] = $scanner->run($root, $manifest);
    compatibilityAssert($actual['agent']['pass']['results'][0]['status'] === 'pass' && $actual['agent']['fail']['results'][0]['status'] === 'fail', 'Agent fixture missed pass/fail.');

    $actual = compatibilityNormalize($actual, $root, $url);
    $snapshot = __DIR__ . '/fixtures/compatibility/baseline.json';
    if ($record) {
        compatibilityAssert(file_put_contents($snapshot, json_encode($actual, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n") !== false, 'Cannot write baseline.');
        echo "CompatibilityBaselineTest: recorded baseline; review the diff before accepting.\n";
    } else {
        compatibilityAssert(is_file($snapshot), 'Missing baseline; do not regenerate it automatically.');
        $expected = json_decode((string)file_get_contents($snapshot), true, 512, JSON_THROW_ON_ERROR);
        $difference = compatibilityFirstDifference($expected, $actual);
        compatibilityAssert($difference === null, 'Compatibility regression at ' . $difference . '. Review behavior; do not blindly update snapshots.');
        echo "CompatibilityBaselineTest: PASS\n";
    }
} finally {
    if (is_resource($socket)) fclose($socket);
    if (is_resource($process)) { proc_terminate($process); proc_close($process); }
    if ($previousCwd !== false) chdir($previousCwd);
    if (is_dir($root)) {
        $nodes = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($nodes as $node) $node->isDir() && !$node->isLink() ? rmdir($node->getPathname()) : unlink($node->getPathname());
        rmdir($root);
    }
}
