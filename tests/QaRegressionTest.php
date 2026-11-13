<?php
declare(strict_types=1);
require_once __DIR__ . '/../vendor/autoload.php';
use Magebean\Engine\{Context, RulePackLoader, ScanRunner};
use Magebean\Engine\Checks\{CheckRegistry, CodeSearchCheck, MagentoCheck, WebServerConfigCheck, FilesystemCheck, PciEvidenceCheck};
use Magebean\Engine\Collectors\HttpCollector;
use Magebean\Engine\Cve\CveAuditor;
use Magebean\Engine\Pci\{PciApplicabilityCompiler, PciExternalEvidenceImporter};
use Magebean\Engine\Reporting\SarifReporter;
$failures = []; $cases = 0;
function qaExpect(bool $ok, string $issue): void { global $failures, $cases; $cases++; if (!$ok) $failures[] = $issue; }
$root = sys_get_temp_dir() . '/magebean-qa-' . bin2hex(random_bytes(6));
mkdir($root . '/app', 0700, true);
$ctx = new Context($root, ''); $code = new CodeSearchCheck($ctx);
$source = static function (string $content) use ($root): void { file_put_contents($root . '/app/fixture.php', $content); };
$rules = array_column(RulePackLoader::loadAll()['rules'], null, 'id');
$run = static fn(string $id): array => (new ScanRunner($ctx, ['rules' => [$rules[$id]]]))->run()['findings'][0];
try {
    $source('<?php echo $_GET["name"];');
    qaExpect($run('MB-R014')['status'] === 'FAIL', 'QA-01 superglobals routing');
    $source('<?php unserialize($_GET["data"]);');
    qaExpect($run('MB-R017')['status'] === 'FAIL', 'QA-01 deserialization routing');
    file_put_contents($root . '/app/forms.phtml', '<form method="post"></form><form method="post"></form>');
    qaExpect($code->csrfFormKey(['paths' => ['app'], 'include_ext' => ['php']])[0] === false, 'QA-02 multi-form');
    $source('<?php unserialize($_GET["a"]);' . str_repeat("\n", 600) . 'unserialize($_GET["b"]);');
    qaExpect($code->unserializeSafety(['paths' => ['app']])[0] === false, 'QA-02 multi-unserialize');
    $source('<?php $url=$_GET["url"]; if(!filter_var($url,FILTER_VALIDATE_URL)){exit;} $client->get($url,["timeout"=>10]);');
    qaExpect($code->ssrfSafeguards(['paths' => ['app']])[0] !== true, 'QA-03 URL syntax is not allowlist');
    $mage = new MagentoCheck(new Context($root, 'http://127.0.0.1:1', '', ['url' => 'http://127.0.0.1:1']));
    qaExpect($mage->adminExposureRestricted(['paths' => ['/admin/'], 'timeout_ms' => 100])[0] === null, 'QA-04 failed probes');
    $headers = (new ReflectionMethod(HttpCollector::class, 'parseHeaders'))->invoke(new HttpCollector(), "HTTP/1.1 302 Found\r\nStrict-Transport-Security: max-age=31536000\r\n\r\nHTTP/1.1 200 OK\r\nX-Final: yes\r\n\r\n");
    qaExpect(!isset($headers['strict-transport-security']) && $headers['x-final'] === 'yes', 'QA-05 final headers');
    file_put_contents($root . '/composer.lock', json_encode(['packages' => [['name' => 'qa/example', 'version' => '2.0.0']]]));
    $vuln = static fn(array $events, string $id = 'QA'): array => ['id' => $id, 'affected' => [['package' => ['name' => 'qa/example', 'ecosystem' => 'Packagist'], 'ranges' => [['type' => 'ECOSYSTEM', 'events' => $events]]]]];
    foreach (['last_affected', 'limit'] as $endpoint) {
        file_put_contents($root . '/vulns.json', json_encode([$vuln([['introduced' => '1.0.0'], [$endpoint => '1.5.0']])]));
        qaExpect((new CveAuditor($ctx))->run($root . '/vulns.json')['packages'][0]['status'] === 'PASS', 'QA-06 ' . $endpoint);
    }
    $registry = new CheckRegistry(); $registry->register('fail', static fn(array $args): array => [false, 'fail']); $registry->register('unknown', static fn(array $args): array => [null, '[UNKNOWN] missing']);
    $report = (new ScanRunner($ctx, ['rules' => [['id' => 'QA', 'title' => 'QA', 'control' => 'QA', 'severity' => 'low', 'op' => 'any', 'checks' => [['name' => 'fail'], ['name' => 'unknown']]]]], null, $registry))->run();
    qaExpect($report['findings'][0]['status'] === 'UNKNOWN' && $report['findings'][0]['passed'] === null, 'QA-07 OR uncertainty');
    $web = new WebServerConfigCheck($ctx); $cipher = new ReflectionMethod($web, 'cipherSuiteEvidence');
    qaExpect($cipher->invoke($web, 'ALL:ECDHE')['ok'] !== true, 'QA-08 broad cipher group');
    qaExpect($cipher->invoke($web, 'HIGH:RC4:!RC4')['ok'] !== false, 'QA-08 cipher exclusion');
    file_put_contents($root . '/rotate.conf', "/var/log/nginx/access.log {\nrotate 0\ndelaycompress\n}\n");
    qaExpect((new FilesystemCheck($ctx))->logRotationConfigured(['file' => 'rotate.conf'])[0] !== true, 'QA-09 rotation');
    $pci = json_decode(file_get_contents(__DIR__ . '/../docs/examples/pci-dss-2.2.2-evidence.example.json'), true);
    foreach ($pci['scope']['components'] as &$component) $component['in_scope'] = false; unset($component);
    $pci['accounts'][0]['intended_use'] = 'NOT_USED'; $pci['accounts'][0]['observed_state'] = 'ENABLED';
    file_put_contents($root . '/pci.json', json_encode($pci));
    qaExpect((new PciEvidenceCheck($ctx))->vendorDefaultAccountsEvidence(['paths' => ['pci.json']])[0] !== false, 'QA-10 out-of-scope account');
    $context = json_decode(file_get_contents(__DIR__ . '/../docs/examples/pci-dss-context.example.json'), true); $context['issuer_or_issuing_services'] = 'false';
    qaExpect((new PciApplicabilityCompiler())->compile(['requirements' => []], $context)['valid'] === false, 'QA-11 boolean schema');
    $external = json_decode(file_get_contents(__DIR__ . '/../docs/examples/pci-dss-external-evidence.example.json'), true);
    $importer = new PciExternalEvidenceImporter([$external['evidence'][0]['requirement']]);
    foreach (['yesterday', 'tomorrow', '2026-02-30'] as $time) {
        $bad = $external; $bad['evidence'][0]['collected_at'] = $time; file_put_contents($root . '/external.json', json_encode($bad));
        qaExpect(!$importer->import($root . '/external.json')['valid'], 'QA-12 timestamp ' . $time);
    }
    (new SarifReporter())->write(['findings' => [['id' => 'QA', 'title' => 'QA', 'message' => 'Missing data', 'status' => 'UNKNOWN', 'passed' => null]]], $root . '/sarif.json');
    $sarif = json_decode(file_get_contents($root . '/sarif.json'), true);
    qaExpect(($sarif['runs'][0]['results'][0]['level'] ?? 'note') !== 'error', 'QA-13 SARIF inconclusive');
    qaExpect((new CveAuditor($ctx))->run($root . '/missing.json')['packages'][0]['status'] === 'UNKNOWN', 'QA-14 missing dataset');
    file_put_contents($root . '/vulns.json', json_encode([$vuln([['introduced' => '1.0.0'], ['fixed' => '2.1.0']], 'QA1'), $vuln([['introduced' => '1.0.0'], ['fixed' => '2.5.0']], 'QA2')]));
    $audit = (new CveAuditor($ctx))->run($root . '/vulns.json');
    qaExpect($audit['packages'][0]['upgrade_hint'] === '2.5.0', 'QA-14 safe upgrade hint');
    qaExpect($audit['summary']['highest_severity'] === 'Unknown', 'QA-14 severity uncertainty');

    // Endpoint equality and public standalone integration, including fixed != last_affected.
    foreach (['last_affected' => 'FAIL', 'limit' => 'PASS', 'fixed' => 'PASS'] as $endpoint => $expected) {
        file_put_contents($root . '/composer.lock', json_encode(['packages' => [['name' => 'qa/example', 'version' => '1.5.0']]]));
        file_put_contents($root . '/vulns.json', json_encode([$vuln([['introduced' => '1.0.0'], [$endpoint => '1.5.0']])]));
        qaExpect((new CveAuditor($ctx))->run($root . '/vulns.json')['packages'][0]['status'] === $expected, 'QA-06 equal endpoint ' . $endpoint);
        qaExpect((new \Magebean\Engine\Checks\ComposerCheck($ctx))->auditOffline(['cve_data' => $root . '/vulns.json'])[0] === ($expected === 'PASS'), 'QA-06 public Composer endpoint ' . $endpoint);
    }
    $intervals = \Magebean\Engine\Cve\OsvRange::intervals([['introduced' => '0'], ['fixed' => '1.0.0'], ['introduced' => '2.0.0'], ['last_affected' => '3.0.0']]);
    foreach (['0.1.0' => true, '1.0.0' => false, '1.5.0' => false, '2.0.0' => true, '3.0.0' => true, '3.0.1' => false] as $version => $expected) {
        $hit = false;
        foreach ($intervals as [$a, $b, $inclusive]) $hit = $hit || \Magebean\Engine\Cve\OsvRange::contains($version, $a, $b, $inclusive);
        qaExpect($hit === $expected, 'QA-06 multiple intervals ' . $version);
    }
    foreach (['ECDHE-RSA-AES256-GCM-SHA384' => true, 'ECDHE-RSA-AES256-GCM-SHA384:RC4' => false, 'ECDHE-RSA-AES256-GCM-SHA384:RC4:!RC4' => true, '!RC4:RC4:ECDHE-RSA-AES256-GCM-SHA384' => true, 'HIGH' => null, 'ECDHE-NONSENSE' => null, 'ECDHE-RSA-AES256-GCM-SHA384:3DES:!DES' => false] as $expression => $expected) {
        qaExpect($cipher->invoke($web, $expression)['ok'] === $expected, 'QA-08 cipher semantics ' . $expression);
    }
    file_put_contents($root . '/nginx.conf', "ssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers ALL:ECDHE;\n");
    qaExpect($web->tlsCiphers(['files' => ['nginx.conf']])[0] === null, 'QA-08 public UNKNOWN');
    foreach ([
        "/var/log/nginx/access.log {\ndaily\nrotate 7\ncompress\n}\n" => true,
        "daily\nrotate 7\ncompress\n/var/log/nginx/access.log {\ndelaycompress\n}\n" => true,
        "/var/log/nginx/access.log {\ndaily\nrotate 7\ndelaycompress\n}\n" => false,
        "/var/log/nginx/access.log {\ndaily\nrotate 7\ncompress\nnocompress\n}\n" => false,
        "/var/log/nginx/a.log {\ndaily\nrotate 7\n}\n/var/log/nginx/b.log {\ncompress\n}\n" => false,
        "/var/log/nginx/access.log {\ndaily\nrotate -1\ncompress\n}\n" => false,
        "include /etc/logrotate.d\n" => null,
    ] as $config => $expected) {
        file_put_contents($root . '/rotate.conf', $config);
        qaExpect((new FilesystemCheck($ctx))->logRotationConfigured(['file' => 'rotate.conf'])[0] === $expected, 'QA-09 block/default/override ' . substr(md5($config), 0, 6));
    }
    foreach (['2024-02-29T23:59:59Z' => true, '2026-02-28T12:00:00.123+07:00' => true, '2026-02-30T12:00:00Z' => false, '2026-01-01T25:00:00Z' => false, '2026-01-01T00:00:00+24:00' => false] as $time => $expected) {
        $bad = $external; $bad['evidence'][0]['collected_at'] = $time; file_put_contents($root . '/external.json', json_encode($bad));
        qaExpect($importer->import($root . '/external.json')['valid'] === $expected, 'QA-12 absolute timestamp ' . $time);
    }
    $markup = new ReflectionMethod(\Magebean\Engine\Checks\HttpCheck::class, 'mixedContentInMarkup');
    $http = new \Magebean\Engine\Checks\HttpCheck($ctx);
    foreach (['<a href="http://example.test/">Navigate</a>' => 0, '<img src="http://example.test/x.png">' => 1, '<link href="http://example.test/x.css" rel="stylesheet">' => 1, '<!-- <img src="http://example.test/x"> -->' => 0, '<img src="http://w3.org/x.png">' => 1] as $html => $expected) {
        qaExpect(count($markup->invoke($http, $html)) === $expected, 'Supplemental mixed content ' . substr(md5($html), 0, 6));
    }
    mkdir($root . '/deploy');
    file_put_contents($root . '/deploy/cron.conf', "# * * * * * php bin/magento cron:run\n");
    $cron = new \Magebean\Engine\Checks\CronCheck($ctx);
    $repoCron = new ReflectionMethod($cron, 'findRepoCronEvidence');
    $patterns = ['bin/magento\\s+cron:run\\b'];
    qaExpect($repoCron->invoke($cron, ['repo_paths' => ['deploy']], $patterns) === [], 'Supplemental commented cron');
    file_put_contents($root . '/deploy/cron.conf', "* * * * * php bin/magento cron:run\n");
    qaExpect(count($repoCron->invoke($cron, ['repo_paths' => ['deploy']], $patterns)) === 1, 'Supplemental active deployment cron evidence');
    $sarifFindings = [];
    foreach (['PASS', 'FAIL', 'UNKNOWN', 'MANUAL_REVIEW'] as $status) $sarifFindings[] = ['id' => $status, 'status' => $status, 'message' => 'reason-' . $status];
    (new SarifReporter())->write(['findings' => $sarifFindings], $root . '/sarif.json');
    $sarif = json_decode(file_get_contents($root . '/sarif.json'), true);
    qaExpect(count($sarif['runs'][0]['results']) === 3 && $sarif['runs'][0]['tool']['driver']['name'] === 'magebean-cli', 'QA-13 SARIF tool and nonpassing results');
    foreach ($sarif['runs'][0]['results'] as $finding) qaExpect($finding['message']['text'] === 'reason-' . $finding['ruleId'] && $finding['level'] === ($finding['ruleId'] === 'FAIL' ? 'error' : 'note'), 'QA-13 reason/level ' . $finding['ruleId']);
} finally {
    $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($files as $file) $file->isDir() ? rmdir($file->getPathname()) : unlink($file->getPathname()); rmdir($root);
}
foreach ($failures as $failure) fwrite(STDERR, "FAIL {$failure}\n");
echo "QA regression: {$cases} cases, " . count($failures) . " failed\n";
exit($failures === [] ? 0 : 1);
