<?php
declare(strict_types=1);

require __DIR__.'/../vendor/autoload.php';

use Magebean\Agent\AgentScanner;
use Magebean\Engine\{ScanContext, ScanExitPolicy, ScanPlanner, ScanReportAssembler, ScanRequest, ScanService};
use Magebean\Engine\Checks\CheckRegistry;

function integrityAssert(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

$root = sys_get_temp_dir().'/mb-integrity-'.bin2hex(random_bytes(6));
$put = static function (string $path, string $content) use ($root): void {
    $target = $root.'/'.$path;
    if (!is_dir(dirname($target))) mkdir(dirname($target), 0700, true);
    file_put_contents($target, $content);
};
$json = static fn(array $value): string => json_encode($value, JSON_THROW_ON_ERROR);
$subject = 'packages/extension';
$attribute = ' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="urn:magento:framework:Fixture/';
$schema = '<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">';
$moduleXml = static fn(string $name): string => '<config'.$attribute.'module.xsd"><module name="'.$name.'"/></config>';
$registration = static fn(string $name): string => '<?php \Magento\Framework\Component\ComponentRegistrar::register(\Magento\Framework\Component\ComponentRegistrar::MODULE, '.var_export($name, true).', __DIR__);';
$scan = static function (array $options) use ($root): array {
    $context = new ScanContext($root, '');
    $registry = CheckRegistry::fromContext($context->toLegacy());
    $plan = (new ScanPlanner())->planCli(new ScanRequest($context, $options), $registry);
    integrityAssert($plan !== null, 'Module profile produced an executable plan.');
    $report = (new ScanService())->run($plan, null, $registry);
    return (new ScanReportAssembler())->assemble($report, $plan)->toLegacy();
};
$route = static fn(string $path, string $method, string $ref): string =>
    '<route url="/V1/'.$path.'" method="GET"><service class="Fixture\Ext\Api\Contract" method="'.$method.'"/><resources><resource ref="'.$ref.'"/></resources></route>';
$webapi = static fn(string $routes): string => '<routes'.$attribute.'webapi.xsd">'.$routes.'</routes>';
try {
    $put('bin/magento', '<?php throw new RuntimeException("Do not execute this fixture");');
    $put('app/etc/config.php', '<?php return ["modules" => ["Fixture_Local" => 1, "Fixture_Ext" => 1]];');
    $put('app/etc/env.php', '<?php return [];');
    $put('composer.json', $json(['name' => 'fixture/project', 'require' => ['magento/framework' => '*']]));
    $put('vendor/composer/installed.json', $json(['packages' => [
        ['name' => 'magento/framework', 'install-path' => '../magento/framework'],
        ['name' => 'fixture/extension', 'version' => '1.0', 'type' => 'magento2-module', 'install-path' => '../../packages/extension'],
        ['name' => 'fixture/replacement', 'type' => 'metapackage', 'replace' => ['fixture/virtual' => '*']],
    ]]));
    $put('vendor/magento/framework/Fixture/module.xsd', $schema.'<xs:element name="config"><xs:complexType><xs:sequence><xs:element name="module"><xs:complexType><xs:attribute name="name" type="xs:string" use="required"/></xs:complexType></xs:element></xs:sequence></xs:complexType></xs:element></xs:schema>');
    $put('vendor/magento/framework/Fixture/webapi.xsd', $schema.'<xs:element name="routes" type="xs:anyType"/></xs:schema>');
    $put('vendor/magento/framework/Fixture/acl.xsd', $schema.'<xs:element name="config" type="xs:anyType"/></xs:schema>');
    $put('app/code/Fixture/Local/registration.php', $registration('Fixture_Local'));
    $put('app/code/Fixture/Local/etc/module.xml', $moduleXml('Fixture_Local'));
    $put('app/code/Fixture/Local/etc/acl.xml', '<config'.$attribute.'acl.xsd"><acl><resources><resource id="Fixture_Local::allowed"/></resources></acl></config>');
    $put($subject.'/registration.php', $registration('Fixture_Ext'));
    $put($subject.'/etc/module.xml', $moduleXml('Fixture_Ext'));
    $put($subject.'/composer.json', $json(['name' => 'fixture/extension', 'require' => ['php' => '*', 'fixture/virtual' => '*', 'fixture/missing' => '*']]));
    $put($subject.'/Api/Contract.php', '<?php namespace Fixture\Ext\Api; interface Contract { public function listItems(): array; }');
    $put($subject.'/Logger.php', '<?php $logger->info("fixture", $_GET);');
    $put($subject.'/etc/webapi.xml', $webapi(
        $route('catalog/public', 'listItems', 'anonymous').$route('private/export', 'listItems', 'anonymous')
        .$route('protected/list', 'listItems', 'Fixture_Local::allowed')
        .$route('owner/list', 'listItems', 'self')
        .$route('internal/list', 'missing', 'Fixture_Ext::typo')
    ));
    $put($subject.'/etc/frontend/routes.xml', '<config>'); // supported XML syntax failure
    $put($subject.'/etc/adminhtml/acl.xml', '<incorrect'.$attribute.'acl.xsd"/>'); // resolvable XSD rejects root

    $default = $scan(['profile' => 'module-integrity']);
    integrityAssert((new ScanExitPolicy())->code($default) === 0, 'Default scope audits app/code and skips Composer source.');
    $options = ['profile' => 'module-integrity', 'modules' => 'Fixture_Ext'];
    $selected = $scan($options);
    $risk = array_column($selected['risk_findings'], 'risk_observation', 'id');
    integrityAssert((new ScanExitPolicy())->code($selected) === 1, 'Confirmed and suspected observations are actionable with complete collection.');
    integrityAssert(array_keys($risk) === ['MB-0809', 'MB-0810', 'MB-0811', 'MB-0812', 'MB-0813', 'MB-0814'], 'All supported detectors report the exact selected failures.');
    integrityAssert(count($risk['MB-0809']['findings']) === 2, 'Malformed syntax and local XSD rejection are both distinguishable.');
    integrityAssert(count($risk['MB-0810']['findings']) === 1 && $risk['MB-0810']['findings'][0]['evidence']['subject']['symbol'] === 'fixture/missing', 'Package replacement and platform requirements do not create false positives.');
    integrityAssert(count($risk['MB-0812']['findings']) === 1 && $risk['MB-0812']['findings'][0]['confidence'] === 'suspected', 'Enabled cross-module ACL and reserved resources resolve.');
    integrityAssert(count($risk['MB-0813']['findings']) === 1 && $risk['MB-0813']['findings'][0]['confidence'] === 'suspected'
        && count($risk['MB-0813']['observations']) === 4, 'Intentional public routes stay informational.');
    integrityAssert($risk['MB-0814']['findings'][0]['category'] === 'policy' && $risk['MB-0814']['findings'][0]['evidence']['subject']['package'] === 'fixture/extension', 'Reused logging policy retains package attribution.');
    integrityAssert(!str_contains(json_encode($selected), '$_GET'), 'Findings do not include raw source.');

    $wire = (new AgentScanner())->run($root, ['schema_version' => '1.0', 'requirement_family' => 'magebean',
        'module_names' => ['Fixture_Ext'], 'rules' => [['rule_key' => 'MB-0813', 'assessment_item_id' => 'fixture-route']]]);
    integrityAssert($wire['results'][0]['assessment_item_id'] === 'fixture-route'
        && $wire['results'][0]['evidence']['risk_observation']['findings'][0]['confidence'] === 'suspected', 'Agent preserves route confidence and manifest identity.');

    $entry = $argv[1] ?? (getenv('MAGEBEAN_TEST_ENTRY') ?: __DIR__.'/../bin/magebean');
    $process = proc_open([PHP_BINARY, $entry, 'scan', '--path='.$root, '--profile=module-integrity', '--modules=Fixture_Ext', '--no-ansi'],
        [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    integrityAssert(is_resource($process), 'CLI fixture launches.');
    $out = stream_get_contents($pipes[1]); $err = stream_get_contents($pipes[2]);
    fclose($pipes[1]); fclose($pipes[2]);
    integrityAssert(proc_close($process) === 1 && !str_contains($out, 'Suspected') && str_contains($out, 'fixture/extension'), 'CLI profile reports scoped findings: '.$out.$err);

    $put($subject.'/Di.php', <<<'PHP'
<?php
namespace Fixture\Di;
interface Contract {}
class Good implements Contract {}
class Wrong {}
class ParentService { public function __construct(string $value) {} }
class Service extends ParentService { final public function execute() {} }
class Hooks { public function beforeExecute(Service $subject) {} }
PHP);
    $put($subject.'/etc/di.xml', <<<'XML'
<config xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <preference for="Fixture\Di\Contract" type="Fixture\Di\Good"/>
  <virtualType name="FixtureVirtual" type="Fixture\Di\Good"/>
  <type name="Fixture\Di\Service">
    <arguments><argument name="value" xsi:type="string">private fixture value</argument></arguments>
    <plugin name="example" type="Fixture\Di\Hooks"/>
  </type>
</config>
XML);
    $put($subject.'/etc/frontend/di.xml', <<<'XML'
<config xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <preference for="Fixture\Di\Contract" type="Fixture\Di\Wrong"/>
  <virtualType name="FixtureVirtual" type="FixtureCycle"/>
  <virtualType name="FixtureCycle" type="FixtureVirtual"/>
  <type name="Fixture\Di\Service">
    <arguments><argument name="value" xsi:type="array"/></arguments>
    <plugin name="example" disabled="true"/>
  </type>
</config>
XML);
    $di = $scan($options + ['rules' => 'MB-0815,MB-0816,MB-0817,MB-0818']);
    $diRisk = array_column($di['risk_findings'], 'risk_observation', 'id');
    integrityAssert(array_keys($diRisk) === ['MB-0815', 'MB-0816', 'MB-0817', 'MB-0818'], 'All four DI criteria report scoped observations.');
    integrityAssert($diRisk['MB-0815']['findings'][0]['evidence']['subject']['area'] === 'frontend', 'Valid global preference does not hide the invalid area override.');
    integrityAssert(str_contains($diRisk['MB-0816']['findings'][0]['issue_key'], 'cycle'), 'Virtual type cycle remains visible.');
    integrityAssert(str_contains($diRisk['MB-0817']['findings'][0]['issue_key'], 'array_argument'), 'Inherited constructor parameter type is resolved.');
    integrityAssert(count($diRisk['MB-0818']['findings']) === 1
        && $diRisk['MB-0818']['findings'][0]['evidence']['subject']['area'] === 'global', 'Disabled frontend plugin is excluded from area findings.');
    integrityAssert(!str_contains(json_encode($di), 'private fixture value'), 'DI argument values stay private.');

    $put($subject.'/etc/frontend/di.xml', '<config><preference for="Fixture\Di\Contract" type="Fixture\Di\GeneratedFactory"/></config>');
    $unsupported = $scan($options + ['rules' => 'MB-0815']);
    integrityAssert((new ScanExitPolicy())->code($unsupported) === 3 && $unsupported['risk_findings'] === [], 'Unindexed generated target is incomplete, not a finding.');

    $sourceOptions = ['profile' => 'module-source', 'modules' => 'Fixture_Ext'];
    $missingTarget = $scan($sourceOptions + ['rules' => 'MB-0819']);
    integrityAssert((new ScanExitPolicy())->code($missingTarget) === 3, 'Missing PHP target is incomplete.');
    $put('composer.json', $json(['name' => 'fixture/project', 'require' => ['magento/framework' => '*'], 'config' => ['platform' => ['php' => '8.1.0']]]));
    $installedPath = 'vendor/composer/installed.json';
    $installed = json_decode(file_get_contents($root.'/'.$installedPath), true, 512, JSON_THROW_ON_ERROR);
    $installed['packages'][0]['version'] = '103.0.6';
    $put($installedPath, $json($installed));
    $put($subject.'/composer.json', $json(['name' => 'fixture/extension', 'require' => ['magento/framework' => '^104.0']]));
    $put($subject.'/Source.php', <<<'PHP'
<?php
namespace Fixture\Source;
readonly class NewSyntax {}
interface Contract { public static function run(): void; }
class Implementation implements Contract { public function run(): void {} }
function query($connection) {
    $value = $_GET['id'];
    $connection->query('SELECT * FROM items WHERE id = '.$value);
    $connection->query('SELECT * FROM items WHERE id = ?', [$_GET['id']]);
    $connection->query('SELECT * FROM items WHERE id = '.(int) $_GET['id']);
    \exec($_POST['job']);
    $connection->query("SELECT * FROM items WHERE id = {$_GET['id']}");
}
PHP);
    $sourceResult = $scan($sourceOptions);
    $sourceRisk = array_column($sourceResult['risk_findings'], 'risk_observation', 'id');
    integrityAssert(array_keys($sourceRisk) === ['MB-0819', 'MB-0820', 'MB-0821', 'MB-0822'], 'Source profile emits all supported detector outcomes.');
    integrityAssert(count($sourceRisk['MB-0822']['findings']) === 3 && $sourceRisk['MB-0822']['findings'][0]['confidence'] === 'suspected',
        'Direct, interpolated and one-hop input flows are flagged while bound parameters and integer casts are excluded.');
    integrityAssert(count($sourceRisk['MB-0822']['findings'][0]['evidence']['locations']) === 2, 'One-hop finding records source and sink.');
    integrityAssert(!str_contains(json_encode($sourceResult), 'SELECT *'), 'Source evidence excludes SQL text.');
    $process = proc_open([PHP_BINARY, $entry, 'scan', '--path='.$root, '--profile=module-source', '--modules=Fixture_Ext', '--no-ansi'],
        [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    integrityAssert(is_resource($process), 'Source CLI fixture launches.');
    $out = stream_get_contents($pipes[1]); $err = stream_get_contents($pipes[2]);
    fclose($pipes[1]); fclose($pipes[2]);
    integrityAssert(proc_close($process) === 1 && str_contains($out, 'MB-0822') && !str_contains($out, 'Suspected'),
        'Source CLI reports suspected observations: '.$out.$err);
    $put($subject.'/BrokenSource.php', '<?php function broken(');
    $partialSource = $scan($sourceOptions);
    integrityAssert((new ScanExitPolicy())->code($partialSource) === 3 && count($partialSource['risk_findings']) === 4,
        'Malformed source leaves collection incomplete and retains valid observations.');

    unlink($root.'/'.$subject.'/BrokenSource.php');
    $lifecycleOptions = ['profile' => 'module-lifecycle', 'modules' => 'Fixture_Ext'];
    $reliabilityOptions = ['profile' => 'module-reliability', 'modules' => 'Fixture_Ext'];
    $put('vendor/magento/framework/Fixture/schema.xsd', $schema.'<xs:element name="schema" type="xs:anyType"/></xs:schema>');
    $put($subject.'/etc/db_schema.xml', '<schema'.$attribute.'schema.xsd"/>');
    $put($subject.'/Operations.php', <<<'PHP'
<?php
namespace Fixture\Operations;
class Handler {
    public function run(): void {}
    private function hidden(): void {}
}
function process(array $items, $connection) {
    try { work(); } catch (\RuntimeException $e) { logError($e); }
    foreach ($items as $item) { $connection->query('SELECT 1'); }
}
PHP);
    $put($subject.'/etc/crontab.xml', '<config><group id="default"><job name="fixture" instance="Fixture\Operations\Handler" method="run"/></group></config>');
    $put($subject.'/etc/queue_consumer.xml', '<config><consumer name="fixture" handler="Fixture\Operations\Handler::run"/><consumer name="custom" consumerInstance="Vendor\Custom\Consumer" handler="Unindexed::handler"/></config>');
    $put($subject.'/etc/communication.xml', '<config><topic name="fixture"><handler name="disabled" type="Unindexed" method="run" disabled="true"/></topic></config>');
    $patch = static function (string $name, string $dependency): string {
        return '<?php namespace Fixture\Ext\Setup\Patch\Data; use Magento\Framework\Setup\Patch\DataPatchInterface; class '.$name
            .' implements DataPatchInterface { public static function getDependencies(): array { return ['.$dependency.']; } }';
    };
    $put($subject.'/Setup/Patch/Data/First.php', $patch('First', ''));
    $put($subject.'/Setup/Patch/Data/Second.php', $patch('Second', 'First::class'));
    $benignLifecycle = $scan($lifecycleOptions);
    integrityAssert((new ScanExitPolicy())->code($benignLifecycle) === 0, 'Valid lifecycle configuration and static patch dependencies pass the supported scope.');
    $benignReliability = $scan($reliabilityOptions);
    integrityAssert((new ScanExitPolicy())->code($benignReliability) === 0 && $benignReliability['risk_findings'] === []
        && count($benignReliability['findings'][1]['risk_observation']['observations']) === 1,
        'A direct loop query is informational and does not increase the exit status.');

    $put($subject.'/etc/db_schema.xml', '<wrong'.$attribute.'schema.xsd"/>');
    $put($subject.'/Setup/Patch/Data/First.php', $patch('First', 'Second::class'));
    $put($subject.'/Setup/Patch/Schema/Invalid.php', '<?php namespace Fixture\Ext\Setup\Patch\Schema; class Invalid {}');
    $put($subject.'/Setup/Patch/Schema/WrongName.php', '<?php namespace Fixture\Ext\Setup\Patch\Schema; class Unrelated {}');
    $put($subject.'/etc/crontab.xml', '<config><group id="default"><job name="fixture" instance="Fixture\Operations\Handler" method="hidden"/></group></config>');
    $put($subject.'/etc/queue_consumer.xml', '<config><consumer name="fixture" handler="Fixture\Operations\Handler::missing"/></config>');
    $lifecycle = $scan($lifecycleOptions);
    $lifecycleRisk = array_column($lifecycle['risk_findings'], 'risk_observation', 'id');
    integrityAssert((new ScanExitPolicy())->code($lifecycle) === 1 && array_keys($lifecycleRisk) === ['MB-0823', 'MB-0824', 'MB-0825'],
        'The lifecycle profile surfaces confirmed schema, patch and handler defects.');
    integrityAssert(count($lifecycleRisk['MB-0825']['findings']) === 2, 'Cron and default consumer declarations resolve separately.');
    $patchKeys = array_column($lifecycleRisk['MB-0824']['findings'], 'issue_key');
    integrityAssert(in_array('patch-interface-mismatch', $patchKeys, true) && in_array('patch-dependency-cycle', $patchKeys, true) && in_array('patch-class-declaration-unavailable', $patchKeys, true),
        'Patch interface mismatch and cycle are separate findings.');

    $put($subject.'/Setup/Patch/Data/Third.php', $patch('Third', '\External\MissingPatch::class'));
    $partialLifecycle = $scan($lifecycleOptions);
    integrityAssert((new ScanExitPolicy())->code($partialLifecycle) === 3 && count($partialLifecycle['risk_findings']) === 3,
        'An unresolved patch dependency preserves confirmed findings and marks coverage incomplete.');
    $put($subject.'/Uncaught.php', '<?php try { work(); } catch (\RuntimeException $e) {}');
    $reliability = $scan($reliabilityOptions);
    $reliabilityRisk = array_column($reliability['risk_findings'], 'risk_observation', 'id');
    integrityAssert((new ScanExitPolicy())->code($reliability) === 1 && array_keys($reliabilityRisk) === ['MB-0826']
        && $reliabilityRisk['MB-0826']['findings'][0]['confidence'] === 'suspected', 'Only the empty catch enters reliability attention.');
    foreach (['module-lifecycle' => ['MB-0824', 3], 'module-reliability' => ['MB-0826', 1]] as $profile => [$rule, $exit]) {
        $process = proc_open([PHP_BINARY, $entry, 'scan', '--path='.$root, '--profile='.$profile, '--modules=Fixture_Ext', '--no-ansi'],
            [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        integrityAssert(is_resource($process), 'Operations CLI fixture launches.');
        $out = stream_get_contents($pipes[1]); $err = stream_get_contents($pipes[2]);
        fclose($pipes[1]); fclose($pipes[2]);
        integrityAssert(proc_close($process) === $exit && str_contains($out, $rule), 'Operations CLI profile reports scoped observations: '.$out.$err);
    }

    $put($subject.'/etc/module.xml', $moduleXml('Fixture_Wrong'));
    $mismatch = $scan($options);
    integrityAssert((new ScanExitPolicy())->code($mismatch) === 3
        && $mismatch['risk_findings'][0]['risk_observation']['findings'][0]['issue_key'] === 'identity-mismatch', 'Confirmed identity mismatch survives incomplete analysis.');

    $unknown = $scan(['profile' => 'module-integrity', 'modules' => 'Missing_Module']);
    integrityAssert((new ScanExitPolicy())->code($unknown) === 3 && $unknown['risk_findings'] === [], 'Unresolved selection cannot look clean.');
} finally {
    if (is_dir($root)) {
        $tree = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($tree as $file) {
            if ($file->isDir() && !$file->isLink()) rmdir($file->getPathname());
            else unlink($file->getPathname());
        }
        rmdir($root);
    }
}
echo "Module integrity profile and CLI passed\n";
