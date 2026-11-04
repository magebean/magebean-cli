<?php
declare(strict_types=1);

require __DIR__.'/../vendor/autoload.php';

use Magebean\Engine\Collectors\CollectorSet;
use Magebean\Engine\Collectors\MagentoXmlIndex;
use Magebean\Engine\Context;

function moduleAssert(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

$root = sys_get_temp_dir().'/magebean-module-analysis-'.bin2hex(random_bytes(6));
$put = static function (string $path, string $source) use ($root): void {
    $target = $root.'/'.$path;
    if (!is_dir(dirname($target))) mkdir(dirname($target), 0700, true);
    file_put_contents($target, $source);
};
$registration = static fn(string $type, string $name): string => '<?php
use Magento\Framework\Component\ComponentRegistrar as Registrar;
Registrar::register(Registrar::'.$type.', '.var_export($name, true).', __DIR__);';
$module = static function (string $path, string $name) use ($put, $registration): void {
    $put($path.'/registration.php', $registration('MODULE', $name)."\nfile_put_contents(__DIR__.'/executed', 'forbidden');");
    $put($path.'/etc/module.xml', '<config xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="urn:magento:framework:Module/etc/module.xsd"><module name="'.$name.'"/></config>');
};
try {
    $config = ['Fixture_Local' => 1, 'Vendor_One' => 1, 'Vendor_Two' => 0, 'Vendor_Standard' => 1, 'Vendor_Absent' => 0];
    $put('app/etc/config.php', '<?php return '.var_export(['modules' => $config], true).';');
    $put('vendor/composer/installed.json', json_encode(['packages' => [
        ['name' => 'magento/framework', 'version' => '103.0.9', 'install-path' => '../magento/framework'],
        ['name' => 'vendor/standard', 'version' => '1.0.0', 'type' => 'magento2-module'],
        ['name' => 'vendor/bundle', 'version' => '2.3.0', 'type' => 'magento2-module', 'install-path' => '../../packages/bundle',
            'autoload' => ['files' => ['One/registration.php', 'Two/registration.php']]],
    ]], JSON_THROW_ON_ERROR));
    $module('app/code/Fixture/Local', 'Fixture_Local');
    $module('packages/bundle/One', 'Vendor_One');
    $module('packages/bundle/Two', 'Vendor_Two');
    $module('vendor/vendor/standard', 'Vendor_Standard');
    $put('app/design/frontend/Fixture/example/registration.php', $registration('THEME', 'frontend/Fixture/example'));
    $put('vendor/magento/framework/Module/etc/module.xsd', '<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"><xs:include schemaLocation="types.xsd"/><xs:element name="config" type="ModuleConfig"/></xs:schema>');
    $put('vendor/magento/framework/Module/etc/types.xsd', '<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"><xs:complexType name="ModuleConfig"><xs:sequence><xs:element name="module"><xs:complexType><xs:attribute name="name" type="xs:string" use="required"/></xs:complexType></xs:element></xs:sequence></xs:complexType></xs:schema>');
    $put('app/code/Fixture/Local/Service.php', <<<'PHP'
<?php
namespace Fixture\Local;
use Vendor\Contracts\Service as Contract;
use Vendor\BaseService as Base;
final class Service extends Base implements Contract {
    public function __construct(private ?Contract $contract = null) {}
    public function run(Contract|string $input): ?Base { return null; }
}
PHP);
    $put('app/code/Fixture/Local/etc/frontend/di.xml', '<config xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="urn:magento:framework:Module/etc/module.xsd"><wrong/></config>');

    $ctx = new Context($root, '');
    $collectors = new CollectorSet();
    $collectors->session->begin();
    $inventory = $collectors->magentoModules->collect($ctx);
    moduleAssert($inventory['complete'], json_encode($inventory['gaps']));
    $modules = array_column($inventory['modules'], null, 'identity');
    moduleAssert(count($modules) === 5 && count($inventory['themes']) === 1, 'Themes and multi-module package are separate inventory records');
    moduleAssert($modules['Fixture_Local']['state'] === 'enabled' && $modules['Vendor_Two']['state'] === 'disabled'
        && $modules['Vendor_Absent']['state'] === 'absent', 'Configuration state remains explicit');
    moduleAssert($modules['Vendor_One']['root'] === 'packages/bundle/One' && $modules['Vendor_One']['package'] === 'vendor/bundle'
        && $modules['Vendor_Two']['version'] === '2.3.0', 'Composer custom paths and provenance come from installed metadata');
    moduleAssert($modules['Vendor_Standard']['origin'] === 'composer'
        && $modules['Vendor_Standard']['package_path_source'] === 'composer_default_layout', 'Composer v1 path fallback keeps its provenance');
    moduleAssert(!file_exists($root.'/app/code/Fixture/Local/executed'), 'Registration code was never executed');
    $analysis = $collectors->magentoAnalysis->collect($ctx, ['Fixture_Local'], ['validate_schemas' => true]);
    moduleAssert($analysis['complete'], json_encode($analysis['gaps']));
    $symbol = $analysis['symbols']['fixture\local\service'][0];
    moduleAssert($symbol['extends'] === ['Vendor\BaseService'] && $symbol['implements'] === ['Vendor\Contracts\Service']
        && $symbol['methods']['__construct']['parameters'][0]['type'] === '?Vendor\Contracts\Service'
        && $symbol['methods']['run']['parameters'][0]['type'] === 'Vendor\Contracts\Service|string', 'Static symbol index resolves aliases and preserves signatures');
    $docs = $analysis['documents'];
    moduleAssert($docs['app/code/Fixture/Local/etc/module.xml']['schema_status'] === 'valid'
        && $docs['app/code/Fixture/Local/etc/frontend/di.xml']['schema_status'] === 'invalid'
        && $docs['app/code/Fixture/Local/etc/frontend/di.xml']['area'] === 'frontend', json_encode($docs));
    $collectors->magentoAnalysis->collect($ctx, ['Fixture_Local'], ['validate_schemas' => true]);
    moduleAssert($collectors->session->stats()['hits'] >= 2, 'Indexes and inventory are shared within the scan');
    $collectors->session->end();

    $put('app/code/Fixture/Local/Broken.php', '<?php function broken(');
    $put('app/code/Fixture/Local/etc/adminhtml/di.xml', '<config>');
    $put('app/code/Fixture/Local/etc/frontend/routes.xml', '<config xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="urn:magento:framework:Module/etc/missing.xsd"/>');
    $partial = $collectors->magentoAnalysis->collect($ctx, ['Fixture_Local'], ['validate_schemas' => true]);
    $reasons = array_column($partial['gaps'], 'reason');
    moduleAssert(!$partial['complete'] && isset($partial['symbols']['fixture\local\service'])
        && in_array('php_parse_unavailable', $reasons, true) && in_array('xml_parse_unavailable', $reasons, true)
        && in_array('schema_unavailable', $reasons, true), 'Malformed and missing inputs preserve partial indexes without a clean result');
    $limited = $collectors->magentoAnalysis->collect($ctx, ['Fixture_Local'], ['max_files' => 1]);
    moduleAssert($limited['files_read'] === 1 && in_array('file_budget_exceeded', array_column($limited['gaps'], 'reason'), true), 'Selected source budget is enforced');

    $put('vendor/magento/framework/Module/etc/types.xsd', '<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"><xs:include schemaLocation="https://example.invalid/remote.xsd"/></xs:schema>');
    $offline = $collectors->magentoAnalysis->collect($ctx, ['Fixture_Local'], ['validate_schemas' => true]);
    moduleAssert($offline['documents']['app/code/Fixture/Local/etc/module.xml']['schema_status'] === 'schema_unavailable', 'External schema dependencies are rejected');
    moduleAssert(MagentoXmlIndex::parse('<!DOCTYPE config [<!ENTITY external SYSTEM "file:///etc/passwd">]><config>&external;</config>') === null, 'External entity documents are rejected');

    $module('app/code/Other/Duplicate', 'Vendor_One');
    $put('app/code/Fixture/Dynamic/registration.php', '<?php \Magento\Framework\Component\ComponentRegistrar::register(\Magento\Framework\Component\ComponentRegistrar::MODULE, getenv("MODULE"), __DIR__);');
    if (function_exists('symlink') && @symlink($root.'/packages/bundle', $root.'/app/code/Linked')) {
        symlink($root.'/does-not-exist', $root.'/app/code/Fixture/Local/broken-link');
        symlink(sys_get_temp_dir(), $root.'/app/code/Fixture/Local/external-link');
        symlink($root.'/app/code/Fixture/Local', $root.'/app/code/Fixture/Local/loop');
        $linked = $collectors->magentoModules->collect($ctx);
        moduleAssert(in_array('symlink_not_followed', array_column($linked['gaps'], 'reason'), true), 'Internal directory symlinks are visible gaps');
        $linkedSources = $collectors->magentoAnalysis->collect($ctx, ['Fixture_Local']);
        $linkGaps = array_column(array_filter($linkedSources['gaps'], static fn(array $gap): bool => $gap['reason'] === 'symlink_not_followed'), 'file');
        moduleAssert(count($linkGaps) === 3, 'Broken, external and recursive source links are not followed');
    }
    $dupe = $collectors->magentoAnalysis->collect($ctx, ['Vendor_One']);
    moduleAssert(!$dupe['complete'] && count($dupe['inventory']['module_roots']['Vendor_One']) === 2
        && in_array('selected_module_unresolvable', array_column($dupe['gaps'], 'reason'), true)
        && in_array('dynamic_registration_unresolved', array_column($dupe['inventory']['gaps'], 'reason'), true), 'Duplicate and dynamic registrations are incomplete, with no arbitrary root selection');

    unlink($root.'/vendor/composer/installed.json');
    $missing = $collectors->magentoModules->collect($ctx);
    moduleAssert(!$missing['complete'] && in_array('metadata_missing', array_column($missing['gaps'], 'reason'), true), 'Missing Composer install metadata is visible');

    $put('app/etc/config.php', '<?php file_put_contents(__DIR__."/executed", "forbidden"); return ["modules" => ["Fixture_Local" => 1]];');
    $uncertain = $collectors->magentoModules->collect($ctx);
    moduleAssert(!file_exists($root.'/app/etc/executed') && in_array('module_state_unresolved', array_column($uncertain['gaps'], 'reason'), true), 'Dynamic config remains unresolved and passive');
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
echo "Magento module inventory and static indexes passed\n";
