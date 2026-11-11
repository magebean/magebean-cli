<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';

use Magebean\Engine\Context;
use Magebean\Engine\Checks\Families\ComposerAdvisoryChecks;
use Magebean\Engine\Checks\MagentoModuleLifecycleCheck;
use Magebean\Engine\Collectors\CollectorSet;

$n = 0;
$assert = static function (bool $ok, string $message) use (&$n): void {
    ++$n;
    if (!$ok) throw new RuntimeException($message);
};
$root = sys_get_temp_dir().'/mb-development-lifecycle-'.bin2hex(random_bytes(6));
mkdir($root, 0700);
try {
    $valid = ['name'=>'fixture/ok', 'version'=>'1.0.0'];
    file_put_contents($root.'/snapshot.json', json_encode([['id'=>'FIXTURE-1', 'affected'=>[
        ['package'=>['name'=>'fixture/ok', 'ecosystem'=>'Packagist'], 'versions'=>['0.1.0']],
    ]]], JSON_THROW_ON_ERROR));
    $audit = static function (array $lock) use ($root): array {
        file_put_contents($root.'/composer.lock', json_encode($lock, JSON_THROW_ON_ERROR));
        return (new ComposerAdvisoryChecks(new Context($root, '')))->auditOffline([
            'require_explicit_snapshot'=>true, 'cve_data'=>'snapshot.json',
        ]);
    };
    foreach ([
        ['packages'=>[$valid, ['name'=>'fixture/missing-version']]],
        ['packages'=>[$valid], 'packages-dev'=>[['name'=>'fixture/dev-without-version']]],
        ['packages'=>[$valid, $valid]],
        ['packages'=>[$valid], 'packages-dev'=>'invalid'],
        ['packages'=>['one'=>$valid]],
        ['packages'=>[$valid, ['name'=>'fixture/blank-version', 'version'=>' ']]],
    ] as $lock) {
        $result = $audit($lock);
        $assert($result[0] === null && ($result[2]['reason_code']??'') === 'COMPOSER_LOCK_SCOPE_INVALID', 'Malformed lock scope cannot be normalized into an advisory PASS');
    }
    $assert($audit(['packages'=>[$valid]])[0] === true, 'A valid snapshot with no matching versions remains clean');
    $vulnerable = $valid; $vulnerable['version'] = '0.1.0';
    $assert($audit(['packages'=>[$vulnerable]])[0] === false, 'Applicable advisory still reports a finding');

    $checker = new MagentoModuleLifecycleCheck(new Context($root, ''), new CollectorSet());
    $invoke = new ReflectionMethod($checker, 'handlers');
    $class = static fn(string $name, array $methods, array $extra = []): array => $extra + [
        'name'=>$name, 'kind'=>'class', 'abstract'=>false,
        'extends'=>[], 'traits'=>[], 'implements'=>[], 'methods'=>$methods,
    ];
    $public = ['visibility'=>'public', 'abstract'=>false];
    $parent = $class('Dependency\ParentJob', ['execute'=>$public]);
    $child = $class('Fixture\Job', [], ['extends'=>['Dependency\ParentJob']]);
    $modules = ['Fixture_Test'=>['identity'=>'Fixture_Test', 'package'=>null, 'version'=>null]];
    $run = static function (array $symbols) use ($checker, $invoke, $modules): array {
        $gaps = [];
        $analysis = ['symbols'=>$symbols, 'documents'=>['etc/crontab.xml'=>[
            'kind'=>'crontab', 'area'=>'global', 'module'=>'Fixture_Test',
            'declarations'=>[['class'=>'Fixture\Job', 'method'=>'execute', 'line'=>1]],
        ]]];
        $args = [$analysis, $modules, &$gaps];
        return [$invoke->invokeArgs($checker, $args), $gaps];
    };
    [$findings, $gaps] = $run(['fixture\job'=>[$child], 'dependency\parentjob'=>[$parent]]);
    $assert($findings === [] && $gaps === [], 'Indexed concrete inherited public handler resolves without a false collection gap');
    [$findings, $gaps] = $run(['fixture\job'=>[$child]]);
    $assert($findings === [] && ($gaps[0]['reason']??'') === 'handler_inheritance_unresolved', 'Unavailable dependency remains a gap');
    $abstract = $class('Fixture\Job', ['execute'=>$public], ['abstract'=>true]);
    [$findings, $gaps] = $run(['fixture\job'=>[$abstract]]);
    $assert($findings === [] && ($gaps[0]['reason']??'') === 'handler_construction_unresolved', 'Abstract DI target is unresolved rather than a false runtime defect or clean result');
    $interface = $class('Fixture\Job', ['execute'=>$public], ['kind'=>'interface']);
    [$findings, $gaps] = $run(['fixture\job'=>[$interface]]);
    $assert($findings === [] && ($gaps[0]['reason']??'') === 'handler_construction_unresolved', 'Interface DI target requires construction context');
    $privateParent = $parent; $privateParent['methods']['execute']['visibility'] = 'private';
    [$findings, $gaps] = $run(['fixture\job'=>[$child], 'dependency\parentjob'=>[$privateParent]]);
    $assert(count($findings) === 1 && $gaps === [], 'Known inherited nonpublic method remains a supported defect');
    // The selected patch points to an indexed dependency patch. Its type is
    // known, but its transitive patch graph is not part of the audited subjects.
    $patchInterface = 'Magento\Framework\Setup\Patch\DataPatchInterface';
    $patchA = $class('Fixture\Test\Setup\Patch\Data\A', [], [
        'implements'=>[$patchInterface], 'file'=>'app/code/Fixture/Test/Setup/Patch/Data/A.php',
        'line'=>3, 'module'=>'Fixture_Test',
        'patch_dependencies'=>['Dependency\Other\Setup\Patch\Data\B'],
    ]);
    $patchB = $class('Dependency\Other\Setup\Patch\Data\B', [], [
        'implements'=>[$patchInterface], 'file'=>'vendor/dependency/other/Setup/Patch/Data/B.php',
        'line'=>3, 'module'=>null,
        // The real external fixture represents B -> A; context indexing does not
        // supply module patch metadata, so its unknown graph must remain visible.
        'patch_dependencies'=>null,
    ]);
    $patchGaps = [];
    $patchMethod = new ReflectionMethod($checker, 'patches');
    $patchSymbols = [strtolower($patchA['name'])=>[$patchA], strtolower($patchB['name'])=>[$patchB]];
    $patchFiles = [$patchA['file']=>['expected_class'=>$patchA['name'], 'module'=>'Fixture_Test', 'kind'=>'Data']];
    $patchArgs = [$patchSymbols, $patchFiles, $modules, &$patchGaps];
    $patchFindings = $patchMethod->invokeArgs($checker, $patchArgs);
    $assert($patchFindings === [] && ($patchGaps[0]['reason']??'') === 'patch_dependency_graph_unobserved', 'External patch type context cannot silently certify an unobserved transitive graph');
    // Even if a context provider exposes B -> A, B is not an audited patch
    // subject. Do not claim this cross-module cycle has been fully assessed.
    $patchB['patch_dependencies'] = [$patchA['name']];
    $patchSymbols[strtolower($patchB['name'])] = [$patchB];
    $patchGaps = [];
    $patchArgs = [$patchSymbols, $patchFiles, $modules, &$patchGaps];
    $patchFindings = $patchMethod->invokeArgs($checker, $patchArgs);
    $assert($patchFindings === [] && ($patchGaps[0]['reason']??'') === 'patch_dependency_graph_unobserved', 'A selected A to external B to A cycle cannot become a false clean graph');


    echo "Development lifecycle/advisory regression: $n assertions passed\n";
} finally {
    foreach (['composer.lock','snapshot.json'] as $file) if (is_file($root.'/'.$file)) unlink($root.'/'.$file);
    rmdir($root);
}
