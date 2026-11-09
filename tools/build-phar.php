<?php
declare(strict_types=1);
require __DIR__.'/PharReleaseGuard.php';
$root=dirname(__DIR__);chdir($root);
function buildRun(array $command):string
{
    $process=proc_open($command,[0=>['pipe','r'],1=>['pipe','w'],2=>['file','php://stderr','w']],$pipes);
    if(!is_resource($process))throw new RuntimeException('Unable to start build command.');
    fclose($pipes[0]);$output=stream_get_contents($pipes[1]);fclose($pipes[1]);$exit=proc_close($process);
    if($exit!==0)throw new RuntimeException('Build command failed ('.$exit.'): '.implode(' ',$command));
    return $output;
}
try{
    if(array_diff(array_slice($argv,1),['--one-time'])!==[])throw new RuntimeException('Usage: php tools/build-phar.php [--one-time]');
    $oneTime=in_array('--one-time',$argv,true);$config=json_decode((string)file_get_contents($oneTime?'box.one-time.json':'box.json'),true,512,JSON_THROW_ON_ERROR);
    $build=$root.'/build';if(!is_dir($build)&&!mkdir($build,0755,true))throw new RuntimeException('Cannot create build directory.');
    $lock=fopen($build.'/release.lock','c');if(!$lock||!flock($lock,LOCK_EX|LOCK_NB))throw new RuntimeException('Another PHAR build is running.');
    $candidate=$build.'/magebean-candidate-'.bin2hex(random_bytes(6)).'.phar';
    $output=$root.'/'.($oneTime?'artifacts/magebean-one-time.phar':'magebean.phar');
    $config['base-path']=$root;$config['output']=$candidate;
    $generated=$build.'/box-release-'.bin2hex(random_bytes(6)).'.json';
    file_put_contents($generated,json_encode($config,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR));
    echo "Building a production-only candidate...\n";
    echo buildRun([PHP_BINARY,'-d','phar.readonly=0',$root.'/box.phar','compile','--config='.$generated,'--no-interaction','--no-ansi','--no-parallel']);
    $report=PharReleaseGuard::inspect($candidate,$root.'/composer.lock');
    $version=buildRun([PHP_BINARY,$candidate,'--version']);if(!str_contains($version,'Magebean'))throw new RuntimeException('CLI version smoke test failed.');
    $list=buildRun([PHP_BINARY,$candidate,'list','--raw']);foreach(['scan','rules:list','agent:status','agent:doctor','agent:tick']as$command)if(!str_contains($list,$command))throw new RuntimeException('Missing command: '.$command);
    $auditHelp = buildRun([PHP_BINARY, $candidate, 'audit', '--help', '--no-ansi']);
    if (!str_contains($auditHelp, '--profile')) throw new RuntimeException('Audit alias smoke test failed.');
    $profiles=json_decode((string)file_get_contents('src/Rules/requirements/internal-profiles.json'),true)['profiles'];
    $definitions=array_column(json_decode((string)file_get_contents('src/Rules/requirements/magebean-catalog.json'),true)['requirements'],null,'id');
    foreach(['basic','hardening','owasp-top-10-2025','module-integrity','module-source','module-lifecycle','module-reliability','development','prelaunch']as$profile){
        $expected=count(array_filter($profiles[$profile]['requirement_ids'],static fn(string$id):bool=>empty($definitions[$id]['applicability']['capability'])&&in_array('LOCAL',$definitions[$id]['target_modes'],true)));
        $listing=buildRun([PHP_BINARY,$candidate,'rules:list','--profile='.$profile,'--no-ansi']);
        if(!str_contains($listing,'Total Rules Listed: '.$expected."\n"))throw new RuntimeException('Profile smoke test failed: '.$profile);
    }
    $report['smoke_tests']=['version','commands','basic','hardening','owasp-top-10-2025','module-integrity','module-source','module-lifecycle','module-reliability','development','prelaunch'];
    $runtime=json_decode(buildRun([PHP_BINARY,$root.'/tools/smoke-phar.php',$candidate]),true,512,JSON_THROW_ON_ERROR);
    $report['runtime_smoke']=$runtime;
    $fixture = buildRun([PHP_BINARY, $root.'/tests/MagentoModuleIntegrityProfileTest.php', $candidate]);
    if (!str_contains($fixture, 'Module integrity profile and CLI passed')) {
        throw new RuntimeException('Packaged module audit fixture did not complete.');
    }
    $report['smoke_tests'][] = 'module-audit-end-to-end';
    $fixture = buildRun([PHP_BINARY, $root.'/tests/DevelopmentPrelaunchProfileTest.php', $candidate]);
    if (!str_contains($fixture, 'Development and prelaunch profiles passed')) {
        throw new RuntimeException('Packaged development/prelaunch fixture did not complete.');
    }
    $report['smoke_tests'][] = 'development-prelaunch-end-to-end';
    if(is_file($output)&&!copy($output,$build.'/previous-'.basename($output)))throw new RuntimeException('Cannot preserve previous release.');
    chmod($candidate,0755);
    if(!rename($candidate,$output))throw new RuntimeException('Cannot publish validated candidate.');
    $candidate=null;
    $manifest = json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)."\n";
    file_put_contents($build.'/release-manifest.json', $manifest);
    file_put_contents($build.'/release-manifest-'.($oneTime ? 'one-time' : 'standard').'.json', $manifest);
    echo 'Published ',basename($output),': ',number_format($report['archive_bytes']/1000000,2),' MB; ',$report['files'],' files; ',$report['runtime_packages']," runtime packages; no forbidden files.\n";
}catch(Throwable $error){fwrite(STDERR,$error->getMessage()."\n");$exitCode=1;}
finally{
    if(isset($generated)&&is_file($generated))unlink($generated);
    if(isset($candidate)&&is_string($candidate)&&is_file($candidate))unlink($candidate);
}
exit($exitCode??0);
