<?php
declare(strict_types=1);
$archive=isset($argv[1])?realpath($argv[1]):null;
if (isset($argv[1]) && !$archive) throw new RuntimeException('Supply a valid PHAR path.');
require $archive?'phar://'.$archive.'/vendor/autoload.php':__DIR__.'/../vendor/autoload.php';
use Magebean\Engine\{Context};
use Magebean\Engine\Collectors\{CollectorSet};
use Magebean\Engine\Checks\{DeploymentStateCheck,CronCheck};
use Magebean\Engine\Checks\Families\{ComposerAdvisoryChecks,ComposerRepositoryChecks,ComposerVersionChecks};
$n=0;$assert=static function(bool $ok,string $m)use(&$n):void{++$n;if(!$ok)throw new RuntimeException($m);};
$root=sys_get_temp_dir().'/mb-phase2-'.bin2hex(random_bytes(6));mkdir($root,0700);$server=null;
$put=static function(string $file,mixed $value)use($root):void{
    $dir=dirname($root.'/'.$file);if(!is_dir($dir))mkdir($dir,0700,true);
    file_put_contents($root.'/'.$file,is_string($value)?$value:json_encode($value,JSON_THROW_ON_ERROR));
};
try {
    $normal=['name'=>'fixture/app','version'=>'1.0.0'];
    $tool=['name'=>'fixture/test-tool','version'=>'1.0.0','require'=>['fixture/dev-only'=>'^1.0']];
    $dev=['name'=>'fixture/dev-only','version'=>'1.0.0'];
    $put('composer.json',['require'=>['fixture/app'=>'^1.0'],'require-dev'=>['fixture/test-tool'=>'^1.0']]);
    $put('composer.lock',['packages'=>[$normal],'packages-dev'=>[$tool,$dev]]);
    $put('vendor/composer/installed.json',['dev'=>false,'packages'=>[$normal]]);
    $put('app/etc/config.php',"<?php return ['modules'=>['Fixture_Enabled'=>1,'Fixture_Disabled'=>0]];");
    $ctx=new Context($root,'');$collectors=new CollectorSet();
    $raw=$collectors->dependencies->collect($ctx);$selected=$collectors->dependencies->select($raw);
    $assert(array_keys($selected['packages'])===['fixture/app'],'Production no-dev selects installed metadata only');
    $assert($selected['scope']==='installed_dependency' && count($selected['excluded_locked_packages'])===2,'Lock-only packages are explicitly excluded from installed scope');
    $assert($selected['declared_modules']===['Fixture_Enabled'=>true,'Fixture_Disabled'=>false],'Enabled and disabled module declarations remain separate facts');
    $assert($selected['packages']['fixture/app']['dependency_observation']['runtime_reachability']==='unverified','Installation metadata is not runtime reachability');
    $assert(isset($selected['observed_at'],$selected['sources']['installed_metadata']['sha256']),'Inventory retains collection time, path and content identity');
    $put('vendor/composer/installed.json',['packages'=>[array_replace($normal,['evidence_source'=>'forged.json','dependency_observation'=>['installed'=>false]])]]);
    $trusted=$collectors->dependencies->select($collectors->dependencies->collect($ctx));
    $assert($trusted['packages']['fixture/app']['dependency_observation']['source_path']==='vendor/composer/installed.json'
        && $trusted['packages']['fixture/app']['dependency_observation']['installed']===true,'Untrusted package fields cannot override collector provenance');
    $put('vendor/composer/installed.json',['packages'=>[$normal,$normal,$normal]]);
    $duplicate=$collectors->dependencies->select($collectors->dependencies->collect($ctx));
    $assert(!$duplicate['complete'] && $duplicate['packages']===[],'Three conflicting duplicate records never reintroduce an arbitrary package identity');
    $put('composer.json',['config'=>['vendor-dir'=>'dependencies'],'require'=>['fixture/app'=>'^1.0'],'require-dev'=>['fixture/test-tool'=>'^1.0']]);
    $put('dependencies/composer/installed.json',['packages'=>[$normal]]);
    $custom=$collectors->dependencies->select($collectors->dependencies->collect($ctx));
    $assert($custom['scope']==='installed_dependency' && $custom['packages']['fixture/app']['dependency_observation']['source_path']==='dependencies/composer/installed.json','Configured vendor directory determines installed evidence source');
    $put('composer.json',['require'=>['fixture/app'=>'^1.0'],'require-dev'=>['fixture/test-tool'=>'^1.0']]);
    $put('vendor/composer/installed.json',['dev'=>false,'packages'=>[$normal]]);
    $socket=stream_socket_server('tcp://127.0.0.1:0');$host=stream_socket_get_name($socket,false);fclose($socket);
    $put('router.php', <<<'PHP'
<?php
$request=json_decode(file_get_contents('php://input'),true);
file_put_contents(__DIR__.'/requests.ndjson',json_encode(['path'=>$_SERVER['REQUEST_URI'],'request'=>$request])."\n",FILE_APPEND);
$control=json_decode(file_get_contents(__DIR__.'/control.json'),true);
if (($control['fail_package']??null)!==null && in_array($control['fail_package'],array_column($request['packages']??[],'name'),true)) { http_response_code(503);echo '{}';return; }
header('Content-Type: application/json');
if ($_SERVER['REQUEST_URI']==='/status') {
    $rows=[];foreach($request['packages'] as $package)$rows[]=$package+['abandoned'=>$package['name']==='fixture/app','abandoned_known'=>true,'release_history_known'=>true,'latest_date'=>'2000-01-01T00:00:00Z'];
    echo json_encode(['schema_version'=>'magebean-package-status-response-v1','packages'=>$rows]);return;
}
if (!empty($control['invalid'])) { echo 'invalid';return; }
echo json_encode(['schema_version'=>'magebean-osv-response-v1','advisories'=>$control['advisories'],'meta'=>['dataset_revision'=>'controlled-phase2']]);
PHP);
    $advisory=static fn(string $name):array=>['id'=>'QA-'.str_replace('/','-',$name),'published'=>'2000-01-01T00:00:00Z','affected'=>[
        ['package'=>['ecosystem'=>'Packagist','name'=>$name],'versions'=>['1.0.0'],'ranges'=>[['type'=>'SEMVER','events'=>[['introduced'=>'0'],['fixed'=>'1.1.0']]]]],
    ]];
    $put('control.json',['advisories'=>[$advisory('fixture/dev-only')]]);
    $server=proc_open([PHP_BINARY,'-S',$host,$root.'/router.php'],[1=>['file',$root.'/server.log','a'],2=>['file',$root.'/server.log','a']],$pipes,$root);
    for($i=0;$i<100;$i++){if($s=@stream_socket_client('tcp://'.$host,timeout:0.05)){fclose($s);break;}usleep(10000);}
    $args=['endpoint'=>'http://'.$host,'status_endpoint'=>'http://'.$host.'/status','strict_scope'=>true,'timeout_ms'=>1000];
    $audit=new ComposerAdvisoryChecks($ctx,$collectors);
    $versionPolicy=(new ComposerVersionChecks($ctx,$collectors))->yankedApi($args);
    $assert($versionPolicy[2]['dependency_inventory']['scope']==='locked_dependency','Explicit yanked build predicate is not silently relabeled as installed runtime state');
    $patchPolicy=(new ComposerAdvisoryChecks($ctx,$collectors))->adobeSecurityPatchesApi($args);
    $assert($patchPolicy[2]['dependency_inventory']['scope']==='locked_dependency','Magento locked-release patch predicate carries build provenance even when product is unavailable');
    $assert($audit->auditApi($args)[0]===true,'No-dev install does not report locked dev advisory as installed vulnerability');
    $assert($audit->transitiveAuditApi($args)[0]===true,'No-dev transitive scope excludes lock-only development graph');
    $locked=$audit->auditApi($args+['dependency_scope'=>'locked']);
    $assert($locked[0]===false && $locked[2]['findings'][0]['dependency_observation']['scope']==='locked_dependency','Explicit lock review retains vulnerable dev package as a build observation');
    $assert(str_contains($locked[1],'installation and runtime exposure unverified'),'Lock-only message does not claim installed runtime vulnerability');
    $put('vendor/composer/installed.json',['dev'=>true,'packages'=>[$normal,$tool,$dev]]);
    $included=$audit->auditApi($args);
    $assert($included[0]===false && $included[2]['findings'][0]['dependency_observation']['development_dependency']===true,'Actually installed development dependency remains actionable');
    $put('snapshot.json',[$advisory('fixture/dev-only')]);
    $snapshot=$audit->auditOffline(['require_explicit_snapshot'=>true,'cve_data'=>'snapshot.json']);
    $assert($snapshot[0]===false && isset($snapshot[2]['dependency_inventory']),'Opt-in snapshot uses the same selected inventory');
    $put('vendor/composer/installed.json',['dev'=>false,'packages'=>[$normal]]);
    $assert($audit->auditOffline(['require_explicit_snapshot'=>true,'cve_data'=>'snapshot.json'])[0]===true,'Snapshot does not resurrect absent dev packages');
    $assert(!is_dir($root.'/.magebean'),'Online and source-only operations do not fabricate a local snapshot directory');
    $put('control.json',['advisories'=>[$advisory('fixture/app')]]);
    $installed=$audit->auditApi($args);
    $assert($installed[0]===false && $installed[2]['findings'][0]['dependency_observation']['installed']===true,'Installed vulnerable package remains a supported finding');
    $put('composer.lock',['packages'=>[array_replace($normal,['version'=>'2.0.0'])],'packages-dev'=>[]]);
    $mismatch=$audit->auditApi($args);
    $assert($mismatch[0]===false && $mismatch[2]['findings'][0]['dependency_observation']['matches_locked_version']===false,'Advisory queries observed installed version despite a different lock version');
    $put('vendor/composer/installed.json',['packages'=>[$normal,['name'=>'fixture/broken']]]);
    $partial=$audit->auditApi($args);
    $assert($partial[0]===false && !$partial[2]['dependency_inventory']['complete'],'Known installed finding survives malformed peer metadata');
    $put('control.json',['advisories'=>[]]);
    $assert($audit->auditApi($args)[0]===null,'Partial installed inventory cannot establish a clean conclusion');
    $put('vendor/composer/installed.json','not json');
    $assert($audit->auditApi($args)[0]===null,'Malformed installed metadata never falls back to an installed lock claim');
    unlink($root.'/vendor/composer/installed.json');
    $put('composer.lock',['packages'=>[$normal],'packages-dev'=>[]]);
    $put('control.json',['advisories'=>[$advisory('fixture/app')]]);
    $sourceOnly=$audit->auditApi($args);
    $assert($sourceOnly[0]===false && $sourceOnly[2]['findings'][0]['dependency_observation']['installed']===null,'Source checkout without installed metadata stays locked-only');

    $put('composer.json',['require'=>['fixture/app'=>'^1.0']]);
    $put('composer.lock',['packages'=>[array_replace($normal,['require'=>['fixture/transitive'=>'^1.0']]),['name'=>'fixture/transitive','version'=>'1.0.0']]]);
    $put('vendor/composer/installed.json',['packages'=>[array_replace($normal,['require'=>['fixture/transitive'=>'^1.0']]),['name'=>'fixture/transitive','version'=>'1.0.0']]]);
    $put('control.json',['advisories'=>[$advisory('fixture/transitive')]]);
    $before=count(file($root.'/requests.ndjson'));
    $collectors->session->begin();
    $assert($audit->auditApi($args)[0]===false,'Shared advisory snapshot finds transitive vulnerability');
    $assert($audit->transitiveAuditApi($args)[0]===false,'Transitive view preserves the same advisory');
    $assert($audit->advisoryLatencyApi($args)[0]===false,'Age view preserves publication-age observation');
    $audit->constraintsConflictApi($args);
    $assert(count(file($root.'/requests.ndjson'))-$before===1,'Related advisory rules share one validated transport response per scan');
    $put('app/etc/config.php',"<?php return ['modules'=>['Fixture_Enabled'=>0]];");
    $moduleSnapshot=$collectors->magentoModules->collect($ctx);
    $assert(in_array('module_state_changed_during_collection',array_column($moduleSnapshot['gaps'],'reason'),true),'Changed module declarations cannot be combined with an older dependency observation as consistent state');
    $config=$root.'/literal.php';$put('literal.php',"<?php return ['value'=>1];");
    $assert($collectors->php->load($config,'literal',static fn()=>['wrong'=>true])===['value'=>1],'Literal declarations are not executed');
    $put('literal.php',"<?php return ['value'=>2];");
    $assert($collectors->php->literal($config)===['value'=>1],'Literal observation is consistent within one session');
    $put('dynamic.php',"<?php return ['value'=>getenv('UNUSED')];");$evaluations=0;
    $evaluate=static function()use(&$evaluations):array{return ['value'=>++$evaluations];};
    $collectors->php->load($root.'/dynamic.php','dynamic',$evaluate);$collectors->php->load($root.'/dynamic.php','dynamic',$evaluate);
    $assert($evaluations===2,'Dynamic legacy configuration retains fresh evaluation frequency');
    $collectors->session->end();
    $assert($collectors->php->literal($config)===['value'=>2],'New observation outside session sees current literal config');
    $put('control.json',['invalid'=>true,'advisories'=>[]]);$collectors->session->begin();
    $assert($audit->auditApi($args)[0]===null,'Invalid feed is UNKNOWN');
    $put('control.json',['advisories'=>[$advisory('fixture/transitive')]]);
    $assert($audit->auditApi($args)[0]===false,'Invalid feed is not cached as a clean response');
    $collectors->session->end();
    $put('control.json',['fail_package'=>'fixture/transitive','advisories'=>[$advisory('fixture/app')]]);
    $partialFeed=$audit->auditApi(array_replace($args,['batch_size'=>1]));
    $assert($partialFeed[0]===false && count($partialFeed[2]['feed_gaps'])===1,'Known advisory survives a later failed feed batch');
    $put('control.json',['fail_package'=>'fixture/transitive','advisories'=>[]]);
    $assert($audit->auditApi(array_replace($args,['batch_size'=>1]))[0]===null,'Failed feed batch cannot produce a clean advisory result');
    $status=(new ComposerRepositoryChecks($ctx,$collectors))->releaseRecencyApi(array_replace($args,['batch_size'=>1]));
    $assert($status[0]===false && count($status[2]['packages_unknown'])===1,'Known stale release survives a failed status batch');

    $pdo=new PDO('sqlite::memory:');$pdo->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);
    $pdo->exec('CREATE TABLE indexer_state (indexer_id TEXT,status TEXT,updated TEXT)');
    $pdo->exec("INSERT INTO indexer_state VALUES ('fixture','working','2000-01-01 00:00:00')");
    $dbctx=new Context($root,'','',['pdo'=>$pdo]);$indexer=(new DeploymentStateCheck($dbctx))->indexersDatabaseReady([]);
    $assert($indexer[0]===null && $indexer[2]['working'][0]['record_age_seconds']>0 && !$indexer[2]['working'][0]['stuck_process_established'],'Old working record includes age but does not prove a stuck process');
    $pdo->exec("UPDATE indexer_state SET status='invalid'");
    $assert((new DeploymentStateCheck($dbctx))->indexersDatabaseReady([])[0]===false,'Recorded invalid indexer remains actionable');
    $pdo->exec('CREATE TABLE cron_schedule (status TEXT,executed_at TEXT,scheduled_at TEXT)');
    $insert=$pdo->prepare('INSERT INTO cron_schedule VALUES (?,?,?)');$insert->execute(['error',gmdate('Y-m-d H:i:s',time()-30),gmdate('Y-m-d H:i:s',time()-60)]);
    $cron=new CronCheck($dbctx);$heartbeat=$cron->heartbeatRecent(['database_only'=>true]);$backlog=$cron->backlogBelowThreshold(['database_only'=>true]);
    $assert($heartbeat[0]===true && !$heartbeat[2]['successful_completion_established'],'Recent failed execution proves activity, not successful completion');
    $assert($backlog[0]===true && $backlog[2]['metric']==='due_pending_backlog','Empty pending queue is a distinct fact from execution success');
    echo "Current-state Phase 2 provenance: $n assertions passed\n";
} finally {
    if(is_resource($server)){proc_terminate($server);proc_close($server);}
    $iterator=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST);
    foreach($iterator as $entry)$entry->isDir()&&!$entry->isLink()?rmdir($entry->getPathname()):unlink($entry->getPathname());rmdir($root);
}
