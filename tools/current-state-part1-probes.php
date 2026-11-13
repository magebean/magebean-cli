<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\Context;
use Magebean\Engine\Checks\{CheckRegistry,CronCheck,DeploymentStateCheck};
use Magebean\Engine\Checks\Families\ComposerRepositoryChecks;
$root=sys_get_temp_dir().'/mb-current-state-part1-'.bin2hex(random_bytes(5));$server=null;$rows=[];
$put=static function(string $path,string $contents)use($root):void{@mkdir(dirname($root.'/'.$path),0755,true);file_put_contents($root.'/'.$path,$contents);};
$record=static function(string $case,string $id,array $result)use(&$rows):void{$rows[]=['case'=>$case,'id'=>$id,'status'=>$result[0]===true?'PASS':($result[0]===false?'FAIL':'UNKNOWN'),'message'=>$result[1]??'','evidence'=>$result[2]??[]];};
$catalog=array_column(json_decode(file_get_contents(__DIR__.'/../src/Rules/requirements/magebean-catalog.json'),true)['requirements'],null,'id');
$run=static function(string $id)use($root,$catalog):array{$r=$catalog[$id];$check=$r['checks'][0];return CheckRegistry::fromContext(new Context($root,''))->run($check['name'],$check['args']);};
try{
 $put('composer.json',json_encode(['minimum-stability'=>'stable','require'=>['acme/direct'=>'^1.0'],'require-dev'=>['acme/test-tool'=>'*']]));
 $record('stable-resolution-but-prefer-stable-omitted','MB-0067',$run('MB-0067'));
 $record('locked-development-tool-wildcard','MB-0065',$run('MB-0065'));
 $put('composer.json',json_encode(['minimum-stability'=>'dev','prefer-stable'=>true,'require'=>['acme/direct'=>'^1.0']]));
 $record('dev-resolution-allowed-with-prefer-stable','MB-0067',$run('MB-0067'));
 $put('composer.json',json_encode(['require'=>['acme/direct'=>'dev-main']]));
 $record('explicit-development-branch','MB-0066',$run('MB-0066'));
 $put('app/etc/env.php','<?php return '.var_export(['MAGE_MODE'=>'production','session'=>['save'=>'files']],true).';');
 $record('file-session-backend-no-redis','MB-0040',$run('MB-0040'));
 $record('persisted-production-declaration-only','MB-0031',$run('MB-0031'));
 $repository=new ComposerRepositoryChecks(new Context($root,''));
 $recency=new ReflectionMethod($repository,'assessReleaseRecencyStatuses');
 $repositories=new ReflectionMethod($repository,'assessRepositoryStatuses');
 $packages=[['name'=>'acme/stable','version'=>'1.0.0','repository_url'=>'https://example.test/acme/stable']];
 foreach(['2000-01-01T00:00:00Z','2026-02-30T00:00:00Z','yesterday',gmdate(DATE_ATOM,time()-86400)]as$date){
  $result=$recency->invoke($repository,$packages,['acme/stable'=>['release_history_known'=>true,'latest'=>'1.0.0','latest_date'=>$date]],['months'=>24,'strict_scope'=>true]);
  $record('release-date:'.$date,'MB-0062',$result);
 }
 foreach([false,true]as$archived)$record('repository-archived:'.($archived?'true':'false'),'MB-0063',$repositories->invoke($repository,$packages,['acme/stable'=>['repository_status_known'=>true,'repository_archived'=>$archived,'repository_disabled'=>false]],['strict_scope'=>true]));
 $pdo=new PDO('sqlite::memory:');$pdo->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);
 $pdo->exec('CREATE TABLE indexer_state (indexer_id TEXT,status TEXT)');$pdo->exec("INSERT INTO indexer_state VALUES ('catalog_product_price','working')");
 $context=new Context($root,'','',['pdo'=>$pdo]);
 $record('indexer-currently-working','MB-0039',(new DeploymentStateCheck($context))->indexersDatabaseReady([]));
 $pdo->exec('CREATE TABLE cron_schedule (status TEXT,executed_at TEXT,scheduled_at TEXT)');
 $statement=$pdo->prepare('INSERT INTO cron_schedule VALUES (?,?,?)');$statement->execute(['error',gmdate('Y-m-d H:i:s',time()-60),gmdate('Y-m-d H:i:s',time()-120)]);
 $record('only-recent-error-cron-execution','MB-0047',(new CronCheck($context))->heartbeatRecent(['database_only'=>true,'seconds'=>900]));
 $record('only-error-no-pending-backlog','MB-0048',(new CronCheck($context))->backlogBelowThreshold(['database_only'=>true,'max'=>1000]));
 $put('composer.json',json_encode(['require'=>['acme/direct'=>'^1.0']]));
 $put('composer.lock',json_encode(['packages'=>[['name'=>'acme/direct','version'=>'1.0.0','require'=>['acme/transitive'=>'^1.0']],['name'=>'acme/transitive','version'=>'1.0.0']],'packages-dev'=>[]]));
 $socket=stream_socket_server('tcp://127.0.0.1:0');$host=stream_socket_get_name($socket,false);fclose($socket);
 $put('router.php','<?php header("Content-Type: application/json");readfile(__DIR__."/feed.json");');
 $server=proc_open([PHP_BINARY,'-S',$host,$root.'/router.php'],[1=>['file',$root.'/server.log','a'],2=>['file',$root.'/server.log','a']],$pipes,$root);
 for($i=0;$i<100;$i++){if($s=@stream_socket_client('tcp://'.$host,timeout:0.05)){fclose($s);break;}usleep(10000);}
 foreach(['2000-01-01T00:00:00Z','2099-01-01T00:00:00Z']as$published){
  $advisory=['id'=>'QA-TRANSITIVE','published'=>$published,'affected'=>[['package'=>['ecosystem'=>'Packagist','name'=>'acme/transitive'],'versions'=>['1.0.0']]]];
  $put('feed.json',json_encode(['schema_version'=>'magebean-osv-response-v1','advisories'=>[$advisory],'meta'=>['dataset_revision'=>'controlled-qa-fixture']]));
  foreach(['MB-0049','MB-0055','MB-0059']as$id){$check=$catalog[$id]['checks'][0];$args=array_replace($check['args'],['endpoint'=>'http://'.$host,'timeout_ms'=>1000]);$record('same-transitive-advisory-published:'.$published,$id,CheckRegistry::fromContext(new Context($root,''))->run($check['name'],$args));}
 }
 $put('composer.json',json_encode(['require'=>['acme/direct'=>'^1.0'],'require-dev'=>['acme/test-tool'=>'^1.0']]));
 $put('composer.lock',json_encode(['packages'=>[['name'=>'acme/direct','version'=>'1.0.0']],'packages-dev'=>[['name'=>'acme/test-tool','version'=>'1.0.0','require'=>['acme/dev-only'=>'^1.0']],['name'=>'acme/dev-only','version'=>'1.0.0']]]));
 $put('vendor/composer/installed.json',json_encode(['dev'=>false,'packages'=>[['name'=>'acme/direct','version'=>'1.0.0']]]));
 $put('feed.json',json_encode(['schema_version'=>'magebean-osv-response-v1','advisories'=>[['id'=>'QA-DEV-ONLY','published'=>'2000-01-01T00:00:00Z','affected'=>[['package'=>['ecosystem'=>'Packagist','name'=>'acme/dev-only'],'versions'=>['1.0.0']]]]]]));
 foreach(['MB-0049','MB-0055']as$id){$check=$catalog[$id]['checks'][0];$args=array_replace($check['args'],['endpoint'=>'http://'.$host,'timeout_ms'=>1000]);$record('no-dev-install-lock-still-has-development-only-advisory',$id,CheckRegistry::fromContext(new Context($root,''))->run($check['name'],$args));}
 echo json_encode(['catalog_count'=>count($catalog),'scope'=>'Read-only current-state QA; temporary fixtures and loopback feed only; no customer project, external API or production mutation','observations'=>$rows],JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES),"\n";
}finally{
 if(is_resource($server)){proc_terminate($server);proc_close($server);}
 if(is_dir($root)){$it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST);foreach($it as$f)$f->isDir()&&!$f->isLink()?rmdir($f->getPathname()):unlink($f->getPathname());rmdir($root);}
}
