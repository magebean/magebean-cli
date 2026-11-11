<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\Context;
use Magebean\Engine\Checks\HttpCheck;
use Magebean\Engine\Checks\BasicExposureCheck;
$root=sys_get_temp_dir().'/mb-url-discovery-'.bin2hex(random_bytes(5));mkdir($root.'/app/etc',0755,true);
$n=0;$assert=static function(bool $ok,string $message)use(&$n):void{++$n;if(!$ok)throw new RuntimeException($message);};
$resolve=new ReflectionMethod(HttpCheck::class,'baseUrl');
$write=static function(array $default)use($root):void{file_put_contents($root.'/app/etc/config.php','<?php return '.var_export(['system'=>['default'=>$default]],true).';');};
try{
 $write(['web'=>['secure'=>['base_url'=>'https://store.example/shop/'],'unsecure'=>['base_url'=>'http://store.example/shop/']]]);
 $check=new HttpCheck(new Context($root,''));
 $assert($resolve->invoke($check)==='https://store.example/shop','Discovery works without strict_scope and prefers secure URL, preserving base path');
 $urls=[];$probe=static function(string $url)use(&$urls):array{$urls[]=$url;return ['status'=>403,'prefix'=>''];};
 $sensitive=(new BasicExposureCheck(new Context($root,''),$probe))->sensitiveHttpPaths([]);
 $assert($sensitive[0]===true&&count($urls)===6&&$urls[0]==='https://store.example/shop/app/etc/env.php','MB-0781 uses configured URL without command-line URL');
 $productionUrls=[];
 $production=new \Magebean\Engine\Checks\ProductionRuntimeCheck(new Context($root,''),static function(string $url)use(&$productionUrls):array{$productionUrls[]=$url;return ['status'=>200,'complete_headers'=>true,'headers'=>['x-content-type-options'=>['nosniff']],'final_url'=>$url];});
 $response=(new ReflectionMethod($production,'response'))->invoke($production,['path'=>'/checkout/']);
 $assert($response[0]===true&&$productionUrls===['https://store.example/shop/checkout/'],'Production response checks discover store config and preserve base path');
 $legacyMagento=new \Magebean\Engine\Checks\MagentoCheck(new Context($root,''));
 $assert((new ReflectionMethod($legacyMagento,'baseUrl'))->invoke($legacyMagento)==='https://store.example/shop','Legacy Magento HTTP probes discover store configuration too');
 $assert($resolve->invoke(new HttpCheck(new Context($root,'https://override.example/')))==='https://override.example','Explicit URL takes precedence');
 $assert($resolve->invoke(new HttpCheck(new Context($root,'.')))==='https://store.example/shop','Placeholder does not block discovery');
 $remote=new Context($root,'','',['meta'=>['target_mode'=>'REMOTE']]);
 $assert($resolve->invoke(new HttpCheck($remote))==='','Remote mode cannot infer a target from local configuration');
 $write(['web/unsecure/base_url'=>'http://fallback.example/']);
 $assert($resolve->invoke(new HttpCheck(new Context($root,'')))==='http://fallback.example','Unlocked secure value can fall back to configured unsecure URL');
 $write(['web/secure/base_url'=>'https://user:secret@invalid.example/']);
 $assert($resolve->invoke(new HttpCheck(new Context($root,'')))==='','Credentials in configured URL are rejected');
 $definition=array_column(\Magebean\Engine\RequirementCatalog::loadAll()['rules'],null,'id')['MB-0781'];
 foreach(['[UNKNOWN] Supply canonical --url for sensitive-path probes','[UNKNOWN] Runtime URL unavailable; provide --url=https://your-store']as$message){
  $assessment=\Magebean\Engine\RequirementAssessmentEvaluator::evaluate($definition,static fn()=>\Magebean\Engine\CheckResult::of(\Magebean\Engine\CheckOutcome::Unknown,$message));
  $risk=\Magebean\Engine\MagebeanRiskObservation::fromAssessment($definition,$assessment);
  $assert(!$risk['needs_attention']&&$risk['findings']===[]&&!$risk['collection_complete']&&$risk['collection_gaps']!==[],'Missing CLI URL stays in execution metadata without becoming finding or clean result');
 }
 // Real MB-0778 dispatch must proceed to its certificate probe, not claim URL missing.
 $socket=stream_socket_server('tcp://127.0.0.1:0',$errno,$error);$port=(int)substr(strrchr(stream_socket_get_name($socket,false),':'),1);fclose($socket);
 $write(['web/secure/base_url'=>'https://127.0.0.1:'.$port.'/']);
 $result=(new HttpCheck(new Context($root,'')))->dispatch('http_tls_cert_days_left',['timeout_ms'=>100]);
 $assert(!str_contains($result[1],'Runtime URL unavailable')&&($result[2]['host']??'')==='127.0.0.1','MB-0778 discovers configured host without strict_scope');
 mkdir($root.'/bin');file_put_contents($root.'/bin/magento','<?php');file_put_contents($root.'/composer.json','{"name":"magento/project-community-edition"}');
 $write(['web/secure/base_url'=>'https://canonical.example/store/']);
 $resolver=new \Magebean\Engine\ScanTargetResolver();
 $target=$resolver->resolve(true,true,$root,'https://unrelated.example/');
 $assert($target->mode==='LOCAL'&&$target->url==='https://canonical.example/store','Confirmed Magento path uses store config even when --url is supplied');
 $assert((new HttpCheck(new Context($root,'https://unrelated.example/')))->runtimeBaseUrl()==='https://canonical.example/store','Individual checks cannot override confirmed local store URL');
 $prelaunch=$resolver->resolveProfile('prelaunch',true,true,$root,'https://unrelated.example/');
 $assert($prelaunch->url===$target->url && $prelaunch->mode===$target->mode,'Prelaunch delegates URL selection to the shared local resolver');
 $preContext=new Context($root,'https://unrelated.example/','',['meta'=>['launch_profile'=>'prelaunch','target_mode'=>'LOCAL']]);
 $assert((new HttpCheck($preContext))->runtimeBaseUrl()===$target->url,'HTTP consumers use the same configured URL for prelaunch');
 $assert($resolver->resolve(false,true,'','https://external.example/')->url==='https://external.example','External scan still accepts explicit URL');
 echo "HttpUrlDiscoveryTest: $n assertions passed\n";
}finally{if(is_file($root.'/bin/magento'))unlink($root.'/bin/magento');if(is_dir($root.'/bin'))rmdir($root.'/bin');if(is_file($root.'/composer.json'))unlink($root.'/composer.json');unlink($root.'/app/etc/config.php');rmdir($root.'/app/etc');rmdir($root.'/app');rmdir($root);}
