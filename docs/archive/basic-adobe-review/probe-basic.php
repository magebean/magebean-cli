<?php
declare(strict_types=1);
require __DIR__.'/../../../vendor/autoload.php';
use Magebean\Engine\{Context,RequirementCatalog};
use Magebean\Engine\Checks\{CheckRegistry,InstalledCronCheck};

// Input fixtures only. No Magento bootstrap, external requests, payload execution or production scan.
$root=sys_get_temp_dir().'/mb-adobe-basic-'.bin2hex(random_bytes(5));mkdir($root,0700);mkdir($root.'/app',0700);mkdir($root.'/app/etc',0700);mkdir($root.'/remote',0700);
$definitions=array_column(RequirementCatalog::loadAll()['rules'],null,'id');$observations=[];
$write=static function(array$config,array$env)use($root):void{file_put_contents($root.'/app/etc/config.php','<?php return '.var_export($config,true).';');file_put_contents($root.'/app/etc/env.php','<?php return '.var_export($env,true).';');};
$observe=static function(string$case,string$id,string$name,array$args,Context$ctx,string$limit)use(&$observations):void{$r=CheckRegistry::fromContext($ctx)->runResult($name,$args);$observations[]=['case'=>$case,'requirement'=>$id,'check'=>$name,'outcome'=>$r->outcome->value,'message'=>$r->message,'interpretation_limit'=>$limit];};
try{
    $args=$definitions['MB-0007']['checks'][0]['args'];
    $write(['modules'=>['Magento_TwoFactorAuth'=>1],'system'=>['default'=>['twofactorauth'=>['general'=>['force_providers'=>'google']]]]],[]);
    $observe('native_google_provider_representation','MB-0007','magento_admin_2fa_enabled',$args,new Context($root,''),'Native provider engine is not a separate provider module; fixture does not prove real enrollment/authentication.');
    $write(['modules'=>['Magento_TwoFactorAuth'=>1,'Magento_GoogleAuthenticator'=>1]],[]);
    $observe('synthetic_provider_module_entry','MB-0007','magento_admin_2fa_enabled',$args,new Context($root,''),'Contrived input shows a declared invented/provider module entry is accepted without reading provider settings or enforcement. Not a real installed Magento sample.');
    $write(['modules'=>['Magento_TwoFactorAuth'=>0,'Magento_AdminAdobeIms'=>1]],[]);
    $observe('ims_indicated_native_disabled','MB-0007','magento_admin_2fa_enabled',$args,new Context($root,''),'IMS module indication is not proof IMS authentication is active; check has no IMS applicability branch and immediately fails native disabled.');
    $write(['modules'=>[]],['backend'=>['frontName'=>'backend']]);
    $observe('common_backend_route','MB-0006','magento_admin_frontname_declared',$definitions['MB-0006']['checks'][0]['args'],new Context($root,''),'PASS matches current not-admin criterion but does not implement broader Adobe uncommon-route guidance.');
    $sources=static fn(array$args):array=>[['name'=>'fixture','available'=>true,'complete'=>true,'system'=>false,'content'=>'@yearly php '.$root.'/bin/magento cron:run']];
    $cron=(new InstalledCronCheck(new Context($root,''),$sources))->configured([]);
    $observations[]=['case'=>'yearly_cron_presence','requirement'=>'MB-0046','check'=>'installed_magento_cron','outcome'=>$cron[0]===true?'PASS':($cron[0]===false?'FAIL':'UNKNOWN'),'message'=>$cron[1],'interpretation_limit'=>'Current claim is entry presence only; this does not establish adequate schedule or recent successful jobs.'];
    $remote=$definitions['MB-0026']['execution_variants']['REMOTE']['obligations'][0]['checks'][0];
    $observe('url_only_admin_route_unavailable','MB-0026',$remote['name'],$remote['args'],new Context($root.'/remote','https://review.invalid'),'Returns before HTTP collection because declared admin route is unavailable; no endpoint was scanned.');
}finally{
    foreach(['config.php','env.php']as$file)if(is_file($root.'/app/etc/'.$file))unlink($root.'/app/etc/'.$file);
    rmdir($root.'/app/etc');rmdir($root.'/app');rmdir($root.'/remote');rmdir($root);
}
file_put_contents(__DIR__.'/observations.json',json_encode(['date'=>'2026-10-17','type'=>'Local artificial input fixtures, not complete Magento integration or external security test.','observations'=>$observations],JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR)."\n");
foreach($observations as$r)echo $r['case'],' => ',$r['outcome'],' (',$r['check'],')',PHP_EOL;
