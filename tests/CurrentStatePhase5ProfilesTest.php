<?php
declare(strict_types=1);
$archive=isset($argv[1])?realpath($argv[1]):null;
require $archive?'phar://'.$archive.'/vendor/autoload.php':__DIR__.'/../vendor/autoload.php';
use Magebean\Engine\{RequirementCatalog,RequirementProfileCatalog,ScanPlanner,ScanRequest,ScanContext};
use Magebean\Engine\Checks\CheckRegistry;
$n=0;$assert=static function(bool $v,string $m)use(&$n):void{++$n;if(!$v)throw new RuntimeException($m);};
$root=sys_get_temp_dir().'/mb-phase5-'.bin2hex(random_bytes(6));mkdir($root,0700);
$context=new ScanContext($root,'');$registry=CheckRegistry::fromContext($context->toLegacy());
$plan=static fn(string $profile,array $extra=[])=>(new ScanPlanner())->planCli(new ScanRequest($context,['profile'=>$profile]+$extra),$registry);
$ids=static fn($p)=>array_column($p->pack['rules'],'id');
try {
 $assert(count(RequirementProfileCatalog::all())===15,'Fifteen built-in profiles');
 $assert(count(RequirementCatalog::loadAll()['rules'])===735,'No rule-count inflation');
 foreach(['basic'=>[37,37],'development'=>[31,29],'prelaunch'=>[60,58],'takeover'=>[86,82],'hardening'=>[86,80],'evidence'=>[2,2]] as $name=>[$inventory,$selected]){
  $p=RequirementProfileCatalog::load($name);$compiled=$plan($name);
  $assert(count($p['requirement_ids'])===$inventory,'Inventory '.$name);
  $assert(count($compiled->pack['rules'])===$selected,'Default executable selection '.$name);
  $assert($ids($compiled)===array_column(RequirementCatalog::forProfile($name)['rules'],'id'),'Listing/planner agree '.$name);
  $assert(!in_array('MB-0731',$p['requirement_ids'],true),'Canonical password membership '.$name);
 }
 foreach(['development','prelaunch','takeover','hardening'] as $name){
  $assert(in_array('MB-0733',$ids($plan($name)),true)&&in_array('MB-0736',$ids($plan($name)),true),'Both template detectors selected '.$name);
  $assert(!in_array('MB-0093',$ids($plan($name)),true)&&!in_array('MB-0806',$ids($plan($name)),true),'Record lint outside technical profiles '.$name);
 }
 $assert($ids($plan('evidence'))===['MB-0093','MB-0806'],'Only two explicit record lint rules');
 $strictIds=['MB-0786','MB-0788','MB-0792','MB-0794','MB-0796','MB-0798'];
 $assert(array_diff($strictIds,$ids($plan('hardening')))===[],'Hardening selects all six strict native API policies by default');
 $assert(array_intersect($strictIds,$ids($plan('basic')))===[],'Basic does not inherit strict hardening policies');
 $assert(!in_array('MB-0744',$ids($plan('development')),true),'Default development makes no maintenance API request');
 $assert(in_array('MB-0744',$ids($plan('development',['capabilities'=>'dependency_maintenance'])),true),'Development maintenance explicitly enabled');
 foreach(['prelaunch','takeover','hardening'] as $name)$assert(in_array('MB-0744',$ids($plan($name)),true),'Online maintenance selected '.$name);
 foreach(['prelaunch','takeover'] as $name){
  $assert(!in_array('MB-0741',$ids($plan($name)),true),'No implicit strict cache policy '.$name);
  $assert(in_array('MB-0741',$ids($plan($name,['capabilities'=>'cache_backend_policy'])),true),'Explicit cache baseline '.$name);
 }
 foreach(['takeover','hardening'] as $name){
  $assert(!in_array('MB-0043',$ids($plan($name)),true),'Missing logrotate context does not invent a required file '.$name);
  $assert(in_array('MB-0043',$ids($plan($name,['capabilities'=>'log_rotation_config'])),true),'Supplied logrotate context selected '.$name);
 }
 $assert(in_array('MB-0728',$ids($plan('prelaunch')),true),'Prelaunch canonical password coverage');
 $assert($ids($plan('prelaunch',['rules'=>'MB-0731']))===['MB-0731'],'Historical selector remains compatible');
 file_put_contents($root.'/.magebean.json',json_encode(['capabilities'=>['dependency_maintenance'=>false,'cache_backend_policy'=>false,'evidence_document_lint'=>false,'strict_native_api_policy'=>false]]));
 $assert(!in_array('MB-0744',$ids($plan('prelaunch')),true),'Explicit false overrides profile maintenance default');
 $assert(!in_array('MB-0741',$ids($plan('hardening')),true),'Explicit false overrides strict baseline default');
 $assert(array_intersect($strictIds,$ids($plan('hardening')))===[],'Explicit false disables the six strict policies');
 $assert($ids($plan('evidence'))===['MB-0806'],'Explicit false overrides evidence lint context');
 unlink($root.'/.magebean.json');
 foreach(['asvs-l1'=>70,'asvs-l2'=>253,'asvs-l3'=>345,'pci'=>280] as $name=>$count){
  $p=RequirementProfileCatalog::load($name);$assert(count($p['requirement_ids'])===$count&&empty($p['default_capabilities']),'Normative profiles unchanged '.$name);
 }
 $baseline=json_decode(file_get_contents(__DIR__.'/../docs/archive/current-state/phase0/baseline.json'),true);
 foreach(['asvs-l1','asvs-l2','asvs-l3','pci-dss-v4.0.1'] as $name)$assert(RequirementProfileCatalog::all()[$name]===$baseline['profiles'][$name],'Exact normative profile preserved '.$name);
 $assert(!file_exists($root.'/.magebean'),'Profile compilation creates no invented snapshot/config directory');
 echo "Current-state Phase 5 profiles: $n assertions passed\n";
}finally{if(is_file($root.'/.magebean.json'))unlink($root.'/.magebean.json');rmdir($root);}
