<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\{RequirementProfileCatalog,RequirementCatalog,RequirementPolicy,ScanPlanner,ScanRequest,ScanContext};
use Magebean\Engine\Checks\CheckRegistry;
$n=0;function hardeningAssert(bool$v,string$m):void{global$n;++$n;if(!$v)throw new RuntimeException($m);}
$h=RequirementProfileCatalog::load('hardening');
$ctx=new ScanContext(sys_get_temp_dir(),'');$registry=CheckRegistry::fromContext($ctx->toLegacy());$planner=new ScanPlanner();
$capabilities=['strict_native_api_policy','runtime_worker_access','admin_role_policy','integration_debug_policy','dependency_source_policy','dependency_mitigation_policy','runtime_worker_inventory','log_rotation_config'];
foreach(['basic'=>37,'hardening'=>86,'owasp'=>50]as$id=>$count){
 $profile=RequirementProfileCatalog::load($id);
 hardeningAssert(count($profile['requirement_ids'])===$count,'Exact automated inventory '.$id);
 hardeningAssert(empty($profile['evidence_tasks'])&&$profile['automation_only'],'No manual checklist '.$id);
 foreach([false,true]as$flag){
  $plan=$planner->planCli(new ScanRequest($ctx,['profile'=>$id,'include-manual-review'=>$flag]),$registry);
  $selected=RequirementCatalog::forProfile($id);
  hardeningAssert(count($plan->pack['rules'])===count($selected['rules']),'Manual flag cannot restore backlog or enable strict policy '.$id);
  hardeningAssert(count($selected['rules'])+count($selected['omitted_requirements'])===$count,'Every member evaluated or explicitly omitted '.$id);
  foreach($selected['omitted_requirements']as$o)hardeningAssert($o['reason_code']==='CAPABILITY_CONTEXT_MISSING'&&in_array($o['capability'],$capabilities,true),'Machine-context and strict-policy omissions are explicit');
  foreach($plan->pack['rules']as$r)hardeningAssert(!RequirementPolicy::requiresHuman($r),'No human criterion '.$r['id']);
 }
 if($id!=='hardening')hardeningAssert(array_diff($profile['requirement_ids'],$h['requirement_ids'])===[],'Hardening inherits all automated '.$id);
}
$strict=RequirementCatalog::forProfile('hardening',['strict_native_api_policy']);
hardeningAssert(count($strict['rules'])===80,'Strict coding policy alone does not enable runtime or expected-policy checks');
hardeningAssert(count($strict['omitted_requirements'])===6,'Six machine-context capabilities still require explicit configuration');
$complete=RequirementCatalog::forProfile('hardening',$capabilities);
hardeningAssert(count($complete['rules'])===count($h['requirement_ids']),'Explicit capabilities select complete local inventory');
hardeningAssert($complete['omitted_requirements']===[],'Complete explicit context removes applicability omissions');
hardeningAssert(count(RequirementCatalog::forProfile('hardening')['rules'])===80,'Default selected local inventory includes supported ungated observations');
$backlog=RequirementCatalog::read('magebean-automation-backlog')['requirements'];
hardeningAssert(count($backlog)===50,'Unproven criteria tracked rather than relabelled');
$all=array_column(RequirementCatalog::loadAll()['rules'],null,'id');
$archive=array_column(RequirementCatalog::read('magebean-retirements')['requirements'],null,'id');
foreach($backlog as$r){hardeningAssert($archive[$r['id']]['criterion']===$r['criterion']&&RequirementPolicy::requiresHuman($archive[$r['id']]),'Original backlog snapshot preserved '.$r['id']);if(isset($all[$r['id']]))hardeningAssert($all[$r['id']]['revision']>$archive[$r['id']]['revision']&&!RequirementPolicy::requiresHuman($all[$r['id']]),'Active restoration has a new automated scope '.$r['id']);}
$file=tempnam(sys_get_temp_dir(),'mb-hardening-profile-');try{
 $bad=$h;$bad['requirement_ids']=array_values(array_diff($h['requirement_ids'],['MB-0730']));file_put_contents($file,json_encode($bad));
 $rejected=false;try{RequirementProfileCatalog::load($file);}catch(RuntimeException$e){$rejected=str_contains($e->getMessage(),'must include');}hardeningAssert($rejected,'Lost automated coverage rejected');
 $bad=$h;$bad['requirement_ids'][]='MB-0016';file_put_contents($file,json_encode($bad));$rejected=false;try{RequirementProfileCatalog::load($file);}catch(RuntimeException$e){$rejected=str_contains($e->getMessage(),'retired');}hardeningAssert($rejected,'Human criterion rejected');
 $bad=$h;$bad['evidence_tasks']=[['id'=>'manual']];file_put_contents($file,json_encode($bad));$rejected=false;try{RequirementProfileCatalog::load($file);}catch(RuntimeException$e){$rejected=str_contains($e->getMessage(),'manual');}hardeningAssert($rejected,'Manual checklist rejected');
}finally{unlink($file);}
echo "HardeningCoverageTest: $n assertions passed\n";
