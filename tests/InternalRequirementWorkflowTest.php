<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Agent\AgentScanner;
use Magebean\Engine\{ScanContext,ScanRequest,ScanPlanner,ScanService,ScanReportAssembler,RequirementCatalog};
use Magebean\Engine\Checks\CheckRegistry;
$assertions=0;
function workflowAssert(bool $ok,string $message):void{global $assertions;$assertions++;if(!$ok)throw new RuntimeException($message);}
$root=sys_get_temp_dir().'/mb-internal-workflow-'.bin2hex(random_bytes(6));mkdir($root.'/app/etc',0700,true);
try{
 $catalog=RequirementCatalog::loadAll()['rules'];$production=null;$human=RequirementCatalog::read('magebean-retirements')['requirements'][0];
 foreach($catalog as$r){if(($r['checks'][0]['name']??'')==='magento_production_mode'&&($r['review_state']??'')==='accepted_scoped_criterion')$production=$r;}
 workflowAssert($production!==null&&$human!==null,'Reviewed scoped and human criteria exist');
 $manifest=['schema_version'=>'1.0','manifest_hash'=>'sha256:internal-workflow','rules'=>[['assessment_item_id'=>'production-item','rule_key'=>$production['id']],['assessment_item_id'=>'human-item','rule_key'=>$human['id']],['assessment_item_id'=>'legacy-item','rule_key'=>'MB-R037']]];
 $scanner=new AgentScanner();
 foreach(['production'=>'pass','developer'=>'fail'] as$mode=>$expected){
  file_put_contents($root.'/app/etc/env.php','<?php return '.var_export(['MAGE_MODE'=>$mode],true).';');
  $payload=$scanner->run($root,$manifest);workflowAssert($payload['schema_version']==='1.0'&&$payload['manifest_hash']===$manifest['manifest_hash'],'Wire envelope unchanged');
  workflowAssert(count($payload['results'])===3,'Mixed manifest exact cardinality');
  workflowAssert(array_column($payload['results'],'assessment_item_id')===['production-item','legacy-item','human-item'],'No unsolicited alias expansion');
  workflowAssert($payload['results'][0]['rule_key']===$production['id']&&$payload['results'][0]['status']===$expected,'Reviewed scoped predicate retains pass/fail');
  workflowAssert($payload['results'][2]['status']==='unsupported' && str_contains($payload['results'][2]['message'], 'retired'),'Historical Magebean item receives a retirement diagnostic');
  workflowAssert(!str_contains(json_encode($payload),$root),'Payload remains root-redacted');
  workflowAssert($payload['results'][0]['evidence']['requirement_id']===$production['id'],'Identity preserved in evidence');
 }
 unlink($root.'/app/etc/env.php');$payload=$scanner->run($root,$manifest);workflowAssert($payload['results'][0]['status']==='error','Missing configuration cannot become violation');
 file_put_contents($root.'/app/etc/env.php','<?php return '.var_export(['MAGE_MODE'=>'production'],true).';');
 $ctx=new ScanContext($root,'https://fixture.example','',['meta'=>['target_mode'=>'HYBRID']]);$registry=CheckRegistry::fromContext($ctx->toLegacy());$plan=(new ScanPlanner())->planCli(new ScanRequest($ctx,['rules'=>$production['id']]),$registry);workflowAssert($plan!==null,'Primary CLI plan');
 $report=(new ScanService())->run($plan,null,$registry);$assembled=(new ScanReportAssembler())->assemble($report,$plan)->toLegacy();
 workflowAssert($assembled['findings'][0]['requirement']['id']===$production['id'],'Report singular identity');
 workflowAssert(($assembled['meta']['assessment_model']??'')==='internal-requirement-v1'&&($assembled['meta']['profile_selector']??'')==='basic','Rerun context persisted');
 workflowAssert(($assembled['meta']['url']??'')==='https://fixture.example','Hybrid URL preserved');
 echo "InternalRequirementWorkflowTest: $assertions assertions passed\n";
}finally{if(is_file($root.'/app/etc/env.php'))unlink($root.'/app/etc/env.php');rmdir($root.'/app/etc');rmdir($root.'/app');rmdir($root);}
