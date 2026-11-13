<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\{RequirementCatalog,ScanContext,ScanRequest,ScanPlanner,ScanService,ScanReportAssembler,ScanExitPolicy,CheckOutcome,CheckResult};
use Magebean\Engine\Checks\CheckRegistry;
use Magebean\Console\ScanConsoleRenderer;
use Symfony\Component\Console\Output\BufferedOutput;
$n=0;function basicAutoAssert(bool$v,string$m):void{global$n;++$n;if(!$v)throw new RuntimeException($m);}
$root=sys_get_temp_dir().'/mb-basic-auto-'.bin2hex(random_bytes(6));mkdir($root);
try{
 $context=new ScanContext($root,'');$registry=CheckRegistry::fromContext($context->toLegacy());$plan=(new ScanPlanner())->planCli(new ScanRequest($context,['profile'=>'basic']),$registry);basicAutoAssert($plan!==null&&count($plan->pack['rules'])===37,'Basic selects thirty-seven checks');
 basicAutoAssert(count(array_unique(array_column($plan->pack['rules'],'id')))===37,'Basic profile contains each scoped requirement exactly once');
 $ids=array_column($plan->pack['rules'],'id');basicAutoAssert(!in_array('MB-0209',$ids,true)&&!in_array('MB-0379',$ids,true)&&!in_array('MB-0072',$ids,true),'Basic uses distinct deployment criteria rather than broad compliance/history');
 foreach($plan->pack['rules']as$r)basicAutoAssert(!$r['human_evidence']['required']&&$r['review_state']==='accepted_scoped_criterion','Every basic requirement is reviewed and automated');
 foreach(['MB-0773','MB-0776','MB-0777','MB-0778','MB-0779','MB-0780','MB-0781','MB-0782','MB-0783','MB-0784','MB-0785']as$id)basicAutoAssert(in_array($id,$ids,true),'Adobe review addition present: '.$id);
 $catalog=array_column(RequirementCatalog::loadAll()['rules'],null,'id');basicAutoAssert($catalog['MB-0209']['human_evidence']['required']&&$catalog['MB-0379']['human_evidence']['required'],'Standard criterion meanings preserved');
 foreach(['PASS','ERROR','FAIL']as$case){$fake=new CheckRegistry();foreach($plan->pack['rules']as$r)foreach($r['checks']as$c){$name=$c['name'];if($fake->has($name))continue;$fake->register($name,static fn(array$args):CheckResult=>CheckResult::of($case==='ERROR'&&$name==='http_cookie_flags'?CheckOutcome::Unknown:($case==='FAIL'&&$name==='cache_type_enabled'?CheckOutcome::Fail:CheckOutcome::Pass),$case==='ERROR'&&$name==='http_cookie_flags'?'[UNKNOWN] Endpoint cannot be reached; provide a reachable --url.':'Verified fixture observation',[],null,$name));}
  $report=(new ScanService())->run($plan,null,$fake);$result=(new ScanReportAssembler())->assemble($report,$plan)->toLegacy();$out=new BufferedOutput();(new ScanConsoleRenderer())->renderPrettySummary($out,$result,$root);$text=$out->fetch();
  basicAutoAssert(!str_contains(strtoupper($text),'INCONCLUSIVE')&&!str_contains($text,'HUMAN VERIFICATION REQUIRED'),'Basic has no inconclusive/human presentation');
  basicAutoAssert($result['summary']['total']===37,'All thirty-seven are attempted');
  basicAutoAssert(array_sum(array_column($result['summary']['lanes'],'total'))===37&&isset($result['summary']['lanes']['security'],$result['summary']['lanes']['readiness']),'Every attempted requirement has a security or readiness lane');
  basicAutoAssert(empty($result['evidence_tasks']),'Magebean Basic has no human evidence checklist');
  basicAutoAssert($result['coverage_summary']['inventory']===37&&$result['coverage_summary']['executed']===37,'Automated coverage counts actual profile observations');
  basicAutoAssert($result['coverage_summary']['assessment_complete']===($case!=='ERROR'),'An unresolved collection blocks assessment coverage; a proven failure still completes assessment');
  if($case==='PASS'){basicAutoAssert($result['summary']['passed']===37&&$result['meta']['scan_complete'],'All verified basic checks pass');basicAutoAssert((new ScanExitPolicy())->code($result)===0,'Completed clean scan exits zero');}
  if($case==='ERROR'){basicAutoAssert(count($result['execution_errors'])===1&&str_contains($text,'need attention')&&$result['summary']['needs_attention']===0&&!$result['meta']['scan_complete'],'Collection failure blocks scan completion');basicAutoAssert($result['summary']['failed']===0&&$result['findings'][array_search('MB-0030',$ids,true)]['status']==='UNKNOWN','Execution gap is neither vulnerability nor false PASS; wire status remains compatible');basicAutoAssert((new ScanExitPolicy())->code($result)===3,'Execution error exits three');}
  if($case==='FAIL')basicAutoAssert((new ScanExitPolicy())->code($result)===1&&$result['summary']['failed']===1,'Verified policy violation remains finding exitone');
 }
 basicAutoAssert((new ScanExitPolicy())->code(['findings'=>[['status'=>'UNKNOWN']]])===0,'Other profile exit policy unchanged');
 echo "BasicAutomationProfileTest: $n assertions passed\n";
}finally{rmdir($root);}
