<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\{RequirementCatalog,RequirementPolicy,RequirementDiagnostics,ScanContext,ScanRequest,ScanPlanner,CheckResult,CheckOutcome,RequirementAssessmentEvaluator,RequirementOutcome};
use Magebean\Engine\Checks\{CheckRegistry};
use Magebean\Engine\Checks\Families\{ComposerAdvisoryChecks,ComposerRepositoryChecks,ComposerVersionChecks};
use Symfony\Component\Console\Output\BufferedOutput;
$n=0;function qualityAssert(bool $v,string $m):void{global$n;++$n;if(!$v)throw new RuntimeException($m);}
$root=sys_get_temp_dir().'/mb-owasp-quality-'.bin2hex(random_bytes(6));mkdir($root);
try{
 $ctx=new ScanContext($root,'');$plan=(new ScanPlanner())->planCli(new ScanRequest($ctx,['profile'=>'owasp-top-10']),CheckRegistry::fromContext($ctx->toLegacy()));
 qualityAssert($plan!==null,'Default OWASP plan');
 foreach($plan->pack['rules'] as$r){qualityAssert(!RequirementPolicy::requiresHuman($r),'No hidden human requirement leaked '.$r['id']);qualityAssert(in_array($r['review_state'],['accepted_scoped_criterion','security_reviewed'],true),'No developer binding gap shipped to scan user '.$r['id']);}
 $fake=new CheckRegistry();foreach($plan->pack['rules'] as $r)foreach($r['checks'] as$c){$name=$c['name'];if($fake->has($name))continue;$fake->register($name,static fn()=>CheckResult::of($name==='http_has_hsts'?CheckOutcome::Unknown:CheckOutcome::Pass,$name==='http_has_hsts'?'[UNKNOWN] HTTP error: SSL certificate problem: self-signed certificate':'Observed')) ;}
 $report=(new \Magebean\Engine\ScanService())->run($plan,null,$fake);$assembled=(new \Magebean\Engine\ScanReportAssembler())->assemble($report,$plan)->toLegacy();
 qualityAssert(count($assembled['execution_errors'])===1&&!$assembled['meta']['scan_complete'],'Default automated OWASP collection failure is incomplete execution');
 qualityAssert((new \Magebean\Engine\ScanExitPolicy())->code($assembled)===3,'Incomplete automated OWASP exits3 rather than clean0');
 qualityAssert($assembled['execution_errors'][0]['id']==='MB-0027'&&$assembled['summary']['failed']===0,'TLS collection failure is not HSTS vulnerability');
 $out=new BufferedOutput();(new \Magebean\Console\ScanConsoleRenderer())->renderPrettySummary($out,$assembled,$root);$text=$out->fetch();qualityAssert(str_contains($text,'need attention')&&$assembled['summary']['needs_attention']===0&&!str_contains($text,'Trust the site CA')&&!str_contains($text,'INCONCLUSIVE'),'Automated console names errors and actions');
 $ids=array_column($plan->pack['rules'],'id');qualityAssert(in_array('MB-0730',$ids,true)&&!in_array('MB-0072',$ids,true),'Deployment scope has no Git-history prerequisite');
 $index=array_column(RequirementCatalog::loadAll()['rules'],null,'id');
 foreach(['0009','0014','0027','0034','0042','0055','0056','0057','0059','0061','0069','0070'] as$suffix){
  $r=$index['MB-'.$suffix];qualityAssert(RequirementAssessmentEvaluator::evaluate($r,fn()=>CheckResult::of(CheckOutcome::Pass,'Observed scoped predicate'))->outcome===RequirementOutcome::Pass,'Verified success can conclude '.$suffix);
  qualityAssert(RequirementAssessmentEvaluator::evaluate($r,fn()=>CheckResult::of(CheckOutcome::Unknown,'Required input unreadable'))->outcome===RequirementOutcome::Unknown,'Missing evidence cannot be promoted '.$suffix);
 }
 $archive=array_column(RequirementCatalog::read('magebean-retirements')['requirements'],null,'id');
 foreach(['0004','0010','0015','0016','0019','0020','0021','0023','0025','0043','0073','0078','0079','0089','0096','0097','0098'] as$suffix)qualityAssert(RequirementPolicy::requiresHuman($archive['MB-'.$suffix]),'Broad heuristic assessment needs human evidence '.$suffix);
 file_put_contents($root.'/composer.json',json_encode(['require'=>['example/package'=>'^1.0']]));
 foreach([['packages'=>[['name'=>'broken/package']]],['packages'=>[],'packages-dev'=>'invalid'],['packages'=>[['name'=>'a/b','version'=>'1.0'],['name'=>'a/b','version'=>'1.0']]]] as$lock){
  file_put_contents($root.'/composer.lock',json_encode($lock));
  foreach([[new ComposerAdvisoryChecks($ctx->toLegacy()),'transitiveAuditApi'],[new ComposerAdvisoryChecks($ctx->toLegacy()),'constraintsConflictApi'],[new ComposerAdvisoryChecks($ctx->toLegacy()),'advisoryLatencyApi'],[new ComposerVersionChecks($ctx->toLegacy()),'yankedApi'],[new ComposerVersionChecks($ctx->toLegacy()),'directOutdatedApi'],[new ComposerRepositoryChecks($ctx->toLegacy()),'abandonedApi']] as[$c,$method])qualityAssert($c->$method(['strict_scope'=>true,'endpoint'=>'invalid','status_endpoint'=>'invalid'])[0]===null,'Malformed scope cannot be clean '.$method);
 }
 $finding=['id'=>'MB-0027','status'=>'UNKNOWN','reason_code'=>'REQUIREMENT_EVIDENCE_INCOMPLETE','title'=>'HSTS','message'=>'HTTP error: SSL certificate problem: self-signed certificate'];
 $finding['collection_guidance']=RequirementDiagnostics::forFinding($finding);qualityAssert($finding['collection_guidance']['category']==='tls_trust'&&str_contains($finding['collection_guidance']['action'],'Keep TLS verification enabled'),'TLS guidance preserves verification');
 $out=new BufferedOutput();(new \Magebean\Console\ScanConsoleRenderer())->renderPrettySummary($out,['findings'=>[$finding],'summary'=>['total'=>1,'passed'=>0],'meta'=>['rules_filter'=>['MB-0027']]],$root);qualityAssert(str_contains($out->fetch(),'Trust the site CA'),'Explicit rule detail shows actionable TLS guidance');
 qualityAssert(RequirementDiagnostics::forFinding(['reason_code'=>'REQUIREMENT_BINDING_UNVALIDATED'])['owner']==='magebean','Tool coverage is owned by tool, not deployment client');
 $knownHttp=RequirementDiagnostics::forFinding(['id'=>'MB-0030','message'=>'http://magento.local/: Cookie probe needs a successful same-host HTTPS response']);
 qualityAssert($knownHttp['category']==='https_response_required'&&!str_contains($knownHttp['action'],'Provide --url=https://your-store'),'Known reachable HTTP site is not mislabeled as missing URL');
 echo "OwaspScanQualityTest: $n assertions passed\n";
}finally{foreach(glob($root.'/*')?:[]as$f)unlink($f);rmdir($root);}
