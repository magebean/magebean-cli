<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\{ScanContext,ScanRequest,ScanPlanner,ScanPlan,ScanService,ScanReportAssembler,CheckResult,CheckOutcome,ScanExitPolicy};
use Magebean\Engine\Checks\CheckRegistry;
use Magebean\Agent\AgentResultMapper;
$n=0;$assert=static function(bool$ok,string$message)use(&$n):void{++$n;if(!$ok)throw new RuntimeException($message);};
$context=new ScanContext(sys_get_temp_dir(),'');
$base=(new ScanPlanner())->planCli(new ScanRequest($context,['profile'=>'basic','rules'=>'MB-0014']),CheckRegistry::fromContext($context->toLegacy()));
foreach(['clean','signal','gap','signal_and_gap']as$case){
 $rule=$base->pack['rules'][0];
 $checks=[['name'=>'qa_signal','args'=>[]],['name'=>'qa_gap','args'=>[]]];
 $rule['checks']=$checks;$rule['obligations']=[['id'=>'O001','role'=>'mandatory','proof'=>'heuristic','op'=>'all','checks'=>$checks]];
 $plan=new ScanPlan($base->request,array_replace($base->pack,['rules'=>[$rule]]),$base->metadata);
 $registry=new CheckRegistry();
 $registry->register('qa_signal',static fn(array$args):CheckResult=>CheckResult::of(str_contains($case,'signal')?CheckOutcome::Fail:CheckOutcome::Pass,str_contains($case,'signal')?'Observed source candidate at app/code/Example.php:4':'No candidate in inspected scope',['matches'=>str_contains($case,'signal')?[['file'=>'app/code/Example.php','line'=>4]]:[]],null,'qa_signal'));
 $registry->register('qa_gap',static fn(array$args):CheckResult=>CheckResult::of(str_contains($case,'gap')?CheckOutcome::Unknown:CheckOutcome::Pass,str_contains($case,'gap')?'[UNKNOWN] Unreadable source path':'Source observed',[],null,'qa_gap'));
 $raw=(new ScanService())->run($plan,null,$registry)->toLegacy();
 $result=(new ScanReportAssembler())->assemble(\Magebean\Engine\ScanReport::fromLegacy($raw),$plan)->toLegacy();
 $gap=str_contains($case,'gap');$attention=str_contains($case,'signal');
 $assert($result['meta']['findings_first']===true,'Magebean profiles enable findings-first');
 $assert(count($result['risk_findings'])===($attention?1:0),'Only actual observations become attention findings: '.$case);
 $assert(count($result['collection_issues'])===($gap?1:0),'Collection gaps remain separate: '.$case);
 $assert($result['meta']['scan_complete']===!$gap,'Heuristic conclusion alone is not a collection error: '.$case);
 if($case==='gap'){
  $assert($result['risk_findings']===[],'Gap-only scan has no ordinary findings');
  $out=new \Symfony\Component\Console\Output\BufferedOutput();
  (new \Magebean\Console\ScanConsoleRenderer())->renderPrettySummary($out,$result,sys_get_temp_dir());$text=$out->fetch();
  $assert(str_contains($text,'Unreadable source path')&&str_contains($text,'Scan collection issues'),'Detailed output names the separate collection diagnostic');
  $assert(str_contains($text,'How to resolve MB-0014'),'Detailed collection diagnostic includes its own action');
 }
 $assert((new ScanExitPolicy())->code($result)===($gap?3:($attention?1:0)),'Exit code follows actual risk and collection state: '.$case);
 $wire=(new AgentResultMapper())->map($raw,['manifest_hash'=>'sha256:test'],['MB-0014'=>['assessment_item_id'=>'item']],[],sys_get_temp_dir());
 $assert($wire['results'][0]['evidence']['risk_observation']['needs_attention']===$attention,'Risk survives agent transport');
 $assert($wire['summary']['needs_attention']===($attention?1:0),'Agent reports findings independently of requirement outcome');
 if(str_contains($case,'signal'))$assert(str_starts_with($wire['results'][0]['title'],'Policy: Observed source candidate'),'Agent title uses observed risk rather than unknown assessment conclusion');
}
echo "MagebeanFindingsFirstPipelineTest: $n assertions passed\n";
