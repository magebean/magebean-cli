<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\{ScanContext,ScanRequest,ScanPlanner,ScanService,ScanReportAssembler,CheckResult,CheckOutcome,RequirementCatalog,RequirementAssessmentEvaluator,MagebeanRiskObservation};
use Magebean\Engine\Checks\CheckRegistry;
use Magebean\Console\ScanConsoleRenderer;
use Symfony\Component\Console\Output\BufferedOutput;
$root=sys_get_temp_dir().'/magebean-specific-source-'.bin2hex(random_bytes(5));mkdir($root.'/app/code/Example',0777,true);
$n=0;$assert=static function(bool$ok,string$message)use(&$n):void{++$n;if(!$ok)throw new RuntimeException($message);};
try{
 file_put_contents($root.'/app/code/Example/Broken.php',"<?php\nfunction broken(\n");
 $context=new ScanContext($root,'');$registry=CheckRegistry::fromContext($context->toLegacy());
 $plan=(new ScanPlanner())->planCli(new ScanRequest($context,['profile'=>'hardening','rules'=>'MB-0789,MB-0790']),$registry);
 $scan=static fn()=> (new ScanReportAssembler())->assemble((new ScanService())->run($plan,null,$registry),$plan)->toLegacy();
 $result=$scan();
 $assert($result['risk_findings']===[] && count($result['findings'])===2,'Parser-only diagnostics preserve assessments without ordinary findings');
 $assert(array_column($result['findings'],'id')===['MB-0789','MB-0790'],'Assessment identities remain independent');
 $specific=$result['collection_issues'][0];
 $assert(str_contains($specific['message'],'app/code/Example/Broken.php'),'Diagnostic names the actual file');
 $assert(isset($specific['evidence']['inspection_issue']['line']),'Diagnostic retains parser line');
 $assert(!empty($specific['collection_guidance']['action']),'Diagnostic retains a concrete collection action');
 $out=new BufferedOutput();(new ScanConsoleRenderer())->renderPrettySummary($out,$result,$root);$text=$out->fetch();
 $assert(str_contains($text,'0 findings need attention')&&str_contains($text,'Scan collection issues'),'Detailed output separates scan problems from risks');
 file_put_contents($root.'/app/code/Example/Second.php',"<?php\nfunction second(\n");
 $result=$scan();$assert($result['risk_findings']===[]&&count($result['collection_issues'])===4,'Specific parser diagnostics remain per requirement and source location');
 unlink($root.'/app/code/Example/Second.php');
 file_put_contents($root.'/app/code/Example/Unsafe.php',"<?php unserialize(\$payload);\n");
 $result=$scan();
 $assert(count($result['risk_findings'])===1 && $result['risk_findings'][0]['id']==='MB-0789','Actual policy violation remains alongside independent diagnostics');
 $assert(!$result['meta']['scan_complete']&&count($result['collection_issues'])===2,'Known issue does not hide incomplete source inspection');
 $definition=array_column(RequirementCatalog::loadAll()['rules'],null,'id')['MB-0789'];
 $assessment=RequirementAssessmentEvaluator::evaluate($definition,static fn()=>CheckResult::of(CheckOutcome::Unknown,'[UNKNOWN] Source policy could not be evaluated completely.',[],'SOURCE_POLICY_INCOMPLETE','automated_source_policy'));
 $risk=MagebeanRiskObservation::fromAssessment($definition,$assessment);
 $assert(!$risk['needs_attention']&&$risk['findings']===[]&&!$risk['collection_complete'],'A generic message without specific evidence remains technical metadata, not a finding');
 echo "SourceInspectionFindingsTest: $n assertions passed\n";
}finally{foreach(glob($root.'/app/code/Example/*')?:[]as$file)unlink($file);rmdir($root.'/app/code/Example');rmdir($root.'/app/code');rmdir($root.'/app');rmdir($root);}
