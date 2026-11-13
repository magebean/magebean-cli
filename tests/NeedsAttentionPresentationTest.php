<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Agent\AgentScanner;
use Magebean\Engine\{Context,ScanContext,ScanRequest,ScanPlanner,ScanService,ScanReportAssembler,CheckResult,CheckOutcome,ScanExitPolicy};
use Magebean\Engine\Checks\CheckRegistry;
use Magebean\Console\ScanConsoleRenderer;
use Symfony\Component\Console\Output\BufferedOutput;
$n=0;function attentionAssert(bool$v,string$m):void{global$n;++$n;if(!$v)throw new RuntimeException($m);}
$root=sys_get_temp_dir().'/mb-attention-'.bin2hex(random_bytes(5));mkdir($root);
try{
 $manifest=['schema_version'=>'1.0','manifest_hash'=>'snapshot-before-human-review','rules'=>[['assessment_item_id'=>'snapshot-item','rule_key'=>'MB-0103','verification'=>'automated','human_evidence'=>['required'=>false]]]];
 $mapped=(new AgentScanner())->run($root,$manifest);$row=$mapped['results'][0];
 attentionAssert($row['assessment_item_id']==='snapshot-item'&&$row['rule_key']==='MB-0103','Stale dashboard snapshot keeps requested identity and item binding');
 attentionAssert($row['status']==='error','Existing wire status preserved, human assessment is not fake PASS');
 attentionAssert(($row['evidence']['assessment_status']??null)==='MANUAL_REVIEW'&&($row['evidence']['human_verification_required']??null)===true,'Bundled current catalog human boundary survives stale automated snapshot');
 attentionAssert(($row['evidence']['attention_reason']??null)==='human_verification_required','Dashboard can classify human review independently of old snapshot');
 attentionAssert(($row['evidence']['collection_guidance']['owner']??null)==='security_reviewer'&&str_contains($row['evidence']['collection_guidance']['action']??'','1.1.1'),'Exact human evidence handoff retained');
 attentionAssert(!str_contains(json_encode($row),'criterion-to-check binding')&&!str_contains(json_encode($row),'REQUIREMENT_BINDING_UNVALIDATED'),'Human item does not surface internal binding failure');
 foreach([false,true]as$detailed){
  $context=new ScanContext($root,'');$real=CheckRegistry::fromContext(new Context($root,''));$plan=(new ScanPlanner())->planCli(new ScanRequest($context,['profile'=>'basic']+($detailed?['rules'=>'MB-0030']:[])),$real);
  $fake=new CheckRegistry();foreach($plan->pack['rules']as$r)foreach($r['checks']as$c)if(!$fake->has($c['name']))$fake->register($c['name'],static fn(array$args):CheckResult=>CheckResult::of(CheckOutcome::Unknown,'Certificate trust failed',['action'=>'Trust the site CA in the scanner trust store','reason_code'=>'TLS_TRUST_FAILED']));
  $scan=(new ScanReportAssembler())->assemble((new ScanService())->run($plan,null,$fake),$plan)->toLegacy();$out=new BufferedOutput();(new ScanConsoleRenderer())->renderPrettySummary($out,$scan,$root);$text=$out->fetch();
  attentionAssert(str_contains($text,'need attention')&&$scan['summary']['needs_attention']===0&&!str_contains($text,'EXECUTION ERROR')&&!str_contains($text,'Execution errors'),'Pure collection gaps remain separate from risk attention in summary and detail');
  attentionAssert((str_contains($text,'Trust the site CA in the scanner trust store')===$detailed)&&(str_contains($text,'Certificate trust failed')===$detailed),'Cause and collector action both remain visible');
  attentionAssert($scan['findings'][0]['status']==='UNKNOWN'&&count($scan['execution_errors'])>0&&(new ScanExitPolicy())->code($scan)===3,'Wire fields and incomplete scan exit semantics unchanged');
 }
 echo 'NeedsAttentionPresentationTest: '.$n." assertions passed\n";
}finally{rmdir($root);}
