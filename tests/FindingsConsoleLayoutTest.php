<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Console\FindingsConsoleRenderer;
use Symfony\Component\Console\Output\BufferedOutput;
use Symfony\Component\Console\Helper\Helper;
$rows=[];
foreach(['low','critical','high','medium']as$i=>$severity)$rows[]=['id'=>'MB-'.(790+$i),'severity'=>$severity,'risk_observation'=>['needs_attention'=>true,'findings'=>[['check'=>'source_policy','message'=>'Observed unsafe configuration requires investigation in the deployed application; confirm its context before changing production.','evidence'=>['matches'=>[['file'=>'app/code/Example/'.str_repeat('VeryLongDirectory',7).'/Input.php','line'=>42]]]]]],'remediation'=>['Review the reported location and use the supported Magento API without removing validation or changing the expected business behavior.'],'requirement'=>['finding_guidance'=>['interpretation'=>'Exact observation only.','verification'=>['Rescan the same release.']]]];
$result=['meta'=>['profile'=>['title'=>'Magento Production Hardening','id'=>'hardening']],'risk_findings'=>$rows,'collection_issues'=>[['id'=>'MB-0807','message'=>'Worker process could not be read.','collection_guidance'=>['action'=>'Grant bounded process inspection access and rerun.']]],'coverage_summary'=>['executed'=>74,'inventory'=>86,'not_evaluated'=>12,'assessment_complete'=>false]];
$result['not_evaluated_requirements']=array_fill(0,12,['reason_code'=>'CAPABILITY_CONTEXT_MISSING']);
$n=0;$assert=static function(bool$ok,string$message)use(&$n):void{++$n;if(!$ok)throw new RuntimeException($message);};
foreach([40,48,80,110]as$width){
 $outputs=[];
 foreach([false,true]as$decorated){$out=new BufferedOutput(BufferedOutput::VERBOSITY_NORMAL,$decorated);(new FindingsConsoleRenderer($width))->render($out,$result,'/var/www/magento');$outputs[]=$out->fetch();}
 [$plain,$ansi]=$outputs;
 $assert(!str_contains($plain,'[NEEDS ATTENTION]'),'No repetitive per-finding status labels');
 $flat=preg_replace('/\s+/u',' ',$plain);
 $assert(str_contains($flat,'74 selected · 12 require additional context')&&!str_contains($plain,'rules executed'),'Rule selection is not presented as completed coverage');
 $assert(str_contains($ansi,"\033["),'Decorated output has real ANSI colors');
 $assert(!str_contains($plain,"\033["),'Plain/CI output has no ANSI');
 $stripped=preg_replace('/\x1B\[[0-?]*[ -\/]*[@-~]/','',$ansi);
 $assert($stripped===$plain,'Colors do not alter content or alignment');
 foreach(explode("\n",$plain)as$line)$assert(Helper::width($line)<=$width,'Every rendered line fits '.$width.' columns');
 $assert(strpos($plain,'CRITICAL')<strpos($plain,'HIGH')&&strpos($plain,'HIGH')<strpos($plain,'MEDIUM'),'Severity order is stable');
 $assert(str_contains(preg_replace('/\s+/u','',$plain),'Input.php:42'),'Source match location remains visible');
}
$out=new BufferedOutput();$detailed=$result;$detailed['meta']['rules_filter']=['MB-0791'];(new FindingsConsoleRenderer(80))->render($out,$detailed,'/var/www/magento');
$assert(str_contains($out->fetch(),'Verification after remediation'),'Selected requirements retain full guidance');
if(in_array('--preview',$argv,true)){
 foreach([false,true]as$decorated){$out=new BufferedOutput(BufferedOutput::VERBOSITY_NORMAL,$decorated);(new FindingsConsoleRenderer(100))->render($out,$result,'/var/www/magento');file_put_contents(__DIR__.'/../artifacts/findings-output-preview.'.($decorated?'ansi':'txt'),$out->fetch());}
}
echo "FindingsConsoleLayoutTest: $n assertions passed\n";
