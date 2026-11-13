<?php
declare(strict_types=1);
require __DIR__.'/../../../vendor/autoload.php';
use Magebean\Engine\{RequirementCatalog,RequirementAssessmentEvaluator,CheckResult,CheckOutcome};
$rules=array_column(RequirementCatalog::loadAll()['rules'],null,'id');
$definition=$rules['MB-0014'];
// In-memory probes only. Catalog and profile files are not mutated.
$out=[];
foreach(['verified_predicate','heuristic']as$proof){
 foreach($definition['obligations']as&$obligation)$obligation['proof']=$proof;unset($obligation);
 $assessment=RequirementAssessmentEvaluator::evaluate($definition,static fn(string$name,array$args):CheckResult=>CheckResult::of(CheckOutcome::Fail,'Synthetic source candidate found; exploitability unverified.',['matches'=>[['file'=>'app/code/Example.php','line'=>4]]],null,$name));
 $out[$proof]=['outcome'=>$assessment->outcome->value,'reason_code'=>$assessment->reasonCode,'message'=>$assessment->message,'nested_observation_status'=>$assessment->evidence['obligations'][0]['checks'][0]['status']];
}
if($out['verified_predicate']['outcome']!=='FAIL'||$out['heuristic']['outcome']!=='UNKNOWN'||$out['heuristic']['nested_observation_status']!=='FAIL')throw new RuntimeException('Risk-first pipeline review assumptions changed; re-review.');
file_put_contents(__DIR__.'/risk-first-pipeline-probe.json',json_encode($out,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR)."\n");
echo "Verified syntax failure => FAIL; heuristic failure => UNKNOWN with retained nested FAIL. No separate attention signal outcome exists.\n";
