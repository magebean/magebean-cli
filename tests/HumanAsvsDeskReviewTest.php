<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\{RequirementCatalog,RequirementAssessmentEvaluator,RequirementOutcome,CheckResult,CheckOutcome};
$n=0;function asvsDeskAssert(bool $v,string $m):void{global$n;++$n;if(!$v)throw new RuntimeException($m);}
$report=json_decode(file_get_contents(__DIR__.'/../docs/archive/reviews/automation-human-asvs-desk-review.json'),true,512,JSON_THROW_ON_ERROR);$review=array_column($report['decisions'],null,'id');$rules=array_values(array_filter(RequirementCatalog::loadAll()['rules'],static fn(array$r):bool=>!empty($r['human_evidence']['required'])&&in_array('OWASP-ASVS',array_column($r['alignments'],'standard'),true)));
asvsDeskAssert(count($review)===$report['reviewed_count']&&count($review)===344,'Historical desk-review ledger retains its344 decisions');
asvsDeskAssert(count($rules)===345,'Current source family owns all345 independent ASVS clauses');
foreach($rules as$r){$id=$r['id'];$entry=$review[$id]??null;if($entry!==null){asvsDeskAssert(($entry['runtime_conformance_validated']??null)===false&&($entry['no_automation_promotion']??null)===true,$id.' historical review makes no runtime/compliance claim');$criteria=array_merge([$r['criterion']],array_column($r['criterion_history']??[],'criterion'));asvsDeskAssert(in_array($entry['criterion'],$criteria,true),$id.' historical reviewed criterion retained as current or revision history');}
 asvsDeskAssert(str_contains($r['human_evidence']['instructions'],'expected versus observed')&&str_contains($r['human_evidence']['instructions'],'Do not attach credentials'),$id.' concrete evidence handoff and safe handling');
 foreach($r['alignments']as$a)if($a['standard']==='OWASP-ASVS')asvsDeskAssert(str_contains($r['human_evidence']['instructions'],$a['reference']),$id.' exact reference present in handoff');
 foreach($r['obligations']as$o)if($o['proof']==='heuristic')asvsDeskAssert($o['role']==='supporting',$id.' heuristics do not masquerade as necessary full-ASVS proof');
 $active=$r;$active['applicability']=['state'=>'APPLICABLE'];$result=RequirementAssessmentEvaluator::evaluate($active,static fn(string$name,array$args):CheckResult=>CheckResult::of(CheckOutcome::Unknown,'Fixture supporting collection gap',[],null,$name));
 asvsDeskAssert($result->outcome===($id==='MB-0379'?RequirementOutcome::Unknown:RequirementOutcome::ManualReview),$id.' human boundary preserved when supporting data missing');
}
$debug=array_values(array_filter($rules,static fn(array$r):bool=>$r['id']==='MB-0379'))[0];$verified=array_filter($debug['obligations'],static fn(array$o):bool=>$o['role']==='mandatory'&&$o['proof']==='verified_predicate');asvsDeskAssert(count($verified)===1,'Debug observations retain the explicit verified counterexample predicate without widening normative criterion');
echo 'HumanAsvsDeskReviewTest: '.$n.' assertions across '.count($rules)." definitions passed\n";
