<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\{RequirementCatalog,RequirementDefinitionValidator,RequirementAssessmentEvaluator,RequirementOutcome,CheckResult,CheckOutcome,Context};
use Magebean\Engine\Checks\CheckRegistry;
$pack=RequirementCatalog::loadAll();$index=array_column($pack['rules'],null,'id');$registry=CheckRegistry::fromContext(new Context('/unused',''));$n=0;
$assert=static function(bool $ok,string $message)use(&$n):void{++$n;if(!$ok)throw new RuntimeException($message);};
$assert(count($index)===724,'Current inventory includes fresh scoped source and production automation definitions');
$allocation=RequirementCatalog::read('allocation-manifest');
$assert(count($allocation['allocations'])===827&&$allocation['next_id']===828,'Automation additions allocate fresh identities without reusing historical IDs');
foreach($index as$r)$assert(RequirementDefinitionValidator::validate($r,$registry)===[],'Valid structural contract '.$r['id']);
foreach(['MB-0002','MB-0062','MB-0063','MB-0072']as$id){$r=$index[$id];$assert($r['human_evidence']['required']===false,'Bounded predicate remains automatic '.$id);$assert(isset($r['criterion_history'])&&count($r['criterion_history'])>0,'Previous criterion retained '.$id);$assert(RequirementAssessmentEvaluator::evaluate($r,fn()=>CheckResult::of(CheckOutcome::Pass,'Observed bounded predicate'))->outcome===RequirementOutcome::Pass,'Verified predicate can pass '.$id);$assert(RequirementAssessmentEvaluator::evaluate($r,fn()=>CheckResult::of(CheckOutcome::Unknown,'Collection incomplete'))->outcome===RequirementOutcome::Unknown,'Missing evidence cannot become clean '.$id);}
foreach(['MB-0062','MB-0063']as$id)foreach($index[$id]['checks']as$c)$assert(($c['args']['strict_scope']??false)===true,'Maintenance scope requires complete status '.$id);
$archive=array_column(RequirementCatalog::read('magebean-retirements')['requirements'],null,'id');
foreach(['MB-0082','MB-0083','MB-0086']as$id){$r=$archive[$id];$assert($r['human_evidence']['required']===true&&trim($r['human_evidence']['instructions'])!=='','Broad payment obligation has actionable human boundary '.$id);foreach($r['obligations']as$o)$assert($o['role']==='supporting'&&$o['proof']==='heuristic','Pattern observations stay supporting '.$id);$assert(RequirementAssessmentEvaluator::evaluate($r,fn()=>CheckResult::of(CheckOutcome::Pass,'No pattern match'))->outcome===RequirementOutcome::ManualReview,'No pattern match cannot certify payment storage '.$id);}
$ledger=RequirementCatalog::read('reconciliation-ledger');$assert($ledger['counts']['active_internal_requirements']===count($index),'Reconciliation inventory matches current independent families');$assert($ledger['counts']['accepted_scoped_criteria']===count(array_filter($index,fn($r)=>!$r['human_evidence']['required']))&&$ledger['counts']['human_evidence_required']===count(array_filter($index,fn($r)=>$r['human_evidence']['required'])),'Ledger automatic and human counts agree with current definitions');
echo "Automation inventory contract: $n assertions passed\n";
