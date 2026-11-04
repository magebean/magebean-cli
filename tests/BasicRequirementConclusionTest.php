<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\{RequirementCatalog,RequirementAssessmentEvaluator,RequirementOutcome,CheckOutcome,CheckResult};
$n=0;function completionAssert(bool $condition,string $message):void{global$n;++$n;if(!$condition)throw new RuntimeException($message);}
$index=array_column(RequirementCatalog::loadAll()['rules'],null,'id');
$ids=['0003','0005','0006','0011','0026','0028','0029','0030','0035','0037','0046','0049','0050','0072'];
foreach($ids as$id){$r=$index['MB-'.$id];completionAssert($r['review_state']==='accepted_scoped_criterion','Reviewed automation binding '.$id);
    $pass=RequirementAssessmentEvaluator::evaluate($r,static fn(string$name,array$args):CheckResult=>CheckResult::of(CheckOutcome::Pass,'Verified fixture observation',[],null,$name));
    completionAssert($pass->outcome===RequirementOutcome::Pass,'Complete successful observations establish bounded criterion '.$id);
    $fail=RequirementAssessmentEvaluator::evaluate($r,static fn(string$name,array$args):CheckResult=>CheckResult::of(CheckOutcome::Fail,'Verified fixture counterexample',[],null,$name));
    completionAssert($fail->outcome===RequirementOutcome::Fail,'Verified counterexample establishes bounded violation '.$id);
    $missing=RequirementAssessmentEvaluator::evaluate($r,static fn(string$name,array$args):CheckResult=>CheckResult::of(CheckOutcome::Unknown,'[UNKNOWN] Provide the missing target-specific evidence.',[],null,$name));
    completionAssert($missing->outcome===RequirementOutcome::Unknown&&str_contains($missing->message,'target-specific evidence'),'Missing evidence carries actionable detector explanation '.$id);
}
$r=$index['MB-0379'];$pass=RequirementAssessmentEvaluator::evaluate($r,static fn(string$name,array$args):CheckResult=>CheckResult::of(CheckOutcome::Pass,'Observed disabled',[],null,$name));completionAssert($pass->outcome===RequirementOutcome::ManualReview,'Debug ASVS all-components scope cannot be certified from a default flag');
$unknown=RequirementAssessmentEvaluator::evaluate($r,static fn(string$name,array$args):CheckResult=>CheckResult::of(CheckOutcome::Unknown,'Missing scoped evidence',[],null,$name));completionAssert($unknown->outcome!==RequirementOutcome::Pass,'Missing ASVS observations cannot establish a complete all-components conclusion');
completionAssert(count($index)===724,'Current independent inventory includes scoped automation additions after Basic expansion');
$references=[];foreach($index as$row)foreach($row['alignments']as$a)$references[$a['standard'].':'.$a['version'].':'.$a['reference']]=true;completionAssert(count($references)===625,'All standard references survive automation review');
echo "BasicRequirementConclusionTest: $n assertions passed\n";
