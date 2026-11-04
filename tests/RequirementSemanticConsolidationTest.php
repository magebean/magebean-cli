<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\{RequirementCatalog,RequirementOutcome,ScanRunner,Context,CheckResult,CheckOutcome,ScanDeadline};
use Magebean\Engine\Checks\CheckRegistry;
$count=0;
function mergeAssert(bool $value,string $message):void{global$count;$count++;if(!$value)throw new RuntimeException($message);}
// The consolidation manifest is an immutable historical ledger, not today's catalog.
$index=array_column(RequirementCatalog::loadAll()['rules'],null,'id');
$manifest=RequirementCatalog::read('semantic-consolidations');
mergeAssert(count($manifest['groups'])===13,'Every historical consolidation group remains recorded');
$retired=[];
$replacements=RequirementCatalog::read('family-separation-manifest')['retired_identity_replacements'];
$allocations=array_column(RequirementCatalog::read('allocation-manifest')['allocations'],null,'id');
foreach($manifest['groups'] as $group){
    mergeAssert(count($group['original_definitions'])===count($group['retired_ids'])+1,'Historical ledger retains every original definition');
    $originalIds=array_column($group['original_definitions'],'id');
    mergeAssert(in_array($group['canonical_id'],$originalIds,true),'Historical canonical definition preserved');
    foreach($group['retired_ids'] as $id){
        $retired[]=$id;
        mergeAssert(in_array($id,$originalIds,true),'Historical retired definition preserved');
        mergeAssert(($allocations[$id]['redirect_to']??null)===$group['canonical_id'],'Historical allocation redirect is immutable');
        mergeAssert(!isset($index[$id]),'Family split must allocate new IDs rather than revive retired identities');
        mergeAssert(RequirementCatalog::resolveAlias($id)===(isset($index[$replacements[$id]]) ? [$replacements[$id]] : []),'Retired selector resolves its source-bound replacement without reviving old identity');
    }
}
mergeAssert(count($retired)===42&&count(array_unique($retired))===42,'Exactly42 unique retired identities stay reserved');
function observedDefinition(string$id,array$args,bool$human=false):array{return['id'=>$id,'revision'=>1,'title'=>'Scoped test policy','criterion'=>'The declared property is satisfied.','control'=>'MB-C01','severity'=>'high','coverage'=>'PARTIAL','verification'=>'automated','review_state'=>'security_reviewed','human_evidence'=>['required'=>$human,'instructions'=>$human?'Independent confirmation required.':''],'alignments'=>[],'target_modes'=>['LOCAL'],'checks'=>[['name'=>'shared_property','args'=>$args]],'obligations'=>[['id'=>'O001','role'=>'mandatory','proof'=>'verified_predicate','op'=>'all','checks'=>[['name'=>'shared_property','args'=>$args]]]]];}
$registry=new CheckRegistry();$calls=0;$registry->register('shared_property',function(array$args)use(&$calls):CheckResult{$calls++;return CheckResult::of(CheckOutcome::Pass,'Scoped observation',[],null,'shared_property');});
$a=observedDefinition('MB-9001',['limit'=>8,'scope'=>'admin']);$b=observedDefinition('MB-9002',['scope'=>'admin','limit'=>8],true);
$runner=new ScanRunner(new Context('/fixture',''),['rules'=>[$a,$b]],null,$registry);$report=$runner->run();mergeAssert($calls===1,'Identical scoped observations reused across criteria');mergeAssert(array_column($report['findings'],'status')===['PASS','MANUAL_REVIEW'],'Assessment conclusions are not cached/shared');$runner->run();mergeAssert($calls===2,'Observation reuse is reset for the next scan');
$c=observedDefinition('MB-9003',['limit'=>15,'scope'=>'admin']);(new ScanRunner(new Context('/fixture',''),['rules'=>[$a,$c]],null,$registry))->run();mergeAssert($calls===4,'Different thresholds cannot reuse an observation');
$b=$a;$b['obligations'][]=['id'=>'O002','role'=>'supporting','proof'=>'heuristic','op'=>'all','checks'=>$a['checks']];$b['checks']=array_merge($a['checks'],$a['checks']);$report=(new ScanRunner(new Context('/fixture',''),['rules'=>[$b]],null,$registry))->run();mergeAssert(count($report['findings'][0]['detail'])===1,'Same technical observation is not displayed twice inside one requirement');mergeAssert(count($report['findings'][0]['evidence']['obligations'])===2,'Distinct obligation contracts remain visible');
$clock=0.0;$deadline=new ScanDeadline(1,static function()use(&$clock):float{return$clock;});$late=new CheckRegistry();$late->register('shared_property',function()use(&$clock):CheckResult{$clock=2.0;return CheckResult::of(CheckOutcome::Pass,'Late observation');});$report=(new ScanRunner(new Context('/fixture',''),['rules'=>[$a]],null,$late,$deadline))->run();mergeAssert($report['findings'][0]['status']==='UNKNOWN','An observation completed after deadline cannot establish PASS');
echo "RequirementSemanticConsolidationTest: $count assertions passed\n";
