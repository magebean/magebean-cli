<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\{RequirementCatalog,RequirementProfileCatalog,ScanContext,ScanRequest,ScanPlanner};
use Magebean\Engine\Checks\CheckRegistry;
use Magebean\Application;
use Symfony\Component\Console\Tester\CommandTester;
function mergedAssert(bool $v,string $m):void{if(!$v)throw new RuntimeException($m);}
$all=RequirementCatalog::loadAll();mergedAssert(count($all['rules'])===724,'Independent family inventory active count');$refs=['OWASP-ASVS'=>[],'PCI-DSS'=>[]];foreach($all['rules'] as $r)foreach($r['alignments'] as $a)if(isset($refs[$a['standard']])){mergedAssert(!isset($refs[$a['standard']][$a['reference']]),'Standard reference has one surviving owner');$refs[$a['standard']][$a['reference']]=$r['id'];}mergedAssert(count($refs['OWASP-ASVS'])===345&&count($refs['PCI-DSS'])===280,'Consolidation retains all625 normative references');
$known=array_fill_keys(array_column($all['rules'],'id'),true);foreach(RequirementProfileCatalog::all() as $p){mergedAssert(count($p['requirement_ids'])===count(array_unique($p['requirement_ids'])),'Profile canonical membership deduplicated');foreach($p['requirement_ids'] as $id)mergedAssert(isset($known[$id]),'Profile membership is active canonical');}
// Former cross-family debug union is now an independent ASVS clause.
$merged=array_column($all['rules'],null,'id')['MB-0379'];
mergedAssert($merged['family']==='asvs'&&$merged['human_evidence']['required'],'ASVS all-components claim retains human boundary');
mergedAssert(!str_contains($merged['criterion'],'Additional mandatory Magento'),'No Magebean deployment clauses appended to normative criterion');
$control=$merged['control'];
$filtered=RequirementCatalog::loadAll([$control]);
mergedAssert(in_array($merged['id'],array_column($filtered['rules'],'id'),true),'Catalog filtering honors document requirement control');
$root=sys_get_temp_dir().'/mb-merged-contract-'.bin2hex(random_bytes(5));mkdir($root);try{$ctx=new ScanContext($root,'');$registry=CheckRegistry::fromContext($ctx->toLegacy());$planner=new ScanPlanner();$profile=$root.'/profile.json';file_put_contents($profile,json_encode(['id'=>'one-merged','requirement_ids'=>[$merged['id']]]));$plan=$planner->planCli(new ScanRequest($ctx,['profile'=>$profile,'controls'=>$control,'include-manual-review'=>true]),$registry);mergedAssert($plan!==null&&array_column($plan->pack['rules'],'id')===[$merged['id']],'Planner honors document control selection');$tester=new CommandTester((new Application())->find('rules:list'));$tester->execute(['--profile'=>$profile,'--control'=>$control,'--include-manual-review'=>true,'--no-ansi'=>true]);mergedAssert(str_contains($tester->getDisplay(),$merged['id']),'Listing honors document control selection');$config=$root.'/.magebean.json';file_put_contents($config,json_encode(['exclude_controls'=>[$control]]));$plan=$planner->planCli(new ScanRequest($ctx,['rules'=>$merged['id']]),$registry);mergedAssert($plan===null,'Excluding document control cannot leave merged criterion selected');unlink($config);unlink($profile);}finally{rmdir($root);}echo "MergedRequirementContractTest passed\n";
