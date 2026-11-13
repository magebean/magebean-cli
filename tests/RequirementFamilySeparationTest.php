<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\{RequirementCatalog,RequirementProfileCatalog};
$count=0;
function familyAssert(bool $ok,string $message):void{global $count;++$count;if(!$ok)throw new RuntimeException($message);}
$aggregate=RequirementCatalog::read('internal-catalog')['requirements'];
$loaded=RequirementCatalog::loadAll()['rules'];
$all=[];
foreach(['magebean'=>110,'asvs'=>345,'pci'=>280] as $family=>$expected){
    $catalog=RequirementCatalog::read($family.'-catalog');
    familyAssert(($catalog['family']??null)===$family,'Physical catalog declares family '.$family);
    familyAssert(count($catalog['requirements'])===$expected,'Independent family inventory '.$family);
    foreach($catalog['requirements'] as $r){
        familyAssert(($r['family']??null)===$family,'Definition family agrees with physical catalog '.$r['id']);
        familyAssert(!isset($all[$r['id']]),'No identity shared across physical catalogs '.$r['id']);
        $all[$r['id']]=$r;
        if($family==='magebean')familyAssert($r['alignments']===[],'Magebean requirements cannot act as normative standard clauses');
        else{
            familyAssert(count($r['alignments'])===1,'One document clause owns one standard requirement '.$r['id']);
            $alignment=$r['alignments'][0];
            familyAssert($alignment['standard']===($family==='asvs'?'OWASP-ASVS':'PCI-DSS'),'No cross-standard alignment');
            familyAssert(($r['source']['reference']??null)===$alignment['reference'],'Document source reference matches clause');
            familyAssert(($r['source']['version']??null)===$alignment['version'],'Document version matches clause');
        }
    }
}
familyAssert(array_column($loaded,null,'id')===$all,'Runtime reads exactly physical family definitions');
familyAssert(array_column($aggregate,null,'id')==$all,'Compatibility aggregate exactly mirrors physical catalogs');
foreach(['asvs'=>'owasp-asvs-v5.0.0','pci'=>'pci-dss-v4.0.1'] as $family=>$file){
    // Read the version-pinned source registry directly; requirement read() resolves its own directory.
    $registry=json_decode(file_get_contents(__DIR__.'/../src/Rules/standards/'.$file.'.json'),true,512,JSON_THROW_ON_ERROR);
    $expected=array_column($registry['requirements'],'id');sort($expected);
    $actual=[];foreach($all as $r)if($r['family']===$family)$actual[]=$r['source']['reference'];sort($actual);
    familyAssert($actual===$expected,'Every version-pinned '.$family.' clause appears exactly once');
}
$asvsDefinitions=[];foreach(RequirementCatalog::read('criterion-definitions')['definitions'] as $d)$asvsDefinitions[$d['source_metadata']['reference']]=$d;
$pciDefinitions=RequirementCatalog::read('pci-criterion-definitions')['criteria'];
foreach($all as $r){
    if($r['family']==='magebean')continue;
    $reference=$r['source']['reference'];
    $original=$r['family']==='asvs'?$asvsDefinitions[$reference]:$pciDefinitions[$reference];
    familyAssert($r['criterion']===$original['criterion'],'Independent source criterion retained verbatim '.$r['id']);
    familyAssert($r['source_metadata']===$original['source_metadata'],'Document provenance retained '.$r['id']);
}
$profileFamilies=['evidence'=>'magebean','takeover'=>'magebean','development'=>'magebean','prelaunch'=>'magebean','module-lifecycle'=>'magebean','module-reliability'=>'magebean','module-source'=>'magebean','module-integrity'=>'magebean','basic'=>'magebean','hardening'=>'magebean','owasp-top-10-2025'=>'magebean','asvs-l1'=>'asvs','asvs-l2'=>'asvs','asvs-l3'=>'asvs','pci-dss-v4.0.1'=>'pci'];
foreach(RequirementProfileCatalog::all() as $profile){
    familyAssert(isset($profileFamilies[$profile['id']]),'Only supported customer profiles are exposed');
    $family=$profileFamilies[$profile['id']];
    familyAssert(($profile['family']??null)===$family,'Profile declares expected family');
    foreach($profile['requirement_ids'] as $id)familyAssert(isset($all[$id])&&$all[$id]['family']===$family,'Profile never crosses requirement families');
}
foreach(['asvs-l1'=>70,'asvs-l2'=>253,'asvs-l3'=>345,'pci'=>280] as $id=>$expected)familyAssert(count(RequirementProfileCatalog::load($id)['requirement_ids'])===$expected,'Profile follows complete document clause membership '.$id);
$tmp=tempnam(sys_get_temp_dir(),'mb-family-');
try{
    $magebean=array_values(array_filter($all,fn($r)=>$r['family']==='magebean'))[0]['id'];
    $asvs=array_values(array_filter($all,fn($r)=>$r['family']==='asvs'))[0]['id'];
    file_put_contents($tmp,json_encode(['id'=>'mixed','requirement_ids'=>[$magebean,$asvs]]));
    $rejected=false;try{RequirementCatalog::forProfile($tmp);}catch(RuntimeException $e){$rejected=true;}
    familyAssert($rejected,'Custom profiles cannot bypass family separation');
}finally{unlink($tmp);}
$ctx=new \Magebean\Engine\ScanContext(sys_get_temp_dir(),'');
$registry=\Magebean\Engine\Checks\CheckRegistry::fromContext($ctx->toLegacy());
$planner=new \Magebean\Engine\ScanPlanner();
foreach(['magebean','asvs','pci'] as $family){
    $definition=array_values(array_filter($all,fn($r)=>$r['family']===$family&&in_array('LOCAL',$r['target_modes'],true)&&!isset($r['applicability']['capability'])))[0];
    $plan=$planner->planCli(new \Magebean\Engine\ScanRequest($ctx,['rules'=>$definition['id'],'include-manual-review'=>true]),$registry);
    familyAssert($plan!==null&&array_column($plan->pack['rules'],'id')===[$definition['id']],'Explicit selector derives family scope '.$family);
    familyAssert(($plan->pack['profile']['family']??null)===$family,'Derived profile family matches selector '.$family);
}
foreach([['rules'=>$magebean.','.$asvs],['profile'=>'basic','rules'=>$asvs],['profile'=>'asvs-l3','rules'=>$magebean]] as $options){
    $rejected=false;try{$planner->planCli(new \Magebean\Engine\ScanRequest($ctx,$options+['include-manual-review'=>true]),$registry);}catch(RuntimeException $e){$rejected=true;}
    familyAssert($rejected,'Explicit selectors cannot cross family or mismatch explicit profile');
}
$manifest=['schema_version'=>'1.0','requirement_family'=>'magebean','rules'=>[['rule_key'=>$magebean,'assessment_item_id'=>'a']]];
$agent=$planner->planAgent(new \Magebean\Engine\ScanRequest($ctx,['manifest'=>$manifest]));
familyAssert(array_column($agent->pack['rules'],'id')===[$magebean],'Agent manifest executes its own declared family');
foreach([
    ['schema_version'=>'1.0','rules'=>[['rule_key'=>$magebean,'assessment_item_id'=>'a'],['rule_key'=>$asvs,'assessment_item_id'=>'b']]],
    ['schema_version'=>'1.0','requirement_family'=>'asvs','rules'=>[['rule_key'=>$magebean,'assessment_item_id'=>'a']]],
] as $manifest){
    $rejected=false;try{$planner->planAgent(new \Magebean\Engine\ScanRequest($ctx,['manifest'=>$manifest]));}catch(RuntimeException $e){$rejected=true;}
    familyAssert($rejected,'Native manifests reject crossed or mismatched families');
}
echo "RequirementFamilySeparationTest: $count assertions passed\n";
