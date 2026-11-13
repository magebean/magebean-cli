<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\{CheckResult,RequirementCatalog,RequirementAssessmentEvaluator,MagebeanRiskObservation};
$root=dirname(__DIR__);$dir=$root.'/docs/archive/current-state/phase3';
$acceptance=json_decode(file_get_contents($root.'/docs/archive/current-state/phase0/acceptance.json'),true,512,JSON_THROW_ON_ERROR);
$part1=json_decode(file_get_contents($dir.'/part1-probes.json'),true,512,JSON_THROW_ON_ERROR)['observations'];
$part2=json_decode(file_get_contents($dir.'/part2-probes.json'),true,512,JSON_THROW_ON_ERROR)['results'];
$catalog=array_column(RequirementCatalog::read('magebean-catalog')['requirements'],null,'id');$rows=[];
foreach ($acceptance['cases'] as $case) {
    if ($case['phase']!==3) continue;
    $first=str_contains($case['source_file'],'part1');$observed=($first?$part1:$part2)[$case['source_index']];
    if ($first) {
        $rule=$catalog[$observed['id']];$status=$observed['status'];
        $check=CheckResult::fromLegacy([$status==='PASS'?true:($status==='FAIL'?false:null),$observed['message'],$observed['evidence']]);
        $assessment=RequirementAssessmentEvaluator::evaluate($rule,static fn()=>$check);
        $risk=MagebeanRiskObservation::fromAssessment($rule,$assessment);
        $category=$risk['findings'][0]['category']??null;$confidence=$risk['findings'][0]['confidence']??null;$attention=$risk['needs_attention'];
    } else {
        $status=$observed['check_outcome'];$category=$observed['category'];$confidence=$observed['confidence'];$attention=$observed['needs_attention'];
    }
    $expectedCategory=$status==='FAIL'?($case['id']==='CS-032'?'security':'policy'):null;
    if ($category!==$expectedCategory || $attention!==($status==='FAIL')
        || ($case['id']==='CS-032' && $confidence!=='suspected')) throw new RuntimeException('Phase 3 acceptance mismatch: '.$case['id']);
    $rows[]=['acceptance_id'=>$case['id'],'rules'=>$case['rules'],'archived_case'=>$case['case'],'executed_case'=>$observed['case'],
        'evidence_file'=>$first?'part1-probes.json':'part2-probes.json','source_index'=>$case['source_index'],
        'status'=>$status,'category'=>$category,'confidence'=>$confidence,'needs_attention'=>$attention,'passed'=>true];
}
file_put_contents($dir.'/acceptance-results.json',json_encode(['phase'=>3,'scope'=>'Fresh synthetic QA probes; legacy check evidence is projected through the production risk interpreter. No live-store qualification.','checks'=>$rows],JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR)."\n");
echo 'Phase 3 QA acceptance: '.count($rows)." cases passed\n";
