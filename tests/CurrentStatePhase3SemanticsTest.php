<?php
declare(strict_types=1);
$archive=isset($argv[1])?realpath($argv[1]):null;
if (isset($argv[1])&&!$archive) throw new RuntimeException('Supply a valid PHAR path.');
require $archive?'phar://'.$archive.'/vendor/autoload.php':__DIR__.'/../vendor/autoload.php';
use Magebean\Engine\{Context,RequirementCatalog,RequirementAssessmentEvaluator,MagebeanRiskObservation,MagebeanFindingSemantics,CheckResult,CheckOutcome,ScanContext,ScanRequest,ScanPlanner};
use Magebean\Engine\Checks\CheckRegistry;
use Magebean\Engine\Reporting\SarifReporter;
use Magebean\Agent\AgentScanner;
$n=0;$assert=static function(bool $ok,string $m)use(&$n):void{++$n;if(!$ok)throw new RuntimeException($m);};
$rules=array_column(RequirementCatalog::read('magebean-catalog')['requirements'],null,'id');
foreach ($rules as $rule) {
    $profile=MagebeanFindingSemantics::profile($rule['id']);
    $assert($profile['claim_type']!=='unclassified_check_observation','Reviewed semantic coverage: '.$rule['id']);
    $assert(in_array($profile['category'],['security','correctness','policy','informational'],true),'Compatible category: '.$rule['id']);
}
$root=sys_get_temp_dir().'/mb-phase3-'.bin2hex(random_bytes(6));mkdir($root.'/app/code/Fixture',0700,true);
$put=static fn(string $code)=>file_put_contents($root.'/app/code/Fixture/Test.php',$code);
$run=static function(string $id)use($rules,$root):array {
    $registry=CheckRegistry::fromContext(new Context($root,''));
    $rule=$rules[$id];if(isset($rule['applicability']['capability'])) $rule['applicability']['state']='APPLICABLE';
    $assessment=RequirementAssessmentEvaluator::evaluate($rule,static fn(string $name,array $args)=>$registry->runResult($name,$args));
    return [$assessment,MagebeanRiskObservation::fromAssessment($rule,$assessment)];
};
try {
    foreach ([['MB-0788',"<?php file_get_contents('local.txt');"],['MB-0792',"<?php file_get_contents('local.txt');"],
        ['MB-0794',"<?php \$color=mt_rand(0,255);"],['MB-0789',"<?php unserialize('s:2:\"ok\";', ['allowed_classes'=>false]);"],
        ['MB-0790',"<?php exec('printf fixed');"],['MB-0786',"<?php \$label='header'; \$translator->query('label_'.\$label);"]] as [$id,$code]) {
        $put($code);[$assessment,$risk]=$run($id);$row=$risk['findings'][0];
        $assert($row['category']==='policy' && $row['confidence']==='confirmed','Exact syntax confirms policy only: '.$id);
        $assert($row['exploitability']==='not_established' && $row['severity']==='low','Benign syntax is not a proven high severity vulnerability: '.$id);
        $assert(str_starts_with($row['message'],'Policy: ') && !empty($row['evidence']['violations'][0]['file']),'Policy message retains real source evidence: '.$id);
        $assert(str_contains($row['guidance']['recheck'],$id) && $row['guidance']['verification']!=='','Action and recheck are inspectable: '.$id);
    }
    $put("<?php final class Example { public function validateForCsrf() { return true; } }");
    [$assessment,$risk]=$run('MB-0787');
    $assert($risk['findings'][0]['category']==='security' && $risk['findings'][0]['confidence']==='suspected','CSRF acceptance override does not prove absence of alternate authorization');
    $put("<?php function broken(\n");[$assessment,$risk]=$run('MB-0790');
    $assert(!$risk['needs_attention'] && $risk['findings']===[] && !$risk['collection_complete'],'Malformed source is a diagnostic, never an ordinary finding');
    $assert(!empty($risk['collection_gaps'][0]['evidence']['locations'][0]['file']),'Diagnostic keeps file and collection action');
    (new SarifReporter())->write(['findings'=>[['id'=>'MB-0790','risk_observation'=>$risk]]],$root.'/gap.sarif');
    $sarif=json_decode(file_get_contents($root.'/gap.sarif'),true);
    $assert($sarif['runs'][0]['results']===[] && !empty($sarif['runs'][0]['invocations'][0]['toolExecutionNotifications']),'SARIF collection issues are execution notifications, not vulnerability results');
    $fake=CheckResult::of(CheckOutcome::Fail,'Known affected version',['findings'=>[['package'=>'fixture/pkg','version'=>'1.0.0','advisory'=>'QA-1']]]);
    $assessment=RequirementAssessmentEvaluator::evaluate($rules['MB-0049'],static fn()=>$fake);
    $row=MagebeanRiskObservation::fromAssessment($rules['MB-0049'],$assessment)['findings'][0];
    $assert($row['category']==='security' && $row['claim_type']==='advisory_or_patch_match' && $row['confidence']==='confirmed','Affected version match remains an actionable security fact');
    $assert($row['exploitability']==='not_established','Confirmed advisory identity is not confirmed exploitation');
    $typed=\Magebean\Engine\MagebeanDetectorAnalysis::result('fixture','1',[[
        'key'=>'unsafe-request-sink','message'=>'Request reaches command argument','reasoning'=>'The indexed direct request value occurs in the command argument.',
        'confidence'=>'suspected','category'=>'security','severity'=>'high','locations'=>[['file'=>'app/code/Fixture/Test.php','line'=>2]],
        'remediation'=>'Remove request influence and verify authorization.',
    ]]);
    $assessment=RequirementAssessmentEvaluator::evaluate($rules['MB-0822'],static fn()=>$typed);
    $row=MagebeanRiskObservation::fromAssessment($rules['MB-0822'],$assessment)['findings'][0];
    $assert($row['category']==='security' && $row['confidence']==='suspected' && $row['severity']==='high','Supported request-to-sink signal retains severity and explicit uncertainty');
    $unknown=CheckResult::of(CheckOutcome::Unknown,'Missing source access');
    $assessment=RequirementAssessmentEvaluator::evaluate($rules['MB-0822'],static fn()=>$unknown);
    $assert(!MagebeanRiskObservation::fromAssessment($rules['MB-0822'],$assessment)['needs_attention'],'Missing data never becomes a risk finding');
    foreach (['MB-0093','MB-0806'] as $id) {
        $rule=$rules[$id];unset($rule['applicability']);
        $assessment=RequirementAssessmentEvaluator::evaluate($rule,static fn()=>CheckResult::of(CheckOutcome::Fail,'Missing document fields',['missing'=>['owner']]));
        $risk=MagebeanRiskObservation::fromAssessment($rule,$assessment);
        $assert(!$risk['needs_attention'] && $risk['findings']===[] && $risk['observations'][0]['category']==='informational','Evidence lint is separate from technical findings: '.$id);
        $assert(str_contains($risk['observations'][0]['guidance']['verification'],'separately'),'Record lint cannot close a security issue: '.$id);
    }
    $manifest=['schema_version'=>'1.0','manifest_hash'=>'sha256:phase3','rules'=>[['rule_key'=>'MB-0093','assessment_item_id'=>'doc'],['rule_key'=>'MB-0806','assessment_item_id'=>'record']]];
    $plan=(new ScanPlanner())->planAgent(new ScanRequest(new ScanContext($root,''),['manifest'=>$manifest]));
    $assert($plan->pack['rules']===[],'Evidence-only checks require opt-in context');
    $wire=(new AgentScanner())->run($root,$manifest);
    $assert(count($wire['results'])===2 && $wire['results'][0]['status']==='unsupported','Gating preserves agent manifest correspondence');
    $manifest['capabilities']=['evidence_document_lint','dependency_mitigation_policy'];
    $plan=(new ScanPlanner())->planAgent(new ScanRequest(new ScanContext($root,''),['manifest'=>$manifest]));
    $assert(count($plan->pack['rules'])===2,'Explicit evidence context enables existing selectors without adding a default profile');
    $custom=\Magebean\Engine\RequirementPolicy::apply(['assessment_model'=>'internal-requirement-v1','rules'=>[$rules['MB-0790']]],
        ['override_rules'=>['MB-0790'=>['severity'=>'critical']]])['rules'][0];
    $prioritized=MagebeanFindingSemantics::decorate($custom,['message'=>'Explicit call policy match','evidence'=>['violations'=>[['file'=>'app/code/Fixture/Test.php','line'=>1]]]]);
    $assert($prioritized['severity']==='critical' && $prioritized['category']==='policy','Explicit project severity override remains priority metadata and does not change the policy category');
    $assert($prioritized['exploitability']==='not_established','Project priority does not manufacture exploitation confidence');
    $links=\Magebean\Engine\EvidenceRecordLinks::fromFindings([
        ['id'=>'MB-0806','detail'=>[['evidence'=>['declared_technical_references'=>[
            ['record_id'=>'mitigation-1','package'=>'fixture/pkg','version'=>'v1.0.0','advisory'=>'QA-1'],
            ['record_id'=>'unmatched','package'=>'fixture/other','version'=>'1.0.0','advisory'=>'QA-2'],
        ]]]]],
        ['id'=>'MB-0049','risk_observation'=>['findings'=>[['category'=>'security','claim_type'=>'advisory_or_patch_match','evidence'=>['findings'=>[
            ['package'=>'fixture/pkg','version'=>'1.0.0','advisory'=>'QA-1','dependency_observation'=>['scope'=>'installed_dependency']],
        ]]]]]],
    ]);
    $assert(count($links)===1 && $links[0]['record_id']==='mitigation-1','Only exact package/version/advisory references link to an independently observed finding');
    $assert(!$links[0]['mitigation_effectiveness_verified'] && !$links[0]['changes_finding_status'],'A linked record cannot close or downgrade the technical issue');
    echo "Current-state Phase 3 semantics: $n assertions passed\n";
} finally {
    $it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST);
    foreach($it as $entry)$entry->isDir()&&!$entry->isLink()?rmdir($entry->getPathname()):unlink($entry->getPathname());rmdir($root);
}
