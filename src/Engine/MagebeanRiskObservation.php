<?php
declare(strict_types=1);
namespace Magebean\Engine;

/** Check-level risk observations are separate from a requirement's conformance conclusion. */
final class MagebeanRiskObservation
{
    private const MAX_ROWS = MagebeanDetectorAnalysis::MAX_ROWS;

    public static function fromAssessment(array $definition,RequirementAssessment $assessment):array
    {
        if(($definition['family']??null)!=='magebean'||RequirementPolicy::requiresHuman($definition)){
            throw new \InvalidArgumentException('Risk projection requires an automated Magebean definition.');
        }
        $out=['schema_version'=>1,'needs_attention'=>false,'findings'=>[],'collection_gaps'=>[],
            'collection_complete'=>true,'assessment_outcome'=>$assessment->outcome->value];
        $definitions=[];
        foreach($definition['obligations']??[] as $obligation)if(is_array($obligation))$definitions[(string)($obligation['id']??'')]=$obligation;
        $observedChecks=0;
        foreach($assessment->evidence['obligations']??[] as $obligation){
            if(!is_array($obligation))continue;
            $source=$definitions[(string)($obligation['id']??'')]??[];
            $operator=$obligation['operator']??($source['op']??'all');
            $proof=$obligation['proof']??($source['proof']??'heuristic');
            $checks=is_array($obligation['checks']??null)?$obligation['checks']:[];
            $observedChecks+=count($checks);
            // A failed alternative is not a risk finding when a real verified alternative succeeded.
            $alternativeSatisfied=$operator==='any'&&$proof==='verified_predicate'
                &&array_filter($checks,static fn(mixed $check):bool=>is_array($check)&&($check['status']??null)===CheckOutcome::Pass->value)!==[];
            if($alternativeSatisfied)continue;
            foreach($checks as $check){
                if(!is_array($check))continue;
                $status=$check['status']??null;
                $row=['check'=>(string)($check['check']??''),'message'=>(string)($check['message']??''),
                    'reason_code'=>isset($check['reason_code'])?(string)$check['reason_code']:null];
                $analysis = $check['evidence'][MagebeanDetectorAnalysis::EVIDENCE_KEY] ?? null;
                if (is_array($analysis)) {
                    self::appendAnalysis($out, $definition['id'], $row, $analysis);
                    continue;
                }
                if($status===CheckOutcome::Fail->value){
                    $row['kind']='observed_issue';
                    $row['confidence'] = $proof === 'verified_predicate' ? 'confirmed' : 'suspected';
                    $out['needs_attention']=true;
                    if(count($out['findings'])<self::MAX_ROWS){
                        $row['evidence']=is_array($check['evidence']??null)?$check['evidence']:[];
                        $out['findings'][]=$row;
                    }else{$out['findings_truncated']=true;$out['collection_complete']=false;}
                    foreach($check['evidence']['inspection_issues']??[]as$issue){
                        if(!is_array($issue)||empty($issue['message'])||empty($issue['reason']))continue;
                        $out['collection_complete']=false;
                        $gap=['check'=>$row['check'],'message'=>$issue['message'],'reason_code'=>$issue['reason']];
                        if(count($out['collection_gaps'])<self::MAX_ROWS)$out['collection_gaps'][]=$gap;else$out['collection_gaps_truncated']=true;
                        if(count($out['findings'])>=self::MAX_ROWS){$out['findings_truncated']=true;continue;}
                        $gap['kind']='collection_issue';$gap['fingerprint']=$issue['fingerprint']??hash('sha256',json_encode([$issue['reason'],$issue['file']??'',$issue['line']??null]));
                        $gap['evidence']=['inspection_issue'=>$issue,'locations'=>[['file'=>$issue['file']??'','line'=>$issue['line']??null]],'collection_guidance'=>['action'=>$issue['action']??'Inspect the named source location and rerun.']];
                        $out['findings'][]=$gap;
                    }
                }elseif($status===CheckOutcome::Unknown->value){
                    $out['collection_complete']=false;
                    if(count($out['collection_gaps'])<self::MAX_ROWS)$out['collection_gaps'][]=$row;
                    else $out['collection_gaps_truncated']=true;
                    // Missing scanner input is execution metadata, never a website risk finding.
                    if (($check['evidence']['reason_code']??$row['reason_code'])==='SCAN_INPUT_URL_MISSING'
                        || preg_match('/^(?:\[UNKNOWN\]\s*)?(?:Runtime URL unavailable\b|Supply canonical --url\b)/i',$row['message'])) continue;
                    $inspectionIssues=$check['evidence']['inspection_issues']??null;
                    if(is_array($inspectionIssues)&&$inspectionIssues!==[]){
                        foreach($inspectionIssues as$issue){
                            if(!is_array($issue)||empty($issue['message'])||empty($issue['reason']))continue;
                            $out['needs_attention']=true;
                            if(count($out['findings'])>=self::MAX_ROWS){$out['findings_truncated']=true;break;}
                            $specific=$row;$specific['kind']='collection_issue';$specific['message']=$issue['message'];
                            $specific['fingerprint']=$issue['fingerprint']??hash('sha256',json_encode([$issue['reason'],$issue['file']??'',$issue['line']??null]));
                            $specific['evidence']=['inspection_issue'=>$issue,'locations'=>[['file'=>$issue['file']??'','line'=>$issue['line']??null]],'collection_guidance'=>['action'=>$issue['action']??'Inspect the named source location and rerun.']];
                            $out['findings'][]=$specific;
                        }
                    }elseif(preg_match('/Source policy could not be evaluated completely\.?/i',$row['message'])!==1&&count($out['findings'])<self::MAX_ROWS){
                        $out['needs_attention']=true;
                        $row['kind']='collection_issue';
                        $row['message']=preg_replace('/^\[UNKNOWN\]\s*/','',$row['message'])??$row['message'];
                        $row['evidence']=is_array($check['evidence']??null)?$check['evidence']:[];
                        $out['findings'][]=$row;
                    }elseif(count($out['findings'])>=self::MAX_ROWS)$out['findings_truncated']=true;
                }
            }
        }
        if($observedChecks===0&&$assessment->outcome===RequirementOutcome::Unknown){
            $out['collection_complete']=false;
            $out['collection_gaps'][]=['check'=>'','message'=>$assessment->message,'reason_code'=>$assessment->reasonCode];
            // No check ran: applicability/binding state is execution metadata, not an observed issue.
        }
        return $out;
    }

    private static function appendAnalysis(array &$out, string $requirementId, array $row, array $analysis): void
    {
        $detector = ['detector' => $analysis['detector'], 'detector_version' => $analysis['detector_version']];
        $out['detector_runs'][] = $detector + [
            'complete' => $analysis['complete'],
            'suppressed_count' => $analysis['suppressed_count'],
            'suppressions' => $analysis['suppressions'],
        ];
        $out['collection_complete'] = $out['collection_complete'] && $analysis['complete'];

        foreach ($analysis['findings'] as $finding) {
            $fingerprint = hash('sha256', json_encode([
                $requirementId, $analysis['detector'], $row['check'], $finding['issue_key'],
                $finding['evidence']['subject'], $finding['evidence']['locations'],
            ], JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR));
            $bucket = $finding['category'] === 'informational' ? 'observations' : 'findings';
            if (in_array($fingerprint, array_column($out[$bucket] ?? [], 'fingerprint'), true)) continue;
            $observation = $finding + $detector + [
                'kind' => 'observed_issue',
                'check' => $row['check'],
                'reason_code' => null,
                'fingerprint' => $fingerprint,
            ];
            if (count($out[$bucket] ?? []) < self::MAX_ROWS) {
                $out[$bucket][] = $observation;
                if ($bucket === 'findings') $out['needs_attention'] = true;
            } else {
                $out['findings_truncated'] = true;
            }
        }
        foreach ($analysis['gaps'] as $gap) {
            if (count($out['collection_gaps']) < self::MAX_ROWS) {
                $out['collection_gaps'][] = $gap + $detector + ['check' => $row['check']];
            } else {
                $out['collection_gaps_truncated'] = true;
            }
        }
        foreach (['findings_truncated', 'collection_gaps_truncated'] as $flag) {
            if ($analysis[$flag]) $out[$flag] = true;
        }
    }
}
