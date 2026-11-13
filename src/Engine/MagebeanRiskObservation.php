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
                    self::appendAnalysis($out, $definition, $row, $analysis);
                    continue;
                }
                if($status===CheckOutcome::Fail->value){
                    $row['kind']='observed_issue';

                    $out['needs_attention']=true;
                    if(count($out['findings'])<self::MAX_ROWS){
                        $row['evidence']=is_array($check['evidence']??null)?$check['evidence']:[];
                        $row=MagebeanFindingSemantics::decorate($definition,$row);
                        if ($row['category']==='informational') {
                            if (count($out['observations']??[])<self::MAX_ROWS) $out['observations'][]=$row;
                            else $out['findings_truncated']=true;
                        }
                        else $out['findings'][]=$row;
                    }else{$out['findings_truncated']=true;$out['collection_complete']=false;}
                    self::appendCoverageGaps($out,$row,$check['evidence']??[]);
                    foreach($check['evidence']['inspection_issues']??[] as $issue) {
                        if (!is_array($issue)||empty($issue['message'])||empty($issue['reason'])) continue;
                        self::appendGap($out,$row,$issue);
                    }
                } elseif ($status===CheckOutcome::Unknown->value) {
                    $row['evidence']=is_array($check['evidence']??null)?$check['evidence']:[];
                    $row['reason_code']??=$row['evidence']['reason_code']??null;
                    if (isset($check['collection_guidance'])) $row['collection_guidance']=$check['collection_guidance'];
                    $issues=$check['evidence']['inspection_issues']??[];
                    if (is_array($issues) && $issues!==[]) {
                        foreach ($issues as $issue) if (is_array($issue)&&!empty($issue['message'])&&!empty($issue['reason'])) self::appendGap($out,$row,$issue);
                    } else self::appendGap($out,$row);
                }

            }
        }
        if($observedChecks===0&&$assessment->outcome===RequirementOutcome::Unknown){
            $out['collection_complete']=false;
            $out['collection_gaps'][]=['check'=>'','message'=>$assessment->message,'reason_code'=>$assessment->reasonCode];
            // No check ran: applicability/binding state is execution metadata, not an observed issue.
        }
        $out['needs_attention']=$out['findings']!==[];
        return $out;
    }

    private static function appendCoverageGaps(array &$out,array $row,array $evidence): void
    {
        $missing=[];
        if (($evidence['dependency_inventory']['complete']??true)===false) $missing[]='dependency inventory';
        foreach (['feed_gaps'=>'advisory feed batches','packages_unknown'=>'package status','unassessed_affected_packages'=>'advisory version/range applicability','missing_published_date'=>'advisory publication dates'] as $field=>$label) {
            if (!empty($evidence[$field])) $missing[]=$label;
        }
        if ($missing===[]) return;
        self::appendGap($out,[
            'check'=>$row['check'],'message'=>'Known findings retained; collection coverage is incomplete for '.implode(', ',$missing).'.',
            'reason_code'=>'OBSERVATION_COVERAGE_INCOMPLETE',
            'collection_guidance'=>['action'=>'Resolve the named inventory/feed/status input gaps and rerun this scope. Preserve independently established findings; incomplete coverage is not a clean conclusion.'],
            'evidence'=>array_intersect_key($evidence,array_flip(['dependency_inventory','feed_gaps','packages_unknown','unassessed_affected_packages','missing_published_date'])),
        ]);
    }

    private static function appendGap(array &$out, array $row, ?array $issue = null): void
    {
        $out['collection_complete']=false;
        if (count($out['collection_gaps'])>=self::MAX_ROWS) { $out['collection_gaps_truncated']=true; return; }
        if ($issue!==null) {
            $row['message']=$issue['message'];$row['reason_code']=$issue['reason'];
            $row['evidence']=['inspection_issue'=>$issue,'locations'=>[['file'=>$issue['file']??'','line'=>$issue['line']??null]]];
            $row['collection_guidance']=['action'=>$issue['action']??'Inspect the named source location and rerun.'];
        }
        $out['collection_gaps'][]=$row;
    }

    private static function appendAnalysis(array &$out, array $definition, array $row, array $analysis): void
    {
        $requirementId=$definition['id'];
        $detector = ['detector' => $analysis['detector'], 'detector_version' => $analysis['detector_version']];
        $out['detector_runs'][] = $detector + [
            'complete' => $analysis['complete'],
            'suppressed_count' => $analysis['suppressed_count'],
            'suppressions' => $analysis['suppressions'],
        ];
        $out['collection_complete'] = $out['collection_complete'] && $analysis['complete'];

        foreach ($analysis['findings'] as $finding) {
            $finding=MagebeanFindingSemantics::decorate($definition,$finding,true);
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
