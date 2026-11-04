<?php
declare(strict_types=1);
namespace Magebean\Engine;

/** Evaluates explicit requirement-owned obligations; never imports a legacy rule or standard mapping. */
final class RequirementAssessmentEvaluator
{
    public static function evaluate(array $definition, callable $observe): RequirementAssessment
    {
        $applicability = $definition['applicability'] ?? ['state'=>'APPLICABLE'];
        if (!is_array($applicability)) throw new \InvalidArgumentException('Requirement applicability must be structured.');
        $state = strtoupper((string)($applicability['state'] ?? (isset($applicability['capability']) ? 'UNKNOWN' : 'APPLICABLE')));
        $evidence=['requirement_id'=>$definition['id'], 'revision'=>$definition['revision'], 'obligations'=>[]];
        if ($state !== 'APPLICABLE') return new RequirementAssessment(RequirementOutcome::Unknown,
            'Requirement applicability is unresolved or excluded; no conformance conclusion was produced.', $evidence, 'REQUIREMENT_APPLICABILITY_UNRESOLVED', $applicability);
        $unknownReasons=[]; $unknown=false; $completedDetector=false; $otherUnknown=false; $human=false; $heuristic=false; $confirmed=false; $hasMandatory=false; $failure='';
        foreach ($definition['obligations'] ?? [] as $obligation) {
            $role=(string)($obligation['role']??'mandatory');
            $proof=(string)($obligation['proof']??'heuristic');
            $any=($obligation['op']??'all')==='any';
            $results=[]; $details=[];
            foreach ($obligation['checks']??[] as $check) {
                $result=$observe((string)$check['name'],$check['args']??[]);
                if (!$result instanceof CheckResult) throw new \LogicException('Check function must produce a typed observation.');
                $results[]=$result;
                $details[]=['check'=>$result->checkName ?: $check['name'],'status'=>$result->outcome->value,'message'=>$result->message,'evidence'=>$result->evidence,'reason_code'=>$result->reasonCode];
                // Real alternatives may short-circuit only on verified technical success.
                if ($any && $proof==='verified_predicate' && $result->outcome===CheckOutcome::Pass) break;
            }
            $outcome=self::combine($results,$any);
            $evidence['obligations'][]=['id'=>$obligation['id'],'role'=>$role,'operator'=>$any?'any':'all','proof'=>$proof,'status'=>$outcome->value,'checks'=>$details];
            if ($role==='supporting') continue;
            $hasMandatory=true;
            foreach ($results as $result) {
                if ($result->outcome !== CheckOutcome::Unknown) continue;
                if (($definition['family'] ?? null) === 'magebean'
                    && ($result->evidence[MagebeanDetectorAnalysis::EVIDENCE_KEY]['complete'] ?? false) === true) {
                    $completedDetector = true;
                    continue;
                }
                $otherUnknown = true;
                if (trim($result->message) !== '') $unknownReasons[] = preg_replace('/^\[UNKNOWN\]\s*/', '', trim($result->message));
            }
            if ($proof==='human') { $human=true; continue; }
            // Missing necessary observations cannot be hidden by an unconfirmed failure signal.
            if ($outcome!==CheckOutcome::Pass && $proof!=='verified_predicate'
                && array_filter($results,static fn(CheckResult $r):bool=>$r->outcome===CheckOutcome::Unknown)!==[]) {
                $unknown=true; continue;
            }
            if ($outcome===CheckOutcome::Unknown) { $unknown=true; continue; }
            if ($proof==='heuristic') { $heuristic=true; continue; }
            if ($outcome===CheckOutcome::ManualReview) { $human=true; continue; }
            if ($outcome===CheckOutcome::Fail && $proof==='verified_predicate') {
                if (!in_array($definition['review_state']??'pending_security_review',['security_reviewed','accepted_scoped_criterion'],true)
                    && array_filter($results,static fn(CheckResult $r):bool=>$r->outcome===CheckOutcome::Unknown)!==[]) $unknown=true;
                $confirmed=true;
                foreach($results as $r) if($r->outcome===CheckOutcome::Fail && $failure==='')$failure=$r->message;
            }
        }
        $requiredHuman=(bool)($definition['human_evidence']['required']??false);
        $reviewPending=!in_array($definition['review_state']??'pending_security_review',['security_reviewed','accepted_scoped_criterion'],true);
        // A verified counterexample can prove failure even if unrelated positive coverage is incomplete.
        // Unreviewed criterion-to-predicate bindings cannot be promoted to a normative failure.
        if ($confirmed && !$reviewPending) return new RequirementAssessment(RequirementOutcome::Fail,
            $failure ?: 'A verified mandatory requirement condition failed.', $evidence, 'REQUIREMENT_CONFIRMED_VIOLATION',$applicability);
        if ($unknown && $completedDetector && !$otherUnknown) return new RequirementAssessment(RequirementOutcome::Unknown,
            'Detector analysis completed within its declared scope.', $evidence, 'REQUIREMENT_AUTOMATION_INSUFFICIENT', $applicability);
        if ($unknown) return new RequirementAssessment(RequirementOutcome::Unknown,
            'Necessary requirement evidence is missing, incomplete or indeterminate.'.($unknownReasons!==[]?' '.implode(' ',array_slice(array_values(array_unique($unknownReasons)),0,2)):''), $evidence,'REQUIREMENT_EVIDENCE_INCOMPLETE',$applicability);
        if ($human || $requiredHuman) {
            $instructions=trim((string)($definition['human_evidence']['instructions']??''));
            $message=$confirmed ? 'Technical failure observations need independent confirmation against the requirement.' : 'Requirement observations do not establish complete conformance; independent assessment is required.';
            return new RequirementAssessment(RequirementOutcome::ManualReview,$message.($instructions!==''?' '.$instructions:''),$evidence,'REQUIREMENT_HUMAN_CONFIRMATION',$applicability);
        }
        // Implementation review is a development gate, not an instruction to the scan user.
        if ($reviewPending) return new RequirementAssessment(RequirementOutcome::Unknown,
            'The criterion-to-check binding has not been validated; technical observations cannot establish a requirement conclusion.',
            $evidence,'REQUIREMENT_BINDING_UNVALIDATED',$applicability);
        if ($heuristic || $confirmed || !$hasMandatory) return new RequirementAssessment(RequirementOutcome::Unknown,
            'Available heuristic observations do not establish all mandatory requirement conditions.',
            $evidence,'REQUIREMENT_AUTOMATION_INSUFFICIENT',$applicability);
        return new RequirementAssessment(RequirementOutcome::Pass,
            'All mandatory conditions were verified in the declared requirement scope.', $evidence,'REQUIREMENT_CONDITIONS_VERIFIED',$applicability);
    }

    private static function combine(array $results,bool $any): CheckOutcome
    {
        if ($results===[])return CheckOutcome::Unknown;
        $outcomes=array_map(static fn(CheckResult $r):CheckOutcome=>$r->outcome,$results);
        if($any && in_array(CheckOutcome::Pass,$outcomes,true))return CheckOutcome::Pass;
        if(!$any && in_array(CheckOutcome::Fail,$outcomes,true))return CheckOutcome::Fail;
        if(in_array(CheckOutcome::Unknown,$outcomes,true))return CheckOutcome::Unknown;
        if(in_array(CheckOutcome::ManualReview,$outcomes,true))return CheckOutcome::ManualReview;
        return $any?CheckOutcome::Fail:CheckOutcome::Pass;
    }
}
