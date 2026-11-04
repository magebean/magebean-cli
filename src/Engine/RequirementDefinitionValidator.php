<?php
declare(strict_types=1);
namespace Magebean\Engine;
use Magebean\Engine\Checks\CheckRegistry;

/** Validates the primary identity and requirement-owned obligation contract. */
final class RequirementDefinitionValidator
{
    public static function validate(array $rule,CheckRegistry $registry):array
    {
        $errors=[];$id=is_string($rule['id']??null)?$rule['id']:'(missing identity)';
        $error=static function(string $message)use(&$errors,$id):void{$errors[]="Requirement $id $message";};
        if(!preg_match('/^MB-[0-9]{4,}$/D',$id))$error('has an invalid canonical identity.');
        if(isset($rule['family'])&&!in_array($rule['family'],['magebean','asvs','pci'],true))$error('has an invalid owning family.');
        if (($rule['family'] ?? null) === 'magebean' && RequirementPolicy::requiresHuman($rule)) $error('cannot require human evidence in the active Magebean family.');
        if(isset($rule['source'])&&!is_array($rule['source']))$error('source must be structured.');
        foreach(['title','criterion','control']as$field)if(!is_string($rule[$field]??null)||trim($rule[$field])==='')$error("requires nonempty $field.");
        if(!is_int($rule['revision']??null)||$rule['revision']<1)$error('revision must be a positive integer.');
        if(!in_array($rule['severity']??null,['low','medium','high','critical'],true))$error('has invalid severity.');
        if(!in_array($rule['verification']??null,['automated','manual'],true))$error('has invalid verification mode.');
        if(!in_array($rule['coverage']??null,['DIRECT','PARTIAL','SUPPORTING','UNMAPPED','AUTOMATED','PARTIALLY_AUTOMATED','MANUAL_REVIEW','CONTEXT_REQUIRED','NOT_YET_COVERED'],true))$error('has invalid coverage.');
        if(!in_array($rule['review_state']??null,['pending_security_review','heuristic_supporting_only','security_reviewed','accepted_scoped_criterion'],true))$error('has invalid review state.');
        $human=$rule['human_evidence']??null;
        if(!is_array($human)||!is_bool($human['required']??null)||!is_string($human['instructions']??null))$error('human evidence policy must be structured.');
        if(($human['required']??false)===true&&(!is_string($human['instructions']??null)||trim($human['instructions'])===''))$error('requires human evidence instructions.');
        $modes=$rule['target_modes']??null;
        if(!is_array($modes)||!array_is_list($modes)||$modes===[]||array_filter($modes,static fn($mode):bool=>!in_array($mode,['LOCAL','REMOTE'],true))!==[])$error('target modes must be a nonempty LOCAL/REMOTE list.');
        $alignments=$rule['alignments']??null;
        if(!is_array($alignments)||!array_is_list($alignments))$error('alignments must be a metadata list.');
        else foreach($alignments as$alignment) {
            if(!is_array($alignment)){$error('alignment must be structured.');continue;}
            foreach(['standard','version','reference','relationship']as$field)if(!is_string($alignment[$field]??null)||trim($alignment[$field])==='')$error("alignment requires $field.");
        }
        if(isset($rule['applicability'])){
            $app=$rule['applicability'];
            if(!is_array($app)|| (isset($app['state'])&&!in_array($app['state'],['APPLICABLE','UNKNOWN','NOT_APPLICABLE','EXCLUDED'],true)) || (isset($app['capability'])&&(!is_string($app['capability'])||trim($app['capability'])==='')))$error('has invalid applicability contract.');
        }
        if(($rule['op']??'all')!=='all')$error('top-level operator must be all; alternatives belong to obligations.');
        $obligations=$rule['obligations']??null;$flat=[];$seen=[];
        if(!is_array($obligations)||!array_is_list($obligations))$error('obligations must be a list.');
        else {
            if($obligations===[]&&($human['required']??false)!==true)$error('must define obligations or require human evidence.');
            foreach($obligations as$o){
                if(!is_array($o)){$error('obligation must be structured.');continue;}
                $oid=$o['id']??null;
                if(!is_string($oid)||trim($oid)===''||isset($seen[$oid]))$error('obligation identities must be nonempty and unique.');
                if(is_string($oid))$seen[$oid]=true;
                if(!in_array($o['role']??null,['mandatory','supporting'],true))$error('has invalid obligation role.');
                if(!in_array($o['proof']??null,['heuristic','verified_predicate','human'],true))$error('has invalid obligation proof.');
                if(!in_array($o['op']??null,['all','any'],true))$error('has invalid obligation operator.');
                $checks=$o['checks']??null;
                if(!is_array($checks)||!array_is_list($checks)){$error('obligation checks must be a list.');continue;}
                if($checks===[]&&($o['proof']??'')!=='human')$error('technical obligations require checks.');
                if(($o['proof']??'')==='human'&&$checks!==[])$error('human obligations must use evidence policy rather than fake checks.');
                foreach($checks as$c){
                    $flat[]=$c;
                    if(!is_array($c)||!is_string($c['name']??null)||$c['name']===''){$error('check must have a nonempty function name.');continue;}
                    if(in_array($c['name'],['requirement_assessment','human_manual_review_required','manual_review','asvs_source_evidence','asvs_response_content_type','asvs_default_accounts'],true))$error('cannot execute legacy assessment or placeholder functions.');
                    if(!$registry->has($c['name']))$error("references unknown function '{$c['name']}'.");
                    if(isset($c['args'])&&!is_array($c['args']))$error('check arguments must be structured.');
                    if(is_array($c['args']??null)&&array_intersect(array_keys($c['args']),['requirement','requirements','standard','standards','legacy_rule_id'])!==[])$error('check arguments cannot dispatch through requirement or standard identity.');
                }
            }
        }
        if(!is_array($rule['checks']??null)||!array_is_list($rule['checks'])||$rule['checks']!==$flat)$error('flattened checks must match obligation checks exactly.');
        if(isset($rule['remediation'])&&(!is_array($rule['remediation'])||$rule['remediation']===[]||array_filter($rule['remediation'],static fn($step):bool=>!is_string($step)||trim($step)==='')!==[]))$error('remediation must be a nonempty string list.');
        return $errors;
    }
}

