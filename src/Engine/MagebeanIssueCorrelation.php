<?php
declare(strict_types=1);
namespace Magebean\Engine;

/** Presentation projection. Original assessments and observations remain authoritative and unmodified. */
final class MagebeanIssueCorrelation
{
    public static function group(array $findings): array
    {
        $groups=[];
        foreach ($findings as $findingIndex=>$finding) {
            foreach ($finding['risk_observation']['findings']??[] as $rowIndex=>$row) {
                if (($row['kind']??'')!=='observed_issue') continue;
                foreach (self::fragments($finding,$row) as [$family,$subject,$fragment,$verified]) {
                    $identity=['version'=>1,'family'=>$family,'subject'=>$subject];
                    $key=hash('sha256',json_encode(self::sorted($identity),JSON_INVALID_UTF8_SUBSTITUTE|JSON_THROW_ON_ERROR));
                    // Unsupported correlations retain the owning assessment instead of guessing equivalence.
                    if (!$verified) $key=hash('sha256',$key.'|'.$finding['id'].'|'.$findingIndex.'|'.$rowIndex);
                    $contributor=['rule_id'=>$finding['id'],'check'=>$row['check'],'observation_index'=>$rowIndex,'observation'=>$fragment];
                    if (!isset($groups[$key])) {
                        $groups[$key]=[
                            'issue_id'=>'mb-issue-v1:'.$key,'issue_family'=>$family,'identity'=>$identity,
                            'correlation_status'=>$verified?'evidence_identity':'unresolved',
                            'id'=>$finding['id'],'canonical_rule_id'=>$family==='admin-password-minimum'?'MB-0728':$finding['id'],
                            'title'=>$finding['title']??$fragment['message'],'message'=>$fragment['message'],
                            'severity'=>$fragment['severity']??$finding['severity'],
                            'remediation'=>$finding['remediation']??[], 'requirement'=>$finding['requirement']??[],
                            'risk_observation'=>['schema_version'=>1,'needs_attention'=>true,'findings'=>[$fragment],
                                'collection_complete'=>$finding['risk_observation']['collection_complete'],'collection_gaps'=>[],
                                'assessment_outcome'=>$finding['risk_observation']['assessment_outcome']??$finding['status']??'UNKNOWN'],
                            'rule_ids'=>[],'contributors'=>[],'assessment_outcomes'=>[],
                        ];
                    }
                    $group=&$groups[$key];
                    if (!in_array($finding['id'],$group['rule_ids'],true)) $group['rule_ids'][]=$finding['id'];
                    $group['contributors'][]=$contributor;
                    $group['assessment_outcomes'][$finding['id']]=$finding['risk_observation']['assessment_outcome']??$finding['status']??'UNKNOWN';
                    $current=$group['risk_observation']['findings'][0];
                    if (self::priority($fragment,$finding['id'])>self::priority($current,$group['id'])) {
                        $group['id']=$finding['id'];$group['title']=$finding['title']??$fragment['message'];
                        $group['message']=$fragment['message'];$group['remediation']=$finding['remediation']??[];
                        $group['requirement']=$finding['requirement']??[];$group['risk_observation']['findings']=[$fragment];
                        $group['risk_observation']['assessment_outcome']=$finding['risk_observation']['assessment_outcome']??$finding['status']??'UNKNOWN';
                    }
                    $rank=['info'=>0,'low'=>1,'medium'=>2,'high'=>3,'critical'=>4];
                    $severity=$fragment['severity']??$finding['severity'];
                    if (($rank[$severity]??0)>($rank[$group['severity']]??0)) $group['severity']=$severity;
                    $group['risk_observation']['collection_complete']=$group['risk_observation']['collection_complete'] && $finding['risk_observation']['collection_complete'];
                    if ($family!=='admin-password-minimum') $group['canonical_rule_id']=$group['id'];
                    unset($group);
                }
            }
        }
        foreach ($groups as &$group) {
            $group['context']=self::context($group['contributors']);
            sort($group['rule_ids'],SORT_STRING);ksort($group['assessment_outcomes'],SORT_STRING);
            usort($group['contributors'],static fn(array $a,array $b):int=>strcmp($a['rule_id'].'|'.$a['check'],$b['rule_id'].'|'.$b['check']));
        }
        unset($group);
        ksort($groups,SORT_STRING);
        return array_values($groups);
    }

    private static function context(array $contributors): array
    {
        $context=[];
        foreach ($contributors as $contributor) {
            $e=$contributor['observation']['evidence'];
            foreach (is_array($e['findings']??null)?$e['findings']:[] as $item) {
                if (!is_array($item)) continue;
                $parts=[];
                if (is_string($item['summary']??null)&&trim($item['summary'])!=='') $parts[]='Vulnerability: '.$item['summary'];
                foreach (array_slice(is_array($item['references']??null)?$item['references']:[],0,5) as $reference) {
                    $url=is_array($reference)?($reference['url']??null):null;
                    if(is_string($url)&&filter_var($url,FILTER_VALIDATE_URL)&&in_array(strtolower((string)parse_url($url,PHP_URL_SCHEME)),['http','https'],true)) $parts[]='Reference: '.$url;
                }
                if (is_string($item['fixed']??null)&&$item['fixed']!=='') $parts[]='published fix >= '.$item['fixed'];
                if (is_array($item['required_by']??null) && $item['required_by']!==[]) $parts[]='required by '.implode(', ',array_slice($item['required_by'],0,10));
                if (isset($item['open_days'])) $parts[]='publication age '.$item['open_days'].' days; threshold '.($item['publication_age_threshold_days']??$item['sla_days']??'?').' days';
                foreach (array_slice(is_array($item['requirements']??null)?$item['requirements']:[],0,10) as $constraint) {
                    if (isset($constraint['source'],$constraint['constraint'])) $parts[]='declared constraint '.$constraint['source'].': '.$constraint['constraint'];
                }
                if ($parts!==[]) $context[]=['rule_id'=>$contributor['rule_id'],'message'=>implode('; ',$parts)];
            }
            foreach (is_array($e['signals']??null)?$e['signals']:[] as $signal) $context[]=['rule_id'=>$contributor['rule_id'],'message'=>'Upload signal: '.($signal['signal']??'observed artifact')];
        }
        $seen=[];$out=[];
        foreach ($context as $row) {
            if (isset($seen[$row['rule_id'].'|'.$row['message']])) continue;
            $seen[$row['rule_id'].'|'.$row['message']]=true;$out[]=$row;
            if (count($out)>=100) break;
        }
        usort($out,static fn(array $a,array $b):int=>strcmp($a['rule_id'].'|'.$a['message'],$b['rule_id'].'|'.$b['message']));
        return $out;
    }

    private static function priority(array $row,string $id): int
    {
        $category=['informational'=>0,'policy'=>10,'correctness'=>20,'security'=>30];
        $confidence=['informational'=>0,'suspected'=>1,'confirmed'=>2];
        // Prefer the narrow, flow-aware/module-specific view; retain all other predicates as contributors.
        $specific=in_array($id,['MB-0728','MB-0741','MB-0744','MB-0736','MB-0800','MB-0814','MB-0822','MB-0049'],true)?1:0;
        return ($category[$row['category']??'policy']??0)*100+($confidence[$row['confidence']??'suspected']??0)*10+$specific;
    }

    private static function fragments(array $finding,array $row): iterable
    {
        $id=$finding['id'];$e=$row['evidence']??[];$check=$row['check'];$emitted=false;$unresolved=false;
        foreach (['abandoned_packages','matches','findings','overdue_advisories','blocked','violations','files','failures','locations'] as $field) {
            if (isset($e[$field]) && (!is_array($e[$field]) || count($e[$field])>100)) {
                yield ['uncorrelated-observation',['owner'=>$id,'check'=>$check,'reason'=>'fragment_budget'],$row,false];return;
            }
        }
        if (in_array($id,['MB-0728','MB-0731'],true) && is_string($e['source']??null) && is_numeric($e['minimum']??null) && is_numeric($e['observed']??null)) {
            $row['message']='Policy: Admin password minimum '.(string)($e['observed']??'?').' is below '.(string)$e['minimum'].'.';
            yield ['admin-password-minimum',['scope'=>$e['scope']??'declared','source'=>$e['source'],'key'=>'admin/security/minimum_password_length','minimum'=>$e['minimum']],$row,true];return;
        }
        if (in_array($id,['MB-0038','MB-0741'],true) && $check==='php_no_file_cache_backend' && isset($e['file'])) {
            $failures=$e['failures']??[];
            if ($failures===[] && isset($e['frontend'])) $failures=[['path'=>'cache.frontend.'.$e['frontend'].'.backend','implicit_file_backend'=>true]];
            foreach (array_slice($failures,0,100) as $item) {
                if (!is_array($item) || !is_string($item['path']??null)) { $unresolved=true; continue; }
                $fragment=$row;$fragment['message']='Policy: File cache backend at '.$item['path'].'.';
                $fragment['evidence']=['file'=>$e['file'],'failures'=>[$item],'locations'=>[['file'=>$e['file']]]];
                $emitted=true; yield ['cache-file-backend',['scope'=>'source_declaration','file'=>$e['file'],'key'=>$item['normalized_path']??$item['path']],$fragment,true];
            }
            if ($emitted && !$unresolved) return;
        }
        if (in_array($id,['MB-0061','MB-0744'],true) && $check==='composer_abandoned_api') {
            foreach (array_slice($e['abandoned_packages']??[],0,100) as $item) {
                if (!is_array($item) || !is_string($item['name']??null) || !is_string($item['installed']??null) || !isset($item['status_observation']['endpoint'])) { $unresolved=true; continue; }
                $subject=['package'=>$item['name'],'version'=>$item['installed'],'predicate'=>'abandoned',
                    'source'=>$item['status_observation']['endpoint'],'dataset_revision'=>$item['status_observation']['dataset_revision']??null,
                    'dependency_scope'=>self::dependencyScope($e,$item['name'])];
                $fragment=$row;$fragment['message']='Policy: Package '.$item['name'].'@'.$item['installed'].' is reported abandoned.';
                $fragment['evidence']=['abandoned_packages'=>[$item],'dependency_observation'=>$e['package_observations'][$item['name']]??[]];
                $emitted=true; yield ['dependency-maintenance',$subject,$fragment,true];
            }
            if ($emitted && !$unresolved) return;
        }
        if (in_array($id,['MB-0049','MB-0055','MB-0056','MB-0059','MB-0828'],true)) {
            // Follow-up views can carry all matches; only their violating subset becomes an issue.
            $items=match($id) {'MB-0059'=>$e['overdue_advisories']??[], 'MB-0056'=>$e['blocked']??[],default=>$e['findings']??[]};
            foreach (array_slice($items,0,100) as $item) {
                if (!is_array($item) || !is_string($item['package']??null) || !is_string($item['version']??null) || !is_string($item['advisory']??null)) { $unresolved=true; continue; }
                $source=self::advisorySource($e);
                if ($source===null) { $unresolved=true; continue; }
                $subject=['package'=>$item['package'],'version'=>ltrim($item['version'],'vV'),'advisory'=>$item['advisory'],
                    'source'=>$source,'dependency_scope'=>self::dependencyScope($e,$item['package'])];
                $fragment=$row;$fragment['evidence']=['findings'=>[$item],'source'=>$source,'dependency_observation'=>$e['package_observations'][$item['package']]??[]];
                $fragment['message']=match($id) {
                    'MB-0059'=>'Policy: Advisory '.$item['advisory'].' for '.$item['package'].' '.$item['version'].' exceeds the publication-age limit.',
                    'MB-0056'=>'Policy: Dependency constraints prevent the published security fix for '.$item['package'].' '.$item['version']."\nAdvisory: ".$item['advisory'],
                    default=>'Known vulnerability found in '.$item['package'].' '.$item['version']."\nAdvisory: ".$item['advisory'],
                };
                $emitted=true; yield ['dependency-advisory',$subject,$fragment,true];
            }
            if ($emitted && !$unresolved) return;
        }
        if (in_array($id,['MB-0733','MB-0736'],true)) {
            foreach (array_slice($e['matches']??[],0,100) as $item) {
                if (!self::anchor($item)) { $unresolved=true; continue; }
                $fragment=$row;$fragment['evidence']=['locations'=>[$item]];
                $emitted=true; yield ['template-output-encoding',['scope'=>'source_declaration','file'=>$item['file'],'byte_offset'=>$item['byte_offset'],'source_sha256'=>$item['source_sha256'],'context'=>$item['context']??'unknown'],$fragment,true];
            }
            if ($emitted && !$unresolved) return;
        }
        if (in_array($id,['MB-0780','MB-0800'],true)) {
            $items=$id==='MB-0780'?array_map(static fn(mixed $p):array=>is_string($p)?['path'=>'pub/media/'.str_replace('\\','/',$p),'signal'=>'php_like_extension']:[],$e['files']??[]):($e['findings']??[]);
            foreach (array_slice($items,0,100) as $item) {
                if (!is_array($item) || !is_string($item['path']??null)) { $unresolved=true; continue; }
                $family=in_array($item['signal']??'', ['php_like_extension','php_open_tag'],true)?'upload-script-artifact':(($item['signal']??'')==='script_handler_directive'?'upload-handler-declaration':null);
                if ($family===null) { $unresolved=true; continue; }
                $fragment=$row;$fragment['evidence']=['locations'=>[['file'=>$item['path']]+(isset($item['line'])?['line'=>$item['line']]:[])],'signals'=>[$item]];
                $emitted=true; yield [$family,['scope'=>'deployment_file_inventory','file'=>$item['path']],$fragment,true];
            }
            if ($emitted && !$unresolved) return;
        }
        $family=match(true) {$id==='MB-0790'=>'source-command-call',$id==='MB-0822'&&($row['issue_key']??'')==='command'=>'source-command-call',in_array($id,['MB-0795','MB-0814'],true)=>'source-request-logging',default=>null};
        if ($family!==null) {
            $items=in_array($id,['MB-0790','MB-0795'],true)?($e['violations']??[]):array_slice($e['locations']??[],0,1);
            foreach (array_slice($items,0,100) as $item) {
                if (!self::anchor($item)) { $unresolved=true; continue; }
                $fragment=$row;
                $fragment['evidence']=array_intersect_key($e,array_flip(['subject','reasoning','remediation','assumptions']));
                $fragment['evidence']['locations']=[$item];
                $emitted=true; yield [$family,['scope'=>'source_declaration','file'=>$item['file'],'byte_offset'=>$item['byte_offset'],'source_sha256'=>$item['source_sha256']],$fragment,true];
            }
            if ($emitted && !$unresolved) return;
        }
        yield ['uncorrelated-observation',['check'=>$check,'owner'=>$id,'issue_key'=>$row['issue_key']??null,'locations'=>$e['locations']??[]],$row,false];
    }

    private static function anchor(mixed $item): bool
    {
        return is_array($item) && is_string($item['file']??null) && $item['file']!=='' && !str_starts_with($item['file'],'/')
            && !str_contains($item['file'],':') && !in_array('..',explode('/',$item['file']),true) && is_int($item['byte_offset']??null) && $item['byte_offset']>=0 && is_string($item['source_sha256']??null) && preg_match('/^[a-f0-9]{64}$/D',$item['source_sha256'])===1;
    }

    private static function dependencyScope(array $e,string $package): array
    {
        $p=$e['package_observations'][$package]??[];
        return ['scope'=>$p['scope']??$e['dependency_inventory']['scope']??'unverified','source_path'=>$p['source_path']??null];
    }

    private static function advisorySource(array $e): ?array
    {
        if (($e['source']??'')==='magebean_osv_api' && isset($e['endpoint'])) {
            $revisions=array_values(array_unique(array_column($e['responses']??[],'dataset_revision'),SORT_REGULAR));
            sort($revisions);
            return ['kind'=>'online_advisory_feed','endpoint'=>$e['endpoint'],'dataset_revisions'=>$revisions];
        }
        if (($e['source']??'')==='offline_dataset' && isset($e['dataset'],$e['snapshot_sha256'])) return ['kind'=>'supplied_snapshot','path'=>$e['dataset'],'sha256'=>$e['snapshot_sha256']];
        return null;
    }

    private static function sorted(array $value): array
    {
        if (!array_is_list($value)) ksort($value,SORT_STRING);
        foreach ($value as &$item) if (is_array($item)) $item=self::sorted($item);
        return $value;
    }
}
