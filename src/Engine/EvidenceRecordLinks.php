<?php
declare(strict_types=1);
namespace Magebean\Engine;

/** Exact supplied-record references to independently observed advisories; never remediation verification. */
final class EvidenceRecordLinks
{
    public static function fromFindings(array $findings): array
    {
        $observed=[];$references=[];
        foreach ($findings as $finding) {
            foreach ($finding['detail']??[] as $detail) {
                foreach ($detail['evidence']['declared_technical_references']??[] as $reference) {
                    if (count($references)<100) $references[]=$reference+['record_rule_id'=>$finding['id']];
                }
            }
            foreach ($finding['risk_observation']['findings']??[] as $row) {
                if (($row['category']??'')!=='security' || ($row['claim_type']??'')!=='advisory_or_patch_match') continue;
                foreach ($row['evidence']['findings']??[] as $advisory) {
                    if (!isset($advisory['package'],$advisory['version'],$advisory['advisory'])) continue;
                    $key=self::key($advisory);
                    $observed[$key][]=['rule_id'=>$finding['id'],'dependency_scope'=>$advisory['dependency_observation']['scope']??'unverified'];
                }
            }
        }
        $links=[];
        foreach ($references as $reference) {
            if (!isset($reference['package'],$reference['version'],$reference['advisory'])) continue;
            foreach ($observed[self::key($reference)]??[] as $target) {
                if (count($links)>=100) break 2;
                $links[]=['record_rule_id'=>$reference['record_rule_id'],'record_id'=>$reference['record_id'],
                    'subject'=>array_intersect_key($reference,array_flip(['package','version','advisory'])),
                    'observed_finding'=>$target,'relation'=>'supplied_record_references_observed_advisory',
                    'mitigation_effectiveness_verified'=>false,'changes_finding_status'=>false];
            }
        }
        return $links;
    }

    private static function key(array $subject): string
    {
        return json_encode([strtolower($subject['package']),ltrim($subject['version'],'vV'),$subject['advisory']],JSON_INVALID_UTF8_SUBSTITUTE|JSON_THROW_ON_ERROR);
    }
}
