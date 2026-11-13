<?php
declare(strict_types=1);
namespace Magebean\Agent;
/** Maps scan observations into the existing redacted Console transport schema. */
final class AgentResultMapper
{
    public function map(array $result, array $manifest, array $manifestIndex, array $unsupported, string $magentoPath, array $manifestBindings = []): array
    {
        $canonicalIssues=\Magebean\Engine\MagebeanIssueCorrelation::group($result['findings']??[]);
        $canonicalRefs=[];foreach($canonicalIssues as $issue)foreach($issue['rule_ids'] as $id)$canonicalRefs[$id][]=[
            'issue_id'=>$issue['issue_id'],'issue_family'=>$issue['issue_family'],'correlation_status'=>$issue['correlation_status'],'related_rule_ids'=>$issue['rule_ids']];
        if($manifestBindings!==[]){
            $executed=array_column($result['findings'],null,'id');$mapped=[];
            foreach($manifestBindings as $binding){$canonical=$binding['canonical_id'];if(!isset($executed[$canonical]))throw new \LogicException('Manifest binding has no canonical assessment result: '.$canonical);$finding=$executed[$canonical];$finding['correlation_owner_id']=$canonical;$finding['id']=$binding['requested_key'];$manifestIndex[$binding['requested_key']]=['assessment_item_id'=>$binding['assessment_item_id']];$mapped[]=$finding;}
            $result['findings']=$mapped;
        }
        $findings=[];foreach($result['findings'] as $finding){
            if (!empty($finding['risk_observation']['needs_attention'])) {
                $finding['message'] = $finding['risk_observation']['findings'][0]['message'] ?? $finding['message'];
            }
            // Keep the established wire status while identifying actual human assessment.
            // An old dashboard item may still say automated after the bundled catalog changes.
            if (($finding['status'] ?? '') === 'MANUAL_REVIEW') {
                $finding['evidence']['assessment_status'] = 'MANUAL_REVIEW';
                $finding['evidence']['attention_reason'] = 'human_verification_required';
                $finding['evidence']['human_verification_required'] = true;
                $finding['evidence']['collection_guidance'] = [
                    'category' => 'human_assessment',
                    'owner' => 'security_reviewer',
                    'reason_code' => 'REQUIREMENT_HUMAN_CONFIRMATION',
                    'action' => (string)$finding['message'],
                    'resources' => [],
                ];
            }
            $owner=$finding['correlation_owner_id']??$finding['id'];
            if (isset($canonicalRefs[$owner])) $finding['evidence']['canonical_issue_refs']=$canonicalRefs[$owner];
            $evidence = $this->sanitize($finding['evidence'] ?? [], $magentoPath);
            if (isset($finding['risk_observation'])) {
                $evidence['risk_observation'] = $this->sanitizeRiskEnvelope($finding['risk_observation'], $magentoPath);
            }
            $ruleKey=strtoupper((string)$finding['id']);$entry=$manifestIndex[$ruleKey];$status=match($finding['status']??'UNKNOWN'){'PASS'=>'pass','FAIL'=>'fail',default=>'error'};$findings[]=['assessment_item_id'=>(string)$entry['assessment_item_id'],'rule_key'=>$ruleKey,'status'=>$status,'message'=>$this->redact((string)$finding['message'],$magentoPath),'detail'=>$this->sanitize($finding['detail']??$finding['details']??[],$magentoPath),'evidence'=>$evidence,'checked_at'=>gmdate(DATE_ATOM)];}
        foreach ($findings as $position => $payload) {
            $findings[$position]['title'] = $this->resultTitle($payload);
        }
        if (array_filter($findings, static fn(array $row):bool => isset($row['evidence']['risk_observation'])) !== []) {
            $result['summary']['needs_attention'] = count(array_filter($findings, static fn(array $row):bool => !empty($row['evidence']['risk_observation']['needs_attention'])));
            $result['summary']['collection_issues'] = array_sum(array_map(static fn(array $row):int => count($row['evidence']['risk_observation']['collection_gaps'] ?? []), $findings));
        }
        if ($canonicalIssues!==[] || isset($result['summary']['needs_attention'])) $result['summary']['canonical_issue_count']=count($canonicalIssues);
        return ['schema_version'=>'1.0','manifest_hash'=>(string)($manifest['manifest_hash']??''),'summary'=>$result['summary'],'results'=>array_merge($findings,$unsupported)];
    }
    public function resultTitle(array $result): string
    {
        // Use the redacted outcome, never the rule's desired-state title.
        $message = trim((string)($result['message'] ?? ''));
        if ($message === '') {
            foreach ($result['detail'] ?? [] as $detail) {
                if (is_array($detail)
                    && strtolower((string)($detail['status'] ?? '')) === $result['status']
                    && trim((string)($detail['message'] ?? '')) !== '') {
                    $message = trim((string)$detail['message']);
                    break;
                }
            }
        }
        $title = rtrim(trim((string)(preg_split('/\R/u', $message, 2)[0] ?? '')), ': ');
        // Rule messages can put remediation on the same line as the issue.
        // Keep the first sentence; dots within paths and versions are not boundaries.
        if (preg_match('/^(.+?[.!?])\s+(?=\p{Lu})/u', $title, $sentence) === 1) {
            $title = $sentence[1];
        }
        if ($title === '') {
            $title = match ($result['status']) {
                'fail' => 'Security check failed',
                'pass' => 'Security check passed',
                default => 'Security check could not be completed',
            };
        }
        // Console accepts at most 255 characters; preserve UTF-8 without mbstring.
        if (preg_match('/^(.{252}).{4}/us', $title, $match) === 1) {
            return rtrim($match[1]) . '...';
        }
        return $title;
    }
    private function sanitize(mixed $value, string $root, int $limit = 50): mixed
    {
        if (is_string($value)) return $this->redact($value, $root);
        if (!is_array($value)) return $value;

        $out = [];
        foreach (array_slice($value, 0, $limit, true) as $key => $entry) {
            $out[$key] = in_array(strtolower((string) $key), ['password', 'token', 'secret', 'authorization', 'cookie'], true)
                ? '[REDACTED]'
                : $this->sanitize($entry, $root);
        }
        return $out;
    }

    private function sanitizeRiskEnvelope(array $risk, string $root): array
    {
        $sanitized = $this->sanitize(array_diff_key($risk, array_flip(['findings', 'collection_gaps', 'detector_runs', 'observations'])), $root);
        foreach (['findings', 'collection_gaps', 'detector_runs', 'observations'] as $key) {
            if (!isset($risk[$key]) || !is_array($risk[$key])) continue;
            $sanitized[$key] = $this->sanitize($risk[$key], $root, 100);
            if (count($risk[$key]) > count($sanitized[$key])) $sanitized[$key.'_truncated'] = true;
        }
        return $sanitized;
    }

    private function redact(string $value,string $root): string { $value=str_replace($root,'[MAGENTO_ROOT]',$value); return preg_replace('/(password|token|secret|authorization|cookie)\s*[:=]\s*\S+/i','$1=[REDACTED]',$value)??$value; }
}
