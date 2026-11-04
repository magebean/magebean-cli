<?php

declare(strict_types=1);

namespace Magebean\Engine;

use Magebean\Engine\Checks\CheckRegistry;

final class ScanRunner
{
    private Context $ctx;
    private array $pack;
    /** Scoped observations are reused only during one primary execution. */
    private array $primaryObservations = [];
    private $checkpoint;
    private ?\Throwable $checkpointError = null;
    private CheckRegistry $registry;
    /** @var null|callable(array): void */
    private $progressCallback;

    public function __construct(Context|ScanContext $ctx, array $pack, ?callable $progressCallback = null, ?CheckRegistry $registry = null, private readonly ?ScanDeadline $deadline = null, ?callable $checkpoint = null)
    {
        $this->ctx = $ctx instanceof ScanContext ? $ctx->toLegacy() : $ctx;
        $this->pack = $pack;
        $this->checkpoint = $checkpoint === null ? null : function () use ($checkpoint): void {
            try { $checkpoint(); }
            catch (\Throwable $error) { $this->checkpointError = $error; throw $error; }
        };
        $this->registry = $registry ?? CheckRegistry::fromContext($this->ctx);
        $this->progressCallback = $progressCallback;
    }

    private function observationKey(string $name, array $args): string
    {
        $normalize = static function (array $value) use (&$normalize): array {
            if (!array_is_list($value)) ksort($value, SORT_STRING);
            foreach ($value as &$item) if (is_array($item)) $item = $normalize($item);
            unset($item);
            return $value;
        };
        return hash('sha256', serialize([$this->ctx->path, $this->ctx->url, $name, $normalize($args)]));
    }

    private function observePrimary(string $name, array $args, string $key): CheckResult
    {
        if (isset($this->primaryObservations[$key])) {
            try {
                if ($this->checkpoint !== null) ($this->checkpoint)();
                if ($this->deadline?->expired()) throw new ScanDeadlineExceeded();
            } catch (ScanDeadlineExceeded) {
                return CheckResult::of(CheckOutcome::Unknown, 'Scan deadline exceeded; cached observations cannot complete this assessment.', [], 'SCAN_DEADLINE_EXCEEDED', $name);
            }
            return $this->primaryObservations[$key];
        }
        try {
            $result = $this->evalCheckWithEvidence($name, $args);
        } catch (\Throwable $error) {
            // Worker checkpoints/cancellation must retain their existing propagation contract.
            if ($this->checkpointError !== null) throw $this->checkpointError;
            $result = CheckResult::of(CheckOutcome::Unknown,
                'Check '.$name.' failed internally; report this check and scanner version to Magebean support.',
                ['reason_code'=>'CHECK_EXECUTION_FAILED','exception_class'=>get_class($error)],
                'CHECK_EXECUTION_FAILED', $name);
        }
        if ($this->checkpointError !== null && !$this->checkpointError instanceof ScanDeadlineExceeded) throw $this->checkpointError;
        if ($this->deadline?->expired()) return CheckResult::of(CheckOutcome::Unknown, 'Scan deadline exceeded before the observation was completed.', [], 'SCAN_DEADLINE_EXCEEDED', $name);
        if ($result->reasonCode !== 'SCAN_DEADLINE_EXCEEDED') $this->primaryObservations[$key] = $result;
        return $result;
    }

    private function evalCheckWithEvidence(
        string $name,
        array $args
    ): CheckResult {
        if ($this->deadline?->expired()) {
            return CheckResult::of(CheckOutcome::Unknown, '[UNKNOWN] Scan deadline exceeded; check was not executed.', [], 'SCAN_DEADLINE_EXCEEDED', $name);
        }
        try {
            if ($this->checkpoint !== null) ($this->checkpoint)();
            if ($this->deadline?->expired()) throw new ScanDeadlineExceeded();
            if ($name === 'requirement_assessment') return RequirementEvaluator::evaluate($args, fn(string $check, array $options): CheckResult => $this->evalCheckWithEvidence($check, $options));
            return $this->registry->runResult($name, $args);
        } catch (ScanDeadlineExceeded) {
            return CheckResult::of(CheckOutcome::Unknown, '[UNKNOWN] Scan deadline exceeded; check could not be completed.', [], 'SCAN_DEADLINE_EXCEEDED', $name);
        }
    }


    public function run(): array
    {
        return $this->runReport()->toLegacy();
    }

    public function runReport(): ScanReport
    {
        $this->registry->beginCollection($this->deadline, $this->checkpoint);
        try {
            return $this->executeReport();
        } finally {
            $this->registry->endCollection();
        }
    }

    private function executeReport(): ScanReport
    {
        $this->primaryObservations = [];
        $this->checkpointError = null;
        $findings = [];
        $checkResults = [];
        $passed = 0;
        $failed = 0;
        $plannedRules = is_array($this->pack['rules'] ?? null) ? count($this->pack['rules']) : 0;
        $executedRules = 0;

        foreach ($this->pack['rules'] as $rule) {
            $this->notifyProgress([
                'type' => 'rule_start',
                'current' => $executedRules + 1,
                'total' => $plannedRules,
                'rule_id' => (string)($rule['id'] ?? ''),
                'title' => (string)($rule['title'] ?? ''),
                'control' => (string)($rule['control'] ?? ''),
            ]);
            $executedRules++;
            if ((preg_match('/^MB-[0-9]{4,}$/D', (string)($rule['id'] ?? '')) === 1) && isset($rule['obligations'])) {
                $observations = [];
                $observationKeys = [];
                try {
                    if ($this->deadline?->expired()) throw new ScanDeadlineExceeded();
                    if ($this->checkpoint !== null) ($this->checkpoint)();
                    if ($this->deadline?->expired()) throw new ScanDeadlineExceeded();
                    $assessment = RequirementAssessmentEvaluator::evaluate($rule, function (string $name, array $args) use (&$observations, &$observationKeys): CheckResult {
                    $key = $this->observationKey($name, $args);
                    $result = $this->observePrimary($name, $args, $key);
                    if (!isset($observationKeys[$key])) { $observations[] = $result; $observationKeys[$key] = true; }
                    return $result;
                    });
                } catch (ScanDeadlineExceeded) {
                    $assessment = new RequirementAssessment(RequirementOutcome::Unknown,
                        'Scan deadline exceeded; requirement assessment could not be completed.',
                        ['requirement_id'=>$rule['id'],'revision'=>$rule['revision'],'obligations'=>[]],
                        'SCAN_DEADLINE_EXCEEDED', $rule['applicability'] ?? ['state'=>'APPLICABLE']);
                }
                $status = $assessment->outcome->value;
                $detail = array_map(static fn(CheckResult $r): array => ['check'=>$r->checkName,'status'=>$r->outcome->value,'message'=>$r->message], $observations);
                $finding = [
                    'id'=>$rule['id'],'title'=>$rule['title'],'control'=>$rule['control'],'severity'=>$rule['severity'],
                    'passed'=>match($assessment->outcome){RequirementOutcome::Pass=>true,RequirementOutcome::Fail=>false,default=>null},
                    'status'=>$status,'message'=>$assessment->message,'detail'=>$detail,
                    'details'=>array_map(static fn(CheckResult $r):array=>[$r->checkName,$r->toLegacy()[1],$r->toLegacy()[0]],$observations),
                    'evidence'=>$assessment->evidence,'requirement'=>['id'=>$rule['id'],'revision'=>$rule['revision'],'criterion'=>$rule['criterion']],
                    'alignment'=>$rule['alignments'] ?? [],'coverage'=>$rule['coverage'],'applicability'=>$assessment->applicability,
                    'reason_code'=>$assessment->reasonCode,
                ];
                if(isset($rule['family']))$finding['requirement']['family']=$rule['family'];
                if(isset($rule['source']))$finding['requirement']['source']=$rule['source'];
                foreach (['policy_source', 'guidance_sources', 'lane', 'finding_guidance'] as $field) {
                    if (isset($rule[$field])) $finding['requirement'][$field] = $rule[$field];
                }
                // Optional technical collection gaps still need an action even when human
                // evidence owns the final conclusion or a counterexample already proves FAIL.
                foreach ($finding['evidence']['obligations'] as &$obligationEvidence) {
                    foreach ($obligationEvidence['checks'] as &$checkEvidence) {
                        if (($checkEvidence['status'] ?? '') !== 'UNKNOWN') continue;
                        if (($rule['family'] ?? '') === 'magebean'
                            && ($checkEvidence['evidence'][MagebeanDetectorAnalysis::EVIDENCE_KEY]['complete'] ?? false)) continue;
                        $checkScope = $rule;
                        $checkScope['checks'] = array_values(array_filter($rule['checks'] ?? [], static fn(array $c): bool => $c['name'] === $checkEvidence['check']));
                        $checkEvidence['collection_guidance'] = RequirementDiagnostics::forFinding([
                            'id'=>$rule['id'],'message'=>$checkEvidence['message'],
                            'reason_code'=>$checkEvidence['reason_code'],
                            'evidence'=>['obligations'=>[['role'=>'mandatory','checks'=>[$checkEvidence]]]],
                        ], $checkScope);
                        foreach ($finding['detail'] as &$detailItem) if ($detailItem['check'] === $checkEvidence['check'] && $detailItem['status'] === 'UNKNOWN') $detailItem['collection_guidance'] = $checkEvidence['collection_guidance'];
                        unset($detailItem);
                    }
                    unset($checkEvidence);
                }
                unset($obligationEvidence);
                if ($status === 'UNKNOWN') {
                    $finding['collection_guidance'] = RequirementDiagnostics::forFinding($finding, $rule);
                    $finding['evidence']['collection_guidance'] = $finding['collection_guidance'];
                }
                foreach(['profile','remediation','assessment_level'] as $field) if(isset($rule[$field]))$finding[$field]=$rule[$field];
                if (($rule['family'] ?? '') === 'magebean' && !RequirementPolicy::requiresHuman($rule)) {
                    $risk = MagebeanRiskObservation::fromAssessment($rule, $assessment);
                    foreach ($risk['findings'] as &$observation) {
                        if (($observation['kind'] ?? '') !== 'collection_issue') continue;
                        if (!empty($observation['evidence']['collection_guidance']['action'])) continue;
                        foreach ($finding['detail'] as $item) {
                            if (($item['check'] ?? '') === $observation['check'] && !empty($item['collection_guidance'])) {
                                $observation['evidence']['collection_guidance'] = $item['collection_guidance'];
                                break;
                            }
                        }
                        $observation['evidence']['collection_guidance'] ??= $finding['collection_guidance'] ?? RequirementDiagnostics::forFinding($finding, $rule);
                    }
                    unset($observation);
                    if ($risk['collection_complete'] && !empty($risk['detector_runs'])) {
                        unset($finding['collection_guidance'], $finding['evidence']['collection_guidance']);
                    }
                    $finding['risk_observation'] = $risk;
                    $finding['evidence']['risk_observation'] = $risk;
                    $finding['needs_attention'] = $risk['needs_attention'];
                }
                $findings[]=$finding; $checkResults[]=$observations;
                if($status==='PASS')$passed++;
                if($status==='FAIL')$failed++;
                $this->notifyProgress(['type'=>'rule_done','current'=>$executedRules,'total'=>$plannedRules,'rule_id'=>$rule['id'],'title'=>$rule['title'],'control'=>$rule['control'],'status'=>$status]);
                continue;
            }
            $op = $rule['op'] ?? 'all';
            // Với 'any' khởi tạo FAIL cho tới khi có check PASS
            $ok = ($op === 'any') ? false : true;

            $ruleResults = [];
            $details  = [];
            $evidence = [];
            $hasTrue = false;
            $hasFalse = false;
            $hasUnknown = false;
            $hasManualReview = false;
            $hasDeadlineExceeded = false;

            foreach ($rule['checks'] as $chk) {
                $name = $chk['name'];
                $args = $chk['args'] ?? [];

                $checkResult = $this->evalCheckWithEvidence($name, $args);
                $hasDeadlineExceeded = $hasDeadlineExceeded || $checkResult->reasonCode === 'SCAN_DEADLINE_EXCEEDED';
                $ruleResults[] = $checkResult;
                [$cok, $msg, $ev] = $checkResult->toLegacy();

                $details[] = [$name, $msg, $cok];
                if (!empty($ev)) {
                    $evidence = array_merge($evidence, is_array($ev) ? $ev : [$ev]);
                }
                if ($op === 'all' && $cok === false) {
                    $ok = false;
                }
                if ($op === 'any' && $cok === true) {   // dùng && thay vì &
                    $ok = true;
                    $hasTrue = true;                    // ghi nhận PASS trước khi break
                    break;
                }
                if ($cok === true) {
                    $hasTrue = true;
                } elseif ($cok === false) {
                    $hasFalse = true;
                } else {
                    $hasUnknown = true;
                    if ($checkResult->outcome === CheckOutcome::ManualReview) {
                        $hasManualReview = true;
                    }
                }
            }

            if ($op === 'any') {
                if ($ok) {
                    $status = 'PASS';
                } elseif ($hasDeadlineExceeded) {
                    $ok = null;
                    $status = 'UNKNOWN';
                } elseif ($hasManualReview) {
                    $ok = null;
                    $status = 'MANUAL_REVIEW';
                } elseif ($hasUnknown) {
                    $ok = null;
                    $status = 'UNKNOWN';
                } else {
                    $status = 'FAIL';
                }
            } else { // op === 'all'
                if ($hasFalse) {
                    $ok = false;
                    $status = 'FAIL';
                } elseif ($hasManualReview) {
                    $ok = null;
                    $status = 'MANUAL_REVIEW';
                } elseif ($hasUnknown) {
                    $ok = null;
                    $status = 'UNKNOWN';
                } else {
                    $ok = true;
                    $status = 'PASS';
                }
            }
            $msgPass = $rule['messages']['pass'] ?? null;
            $msgFail = $rule['messages']['fail'] ?? null;
            if ($status === 'MANUAL_REVIEW') {
                $manualMsgs = array_values(array_map(
                    fn($d) => preg_replace('/^\[MANUAL_REVIEW\]\s*/', '', (string)$d[1]),
                    array_filter($details, fn($d) => is_string($d[1]) && str_starts_with($d[1], '[MANUAL_REVIEW]'))
                ));
                $finalMsg = $manualMsgs[0] ?? 'NOT VERIFIED BY MAGEBEAN CLI. Independent human assessment and documented supporting evidence are mandatory.';
            } elseif ($status === 'UNKNOWN') {
                $unkMsgs = array_values(array_map(
                    fn($d) => $d[1],
                    array_filter($details, fn($d) => ($d[2] === null) || (is_string($d[1]) && str_starts_with((string)$d[1], '[UNKNOWN]')))
                ));
                $finalMsg = $unkMsgs[0] ?? 'CVE file not found (requires --cve-data package)';
            } elseif ($ok) {
                if ($msgPass) {
                    $finalMsg = $msgPass;
                } else {
                    $okMsgs = array_values(array_map(
                        fn($d) => $d[1],
                        array_filter($details, fn($d) => $d[2] === true)
                    ));
                    $finalMsg = $okMsgs[0] ?? 'Rule passed';
                }
            } else {
                if ($msgFail) {
                    $finalMsg = $msgFail;
                } else {
                    $bad = array_values(array_map(
                        fn($d) => $d[1],
                        array_filter($details, fn($d) => $d[2] === false)
                    ));
                    $finalMsg = $bad ? implode("\n", $bad) : 'Rule requires attention';
                }
            }

            if ($status === 'UNKNOWN' && (!isset($finalMsg) || trim((string)$finalMsg) === '')) {
                $finalMsg = 'CVE file not found (requires --cve-data package)';
            }
            $detail = array_map(
                static fn(array $item): array => [
                    'check' => (string)($item[0] ?? ''),
                    'status' => is_string($item[1] ?? null) && str_starts_with((string)$item[1], '[MANUAL_REVIEW]')
                        ? 'MANUAL_REVIEW'
                        : (($item[2] ?? null) === true
                        ? 'PASS'
                        : (($item[2] ?? null) === false ? 'FAIL' : 'UNKNOWN')),
                    'message' => (string)($item[1] ?? ''),
                ],
                $details
            );

            $finding = [
                'id'       => $rule['id'],
                'title'    => $rule['title'],
                'control'  => $rule['control'],
                'severity' => $rule['severity'],
                'passed'   => $ok,
                'status'   => $status,
                'message'  => $finalMsg,
                'detail'   => $detail,
                'details'  => $details,
                'evidence' => $evidence,
            ];
            if (isset($rule['profile']) && is_array($rule['profile'])) {
                $finding['profile'] = $rule['profile'];
            }

            if (isset($rule['remediation']) && is_array($rule['remediation'])) {
                $finding['remediation'] = array_values(array_filter(
                    $rule['remediation'],
                    static fn($step): bool => is_string($step) && trim($step) !== ''
                ));
            }

            $findings[] = $finding;
            $checkResults[] = $ruleResults;

            // Đếm theo status để UNKNOWN không bị tính là failed
            if ($status === 'PASS') {
                $passed++;
            } elseif ($status === 'FAIL') {
                $failed++;
            } // UNKNOWN: không cộng vào passed/failed

            $this->notifyProgress([
                'type' => 'rule_done',
                'current' => $executedRules,
                'total' => $plannedRules,
                'rule_id' => (string)($rule['id'] ?? ''),
                'title' => (string)($rule['title'] ?? ''),
                'control' => (string)($rule['control'] ?? ''),
                'status' => $status,
            ]);
        }

        $unknown = 0;
        $manualReview = 0;
        foreach ($findings as $f) {
            if (($f['status'] ?? '') === 'UNKNOWN') $unknown++;
            if (($f['status'] ?? '') === 'MANUAL_REVIEW') $manualReview++;
        }
        // Lấy transport counters từ HttpCheck nếu có (để tính transport_success_percent ở ScanCommand)
        $tc = $this->registry->transportCounts();
        $transportOk    = (int)($tc['ok'] ?? 0);
        $transportTotal = (int)($tc['total'] ?? 0);

        return ScanReport::fromLegacy([
            'summary'  => ['passed' => $passed, 'failed' => $failed, 'unknown' => $unknown, 'manual_review' => $manualReview, 'total' => count($findings)],
            'findings' => $findings,
            'meta'     => [
                'planned_rules'  => $plannedRules,
                'executed_rules' => $executedRules,
                'transport_ok'   => $transportOk,
                'transport_total' => $transportTotal,
                'suppress_confidence' => $suppressConfidence ?? false
            ]
        ], $checkResults);
    }

    private function notifyProgress(array $event): void
    {
        if (is_callable($this->progressCallback)) {
            ($this->progressCallback)($event);
        }
    }
}
