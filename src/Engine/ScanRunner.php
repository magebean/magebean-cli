<?php

declare(strict_types=1);

namespace Magebean\Engine;

use Magebean\Engine\Checks\CheckRegistry;

final class ScanRunner
{
    private Context $ctx;
    private array $pack;
    private CheckRegistry $registry;
    /** @var null|callable(array): void */
    private $progressCallback;

    public function __construct(Context $ctx, array $pack, ?callable $progressCallback = null, ?CheckRegistry $registry = null)
    {
        $this->ctx = $ctx;
        $this->pack = $pack;
        $this->registry = $registry ?? CheckRegistry::fromContext($ctx);
        $this->progressCallback = $progressCallback;
    }

    private function evalCheckWithEvidence(
        string $name,
        array $args
    ): array {
        $res = $this->registry->run($name, $args);
        if (!is_array($res)) {
            $res = [false, 'Unknown check: ' . $name];
        }
        $ok  = $res[0] ?? null;
        $msg = (string)($res[1] ?? '');
        $ev  = $res[2] ?? [];
        if (!is_array($ev)) {
            $ev = $ev !== null ? [$ev] : [];
        }
        return [$ok, $msg, $ev];
    }


    public function run(): array
    {
        $findings = [];
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
            $op = $rule['op'] ?? 'all';
            // Với 'any' khởi tạo FAIL cho tới khi có check PASS
            $ok = ($op === 'any') ? false : true;

            $details  = [];
            $evidence = [];
            $hasTrue = false;
            $hasFalse = false;
            $hasUnknown = false;

            foreach ($rule['checks'] as $chk) {
                $name = $chk['name'];
                $args = $chk['args'] ?? [];

                [$cok, $msg, $ev] = $this->evalCheckWithEvidence(
                    $name,
                    $args
                );

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
                }
            }

            if ($op === 'any') {
                if ($ok) {
                    $status = 'PASS';
                } elseif ($hasUnknown && !$hasFalse) {
                    $status = 'UNKNOWN';
                } else {
                    $status = 'FAIL';
                }
            } else { // op === 'all'
                if ($hasFalse) {
                    $ok = false;
                    $status = 'FAIL';
                } elseif ($hasUnknown && !$hasTrue) {
                    $status = 'UNKNOWN';
                } else {
                    $ok = true;
                    $status = 'PASS';
                }
            }
            $msgPass = $rule['messages']['pass'] ?? null;
            $msgFail = $rule['messages']['fail'] ?? null;
            if ($status === 'UNKNOWN') {
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
                    $finalMsg = $bad ? implode(' | ', array_slice($bad, 0, 2)) : 'Rule failed';
                }
            }

            if ($status === 'UNKNOWN' && (!isset($finalMsg) || trim((string)$finalMsg) === '')) {
                $finalMsg = 'CVE file not found (requires --cve-data package)';
            }
            $finding = [
                'id'       => $rule['id'],
                'title'    => $rule['title'],
                'control'  => $rule['control'],
                'severity' => $rule['severity'],
                'passed'   => $ok,
                'status'   => $status,
                'message'  => $finalMsg,
                'details'  => $details,
                'evidence' => $evidence,
            ];
            if (isset($rule['profile']) && is_array($rule['profile'])) {
                $finding['profile'] = $rule['profile'];
            }

            $findings[] = $finding;

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
        foreach ($findings as $f) {
            if (($f['status'] ?? '') === 'UNKNOWN') $unknown++;
        }
        // Lấy transport counters từ HttpCheck nếu có (để tính transport_success_percent ở ScanCommand)
        $tc = $this->registry->transportCounts();
        $transportOk    = (int)($tc['ok'] ?? 0);
        $transportTotal = (int)($tc['total'] ?? 0);

        return [
            'summary'  => ['passed' => $passed, 'failed' => $failed, 'unknown' => $unknown, 'total' => count($findings)],
            'findings' => $findings,
            'meta'     => [
                'planned_rules'  => $plannedRules,
                'executed_rules' => $executedRules,
                'transport_ok'   => $transportOk,
                'transport_total' => $transportTotal,
                'suppress_confidence' => $suppressConfidence ?? false
            ]
        ];
    }

    private function notifyProgress(array $event): void
    {
        if (is_callable($this->progressCallback)) {
            ($this->progressCallback)($event);
        }
    }
}
