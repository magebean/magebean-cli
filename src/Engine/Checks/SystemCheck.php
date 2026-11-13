<?php
declare(strict_types=1);

namespace Magebean\Engine\Checks;

use Magebean\Engine\Context;

final class SystemCheck
{
    private Context $context;

    public function __construct(Context $ctx)
    {
        $this->context = $ctx;
    }

    /**
     * PASS nếu hệ thống đang chặn outbound (egress) ở mức firewall:
     * - UFW: Status active + Default: deny (outgoing) hoặc Outgoing: DENY
     * - IPTABLES: Chain OUTPUT policy DROP/REJECT (hoặc không phải ACCEPT)
     * UNKNOWN nếu thiếu quyền/chưa cài ufw/iptables; FAIL nếu thấy rõ ràng policy ACCEPT (mở hết).
     */
    public function egressRestricted(array $args = []): array
    {
        // 1) UFW trước, nếu có
        if ($this->isCmdAvailable('ufw')) {
            $out = $this->safeShell('ufw status verbose');
            if ($out['ok']) {
                $t = strtolower($out['stdout']);
                $active = (strpos($t, 'status: active') !== false);
                $deny1 = preg_match('~default:[^\r\n]*\b(?:deny|reject)\s*\(outgoing\)~', $t) === 1;
                // một số distro in khác: "Outgoing: DENY"
                $deny2  = (strpos($t, 'outgoing: deny') !== false);
                if ($active && ($deny1 || $deny2) && preg_match('/\bALLOW\s+OUT\b|\bOUT\s+ALLOW\b/i', $out['stdout'])) return [null, '[UNKNOWN] UFW outgoing exceptions require effective-rule evaluation', ['tool' => 'ufw', 'output' => $out['stdout']]];
                if ($active && ($deny1 || $deny2)) {
                    return [true, 'UFW is active and denies outgoing traffic by default', [
                        'tool' => 'ufw',
                        'output' => $out['stdout'],
                    ]];
                }
                if ($active && preg_match('~default:[^\r\n]*\ballow\s*\(outgoing\)|outgoing:\s*allow~', $t) === 1) {
                    // active nhưng cho phép outbound
                    return [false, 'UFW is active but does not deny outgoing traffic', [
                        'tool' => 'ufw',
                        'output' => $out['stdout'],
                    ]];
                }
                if ($active) return [null, '[UNKNOWN] UFW outgoing default policy was not observable', ['tool' => 'ufw', 'output' => $out['stdout']]];
                // not active → tiếp tục thử iptables
            } else {
                // không chạy được ufw → tiếp tục iptables
            }
        }

        // 2) IPTABLES
        if ($this->isCmdAvailable('iptables')) {
            // Thử dạng -S trước (rule dạng câu lệnh)
            $out = $this->safeShell('iptables -S OUTPUT');
            if ($out['ok'] && trim($out['stdout']) !== '') {
                $policy = $this->parseIptablesPolicy($out['stdout']);
                if ($policy === 'DROP' || $policy === 'REJECT') {
                    $rules = preg_split('/\R/', $out['stdout']) ?: [];
                    $hasRules = false;
                    foreach ($rules as $rule) {
                        if (!preg_match('/^-A\s+OUTPUT\b/', trim($rule))) continue;
                        $hasRules = true;
                        // A comment match cannot restrict packets. Strip only this known inert extension.
                        $plain = preg_replace('/\s+-m\s+comment\b|\s+--comment\s+(?:"[^"]*"|\'[^\']*\'|\S+)/', '', trim($rule));
                        if (preg_match('/^-A\s+OUTPUT\s+-j\s+ACCEPT\s*$/', $plain ?? '')) return [false, 'Unconditional OUTPUT ACCEPT bypasses the default deny policy', ['tool' => 'iptables -S', 'output' => $out['stdout']]];
                    }
                    if ($hasRules) return [null, '[UNKNOWN] OUTPUT exceptions or chain jumps require effective firewall evaluation; default deny alone is insufficient', ['tool' => 'iptables -S', 'output' => $out['stdout']]];
                    return [true, 'Observed iptables OUTPUT chain has deny policy and no listed exceptions', ['tool' => 'iptables -S', 'policy' => $policy, 'output' => $out['stdout'], 'scope' => 'Observed IPv4 OUTPUT chain only; other network namespaces, address families and external controls are not assessed']];
                }
                if ($policy === 'ACCEPT' && preg_match('~^-A\s+OUTPUT\b~m', $out['stdout']) === 1) return [null, '[UNKNOWN] OUTPUT rules require effective firewall evaluation', ['output' => $out['stdout']]];
                if ($policy === 'ACCEPT') {
                    return [false, 'iptables OUTPUT policy is ACCEPT (unrestricted)', [
                        'tool' => 'iptables -S',
                        'policy' => $policy,
                        'output' => $out['stdout'],
                    ]];
                }
                // unknown policy string → thử -L
            }

            // Fallback: -L (human readable)
            $out2 = $this->safeShell('iptables -L OUTPUT -n');
            if ($out2['ok'] && trim($out2['stdout']) !== '') {
                $line1 = strtolower(strtok($out2['stdout'], "\n")); // "Chain OUTPUT (policy ACCEPT)"
                if (strpos($line1, '(policy drop)') !== false || strpos($line1, '(policy reject)') !== false) {
                    return [null, '[UNKNOWN] Human-readable OUTPUT default policy cannot establish effective exception handling; collect the complete machine-readable rules', ['tool' => 'iptables -L', 'output' => $out2['stdout']]];
                }
                if (strpos($line1, '(policy accept)') !== false) {
                    return [false, 'iptables OUTPUT policy is ACCEPT (unrestricted)', [
                        'tool' => 'iptables -L',
                        'output' => $out2['stdout'],
                    ]];
                }
            }
        }

        // 3) Không có ufw/iptables hoặc không đủ quyền → UNKNOWN
        return [null, 'Cannot determine egress firewall policy (missing tools or permissions)', [
            'tools' => [
                'ufw_available' => $this->isCmdAvailable('ufw'),
                'iptables_available' => $this->isCmdAvailable('iptables'),
            ]
        ]];
    }

    private function isCmdAvailable(string $cmd): bool
    {
        $check = $this->safeShell('command -v ' . escapeshellarg($cmd));
        return $check['ok'] && trim($check['stdout']) !== '';
    }

    private function safeShell(string $cmd): array
    {
        if (!function_exists('proc_open')) return ['ok'=>false,'stdout'=>'','code'=>null];
        $process=@proc_open(['/bin/sh','-c',$cmd],[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
        if (!is_resource($process)) return ['ok'=>false,'stdout'=>'','code'=>null];
        fclose($pipes[0]);stream_set_blocking($pipes[1],false);stream_set_blocking($pipes[2],false);
        $end=microtime(true)+2;$stdout='';$bytes=0;$exit=null;$complete=true;
        do {
            $chunk=(string)stream_get_contents($pipes[1],65537);$discard=(string)stream_get_contents($pipes[2],65537);
            $stdout.=$chunk;$bytes+=strlen($chunk)+strlen($discard);
            $state=proc_get_status($process);
            if ($bytes>131072) {$complete=false;proc_terminate($process);break;}
            if (!$state['running']) {$exit=$state['exitcode'];break;}
            if (microtime(true)>$end) {$complete=false;proc_terminate($process);break;}
            usleep(10000);
        } while(true);
        fclose($pipes[1]);fclose($pipes[2]);$closed=proc_close($process);$exit??=$closed;
        return ['ok'=>$complete&&$exit===0,'stdout'=>$complete?substr($stdout,0,131072):'','code'=>$exit];
    }

    private function parseIptablesPolicy(string $s): string
    {
        // ví dụ: "-P OUTPUT ACCEPT"
        foreach (explode("\n", $s) as $line) {
            $line = trim($line);
            if (preg_match('~^-P\s+OUTPUT\s+(ACCEPT|DROP|REJECT)~i', $line, $m)) {
                return strtoupper($m[1]);
            }
        }
        return '';
    }
}
