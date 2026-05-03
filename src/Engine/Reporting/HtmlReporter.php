<?php

declare(strict_types=1);

namespace Magebean\Engine\Reporting;

final class HtmlReporter
{
    private string $tpl;
    private bool $showDetails = false;
    public function __construct(string $tpl, bool $showDetails = false)
    {
        $this->tpl = $tpl;
        $this->showDetails = $showDetails;
    }

    public function write(array $result, string $outFile): void
    {
        // 1) Đọc template an toàn; nếu không có -> dùng fallback nhỏ
        $html = file_get_contents($this->tpl);
        if ($html === false || $html === '') {
            $html = $this->fallbackTemplate();
        }
        // Nếu --detail bật, thêm cột Details vào header
        if ($this->showDetails) {
            if (strpos($html, '<th>Details</th>') === false) {
                $html = preg_replace('/<\/tr>\s*<\/thead>/', '<th>Details</th></tr></thead>', $html, 1);
            }
        }
        // --- Summary inputs ---
        $sum = $result['summary'] ?? [];
        $completedRaw = $sum['completed'] ?? $result['completed'] ?? $sum['end'] ?? $result['end']
            ?? $sum['completed_at'] ?? $result['completed_at'] ?? null;
        $scanCompleted = $this->formatTsOrNow($completedRaw);

        $pathAudited = $sum['path'] ?? ($result['path'] ?? ($result['meta']['path'] ?? ($result['args']['path'] ?? '')));
        $pathEsc = htmlspecialchars((string)$pathAudited, ENT_QUOTES, 'UTF-8');

        $rulesPassed = (int)($sum['passed'] ?? 0);
        $rulesFailed = (int)($sum['failed'] ?? 0);
        $rulesUnknown = (int)($sum['unknown'] ?? max(0, (($sum['total'] ?? 0) - ($rulesPassed + $rulesFailed))));
        $rulesTotal  = (int)($sum['total']  ?? ($rulesPassed + $rulesFailed + $rulesUnknown));
        $rulesPct    = $rulesTotal > 0 ? round(($rulesPassed / $rulesTotal) * 100, 1) : 0.0;

        // Lấy meta & cờ suppress confidence (được set bởi ScanRunner)
        $meta = (array)($result['meta'] ?? []);
        $suppressConfidence = (bool)($meta['suppress_confidence'] ?? false);
        $profile = (array)($meta['profile'] ?? []);
        $profileId = htmlspecialchars((string)($profile['id'] ?? 'baseline'), ENT_QUOTES, 'UTF-8');
        $profileTitle = htmlspecialchars((string)($profile['title'] ?? 'Magebean Baseline'), ENT_QUOTES, 'UTF-8');
        $profileDescription = htmlspecialchars((string)($profile['description'] ?? ''), ENT_QUOTES, 'UTF-8');

        $sevCounts = ['Critical' => 0, 'High' => 0, 'Medium' => 0, 'Low' => 0];
        $rows = '';

        foreach ($result['findings'] ?? [] as $f) {
            $id       = htmlspecialchars((string)($f['id'] ?? ''), ENT_QUOTES, 'UTF-8');
            $title    = htmlspecialchars((string)($f['title'] ?? ''), ENT_QUOTES, 'UTF-8');
            $severity = htmlspecialchars((string)($f['severity'] ?? ''), ENT_QUOTES, 'UTF-8');
            $passed   = (bool)($f['passed'] ?? false);
            $status   = $passed ? 'PASS' : 'FAIL';
            $status   = strtoupper((string)($f['status'] ?? ($passed ? 'PASS' : 'FAIL')));
            $statusClass = match ($status) {
                'PASS' => 'status-pass',
                'FAIL' => 'status-fail',
                'UNKNOWN' => 'status-unknown',
                default => 'status-fail'
            };
            $userMsgRaw = (string)($f['message'] ?? '');
            if ($status === 'UNKNOWN' && trim($userMsgRaw) === '') {
                $userMsgRaw = 'CVE file not found (requires --cve-data package)';
            }
            $userMsg  = htmlspecialchars($userMsgRaw, ENT_QUOTES, 'UTF-8');

            if ($status === 'FAIL') {
                $sevKey = ucfirst(strtolower((string)($f['severity'] ?? 'Low')));
                if (!isset($sevCounts[$sevKey])) $sevKey = 'Low';
                $sevCounts[$sevKey]++;
            }

            // Cột nội dung: chỉ in message theo yêu cầu mới
            $messageParts = ['<div style="color:#333;margin-top:4px;">' . $title . '</div>'];
            if ($userMsg !== '') {
                $messageParts[] = '<div style="margin-top:4px;"><i>' . $userMsg . '</i></div>';
            }

            $rows .= '<tr>'
                . '<td><a href="https://magebean.com/baseline/' . $id . '" target="_blank">' . $id . '</a></td>'
                . '<td>' . $severity . '</td>'
                . '<td class="' . $statusClass . '">' . $status . '</td>'
                . '<td>' . implode('', $messageParts)
                . '</td>'  /* Quan trọng: đóng ô Message trước khi thêm ô Details */
                . ($this->showDetails ? '<td>' 
                . $this->renderDetails($f) 
                . '</td>' : '')
                . '</tr>';
        }

        $findingsTotal = array_sum($sevCounts);
        // Footer note nếu có UNKNOWN
        $isExternal = $this->isExternal($result);
        $hasUnknown = false;
        foreach (($result['findings'] ?? []) as $f) {
            if (strtoupper((string)($f['status'] ?? '')) === 'UNKNOWN') {
                $hasUnknown = true;
                break;
            }
        }
        if ($hasUnknown && !$isExternal) {
            $html = str_replace('{{cve_section}}', '<div class="section"><strong>Note:</strong> Some CVE-related rules are <span class="status-unknown">UNKNOWN</span> because CVE data was missing. Provide a CVE bundle via <code>--cve-data=path.zip</code> to enable full checks.</div>' . '{{cve_section}}', $html);
        }

        // Thay placeholder phần findings
        $html = strtr($html, [
            '{{scan_completed}}'       => $scanCompleted,
            '{{path_audited}}'         => $pathEsc,
            '{{rules_total}}'          => (string)$rulesTotal,
            '{{rules_passed}}'         => (string)$rulesPassed,
            '{{rules_failed}}'         => (string)$rulesFailed,
            '{{rules_unknown}}'        => (string)$rulesUnknown,
            '{{rules_passed_percent}}' => (string)$rulesPct,
            '{{findings_critical}}'    => (string)$sevCounts['Critical'],
            '{{findings_high}}'        => (string)$sevCounts['High'],
            '{{findings_medium}}'      => (string)$sevCounts['Medium'],
            '{{findings_low}}'         => (string)$sevCounts['Low'],
            '{{findings_total}}'       => (string)$findingsTotal,
            '{{profile_id}}'           => $profileId,
            '{{profile_title}}'        => $profileTitle,
            '{{profile_description}}'  => $profileDescription,
        ]);
        $html = str_replace('{{table}}', $rows, $html);

        // --- CVE section ---
        if (!$isExternal) {
            $cveHtml = $this->renderCveSection($result['cve_audit'] ?? null);
            if (strpos($html, '{{cve_section}}') !== false) {
                $html = str_replace('{{cve_section}}', $cveHtml, $html);
            } else {
                $html = str_replace('</body>', $cveHtml . '</body>', $html);
            }
        }

        // --- Confidence section (URL mode) ---
        // Nếu meta đã có các trường confidence do ScanCommand/ScanRunner tính, hiển thị một block gọn.
        if ($isExternal && !$suppressConfidence) {
            $meta = (array)($result['meta'] ?? []);
            $det  = (array)($meta['detected'] ?? []);
            $detConf = (int)($det['confidence'] ?? 0);
            $signals = isset($det['signals']) && is_array($det['signals']) ? $det['signals'] : [];

            $confHtml = '<div class="section"><h3>Scan Confidence</h3>'
                . '<div>Detected platform: <strong>Magento 2</strong> (confidence ' . $detConf . '%)</div>'
                //                . '<div>Overall confidence: <strong>' . $overall . '%</strong> &nbsp;—&nbsp; transport ' . $tPct . '% &middot; coverage ' . $cPct . '%' . ($planned > 0 ? ' (' . $execd . '/' . $planned . ')' : '') . '</div>'
                . (!empty($signals) ? '<div style="opacity:.85;margin-top:6px"><small>Signals: ' . htmlspecialchars(implode(' • ', $signals), ENT_QUOTES, 'UTF-8') . '</small></div>' : '')
                . '</div>';
            $html = str_replace('</body>', $confHtml . '</body>', $html);
        }

        $footer = '<p>This report was generated using Magebean CLI, based on the <a href="https://magebean.com/baseline" target="_blank">Magebean Security Baseline v1</a>. Findings are provided for informational and audit purposes only.</p>';
        $html = str_replace('</body>', $footer . '</body>', $html);

        // 2) Đảm bảo thư mục output tồn tại
        $dir = dirname($outFile);
        if ($dir !== '' && $dir !== '.' && !is_dir($dir)) {
            @mkdir($dir, 0777, true);
        }

        // 3) Ghi file và kiểm tra lỗi
        $ok = file_put_contents($outFile, $html);
        if ($ok === false) {
            throw new \RuntimeException('Failed to write HTML report to: ' . $outFile);
        }
    }

    private function isExternal(array $result): bool
    {
        $p = (string)($result['summary']['path'] ?? '');
        return str_starts_with($p, 'URL:');
    }

    private function renderCveSection($cve): string
    {
        // Summary-first UX: show a compact summary; expand full list on demand in a fixed-height scroll box.
        if (!$cve) {
            return '<section class="section" id="cve"><h3>CVE Summary</h3>
                <div style="margin:.5rem 0">CVE checks were skipped.</div>
                <div>→ Provide a CVE bundle via <code>--cve-data=&lt;bundle.zip&gt;</code> to enable this section.</div>
            </section>';
        }

        $sum = $cve['summary'] ?? [];
        $pkgs = is_array($cve['packages'] ?? null) ? $cve['packages'] : [];

        // Compute meta
        $packagesTotal  = (int)($sum['packages_total'] ?? count($pkgs));
        $datasetTotal   = (int)($sum['dataset_total'] ?? 0);
        $affectedTotal  = (int)($sum['packages_affected'] ?? 0);

        // Highest severity + Fixable now
        $highestSeverity = 'None';
        $sevOrder = ['None' => 0, 'Low' => 1, 'Medium' => 2, 'High' => 3, 'Critical' => 4];
        $fixableNow = 0;
        foreach ($pkgs as $p) {
            $sev = (string)($p['highest_severity'] ?? 'None');
            if (!isset($sevOrder[$sev])) $sev = 'None';
            if ($sevOrder[$sev] > $sevOrder[$highestSeverity]) {
                $highestSeverity = $sev;
            }
            $status = (string)($p['status'] ?? 'PASS'); // FAIL means affected
            $hint   = (string)($p['upgrade_hint'] ?? '');
            if ($status === 'FAIL' && $hint !== '') $fixableNow++;
        }

        // Summary header
        $hdr = sprintf(
            '<div class="cve-kpis">
                <div class="kpi"><div class="kpi-label">Packages scanned</div><div class="kpi-value">%d</div></div>
                <div class="kpi"><div class="kpi-label">Total advisories</div><div class="kpi-value">%d</div></div>
                <div class="kpi"><div class="kpi-label">Affected packages</div><div class="kpi-value">%d</div></div>
                <div class="kpi"><div class="kpi-label">Highest severity</div><div class="kpi-value">%s</div></div>
                <div class="kpi"><div class="kpi-label">Fixable now</div><div class="kpi-value">%d</div></div>
            </div>',
            $packagesTotal,
            $datasetTotal,
            $affectedTotal,
            htmlspecialchars($highestSeverity, ENT_QUOTES, 'UTF-8'),
            $fixableNow
        );

        // Build full list table (hidden by default)
        $rows = '';
        foreach ($pkgs as $p) {
            $name = htmlspecialchars((string)($p['name'] ?? ''), ENT_QUOTES, 'UTF-8');
            $ver  = htmlspecialchars((string)($p['installed'] ?? ''), ENT_QUOTES, 'UTF-8');
            $stat = (string)($p['status'] ?? 'PASS');
            $advc = (int)($p['advisories_count'] ?? 0);
            $sev  = htmlspecialchars((string)($p['highest_severity'] ?? 'None'), ENT_QUOTES, 'UTF-8');
            $fx   = htmlspecialchars((string)($p['upgrade_hint'] ?? ''), ENT_QUOTES, 'UTF-8');
            $cls  = $stat === 'FAIL' ? 'status-fail' : ($stat === 'UNKNOWN' ? 'status-unknown' : 'status-pass');

            $rows .= '<tr>'
                . '<td>' . $name . '</td>'
                . '<td>' . $ver . '</td>'
                . '<td class="' . $cls . '">' . htmlspecialchars($stat, ENT_QUOTES, 'UTF-8') . '</td>'
                . '<td>' . $advc . '</td>'
                . '<td>' . $sev . '</td>'
                . '<td>' . ($fx !== '' ? $fx : '&mdash;') . '</td>'
                . '</tr>';
        }

        $table = '
            <div class="cve-list" id="cve-list" style="display:none">
                <div class="cve-list-toolbar">
                    <strong>All packages</strong>
                </div>
                <div class="cve-list-scroll">
                    <table>
                        <thead>
                            <tr>
                                <th>Package</th>
                                <th>Current</th>
                                <th>Status</th>
                                <th>Advisories</th>
                                <th>Highest</th>
                                <th>Min fixed</th>
                            </tr>
                        </thead>
                        <tbody>' . $rows . '</tbody>
                    </table>
                </div>
            </div>';

        // CTA buttons
        $hasAny = $packagesTotal > 0;
        $btns = $hasAny
            ? '<div class="cve-actions">'
            . ($affectedTotal > 0
                ? '<span class="status-fail" style="padding:2px 8px;border-radius:10px;margin-right:8px">Attention required</span>'
                : '<span class="status-pass" style="padding:2px 8px;border-radius:10px;margin-right:8px">No affected packages</span>')
            . '<button id="btn-cve-toggle" type="button" class="btn btn-link">Show all packages</button></div>'
            : '';

        // Minimal CSS + JS scoped to CVE block
        $css = '<style>
            #cve .cve-kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin:.5rem 0 1rem}
            #cve .kpi{background:#f8f9fa;border:1px solid #eee;border-radius:8px;padding:10px}
            #cve .kpi-label{font-size:.8rem;opacity:.75}
            #cve .kpi-value{font-weight:700;font-size:1.1rem}
            #cve .cve-actions{display:flex;gap:10px;align-items:center;margin:.5rem 0 0}
            #cve .btn{padding:6px 10px;border:1px solid #ccc;border-radius:6px;background:#fff;cursor:pointer}
            #cve .btn:hover{background:#f0f0f0}
            #cve .btn-link{border:none;background:transparent;text-decoration:underline;padding:6px 4px}
            #cve .cve-list{margin-top:.75rem}
            #cve .cve-list-toolbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:.5rem}
            #cve .cve-list-scroll{max-height:640px;overflow:auto;border:1px solid #eee;border-radius:8px;padding:8px}
            #cve .status-pass{color:#1E8449}
            #cve .status-fail{color:#C0392B}
            #cve .status-unknown{color:#D68910}
            @media print{#cve .cve-list,.cve-actions .btn{display:none!important}}
        </style>';

        $js = '<script>(function(){
            var toggled=false;
            var btn=document.getElementById("btn-cve-toggle");
            var list=document.getElementById("cve-list");
            if(btn && list){
                btn.addEventListener("click", function(){
                    toggled = !toggled;
                    list.style.display = toggled ? "block" : "none";
                    btn.textContent = toggled ? "Hide list" : "Show all packages";
                });
            }
            function collect(){
                var data=[]; var trs=(list?list.querySelectorAll("tbody tr"):[]);
                for (var i=0;i<trs.length;i++){
                    var tds=trs[i].querySelectorAll("td");
                    data.push({name:tds[0].textContent,ver:tds[1].textContent,stat:tds[2].textContent,advc:tds[3].textContent,sev:tds[4].textContent,fx:tds[5].textContent});
                }
                return data;
            }
        })();</script>';

        $out = '<section class="section" id="cve"><h3>CVE Summary</h3>' . $hdr . $btns . $table . $css . $js . '</section>';

        return $out;
    }


    private function renderDetails(array $f): string
    {
        $out = '';
        $details = $f['details'] ?? [];
        if (is_array($details) && !empty($details)) {
            foreach ($details as $d) {
                if (is_array($d)) {
                    $line = implode(' — ', array_map(static function ($x) {
                        if (is_array($x)) {
                            return json_encode($x, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
                        }
                        return (string)$x;
                    }, $d));
                    // escape trước, rồi chuyển \n thành <br>
                    $safe = htmlspecialchars($line, ENT_QUOTES, 'UTF-8');
                    $safe = nl2br($safe); // <br /> cho newline
                    $out .= '<div>' . $safe . '</div>';
                } else {
                    $line = (string)$d;
                    $safe = htmlspecialchars($line, ENT_QUOTES, 'UTF-8');
                    $safe = nl2br($safe);
                    $out .= '<div>' . $safe . '</div>';
                }
            }
        }
        return $out;
    }


    private function formatTsOrNow($tsOrStr): string
    {
        if (is_numeric($tsOrStr)) return date('Y-m-d H:i:s');
        if (is_string($tsOrStr) && $tsOrStr !== '') return $tsOrStr;
        return date('Y-m-d H:i:s');
    }

    private function fallbackTemplate(): string
    {
        // Template mini có đủ placeholder cần thiết
        return <<<HTML
<!doctype html><html><head><meta charset="utf-8"><title>Magebean Report</title>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;padding:16px;}
table{width:100%;border-collapse:collapse;margin-top:12px}
td,th{border:1px solid #eee;padding:8px;vertical-align:top}
.status-pass{color:#0a0;font-weight:bold}
.status-unknown{color:#a80;font-weight:bold}
.status-fail{color:#a00;background:#fdeaea;font-weight:600;text-align:center}
summary{cursor:pointer}
.section{margin-top:24px}
</style>
</head><body>
<h2>Magebean Scan</h2>
<div>Completed: {{scan_completed}}</div>
<div>Path: {{path_audited}}</div>
<div>Rules: {{rules_passed}} / {{rules_total}} ({{rules_passed_percent}}%) — Failed: {{rules_failed}} — Unknown: {{rules_unknown}}</div>
<div>Findings Overview — Critical: {{findings_critical}} | High: {{findings_high}} | Medium: {{findings_medium}} | Low: {{findings_low}} | Total: {{findings_total}}</div>
<table>
<thead><tr><th>ID</th><th>Severity</th><th>Status</th><th>Message</th></tr></thead>
<tbody>
{{table}}
</tbody>
</table>
{{cve_section}}
</body></html>
HTML;
    }
}
