<?php
declare(strict_types=1);
namespace Magebean\Engine\Checks\Families;
use Magebean\Engine\Context;
use Magebean\Engine\Collectors\CollectorSet;

final class PaymentSourceChecks extends CodeSearchSupport
{
    public function cardholderDataStorage(array $args): array
    {
        $roots = $args['paths'] ?? ['app/code', 'app/etc', 'db'];
        $inc = $args['include_ext'] ?? ['php', 'xml', 'sql', 'json'];
        $max = max(1, (int)($args['max_results'] ?? 100));
        $excludeDirs = array_values(array_filter(array_map(
            static fn(mixed $path): string => trim(str_replace('\\', '/', (string)$path), '/'),
            (array)($args['exclude_dirs'] ?? ['setup', 'dev/tests', 'dev/tools', 'vendor', 'var', 'generated', 'pub/static', 'pub/media'])
        ), static fn(string $path): bool => $path !== ''));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $findings = [];
        $filesRead = 0;
        foreach ($this->collectFiles($rootsAbs, $inc) as $file) {
            $relativeFile = $this->relativeFile($file);
            if ($this->isExcludedRelativePath($relativeFile, $excludeDirs)) {
                continue;
            }
            $content = $this->collectors->files->read($file);
            if ($content === false) {
                continue;
            }

            $filesRead++;
            foreach ($this->cardholderDataStorageFindings($file, $content) as $finding) {
                $findings[] = $finding;
                if (count($findings) >= $max) {
                    break 2;
                }
            }
        }

        $evidence = [
            'paths' => array_values($roots),
            'exclude_dirs' => $excludeDirs,
            'files_scanned' => $filesRead,
            'findings' => $findings,
            'truncated' => count($findings) >= $max,
        ];

        if ($findings !== []) {
            $lines = ['Raw cardholder data storage patterns detected:'];
            foreach ($findings as $finding) {
                $lines[] = sprintf(
                    '    - %s:%d [%s] %s',
                    $finding['file'],
                    $finding['line'],
                    $finding['kind'],
                    $finding['field'] ?? $finding['pattern']
                );
            }
            if ($evidence['truncated']) {
                $lines[] = sprintf('    - output truncated at %d findings', $max);
            }

            return [false, implode("\n", $lines), $evidence];
        }

        if ($filesRead === 0) {
            return [null, '[UNKNOWN] No readable schema/code files were collected for cardholder storage candidates', $evidence];
        }

        return [null, '[UNKNOWN] No supported source storage candidate found; deployment database contents were not inspected', $evidence];
    }

    public function cardholderDataFiles(array $args): array
    {
        $roots = $args['paths'] ?? ['var/export', 'var/import', 'var/backups', 'var/backup', 'var/log', 'var/report', 'pub/media', 'pub/import', 'backups', 'backup'];
        $inc = $args['include_ext'] ?? ['csv', 'sql', 'txt', 'log', 'json', 'xml', 'bak', 'old'];
        $max = max(1, (int)($args['max_results'] ?? 100));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $findings = [];
        $filesRead = 0;
        foreach ($this->collectFiles($rootsAbs, $inc) as $file) {
            $content = $this->collectors->files->read($file);
            if ($content === false) {
                continue;
            }

            $filesRead++;
            foreach ($this->cardholderDataFileFindings($file, $content) as $finding) {
                $findings[] = $finding;
                if (count($findings) >= $max) {
                    break 2;
                }
            }
        }

        $evidence = [
            'paths' => array_values($roots),
            'files_scanned' => $filesRead,
            'findings' => $findings,
            'truncated' => count($findings) >= $max,
        ];

        if ($findings !== []) {
            $lines = ['Cardholder data found in files, exports, or backups:'];
            foreach ($findings as $finding) {
                $lines[] = sprintf(
                    '    - %s:%d [%s] %s',
                    $finding['file'],
                    $finding['line'],
                    $finding['kind'],
                    $finding['field'] ?? $finding['pattern']
                );
            }
            if ($evidence['truncated']) {
                $lines[] = sprintf('    - output truncated at %d findings', $max);
            }

            return [false, implode("\n", $lines), $evidence];
        }

        if ($filesRead === 0) {
            return [null, '[UNKNOWN] No readable eligible export, backup, media or log file was collected', $evidence];
        }

        return [true, 'No cardholder data detected in high-risk files, exports, or backups', $evidence];
    }

    public function cardholderDataLogs(array $args): array
    {
        $roots = $args['paths'] ?? ['var/log', 'var/report', 'pub/media/log', 'pub/media/report'];
        $inc = $args['include_ext'] ?? ['log', 'txt', 'json', 'xml'];
        $max = max(1, (int)($args['max_results'] ?? 100));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $findings = [];
        $filesRead = 0;
        foreach ($this->collectFiles($rootsAbs, $inc) as $file) {
            $content = $this->collectors->files->read($file);
            if ($content === false) {
                continue;
            }

            $filesRead++;
            foreach ($this->cardholderDataFileFindings($file, $content) as $finding) {
                $findings[] = $finding;
                if (count($findings) >= $max) {
                    break 2;
                }
            }
        }

        $evidence = [
            'paths' => array_values($roots),
            'files_scanned' => $filesRead,
            'findings' => $findings,
            'truncated' => count($findings) >= $max,
        ];

        if ($findings !== []) {
            $lines = ['Cardholder data found in application logs or reports:'];
            foreach ($findings as $finding) {
                $lines[] = sprintf(
                    '    - %s:%d [%s] %s',
                    $finding['file'],
                    $finding['line'],
                    $finding['kind'],
                    $finding['field'] ?? $finding['pattern']
                );
            }
            if ($evidence['truncated']) {
                $lines[] = sprintf('    - output truncated at %d findings', $max);
            }

            return [false, implode("\n", $lines), $evidence];
        }

        if ($filesRead === 0) {
            return [null, '[UNKNOWN] No readable application log/report file was collected', $evidence];
        }

        return [true, 'No cardholder data detected in application logs or reports', $evidence];
    }

    public function paymentMethodScope(array $args): array
    {
        $roots = $args['paths'] ?? ['app/code', 'app/design'];
        $inc = $args['include_ext'] ?? ['php', 'phtml', 'js', 'xml'];
        $max = max(1, (int)($args['max_results'] ?? 100));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $findings = [];
        $filesRead = 0;
        foreach ($this->collectFiles($rootsAbs, $inc) as $file) {
            $content = $this->collectors->files->read($file);
            if ($content === false) {
                continue;
            }

            $filesRead++;
            foreach ($this->paymentMethodScopeFindings($file, $content) as $finding) {
                $findings[] = $finding;
                if (count($findings) >= $max) {
                    break 2;
                }
            }
        }

        $evidence = [
            'paths' => array_values($roots),
            'files_scanned' => $filesRead,
            'findings' => $findings,
            'truncated' => count($findings) >= $max,
        ];

        if ($findings !== []) {
            $lines = ['Payment method patterns may expand PCI scope:'];
            foreach ($findings as $finding) {
                $lines[] = sprintf(
                    '    - %s:%d [%s] %s',
                    $finding['file'],
                    $finding['line'],
                    $finding['kind'],
                    $finding['field'] ?? $finding['pattern']
                );
            }
            if ($evidence['truncated']) {
                $lines[] = sprintf('    - output truncated at %d findings', $max);
            }

            return [false, implode("\n", $lines), $evidence];
        }

        if ($filesRead === 0) {
            return [null, '[UNKNOWN] No custom payment method source was collected', $evidence];
        }

        return [null, '[UNKNOWN] Payment-source candidates were inspected; payment inventory and data-flow documentation were not verified', $evidence];
    }

    public function checkoutRawCardCollection(array $args): array
    {
        $roots = $args['paths'] ?? ['app/code', 'app/design'];
        $inc = $args['include_ext'] ?? ['php', 'phtml', 'js', 'html', 'xml'];
        $max = max(1, (int)($args['max_results'] ?? 100));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $findings = [];
        $filesRead = 0;
        foreach ($this->collectFiles($rootsAbs, $inc) as $file) {
            $content = $this->collectors->files->read($file);
            if ($content === false) {
                continue;
            }

            $filesRead++;
            foreach ($this->checkoutRawCardCollectionFindings($file, $content) as $finding) {
                $findings[] = $finding;
                if (count($findings) >= $max) {
                    break 2;
                }
            }
        }

        $evidence = [
            'paths' => array_values($roots),
            'files_scanned' => $filesRead,
            'findings' => $findings,
            'truncated' => count($findings) >= $max,
        ];

        if ($findings !== []) {
            $lines = ['Raw card collection patterns detected in checkout code:'];
            foreach ($findings as $finding) {
                $lines[] = sprintf(
                    '    - %s:%d [%s] %s',
                    $finding['file'],
                    $finding['line'],
                    $finding['kind'],
                    $finding['field'] ?? $finding['pattern']
                );
            }
            if ($evidence['truncated']) {
                $lines[] = sprintf('    - output truncated at %d findings', $max);
            }

            return [false, implode("\n", $lines), $evidence];
        }

        if ($filesRead === 0) {
            return [null, '[UNKNOWN] No readable checkout source was collected', $evidence];
        }

        return [null, '[UNKNOWN] No supported literal raw-card declaration found; dynamic/rendered checkout collection is unresolved', $evidence];
    }

    public function paymentScriptInventory(array $args): array
    {
        $inventoryFiles = $args['inventory_files'] ?? ['.magebean/payment-scripts.json', 'docs/payment-script-inventory.md'];
        if (!is_array($inventoryFiles)) {
            $inventoryFiles = ['.magebean/payment-scripts.json', 'docs/payment-script-inventory.md'];
        }
        $roots = $args['paths'] ?? ['app/design', 'app/code'];
        $inc = $args['include_ext'] ?? ['xml', 'phtml', 'html', 'js'];
        $max = max(1, (int)($args['max_results'] ?? 100));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $inventory = $this->paymentScriptInventoryEvidence(array_values(array_map('strval', $inventoryFiles)));
        $scripts = [];
        $filesRead = 0;
        foreach ($this->collectFiles($rootsAbs, $inc) as $file) {
            $content = $this->collectors->files->read($file);
            if ($content === false) {
                continue;
            }

            $filesRead++;
            foreach ($this->paymentScriptSourceFindings($file, $content) as $finding) {
                $scripts[] = $finding;
                if (count($scripts) >= $max) {
                    break 2;
                }
            }
        }

        $evidence = [
            'inventory' => $inventory,
            'paths' => array_values($roots),
            'files_scanned' => $filesRead,
            'script_sources' => $scripts,
            'truncated' => count($scripts) >= $max,
        ];

        $listed = $this->inventorySources(array_values(array_map('strval', $inventoryFiles)));
        $unlisted = array_values(array_filter($scripts, static fn(array $script): bool => !isset($listed[$script['source'] ?? ''])));
        $evidence['unlisted_sources'] = array_values(array_unique(array_column($unlisted, 'source')));
        if ($scripts !== [] && $unlisted === []) return [true, 'Every collected literal payment script source is present in the supplied inventory; runtime completeness is not established', $evidence];
        if ($scripts !== []) {
            $lines = ['Payment page script sources detected without an inventory:'];
            foreach ($scripts as $script) {
                $lines[] = sprintf(
                    '    - %s:%d [%s] %s',
                    $script['file'],
                    $script['line'],
                    $script['kind'],
                    $script['source'] ?? $script['snippet'] ?? 'script'
                );
            }
            if ($evidence['truncated']) {
                $lines[] = sprintf('    - output truncated at %d findings', $max);
            }

            return [false, implode("\n", $lines), $evidence];
        }

        if ($filesRead === 0) {
            return [null, '[UNKNOWN] No readable payment-page source was collected for inventory comparison', $evidence];
        }

        return [null, '[UNKNOWN] No supported literal payment-page script source was collected; dynamic runtime inventory is unresolved', $evidence];
    }

    public function paymentScriptIntegrity(array $args): array
    {
        $evidenceFiles = $args['evidence_files'] ?? ['.magebean/payment-script-integrity.json'];
        if (!is_array($evidenceFiles)) {
            $evidenceFiles = ['.magebean/payment-script-integrity.json'];
        }
        $roots = $args['paths'] ?? ['app/design', 'app/code'];
        $inc = $args['include_ext'] ?? ['xml', 'phtml', 'html', 'js'];
        $max = max(1, (int)($args['max_results'] ?? 100));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $controlEvidence = $this->paymentScriptIntegrityEvidence(array_values(array_map('strval', $evidenceFiles)));
        $scripts = [];
        $filesRead = 0;
        foreach ($this->collectFiles($rootsAbs, $inc) as $file) {
            $content = $this->collectors->files->read($file);
            if ($content === false) {
                continue;
            }

            $filesRead++;
            $controlEvidence = $this->mergePaymentScriptIntegrityEvidence($controlEvidence, $this->paymentScriptInlineControlEvidence($file, $content));
            foreach ($this->paymentScriptSourceFindings($file, $content) as $finding) {
                $scripts[] = $finding;
                if (count($scripts) >= $max) {
                    break 2;
                }
            }
        }

        $evidence = [
            'controls' => $controlEvidence,
            'paths' => array_values($roots),
            'files_scanned' => $filesRead,
            'script_sources' => $scripts,
            'truncated' => count($scripts) >= $max,
        ];

        if ($scripts === []) return [null, '[UNKNOWN] No supported literal payment script was collected for bound integrity inspection', $evidence];
        $bound = $this->boundScriptIntegrity($scripts);
        $evidence['bound_integrity'] = $bound;
        if ($bound['missing'] === [] && $bound['unsupported'] !== []) return [null, '[UNKNOWN] Script integrity requires unsupported inline/dynamic or external content validation', $evidence];
        if ($bound['missing'] === [] && $bound['unsupported'] === []) return [true, 'Each collected literal external script tag declares a syntactically valid SRI hash; fetched bytes and runtime DOM were not verified', $evidence];
        $lines = ['Payment page scripts detected without allowlist or integrity controls:'];
        foreach ($scripts as $script) {
            $lines[] = sprintf(
                '    - %s:%d [%s] %s',
                $script['file'],
                $script['line'],
                $script['kind'],
                $script['source'] ?? $script['snippet'] ?? 'script'
            );
        }
        if ($evidence['truncated']) {
            $lines[] = sprintf('    - output truncated at %d findings', $max);
        }

        return [false, implode("\n", $lines), $evidence];
    }

    public function paymentPageTamperMonitoring(array $args): array
    {
        $evidenceFiles = $args['evidence_files'] ?? ['.magebean/payment-page-monitoring.json', 'docs/payment-page-monitoring.md'];
        if (!is_array($evidenceFiles)) {
            $evidenceFiles = ['.magebean/payment-page-monitoring.json', 'docs/payment-page-monitoring.md'];
        }
        $roots = $args['paths'] ?? ['app/code', 'app/etc', 'app/design', 'pub/.htaccess', '.htaccess', 'nginx.conf'];
        $inc = $args['include_ext'] ?? ['xml', 'php', 'phtml', 'js', 'html', 'conf', 'htaccess'];
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $signals = [
            'payment_scope' => false,
            'csp_reporting' => false,
            'integrity_baseline' => false,
            'scheduled_detection' => false,
            'alerting' => false,
        ];
        $locations = [];
        $evidenceEntries = [];

        foreach ($evidenceFiles as $relative) {
            $relative = (string)$relative;
            $entry = $this->paymentPageTamperEvidenceFile($relative);
            $evidenceEntries[] = $entry;
            $signals = $this->mergeBooleanSignals($signals, $entry['signals'] ?? []);
            if (!empty($entry['locations']) && is_array($entry['locations'])) {
                $locations = array_merge($locations, $entry['locations']);
            }
        }

        $files = [];
        foreach ($rootsAbs as $root) {
            if (is_file($root)) {
                $files[] = $root;
                continue;
            }
            if (is_dir($root)) {
                foreach ($this->collectFiles([$root], $inc) as $file) {
                    $files[] = $file;
                }
            }
        }
        $files = array_values(array_unique($files));

        $filesRead = 0;
        foreach ($files as $file) {
            $content = $this->collectors->files->read($file);
            if ($content === false) {
                continue;
            }
            $filesRead++;
            $entry = $this->paymentPageTamperEvidenceInFile($file, $content);
            $signals = $this->mergeBooleanSignals($signals, $entry['signals']);
            if ($entry['locations'] !== []) {
                $locations = array_merge($locations, $entry['locations']);
            }
        }

        $hasCspMonitoring = $signals['payment_scope'] && $signals['csp_reporting'] && $signals['alerting'];
        $hasIntegrityMonitoring = $signals['payment_scope'] && $signals['integrity_baseline'] && $signals['scheduled_detection'] && $signals['alerting'];
        $missing = [];
        if (!$signals['payment_scope']) {
            $missing[] = 'payment/checkout page scope';
        }
        if (!$signals['alerting']) {
            $missing[] = 'alerting destination or notification workflow';
        }
        if (!$signals['csp_reporting'] && !($signals['integrity_baseline'] && $signals['scheduled_detection'])) {
            $missing[] = 'CSP reporting or scheduled file/script integrity detection';
        }

        $evidence = [
            'evidence_files' => $evidenceEntries,
            'paths' => array_values($roots),
            'files_scanned' => $filesRead,
            'signals' => $signals,
            'locations' => $locations,
            'missing' => $missing,
        ];

        if ($hasCspMonitoring || $hasIntegrityMonitoring) {
            return [null, '[UNKNOWN] Monitoring declaration markers were collected; scheduled execution, baseline comparison and delivered alerts were not verified', $evidence];
        }

        $lines = ['Payment page tamper monitoring evidence is incomplete:'];
        foreach ($missing as $item) {
            $lines[] = '    - missing ' . $item;
        }
        if ($filesRead === 0 && !$this->hasPresentEvidenceFile($evidenceEntries)) {
            $lines[] = '    - no monitoring evidence files or readable app/config files found';
        }

        return [null, '[UNKNOWN] Monitoring execution evidence is unavailable; declaration markers alone do not establish readiness', $evidence];
    }

    public function securityHeadersBaseline(array $args): array
    {
        $roots = $args['paths'] ?? ['app/etc', 'app/code', 'app/design', 'pub/.htaccess', '.htaccess', 'nginx.conf'];
        $inc = $args['include_ext'] ?? ['xml', 'php', 'phtml', 'html', 'conf', 'htaccess'];
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $files = [];
        foreach ($rootsAbs as $root) {
            if (is_file($root)) {
                $files[] = $root;
                continue;
            }
            if (is_dir($root)) {
                foreach ($this->collectFiles([$root], $inc) as $file) {
                    $files[] = $file;
                }
            }
        }
        $files = array_values(array_unique($files));

        $signals = [
            'csp' => false,
            'csp_not_permissive' => false,
            'frame_protection' => false,
            'nosniff' => false,
        ];
        $locations = [];
        $permissive = [];
        $filesRead = 0;
        foreach ($files as $file) {
            $content = $this->collectors->files->read($file);
            if ($content === false) {
                continue;
            }
            $filesRead++;
            $evidence = $this->securityHeaderEvidenceInFile($file, $content);
            foreach ($signals as $key => $_) {
                $signals[$key] = $signals[$key] || !empty($evidence['signals'][$key]);
            }
            $locations = array_merge($locations, $evidence['locations']);
            $permissive = array_merge($permissive, $evidence['permissive']);
        }

        if ($permissive !== []) {
            $signals['csp_not_permissive'] = false;
        }

        $missing = [];
        if (!$signals['csp']) {
            $missing[] = 'Content-Security-Policy';
        } elseif (!$signals['csp_not_permissive']) {
            $missing[] = 'non-permissive Content-Security-Policy';
        }
        if (!$signals['frame_protection']) {
            $missing[] = 'X-Frame-Options DENY/SAMEORIGIN or CSP frame-ancestors';
        }
        if (!$signals['nosniff']) {
            $missing[] = 'X-Content-Type-Options nosniff';
        }

        $evidence = [
            'paths' => array_values($roots),
            'files_scanned' => $filesRead,
            'signals' => $signals,
            'locations' => $locations,
            'permissive' => $permissive,
            'missing' => $missing,
        ];

        if ($filesRead === 0) {
            return [null, '[UNKNOWN] No readable security-header source configuration was collected', $evidence];
        }

        if ($missing !== [] || $permissive !== []) {
            $lines = ['Security header baseline is incomplete:'];
            foreach ($missing as $item) {
                $lines[] = '    - missing ' . $item;
            }
            foreach ($permissive as $issue) {
                $lines[] = sprintf('    - %s:%d [%s] %s', $issue['file'], $issue['line'], $issue['kind'], $issue['snippet']);
            }
            return [null, '[UNKNOWN] Runtime response policy is unobserved; source declaration diagnostics are supporting only', $evidence];
        }

        return [null, '[UNKNOWN] Header declaration markers were collected; emitted application response headers were not inspected', $evidence];
    }

    public function checkoutCspEnforced(array $args): array
    {
        $roots = $args['paths'] ?? ['app/code', 'app/etc', 'app/design', 'pub/.htaccess', '.htaccess', 'nginx.conf'];
        $inc = $args['include_ext'] ?? ['xml', 'php', 'phtml', 'html', 'conf', 'htaccess'];
        $required = $args['required_directives'] ?? ['script-src', 'connect-src', 'frame-src', 'form-action', 'object-src', 'base-uri'];
        if (!is_array($required)) {
            $required = ['script-src', 'connect-src', 'frame-src', 'form-action', 'object-src', 'base-uri'];
        }
        $required = array_values(array_unique(array_map(static fn(mixed $value): string => strtolower((string)$value), $required)));
        $requireReporting = (bool)($args['require_reporting'] ?? true);
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $files = [];
        foreach ($rootsAbs as $root) {
            if (is_file($root)) {
                $files[] = $root;
                continue;
            }
            if (is_dir($root)) {
                foreach ($this->collectFiles([$root], $inc) as $file) {
                    $files[] = $file;
                }
            }
        }
        $files = array_values(array_unique($files));

        $directives = [];
        $locations = [];
        $permissive = [];
        $hasReporting = false;
        $filesRead = 0;
        foreach ($files as $file) {
            $content = $this->collectors->files->read($file);
            if ($content === false) {
                continue;
            }
            $filesRead++;
            $evidence = $this->checkoutCspEvidenceInFile($file, $content);
            foreach ($evidence['directives'] as $directive) {
                $directives[$directive] = true;
            }
            if (!empty($evidence['has_reporting'])) {
                $hasReporting = true;
            }
            foreach ($evidence['locations'] as $location) {
                $locations[] = $location;
            }
            foreach ($evidence['permissive'] as $issue) {
                $permissive[] = $issue;
            }
        }

        $missing = array_values(array_filter($required, static fn(string $directive): bool => empty($directives[$directive])));
        if ($requireReporting && !$hasReporting) {
            $missing[] = 'report-uri/report-to';
        }

        $evidence = [
            'paths' => array_values($roots),
            'files_scanned' => $filesRead,
            'required_directives' => $required,
            'directives' => array_keys($directives),
            'has_reporting' => $hasReporting,
            'locations' => $locations,
            'permissive' => $permissive,
            'missing' => $missing,
        ];

        if ($filesRead === 0) {
            return [null, '[UNKNOWN] No checkout CSP source configuration was collected', $evidence];
        }

        if ($missing !== [] || $permissive !== []) {
            $lines = ['Checkout CSP is incomplete or overly permissive:'];
            if ($missing !== []) {
                $lines[] = '    - missing ' . implode(', ', $missing);
            }
            foreach ($permissive as $issue) {
                $lines[] = sprintf('    - %s:%d [%s] %s', $issue['file'], $issue['line'], $issue['kind'], $issue['snippet']);
            }
            return [null, '[UNKNOWN] Runtime response policy is unobserved; source declaration diagnostics are supporting only', $evidence];
        }

        return [null, '[UNKNOWN] CSP declaration markers were collected; an enforced checkout response policy was not inspected', $evidence];
    }

    private function paymentPageTamperEvidenceFile(string $relative): array
    {
        $path = $this->ctx->abs($relative);
        $entry = [
            'file' => $relative,
            'present' => is_file($path),
            'readable' => false,
            'signals' => [
                'payment_scope' => false,
                'csp_reporting' => false,
                'integrity_baseline' => false,
                'scheduled_detection' => false,
                'alerting' => false,
            ],
            'locations' => [],
        ];

        if (!is_file($path)) {
            return $entry;
        }

        $content = $this->collectors->files->read($path);
        if ($content === false || trim($content) === '') {
            return $entry;
        }

        $entry['readable'] = true;
        $evidence = $this->paymentPageTamperEvidenceInFile($path, $content);
        $entry['signals'] = $evidence['signals'];
        $entry['locations'] = $evidence['locations'];

        return $entry;
    }

    private function paymentPageTamperEvidenceInFile(string $file, string $content): array
    {
        $extension = strtolower(pathinfo($file, PATHINFO_EXTENSION));
        $scanContent = in_array($extension, ['md', 'markdown', 'json'], true)
            ? $content
            : $this->maskSourceComments($content, $extension);
        $relative = $this->relativeFile($file);
        $text = $relative . "\n" . $scanContent;

        $patterns = [
            'payment_scope' => '~\b(?:checkout|payment(?:[-_ ]?page)?|onepage|cart/checkout|hosted[_-]?payment|stripe|paypal|braintree|adyen|authorizenet|authorize(?:\.net)?)\b~i',
            'csp_reporting' => '~\b(?:report-uri|report-to|SecurityPolicyViolationEvent|content-security-policy-report-only|csp[_/-]?report(?:[_/-]?uri)?|report_uri|report_only)\b~i',
            'integrity_baseline' => '~\b(?:checksum|sha(?:256|384|512)-?|integrity|subresource integrity|\bsri\b|file[_ -]?integrity|script[_ -]?integrity|baseline|tamper[_ -]?(?:hash|check|detect)|\bfim\b)\b~i',
            'scheduled_detection' => '~\b(?:cron|schedule|scheduled|hourly|daily|continuous|interval|watcher|monitor(?:ing)?|detector|observer|synthetic|probe|scanner|runbook)\b~i',
            'alerting' => '~\b(?:alert(?:ing)?|notify|notification|email|slack|msteams|teams|pagerduty|opsgenie|webhook|siem|splunk|datadog|newrelic|sentry|cloudwatch|grafana|incident)\b~i',
        ];

        $signals = [];
        $locations = [];
        foreach ($patterns as $name => $regex) {
            $signals[$name] = preg_match($regex, $text, $match, PREG_OFFSET_CAPTURE) === 1;
            if ($signals[$name]) {
                $offset = (int)$match[0][1] - strlen($relative) - 1;
                $locations[] = $this->matchEvidence($file, $content, $name, max(0, $offset));
            }
        }

        return [
            'signals' => $signals,
            'locations' => $locations,
        ];
    }

    private function mergeBooleanSignals(array $left, array $right): array
    {
        foreach ($left as $key => $value) {
            $left[$key] = !empty($value) || !empty($right[$key]);
        }
        return $left;
    }

    private function hasPresentEvidenceFile(array $entries): bool
    {
        foreach ($entries as $entry) {
            if (!empty($entry['present']) && !empty($entry['readable'])) {
                return true;
            }
        }
        return false;
    }

    private function securityHeaderEvidenceInFile(string $file, string $content): array
    {
        $extension = strtolower(pathinfo($file, PATHINFO_EXTENSION));
        $scanContent = $this->maskSourceComments($content, $extension);
        $signals = [
            'csp' => false,
            'csp_not_permissive' => false,
            'frame_protection' => false,
            'nosniff' => false,
        ];
        $locations = [];
        $permissive = [];

        $patterns = [
            'nosniff' => '~\bX-Content-Type-Options\b[^\r\n;<>]*(?:nosniff)|<header\b[^>]*\bname\s*=\s*([\'\"])X-Content-Type-Options\1[^>]*\bvalue\s*=\s*([\'\"])nosniff\2~i',
            'x_frame_options' => '~\bX-Frame-Options\b[^\r\n;<>]*(?:DENY|SAMEORIGIN)|<header\b[^>]*\bname\s*=\s*([\'\"])X-Frame-Options\1[^>]*\bvalue\s*=\s*([\'\"])(?:DENY|SAMEORIGIN)\2~i',
            'frame_ancestors' => '~\bframe-ancestors\b\s+(?![^;\r\n]*\*)[^;\r\n]+~i',
            'csp_header' => '~\bContent-Security-Policy\b|<header\b[^>]*\bname\s*=\s*([\'\"])Content-Security-Policy\1~i',
        ];

        foreach ($patterns as $kind => $regex) {
            if (preg_match($regex, $scanContent, $match, PREG_OFFSET_CAPTURE) !== 1) {
                continue;
            }
            $evidence = $this->matchEvidence($file, $content, $kind, (int)$match[0][1]);
            $evidence['kind'] = $kind;
            $locations[] = $evidence;
            if ($kind === 'nosniff') {
                $signals['nosniff'] = true;
            } elseif ($kind === 'x_frame_options' || $kind === 'frame_ancestors') {
                $signals['frame_protection'] = true;
                if ($kind === 'frame_ancestors') {
                    $signals['csp'] = true;
                }
            } elseif ($kind === 'csp_header') {
                $signals['csp'] = true;
            }
        }

        $signals['csp_not_permissive'] = $signals['csp'];
        $badPatterns = [
            'x_frame_options_allowall' => '~\bX-Frame-Options\b[^\r\n;<>]*ALLOWALL\b~i',
            'frame_ancestors_wildcard' => '~\bframe-ancestors\b[^;\r\n]*\*~i',
            'csp_wildcard_default_or_script' => '~\b(?:default-src|script-src|object-src|frame-ancestors)\b[^;\r\n]*\*~i',
            'csp_unsafe_eval' => '~\bunsafe-eval\b~i',
        ];
        foreach ($badPatterns as $kind => $regex) {
            if (preg_match($regex, $scanContent, $match, PREG_OFFSET_CAPTURE) !== 1) {
                continue;
            }
            $evidence = $this->matchEvidence($file, $content, $kind, (int)$match[0][1]);
            $evidence['kind'] = $kind;
            $permissive[] = $evidence;
        }

        return [
            'signals' => $signals,
            'locations' => $locations,
            'permissive' => $permissive,
        ];
    }

    private function checkoutCspEvidenceInFile(string $file, string $content): array
    {
        $extension = strtolower(pathinfo($file, PATHINFO_EXTENSION));
        $scanContent = $this->maskSourceComments($content, $extension);
        $directives = [];
        $locations = [];
        $permissive = [];
        $reporting = preg_match('~\b(?:report-uri|report-to|SecurityPolicyViolationEvent|csp[_/-]?report(?:[_/-]?uri)?|report_uri|report_only)\b~i', $scanContent) === 1;
        $directiveRegex = '~\b(?P<directive>script-src|connect-src|frame-src|form-action|object-src|base-uri)\b~i';
        if (preg_match_all($directiveRegex, $scanContent, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) > 0) {
            foreach ($matches as $match) {
                $directive = strtolower((string)$match['directive'][0]);
                $directives[$directive] = true;
                $locations[] = $this->matchEvidence($file, $content, 'csp_directive', (int)$match['directive'][1]);
            }
        }

        if (preg_match_all('~<policy\b[^>]*\bid\s*=\s*([\'\"])(?P<directive>script-src|connect-src|frame-src|form-action|object-src|base-uri)\1~i', $scanContent, $policyMatches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) > 0) {
            foreach ($policyMatches as $match) {
                $directive = strtolower((string)$match['directive'][0]);
                $directives[$directive] = true;
                $locations[] = $this->matchEvidence($file, $content, 'csp_policy', (int)$match['directive'][1]);
            }
        }

        $badPatterns = [
            'wildcard_source' => '~(?:\b(?:script-src|connect-src|frame-src|form-action|object-src|base-uri)\b|<policy\b[^>]*\bid\s*=\s*([\'\"])(?:script-src|connect-src|frame-src|form-action|object-src|base-uri)\1)[\s\S]{0,500}(?:\s\*\s|<value\b[^>]*>\s*\*\s*</value>)~i',
            'unsafe_eval' => '~\bunsafe-eval\b~i',
            'unsafe_inline_without_nonce' => '~\bunsafe-inline\b(?![\s\S]{0,300}(?:nonce-|sha256-|sha384-|sha512-))~i',
        ];
        foreach ($badPatterns as $kind => $regex) {
            if (preg_match_all($regex, $scanContent, $badMatches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) < 1) {
                continue;
            }
            foreach ($badMatches as $match) {
                $evidence = $this->matchEvidence($file, $content, $kind, (int)$match[0][1]);
                $evidence['kind'] = $kind;
                $permissive[] = $evidence;
            }
        }

        return [
            'directives' => array_keys($directives),
            'has_reporting' => $reporting,
            'locations' => $locations,
            'permissive' => $permissive,
        ];
    }

    private function inventorySources(array $files): array
    {
        $sources = [];
        foreach ($files as $relative) {
            $content = $this->collectors->files->read($this->ctx->abs($relative));
            if (!is_string($content)) continue;
            $data = json_decode($content, true);
            if (!is_array($data)) continue;
            $entries = array_is_list($data) ? $data : ($data['scripts'] ?? $data['entries'] ?? []);
            foreach (is_array($entries) ? $entries : [] as $entry) {
                if (!is_array($entry)) continue;
                $source = $entry['source'] ?? $entry['src'] ?? $entry['url'] ?? $entry['path'] ?? null;
                if (is_string($source) && trim($source) !== '') $sources[trim($source)] = true;
            }
        }
        return $sources;
    }

    private function boundScriptIntegrity(array $scripts): array
    {
        $missing = []; $unsupported = [];
        foreach ($scripts as $script) {
            if (($script['kind'] ?? '') !== 'script_tag' || !preg_match('~^https?://|^/~i', $script['source'] ?? '')) { $unsupported[] = $script['file']; continue; }
            $text = $this->collectors->files->read($this->ctx->abs($script['file']));
            if (!is_string($text)) { $unsupported[] = $script['file']; continue; }
            $matched = false; $valid = true;
            preg_match_all('~<script\b(?P<attrs>[^>]*)>~is', $text, $tags, PREG_SET_ORDER);
            foreach ($tags as $tag) {
                if (!preg_match('~(?:^|\s)src\s*=\s*([\'\"])(.*?)\1~is', $tag['attrs'], $src) || $src[2] !== $script['source']) continue;
                $matched = true; $tagValid = false;
                if (preg_match('~(?:^|\s)integrity\s*=\s*([\'\"])(.*?)\1~is', $tag['attrs'], $hash)) {
                    foreach (preg_split('/\s+/', trim($hash[2])) ?: [] as $value) {
                        if (!preg_match('/^sha(256|384|512)-([A-Za-z0-9+\/=]+)$/D', $value, $parts)) continue;
                        $bytes = base64_decode($parts[2], true);
                        if (is_string($bytes) && strlen($bytes) === (int)$parts[1] / 8) $tagValid = true;
                    }
                }
                $valid = $valid && $tagValid;
            }
            if (!$matched) $unsupported[] = $script['file'];
            elseif (!$valid) $missing[] = ['file'=>$script['file'],'line'=>$script['line'],'source'=>$script['source']];
        }
        return ['missing'=>$missing,'unsupported'=>array_values(array_unique($unsupported))];
    }

    private function paymentScriptIntegrityEvidence(array $files): array
    {
        $evidence = [
            'ok' => false,
            'manifest' => false,
            'sri_or_hash' => false,
            'nonce' => false,
            'csp_allowlist' => false,
            'monitoring' => false,
            'files' => [],
        ];

        foreach ($files as $relative) {
            $path = $this->ctx->abs($relative);
            $entry = ['file' => $relative, 'present' => is_file($path), 'ok' => false];
            if (!is_file($path)) {
                $evidence['files'][] = $entry;
                continue;
            }

            $content = $this->collectors->files->read($path);
            if ($content === false) {
                $entry['readable'] = false;
                $evidence['files'][] = $entry;
                continue;
            }

            $entry['readable'] = true;
            $decoded = json_decode($content, true);
            if (is_array($decoded)) {
                $entry['entries'] = $this->countPaymentScriptInventoryEntries($decoded);
                $entry['ok'] = $entry['entries'] > 0;
                $evidence['manifest'] = $evidence['manifest'] || $entry['ok'];
                $evidence['sri_or_hash'] = $evidence['sri_or_hash'] || preg_match('~\b(?:sha(?:256|384|512)-|integrity|hash|sri)\b~i', $content) === 1;
                $evidence['nonce'] = $evidence['nonce'] || preg_match('~\bnonce\b~i', $content) === 1;
                $evidence['monitoring'] = $evidence['monitoring'] || preg_match('~\b(?:monitor|tamper|report-uri|report-to|violation)\b~i', $content) === 1;
            }

            $evidence['files'][] = $entry;
        }

        $evidence['ok'] = $evidence['manifest'] || $evidence['sri_or_hash'] || $evidence['nonce'] || $evidence['csp_allowlist'] || $evidence['monitoring'];
        return $evidence;
    }

    private function paymentScriptInlineControlEvidence(string $file, string $content): array
    {
        $relative = $this->relativeFile($file);
        $text = $relative . "\n" . $content;
        $evidence = [
            'ok' => false,
            'manifest' => false,
            'sri_or_hash' => preg_match('~\b(?:integrity\s*=|sha(?:256|384|512)-|sri|script_hash)\b~i', $text) === 1,
            'nonce' => preg_match('~\b(?:nonce\s*=|csp_nonce|script_nonce|nonceProvider|getNonce)\b~i', $text) === 1,
            'csp_allowlist' => preg_match('~\b(?:csp_whitelist|script-src|connect-src|frame-src|form-action|object-src|base-uri)\b~i', $text) === 1,
            'monitoring' => preg_match('~\b(?:report-uri|report-to|SecurityPolicyViolationEvent|tamper|integrity[_-]?monitor|checkout[_-]?monitor)\b~i', $text) === 1,
            'files' => [],
        ];
        $evidence['ok'] = $evidence['sri_or_hash'] || $evidence['nonce'] || $evidence['csp_allowlist'] || $evidence['monitoring'];
        return $evidence;
    }

    private function mergePaymentScriptIntegrityEvidence(array $left, array $right): array
    {
        foreach (['manifest', 'sri_or_hash', 'nonce', 'csp_allowlist', 'monitoring'] as $key) {
            $left[$key] = !empty($left[$key]) || !empty($right[$key]);
        }
        $left['ok'] = !empty($left['manifest']) || !empty($left['sri_or_hash']) || !empty($left['nonce']) || !empty($left['csp_allowlist']) || !empty($left['monitoring']);
        if (!empty($right['files']) && is_array($right['files'])) {
            $left['files'] = array_merge($left['files'] ?? [], $right['files']);
        }
        return $left;
    }

    private function paymentScriptInventoryEvidence(array $files): array
    {
        $checked = [];
        foreach ($files as $relative) {
            $path = $this->ctx->abs($relative);
            $entry = ['file' => $relative, 'present' => is_file($path), 'ok' => false];
            if (!is_file($path)) {
                $checked[] = $entry;
                continue;
            }

            $content = $this->collectors->files->read($path);
            if ($content === false) {
                $entry['readable'] = false;
                $checked[] = $entry;
                continue;
            }

            $entry['readable'] = true;
            $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
            if ($ext === 'json') {
                $decoded = json_decode($content, true);
                $entries = $this->countPaymentScriptInventoryEntries($decoded);
                $entry['entries'] = $entries;
                $entry['ok'] = $entries > 0;
            } else {
                $hasScript = preg_match('~\b(?:script|src|source|checkout|payment|owner|justification|approved)\b~i', $content) === 1;
                $entry['ok'] = $hasScript && preg_match('~\b(?:checkout|payment)\b~i', $content) === 1;
            }

            $checked[] = $entry;
            if (!empty($entry['ok'])) {
                return ['ok' => true, 'files' => $checked];
            }
        }

        return ['ok' => false, 'files' => $checked];
    }

    private function countPaymentScriptInventoryEntries(mixed $decoded): int
    {
        if (!is_array($decoded)) {
            return 0;
        }

        $entries = array_is_list($decoded) ? $decoded : ($decoded['scripts'] ?? $decoded['entries'] ?? []);
        if (!is_array($entries)) {
            return 0;
        }

        $count = 0;
        foreach ($entries as $entry) {
            if (!is_array($entry)) {
                continue;
            }
            $source = (string)($entry['source'] ?? $entry['src'] ?? $entry['url'] ?? $entry['path'] ?? '');
            if ($source !== '') {
                $count++;
            }
        }

        return $count;
    }

    private function paymentScriptSourceFindings(string $file, string $content): array
    {
        $relative = $this->relativeFile($file);
        if (!$this->hasPaymentPageScriptContext($relative, $content)) {
            return [];
        }

        $extension = strtolower(pathinfo($file, PATHINFO_EXTENSION));
        $findings = [];
        $patterns = [];
        if (in_array($extension, ['phtml', 'html'], true)) {
            $patterns['script_tag'] = '~<script\b(?P<attrs>[^>]*)>~is';
        }
        if ($extension === 'xml') {
            $patterns['layout_script'] = '~<(?:script|link)\b[^>]*(?:\bsrc\s*=\s*([\'\"])(?P<src>[^\'\"]+)\1|>(?P<body>[^<]+)</(?:script|link)>)~is';
            $patterns['csp_whitelist_script'] = '~<policy\b[^>]*\bid\s*=\s*([\'\"])(?:script-src|connect-src|frame-src)\1[\s\S]{0,800}<value\b[^>]*>(?P<src>[^<]+)</value>~is';
        }
        if ($extension === 'js' && preg_match('~(?:checkout|payment|placeOrder|setPaymentInformation|script|src|loadScript|require\s*\()~i', $relative . "\n" . $content) === 1) {
            $patterns['custom_payment_js'] = '~\b(?:define\s*\(|require\s*\(|loadScript|script|src|checkout|payment|placeOrder|setPaymentInformation)\b~i';
        }

        foreach ($patterns as $kind => $regex) {
            if (preg_match_all($regex, $content, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) < 1) {
                continue;
            }

            foreach ($matches as $match) {
                $offset = (int)$match[0][1];
                $source = $this->paymentScriptSourceFromMatch($kind, $match, $content, $offset, $relative);
                if ($source === null) {
                    continue;
                }

                $evidence = $this->matchEvidence($file, $content, $kind, $offset);
                $evidence['kind'] = $kind;
                $evidence['source'] = $source;
                $findings[] = $evidence;
            }
        }

        return $this->dedupeFindings($findings);
    }

    private function hasPaymentPageScriptContext(string $relative, string $content): bool
    {
        return preg_match('~(?:checkout|payment|billing|placeOrder|setPaymentInformation|Magento_Checkout|csp_whitelist|script-src|connect-src|frame-src)~i', $relative . "\n" . $content) === 1;
    }

    private function paymentScriptSourceFromMatch(string $kind, array $match, string $content, int $offset, string $relative): ?string
    {
        if (isset($match['src']) && is_array($match['src']) && trim((string)$match['src'][0]) !== '') {
            return trim((string)$match['src'][0]);
        }
        if (isset($match['body']) && is_array($match['body']) && trim((string)$match['body'][0]) !== '') {
            return trim((string)$match['body'][0]);
        }
        if ($kind === 'script_tag') {
            $attrs = isset($match['attrs']) && is_array($match['attrs']) ? (string)$match['attrs'][0] : '';
            if (preg_match('~\bsrc\s*=\s*([\'\"])(?P<src>[^\'\"]+)\1~i', $attrs, $srcMatch) === 1) {
                return trim((string)$srcMatch['src']);
            }
            return 'inline script in payment/checkout template';
        }
        if ($kind === 'custom_payment_js') {
            return $relative;
        }

        return null;
    }

    private function checkoutRawCardCollectionFindings(string $file, string $content): array
    {
        $relative = $this->relativeFile($file);
        $extension = strtolower(pathinfo($file, PATHINFO_EXTENSION));
        $searchable = $this->maskSourceComments($content, $extension);
        if (!$this->hasCheckoutRawCardContext($relative, $searchable)) {
            return [];
        }

        $findings = [];
        foreach ($this->paymentMethodScopeFindings($file, $content) as $finding) {
            $window = $this->codeWindow($searchable, max(0, (int)($finding['offset'] ?? 0)), 1800);
            if ($this->hasCheckoutRawCardContext($relative, $window)) {
                unset($finding['offset']);
                $findings[] = $finding;
            }
        }

        return $this->dedupeFindings($findings);
    }

    private function hasCheckoutRawCardContext(string $relative, string $text): bool
    {
        return preg_match('~(?:checkout|onepage|payment|billing|Magento_Checkout|checkout_index_index|payment-method|payment_method|placeOrder|setPaymentInformation|savePaymentInformation|card|creditcard|cvv|cvc)~i', $relative . "\n" . $text) === 1;
    }

    private function paymentMethodScopeFindings(string $file, string $content): array
    {
        $extension = strtolower(pathinfo($file, PATHINFO_EXTENSION));
        $relative = $this->relativeFile($file);
        $searchable = $this->maskSourceComments($content, $extension);
        if (!$this->hasPaymentScopeContext($relative, $searchable)) {
            return [];
        }

        $findings = [];
        $patterns = [
            'direct_post' => '~\b(?:direct[_ -]?post|raw[_ -]?card|onsite[_ -]?card|manual[_ -]?card)\b~i',
            'raw_card_form_field' => '~<(?P<tag>input|select|textarea|field)\b[^>]*(?:\b(?:name|id|data-bind|ko-value|data-validate)\s*=\s*([\'\"])(?P<field>[^\'\"]*(?:cc[_-]?(?:num|number)|card[_-]?number|credit[_-]?card[_-]?number|cvv|cvc|cid)[^\'\"]*)\2)[^>]*>~i',
            'php_raw_card_request' => '~(?:->\s*(?:getParam|getPost|getPostValue|getData)\s*\(|\$_(?:POST|REQUEST)\s*\[)\s*[\'\"](?P<field>[^\'\"]*(?:cc[_-]?(?:num|number)|card[_-]?number|credit[_-]?card[_-]?number|cvv|cvc|cid)[^\'\"]*)[\'\"]~i',
            'js_raw_card_capture' => '~(?:querySelector|getElementById|\$\s*\(|document\.forms?|\.val\s*\(|\.value\b)[^;\n]{0,220}(?P<field>\b(?:cc[_-]?(?:num|number)|card[_-]?number|cardNumber|creditCardNumber|cvv|cvc|cid)\b)~i',
            'js_raw_card_config' => '~\b(?:dataScope|name|id|field|component|value)\s*:\s*([\'\"])(?P<field>[^\'\"]*(?:cc[_-]?(?:num|number)|card[_-]?number|cardNumber|creditCardNumber|cvv|cvc|cid)[^\'\"]*)\1~i',
            'xml_raw_card_config' => '~<item\b[^>]*\bname\s*=\s*([\'\"])(?P<field>[^\'\"]*(?:cc[_-]?(?:num|number)|card[_-]?number|cvv|cvc|cid)[^\'\"]*)\1[^>]*>~i',
            'php_additional_data_raw_card' => '~(?:getAdditionalInformation|getData|setAdditionalInformation|setData)\s*\(\s*([\'\"])(?P<field>[^\'\"]*(?:cc[_-]?(?:num|number)|card[_-]?number|credit[_-]?card[_-]?number|cvv|cvc|cid)[^\'\"]*)\1~i',
            'ajax_raw_card_submit' => '~(?P<field>\b(?:cc[_-]?(?:num|number)|card[_-]?number|cardNumber|creditCardNumber|cvv|cvc|cid)\b)[\s\S]{0,360}\b(?:fetch|XMLHttpRequest|\.ajax|mage/storage|storage\.post|post\s*\()\b~i',
        ];

        foreach ($patterns as $kind => $regex) {
            if (preg_match_all($regex, $searchable, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) < 1) {
                continue;
            }

            foreach ($matches as $match) {
                $offset = (int)$match[0][1];
                $window = $this->codeWindow($searchable, $offset, 1800);
                $field = isset($match['field']) && is_array($match['field']) ? (string)$match['field'][0] : $kind;

                if ($kind !== 'direct_post' && !$this->looksLikeRawPaymentField($field)) {
                    continue;
                }
                if ($this->isSafeHostedPaymentScopeContext($window) && !in_array($kind, ['raw_card_form_field', 'php_raw_card_request', 'php_additional_data_raw_card'], true)) {
                    continue;
                }
                if (!$this->hasPaymentScopeContext($relative, $window)) {
                    continue;
                }

                $evidence = $this->matchEvidence($file, $content, $kind, $offset);
                $evidence['kind'] = $kind;
                $evidence['field'] = $field;
                $evidence['offset'] = $offset;
                $findings[] = $evidence;
            }
        }

        return $this->dedupeFindings($findings);
    }

    private function hasPaymentScopeContext(string $relative, string $text): bool
    {
        return preg_match('~(?:checkout|payment|billing|card|creditcard|gateway|directpost|paypal|braintree|stripe|adyen|authorizenet|authorize|klarna|vault|hosted[_ -]?field|iframe|tokeni[sz]e)~i', $relative . "\n" . $text) === 1;
    }

    private function looksLikeRawPaymentField(string $field): bool
    {
        $normalized = strtolower(str_replace(['-', '.', '/', ':', '[', ']'], '_', trim($field)));
        if (preg_match('~(?:last4|last_four|token|nonce|vault|masked|brand|type|expiry|exp_month|exp_year|cardholder|holder|name)~i', $normalized) === 1) {
            return false;
        }

        return preg_match('~(?:^|_)(?:cc_(?:num|number)|card_number|credit_card_number|cvv|cvc|cid|cardnumber|creditcardnumber)(?:_|$)~i', $normalized) === 1;
    }

    private function isSafeHostedPaymentScopeContext(string $window): bool
    {
        return preg_match('~\b(?:hosted[_ -]?fields?|iframe|redirect|checkout\.com|stripe\.elements|elements\s*\(|createToken|confirmCardPayment|payment_method_nonce|paymentMethodNonce|tokeni[sz]e|braintree\.hostedFields|hostedFields\.create|paypal\.Buttons|AdyenCheckout|encryptedCardNumber|encryptedSecurityCode|klarna|vault[_ -]?token|payment[_ -]?token)\b~i', $window) === 1;
    }

    private function cardholderDataFileFindings(string $file, string $content): array
    {
        $extension = strtolower(pathinfo($file, PATHINFO_EXTENSION));
        $findings = [];

        foreach ($this->cardholderFilePanFindings($file, $content) as $finding) {
            $findings[] = $finding;
        }

        foreach ($this->cardholderFileSensitiveFieldFindings($file, $content, $extension) as $finding) {
            $findings[] = $finding;
        }

        return $this->dedupeFindings($findings);
    }

    private function cardholderFilePanFindings(string $file, string $content): array
    {
        $findings = [];
        $seen = [];
        if (preg_match_all('~(?<!\d)(?:\d[ -]?){13,19}(?!\d)~', $content, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) < 1) {
            return [];
        }

        foreach ($matches as $match) {
            $raw = (string)$match[0][0];
            $digits = preg_replace('~\D+~', '', $raw) ?? '';
            if (!$this->isLuhnValidPan($digits)) {
                continue;
            }

            $offset = (int)$match[0][1];
            $window = $this->codeWindow($content, $offset, 220);

            $fingerprint = substr($digits, 0, 6) . ':' . substr($digits, -4);
            if (isset($seen[$fingerprint])) {
                continue;
            }
            $seen[$fingerprint] = true;

            $evidence = $this->matchEvidence($file, $content, 'pan', $offset);
            $evidence['kind'] = 'pan';
            $evidence['snippet'] = '[REDACTED: payment data]';
            $evidence['field'] = 'Luhn-valid PAN-like value ending ' . substr($digits, -4);
            $findings[] = $evidence;
        }

        return $findings;
    }

    private function cardholderFileSensitiveFieldFindings(string $file, string $content, string $extension): array
    {
        $findings = [];
        $patterns = [
            'cvv' => '~(?P<field>\b(?:cvv|cvc|cid|card[_ -]?security[_ -]?code)\b)\s*(?:=|:|,|;|\t|=>)\s*[\'\"]?(?P<value>\d{3,4})\b~i',
            'track_data' => '~(?P<field>\b(?:track\s*[12]|track_[12]|magnetic[_ -]?stripe)\b)\s*(?:=|:|,|;|\t|=>)?\s*(?P<value>[^\r\n]{0,160})~i',
        ];

        foreach ($patterns as $kind => $regex) {
            if (preg_match_all($regex, $content, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) < 1) {
                continue;
            }

            foreach ($matches as $match) {
                $field = (string)$match['field'][0];
                $value = isset($match['value']) && is_array($match['value']) ? trim((string)$match['value'][0]) : '';
                $offset = (int)$match['field'][1];
                $window = $this->codeWindow($content, $offset, 260);

                if ($kind === 'track_data' && !$this->looksLikeTrackDataValue($value, $window)) {
                    continue;
                }
                if ($kind === 'cvv' && $extension === 'xml' && preg_match('~<field\b[^>]*\bid\s*=~i', $window) === 1) {
                    continue;
                }

                $evidence = $this->matchEvidence($file, $content, $kind, $offset);
                $evidence['kind'] = $kind;
                $evidence['snippet'] = '[REDACTED: payment data]';
                $evidence['field'] = $field;
                $evidence['offset'] = $offset;
                $findings[] = $evidence;
            }
        }

        return $findings;
    }

    private function isLuhnValidPan(string $digits): bool
    {
        $length = strlen($digits);
        if ($length < 13 || $length > 19) {
            return false;
        }
        if (preg_match('~^(\d)\1+$~', $digits) === 1) {
            return false;
        }
        if (preg_match('~^(?:0+|1+|9+)$~', $digits) === 1) {
            return false;
        }

        $sum = 0;
        $alternate = false;
        for ($i = $length - 1; $i >= 0; $i--) {
            $n = (int)$digits[$i];
            if ($alternate) {
                $n *= 2;
                if ($n > 9) {
                    $n -= 9;
                }
            }
            $sum += $n;
            $alternate = !$alternate;
        }

        return $sum % 10 === 0;
    }

    private function isMaskedOrTokenizedCardFileContext(string $window): bool
    {
        return preg_match('~(?:\*{4,}|x{4,}|X{4,}|last\s*4|last4|cc_last4|ending[_ -]?in|token|nonce|vault|payment[_ -]?token|customer[_ -]?profile|payment[_ -]?profile|reference|masked|redacted|fingerprint)~i', $window) === 1;
    }

    private function looksLikeTrackDataValue(string $value, string $window): bool
    {
        return preg_match('~(?:%?B\d{13,19}\^|;\d{13,19}=|\b(?:track\s*[12]|track_[12]|magnetic[_ -]?stripe)\b\s*(?:=|:|,|;|\t|=>)\s*[^\r\n]{6,})~i', $value . "\n" . $window) === 1;
    }

    private function cardholderDataStorageFindings(string $file, string $content): array
    {
        $extension = strtolower(pathinfo($file, PATHINFO_EXTENSION));
        $relative = $this->relativeFile($file);
        $searchable = $this->maskSourceComments($content, $extension);
        $findings = [];

        foreach ($this->cardholderSchemaColumnFindings($file, $content, $searchable, $extension) as $finding) {
            $findings[] = $finding;
        }

        foreach ($this->cardholderSqlStorageFindings($file, $content, $searchable, $extension) as $finding) {
            $findings[] = $finding;
        }

        if (in_array($extension, ['php', 'json', 'xml'], true)) {
            foreach ($this->cardholderCodeStorageFindings($file, $content, $searchable, $relative, $extension) as $finding) {
                $findings[] = $finding;
            }
        }

        return $this->dedupeFindings($findings);
    }

    private function cardholderSchemaColumnFindings(string $file, string $content, string $searchable, string $extension): array
    {
        $findings = [];
        $relative = $this->relativeFile($file);
        if ($extension !== 'xml' || preg_match('~(?:db_schema\.xml|schema\.xml)$~i', $relative) !== 1) {
            return [];
        }

        if (preg_match_all('~<column\b(?P<attrs>[^>]*)>~is', $searchable, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) < 1) {
            return [];
        }

        foreach ($matches as $match) {
            $attrs = (string)$match['attrs'][0];
            $field = $this->xmlAttributeValue($attrs, 'name') ?? $this->xmlAttributeValue($attrs, 'xsi:type') ?? 'column';
            if (!$this->isRawCardholderField($field)) {
                continue;
            }

            $offset = (int)$match[0][1];
            $evidence = $this->matchEvidence($file, $content, 'schema_column', $offset);
            $evidence['kind'] = 'schema_column';
            $evidence['field'] = $field;
            $findings[] = $evidence;
        }

        return $findings;
    }

    private function cardholderSqlStorageFindings(string $file, string $content, string $searchable, string $extension): array
    {
        $findings = [];
        $sqlContext = $extension === 'sql' || preg_match('~\b(?:CREATE|ALTER)\s+TABLE|\b(?:INSERT\s+INTO|UPDATE)\b~i', $searchable) === 1;
        if (!$sqlContext) {
            return [];
        }

        $patterns = [
            'sql_schema_column' => '~\b(?:CREATE|ALTER)\s+TABLE\b[^;]{0,1800}(?P<field>\b[A-Za-z0-9_]*(?:cc[_-]?(?:num|number)|card[_-]?number|credit[_-]?card[_-]?number|primary[_-]?account[_-]?number|pan|cvv|cvc|cid|pin[_-]?block|track[12]|magnetic[_-]?stripe)[A-Za-z0-9_]*\b)~is',
            'sql_dml_write' => '~\b(?:INSERT\s+INTO|UPDATE)\b[^;]{0,1600}(?P<field>\b[A-Za-z0-9_]*(?:cc[_-]?(?:num|number)|card[_-]?number|credit[_-]?card[_-]?number|primary[_-]?account[_-]?number|pan|cvv|cvc|cid|pin[_-]?block|track[12]|magnetic[_-]?stripe)[A-Za-z0-9_]*\b)~is',
        ];

        foreach ($patterns as $kind => $regex) {
            if (preg_match_all($regex, $searchable, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) < 1) {
                continue;
            }

            foreach ($matches as $match) {
                $field = (string)$match['field'][0];
                if (!$this->isRawCardholderField($field)) {
                    continue;
                }

                $offset = (int)$match['field'][1];
                $evidence = $this->matchEvidence($file, $content, $kind, $offset);
                $evidence['kind'] = $kind;
                $evidence['field'] = $field;
                $evidence['offset'] = $offset;
                $findings[] = $evidence;
            }
        }

        return $findings;
    }

    private function cardholderCodeStorageFindings(string $file, string $content, string $searchable, string $relative, string $extension): array
    {
        $findings = [];
        $rawFieldRegex = '(?P<field>\b[A-Za-z0-9_./-]*(?:cc[_-]?(?:num|number)|card[_-]?number|credit[_-]?card[_-]?number|primary[_-]?account[_-]?number|pan|cvv|cvc|cid|pin[_-]?block|track[12]|magnetic[_-]?stripe)[A-Za-z0-9_./-]*\b)';
        if (preg_match_all('~' . $rawFieldRegex . '~i', $searchable, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) < 1) {
            return [];
        }

        foreach ($matches as $match) {
            $field = (string)$match['field'][0];
            if (!$this->isRawCardholderField($field)) {
                continue;
            }

            $offset = (int)$match['field'][1];
            $window = $this->codeWindow($searchable, $offset, 1400);
            $kind = $this->cardholderStorageKind($window, $relative, $extension);
            if ($kind === null) {
                continue;
            }

            $evidence = $this->matchEvidence($file, $content, $kind, $offset);
            $evidence['kind'] = $kind;
            $evidence['field'] = $field;
            $findings[] = $evidence;
        }

        return $findings;
    }

    private function cardholderStorageKind(string $window, string $relative, string $extension): ?string
    {
        $isSetupFile = preg_match('~(?:^|/)(?:Setup|Patch|DataPatch|SchemaPatch)/|(?:Install|Upgrade)(?:Schema|Data)\.php$~i', $relative) === 1;
        $hasDbWrite = preg_match('~(?:->\s*(?:insert|insertMultiple|update|save|saveData|setData|addData|setValue|saveConfig)\s*\(|\b(?:INSERT\s+INTO|UPDATE|CREATE\s+TABLE|ALTER\s+TABLE)\b|\b(?:SchemaSetupInterface|ModuleDataSetupInterface|addColumn|modifyColumn|newTable|createTable)\b)~i', $window) === 1;
        $hasTableContext = preg_match('~\b(?:table|db_schema|schema|resource|collection|connection|core_config_data|sales_order_payment|quote_payment|payment|transaction)\b~i', $window) === 1;

        if ($extension === 'json' && preg_match('~\b(?:schema|table|column|field|migration|fixture|seed)\b~i', $relative . "\n" . $window) === 1) {
            return 'json_storage_field';
        }

        if ($isSetupFile && ($hasDbWrite || $hasTableContext)) {
            return 'setup_storage_write';
        }

        if ($hasDbWrite && $hasTableContext) {
            return 'db_storage_write';
        }

        return null;
    }

    private function isRawCardholderField(string $field): bool
    {
        $normalized = strtolower(str_replace(['-', '.', '/', ':', '[', ']'], '_', trim($field)));
        if ($normalized === '') {
            return false;
        }

        if (preg_match('~(?:last4|last_four|token|nonce|vault|profile|customer_profile|payment_profile|transaction|trans_id|reference|masked|mask|hash|fingerprint|bin|brand|type|expiry|exp_month|exp_year)~i', $normalized) === 1) {
            return false;
        }

        if (preg_match('~(?:span|panel|company|companion|campaign|expand|panels|japan|metadata|shipping|billing|giftcard|cardholder_name|card_name)~i', $normalized) === 1) {
            return false;
        }

        return preg_match('~^(?:cc_(?:num|number)|card_number|credit_card_number|primary_account_number|pan|cvv|cvc|cid|pin_block|track1|track2|magnetic_stripe)$~i', $normalized) === 1
            || preg_match('~(?:^|_)(?:cc_(?:num|number)|card_number|credit_card_number|primary_account_number|pan|cvv|cvc|cid|pin_block|track1|track2|magnetic_stripe)(?:_|$)~i', $normalized) === 1;
    }

    private function xmlAttributeValue(string $attrs, string $name): ?string
    {
        if (preg_match('~\b' . preg_quote($name, '~') . '\s*=\s*([\'\"])(?P<value>[^\'\"]*)\1~i', $attrs, $match) === 1) {
            return (string)$match['value'];
        }

        return null;
    }
}
