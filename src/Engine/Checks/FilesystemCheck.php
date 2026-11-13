<?php

declare(strict_types=1);

namespace Magebean\Engine\Checks;

use Magebean\Engine\Context;
use Magebean\Engine\Collectors\CollectorSet;

final class FilesystemCheck
{
    private Context $ctx;
    public function __construct(Context $ctx, private ?CollectorSet $collectors = null)
    {
        $this->ctx = $ctx;
        $this->collectors ??= new CollectorSet();
    }

    public function noWorldWritable(array $args): array
    {
        if (!empty($args['strict_observation'])) return $this->strictNoWorldWritable($args);
        $root = $this->ctx->abs($args['path'] ?? '.');
        $max = max(1, (int)($args['max_results'] ?? 50));
        if (!file_exists($root)) {
            return [false, "Path not found: {$root}"];
        }

        $offenders = [];
        $truncated = false;
        $flags = \FilesystemIterator::SKIP_DOTS;

        $this->collectWorldWritableOffender($root, $offenders, $max, $truncated);

        $rii = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($root, $flags),
            \RecursiveIteratorIterator::SELF_FIRST
        );
        foreach ($rii as $file) {
            if ($file->isLink()) {
                continue;
            }

            $this->collectWorldWritableOffender($file->getPathname(), $offenders, $max, $truncated);
            if ($truncated) {
                break;
            }
        }

        if ($offenders) {
            $shown = count($offenders);
            $msg = "World-writable entries found ({$shown}" . ($truncated ? '+' : '') . " shown): "
                . implode(', ', array_map(
                    static fn(array $o): string => $o['path'] . ' [' . $o['type'] . ':' . $o['mode'] . ']',
                    $offenders
                ));
            if ($truncated) {
                $msg .= ". More offenders exist; increase max_results to inspect additional entries.";
            }
            return [false, $msg, $offenders];
        }
        return [true, "No world-writable files or directories detected under {$root}"];
    }

    public function fileModeMax(array $args): array
    {
        $rel = $args['file'] ?? 'app/etc/env.php';
        $file = $this->ctx->abs($rel);
        $allowedModeRaw = (string)($args['max_octal'] ?? '0640');
        $allowedMode = octdec($allowedModeRaw);
        if (!is_file($file)) return !empty($args['strict_observation']) ? [null, '[UNKNOWN] Required file is unavailable: ' . $rel] : [false, "{$rel} is missing"];
        $stat = @fileperms($file);
        if ($stat === false) return [null, '[UNKNOWN] Unable to read file permission mode: ' . $rel];
        $perm = $stat & 0777;

        $extraBits = $perm & (~$allowedMode & 0777);
        $evidence = [
            'path' => $file,
            'observed_mode' => sprintf('%o', $perm),
            'allowed_mode' => sprintf('%o', $allowedMode),
        ];
        if ($extraBits !== 0) {
            $evidence['excess_bits'] = sprintf('%o', $extraBits);
            return [
                false,
                "{$rel} mode " . sprintf('%o', $perm) . " is more permissive than allowed policy " . sprintf('%o', $allowedMode),
                $evidence,
            ];
        }

        return [
            true,
            "{$rel} mode " . sprintf('%o', $perm) . " complies with allowed policy " . sprintf('%o', $allowedMode),
            $evidence,
        ];
    }

    public function fileOwnerGroupMatches(array $args): array
    {
        $rel = (string)($args['file'] ?? '');
        if ($rel === '') {
            return [false, 'file_owner_group_matches requires file'];
        }

        $file = $this->ctx->abs($rel);
        if (!is_file($file)) {
            return !empty($args['strict_observation']) ? [null, '[UNKNOWN] ' . "{$rel} is missing"] : [false, "{$rel} is missing"];
        }

        $ownerRefRel = (string)($args['owner_reference'] ?? '.');
        $groupRefRel = (string)($args['group_reference'] ?? $ownerRefRel);
        $ownerRef = $this->ctx->abs($ownerRefRel);
        $groupRef = $this->ctx->abs($groupRefRel);

        if (!file_exists($ownerRef)) {
            return !empty($args['strict_observation']) ? [null, '[UNKNOWN] ' . "Owner reference not found: {$ownerRefRel}"] : [false, "Owner reference not found: {$ownerRefRel}"];
        }
        if (!file_exists($groupRef)) {
            return !empty($args['strict_observation']) ? [null, '[UNKNOWN] ' . "Group reference not found: {$groupRefRel}"] : [false, "Group reference not found: {$groupRefRel}"];
        }

        $owner = @fileowner($file);
        $group = @filegroup($file);
        $expectedOwner = @fileowner($ownerRef);
        $expectedGroup = @filegroup($groupRef);
        if ($owner === false || $group === false || $expectedOwner === false || $expectedGroup === false) {
            return !empty($args['strict_observation']) ? [null, '[UNKNOWN] ' . "Could not stat ownership for {$rel}"] : [false, "Could not stat ownership for {$rel}"];
        }

        $evidence = [
            'path' => $file,
            'owner' => $this->formatIdentity((int)$owner, true),
            'group' => $this->formatIdentity((int)$group, false),
            'owner_reference' => $ownerRef,
            'expected_owner' => $this->formatIdentity((int)$expectedOwner, true),
            'group_reference' => $groupRef,
            'expected_group' => $this->formatIdentity((int)$expectedGroup, false),
        ];

        if ($owner !== $expectedOwner || $group !== $expectedGroup) {
            return [
                false,
                "{$rel} ownership does not match expected application owner/group",
                $evidence,
            ];
        }

        return [
            true,
            "{$rel} ownership matches expected application owner/group",
            $evidence,
        ];
    }

    public function webrootHygiene(array $args): array
    {
        $webroot = $this->ctx->abs($args['webroot'] ?? 'pub');
        $bad = $args['forbidden'] ?? ['.git', '.env', '.env.local', '*.bak', '*.old', '*~'];
        if (!is_dir($webroot)) return [true, "Webroot {$webroot} not found (skipped)"];
        $matches = [];
        $max = max(1, (int)($args['max_results'] ?? 50));
        $truncated = false;

        $this->collectForbiddenWebrootArtifact($webroot, $bad, $matches, $max, $truncated);

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($webroot, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::SELF_FIRST,
            \RecursiveIteratorIterator::CATCH_GET_CHILD
        );
        foreach ($iterator as $file) {
            $path = $file->getPathname();
            $this->collectForbiddenWebrootArtifact($path, $bad, $matches, $max, $truncated);
            if ($file->isLink()) {
                continue;
            }
            if ($truncated) {
                break;
            }
        }
        if ($matches) {
            $shown = count($matches);
            $msg = "Forbidden artifacts found in webroot ({$shown}" . ($truncated ? '+' : '') . " shown): "
                . implode(', ', array_map(
                    static fn(array $match): string => $match['path'] . ' [' . $match['type'] . ', pattern:' . $match['pattern'] . ']',
                    $matches
                ));
            if ($truncated) {
                $msg .= ". More matches exist; increase max_results to inspect additional entries.";
            }
            return [false, $msg, $matches];
        }
        return [true, "Webroot clean: {$webroot}"];
    }

    public function logsReportsNotInWebroot(array $args): array
    {
        if (!empty($args['strict_scope'])) return $this->strictLogsReportsPlacement($args);
        $webrootRel = (string)($args['webroot'] ?? 'pub');
        $webroot = $this->ctx->abs($webrootRel);
        if (!is_dir($webroot)) {
            return [null, '[UNKNOWN] Webroot not found for log/report exposure check', ['webroot' => $webrootRel]];
        }

        $forbidden = $args['forbidden_paths'] ?? ['var/log', 'var/report'];
        if (!is_array($forbidden)) {
            $forbidden = ['var/log', 'var/report'];
        }
        $forbidden = array_values(array_filter(array_map(
            static fn(mixed $value): string => trim(str_replace('\\', '/', (string)$value), '/'),
            $forbidden
        )));

        $projectTargets = [];
        foreach ($forbidden as $relative) {
            $target = realpath($this->ctx->abs($relative));
            if ($target !== false) {
                $projectTargets[$relative] = $target;
            }
        }

        $matches = [];
        $max = max(1, (int)($args['max_results'] ?? 50));
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($webroot, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::SELF_FIRST,
            \RecursiveIteratorIterator::CATCH_GET_CHILD
        );

        foreach ($iterator as $file) {
            $path = $file->getPathname();
            $relative = str_replace('\\', '/', ltrim(substr($path, strlen(rtrim($webroot, DIRECTORY_SEPARATOR))), DIRECTORY_SEPARATOR));
            foreach ($forbidden as $pattern) {
                if ($relative === $pattern || str_starts_with($relative, $pattern . '/')) {
                    $matches[] = [
                        'path' => $path,
                        'relative_path' => $relative,
                        'pattern' => $pattern,
                        'type' => is_link($path) ? 'link' : (is_dir($path) ? 'dir' : 'file'),
                    ];
                    break;
                }
            }

            if (is_link($path)) {
                $target = realpath($path);
                if ($target !== false) {
                    foreach ($projectTargets as $pattern => $projectTarget) {
                        if ($target === $projectTarget || str_starts_with($target, rtrim($projectTarget, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR)) {
                            $matches[] = [
                                'path' => $path,
                                'relative_path' => $relative,
                                'pattern' => $pattern,
                                'type' => 'link',
                                'target' => $target,
                            ];
                            break;
                        }
                    }
                }
            }

            if (count($matches) >= $max) {
                break;
            }
        }

        if ($matches !== []) {
            return [false, 'Log/report paths are exposed under webroot', ['webroot' => $webrootRel, 'matches' => $matches]];
        }

        return [true, 'Log and report paths are not exposed under webroot', ['webroot' => $webrootRel, 'checked' => $forbidden]];
    }

    /** Every directory and leaf consumes the same bounded traversal budget. Links are never followed. */
    private function strictPathInventory(array $roots, array $args = []): array
    {
        $limit = max(1, min(1000000, (int)($args['max_entries'] ?? 200000)));
        $deadline = microtime(true) + max(1, min(30000, (int)($args['max_duration_ms'] ?? 10000))) / 1000;
        $paths = []; $gaps = []; $pending = $roots; $seen = [];
        while ($pending !== []) {
            $this->collectors->session->checkpoint();
            if (count($paths) >= $limit || microtime(true) > $deadline) { $gaps[] = 'traversal_budget_exceeded'; break; }
            $path = array_pop($pending);
            if (isset($seen[$path])) continue;
            $seen[$path] = true;
            if (!file_exists($path) && !is_link($path)) { $gaps[] = $path; continue; }
            $paths[] = $path;
            if (is_link($path)) {
                if (realpath($path) === false || is_dir($path)) $gaps[] = $path;
                continue;
            }
            if (!is_dir($path)) continue;
            try { $children = new \FilesystemIterator($path, \FilesystemIterator::SKIP_DOTS); }
            catch (\UnexpectedValueException) { $gaps[] = $path; continue; }
            foreach ($children as $child) {
                $this->collectors->session->checkpoint();
                if (count($pending)+count($paths) >= $limit || microtime(true) > $deadline) { $gaps[] = 'traversal_budget_exceeded'; break; }
                $pending[] = $child->getPathname();
            }
        }
        return [$paths, array_values(array_unique($gaps))];
    }

    private function strictCodeModes(array $args): array
    {
        $dirs = array_values($args['dirs'] ?? ['app', 'vendor', 'lib']);
        if ($dirs === []) return [null, '[UNKNOWN] No code directories configured'];
        [$paths, $gaps] = $this->strictPathInventory(array_map(fn($dir) => $this->ctx->abs((string)$dir), $dirs));
        $offenders = [];
        foreach ($paths as $path) {
            $mode = @fileperms($path);
            if ($mode === false) { $gaps[] = $path; continue; }
            if (($mode & 0222) !== 0) $offenders[] = ['path' => $path, 'mode' => sprintf('%04o', $mode & 0777)];
        }
        $evidence = ['dirs' => $dirs, 'paths_checked' => count($paths), 'coverage_gaps' => array_values(array_unique($gaps)), 'offenders' => array_slice($offenders, 0, max(1, (int)($args['max_results'] ?? 50)))];
        if ($offenders !== []) return [false, 'Code paths have Unix permission write bits enabled', $evidence];
        if ($gaps !== []) return [null, '[UNKNOWN] Cannot inspect all configured code path permissions', $evidence];
        return [true, 'Inspected code paths have no Unix permission write bits', $evidence];
    }

    private function strictLogsReportsPlacement(array $args): array
    {
        $relative = (string)($args['webroot'] ?? 'pub');
        $webroot = realpath($this->ctx->abs($relative));
        if ($webroot === false || !is_dir($webroot)) return [null, '[UNKNOWN] Configured webroot is unavailable', ['webroot' => $relative]];
        $forbidden = array_values($args['forbidden_paths'] ?? ['var/log', 'var/report']);
        if ($forbidden === []) return [null, '[UNKNOWN] No forbidden log/report paths configured'];
        [$paths, $gaps] = $this->strictPathInventory([$webroot], $args);
        $targets = []; $matches = [];
        foreach ($forbidden as $item) {
            $target = realpath($this->ctx->abs((string)$item));
            if ($target !== false) $targets[] = $target;
        }
        foreach ($paths as $path) {
            $under = str_replace('\\', '/', ltrim(substr($path, strlen($webroot)), DIRECTORY_SEPARATOR));
            foreach ($forbidden as $item) {
                $item = trim(str_replace('\\', '/', (string)$item), '/');
                if ($under === $item || str_starts_with($under, $item . '/')) $matches[] = ['path' => $path, 'reason' => 'forbidden_relative_path'];
            }
            if (is_link($path)) {
                $target = realpath($path);
                if ($target !== false) foreach ($targets as $forbiddenTarget) if ($target === $forbiddenTarget || str_starts_with($target, $forbiddenTarget . DIRECTORY_SEPARATOR)) $matches[] = ['path' => $path, 'reason' => 'forbidden_symlink_target'];
            }
        }
        $evidence = ['webroot' => $relative, 'paths_checked' => count($paths), 'coverage_gaps' => $gaps, 'matches' => $matches];
        if ($matches !== []) return [false, 'Configured log/report paths are physically present or linked in webroot', $evidence];
        if ($gaps !== []) return [null, '[UNKNOWN] Cannot inspect all configured webroot paths and links', $evidence];
        return [true, 'Configured log/report paths are absent from inspected webroot', $evidence];
    }
    public function logRotationConfigured(array $args): array
    {
        $fileRel = (string)($args['file'] ?? 'devops/logrotate.conf');
        $this->collectors->session->checkpoint();
        $content = @file_get_contents($this->ctx->abs($fileRel), false, null, 0, 1048577);
        if ($content === false) return [null, '[UNKNOWN] Log rotation configuration unavailable', ['file' => $fileRel]];
        if (strlen($content) > 1048576) return [null, '[UNKNOWN] Log rotation configuration exceeds the bounded input size', ['file' => $fileRel]];
        $defaults = ['rotate' => null, 'compress' => false, 'cadence' => null]; $blocks = []; $state = $defaults;
        $target = ''; $inside = false; $script = false; $pending = ''; $unsupported = false;
        foreach (preg_split('~\r?\n~', $content) ?: [] as $raw) {
            $line = trim(preg_replace('~\s+#.*$~', '', $raw) ?? '');
            if ($line === '' || str_starts_with($line, '#')) continue;
            if ($script) { if ($line === 'endscript') $script = false; continue; }
            if (preg_match('~^(?:pre|post|first|last)action\b|^(?:pre|post)rotate\b~', $line)) { $script = true; continue; }
            if (!$inside && str_contains($line, '{')) {
                [$head, $tail] = explode('{', $line, 2);
                $target = trim($pending . ' ' . $head); $pending = ''; $state = $defaults; $inside = true;
                if (trim($tail) !== '') $unsupported = true;
                continue;
            }
            if ($line === '}' && $inside) {
                $blocks[] = ['target' => $target] + $state; $inside = false; continue;
            }
            if (preg_match('~^rotate\s+(-?\d+)\s*$~', $line, $match)) {
                if ($inside) $state['rotate'] = (int)$match[1]; else $defaults['rotate'] = (int)$match[1];
            } elseif (preg_match('~^(?:hourly|daily|weekly|monthly|yearly)$~D', $line)
                || preg_match('~^(?:size|minsize|maxsize)\s+[1-9][0-9]*[kKmMgGtT]?\s*$~D', $line)) {
                if ($inside) $state['cadence'] = $line; else $defaults['cadence'] = $line;
            } elseif ($line === 'compress' || $line === 'nocompress') {
                if ($inside) $state['compress'] = $line === 'compress'; else $defaults['compress'] = $line === 'compress';
            } elseif (preg_match('~^include\b~', $line)) {
                $unsupported = true;
            } elseif (!$inside && (str_contains($line, '/') || str_contains($line, '.log') || $line === '{')) {
                $pending .= ' ' . $line;
            }
        }
        $evidence = ['file' => $fileRel, 'blocks' => $blocks];
        if ($inside || $script || $unsupported) return [null, '[UNKNOWN] Logrotate syntax or includes require effective configuration review', $evidence];
        $relevant = array_filter($blocks, static fn(array $block): bool => preg_match('~(?:var/log/|\.log(?:["\s*]|$))~', $block['target']) === 1);
        if ($relevant === []) return [null, '[UNKNOWN] No supported log target block was observed in the supplied candidate configuration', $evidence];
        foreach ($relevant as $block) if ($block['rotate'] !== null && $block['rotate'] <= 0) return [false, 'Log target declares nonpositive retention: ' . $block['target'], $evidence];
        foreach ($relevant as $block) if (!$block['compress']) return [false, 'Log target lacks enabled compression in the supplied candidate declaration: ' . $block['target'], $evidence];
        foreach ($relevant as $block) if ($block['cadence'] === null || $block['rotate'] === null) return [null, '[UNKNOWN] Log cadence or retention may be inherited from external configuration; no complete candidate declaration was observed', $evidence];
        return [true, 'Each collected candidate log stanza declares supported cadence, positive retention and compression', $evidence + ['scope' => 'Supplied candidate configuration only; installation and host execution are not established']];
    }

    public function codeDirsReadonly(array $args): array
    {
        if (!empty($args['strict_scope'])) return $this->strictCodeModes($args);
        $dirs = $args['dirs'] ?? ['app', 'vendor', 'lib'];
        $max = max(1, (int)($args['max_results'] ?? 50));
        $off = [];
        $truncated = false;
        foreach ($dirs as $rel) {
            $path = $this->ctx->abs($rel);
            if (!is_dir($path)) continue;

            $this->collectWritableCodePath($path, $off, $max, $truncated);
            if ($truncated) {
                break;
            }

            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($path, \FilesystemIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::SELF_FIRST,
                \RecursiveIteratorIterator::CATCH_GET_CHILD
            );
            foreach ($iterator as $file) {
                $this->collectWritableCodePath($file->getPathname(), $off, $max, $truncated);
                if ($truncated) {
                    break 2;
                }
            }
        }

        if ($off) {
            $shown = count($off);
            $msg = "Writable code paths found ({$shown}" . ($truncated ? '+' : '') . " shown): "
                . implode(', ', array_map(
                    static fn(array $entry): string => $entry['path'] . ' [' . $entry['type'] . ':' . $entry['mode'] . ']'
                        . (isset($entry['target']) ? ' -> ' . $entry['target'] : ''),
                    $off
                ));
            if ($truncated) {
                $msg .= ". More offenders exist; increase max_results to inspect additional entries.";
            }
            return [false, $msg, $off];
        }

        return [true, "Code directories are read-only"];
    }

    public function noDirectoryListing(array $args): array
    {
        $pub = $this->ctx->abs($args['webroot'] ?? 'pub');
        $ht = $pub . '/.htaccess';
        if (is_file($ht)) {
            $c = (string)file_get_contents($ht);
            if (stripos($c, 'Options -Indexes') !== false) return [true, "Apache: Options -Indexes present"];
        }
        $ng = $this->ctx->abs('nginx.conf');
        if (is_file($ng)) {
            $c = (string)file_get_contents($ng);
            if (stripos($c, 'autoindex off') !== false) return [true, "Nginx: autoindex off"];
        }
        return [false, "Could not verify directory listing disabled"];
    }

    public function fsExists(array $args): array
    {
        $rel = (string)($args['path'] ?? '');
        if ($rel === '') return [false, 'fs_exists requires path'];
        $abs = $this->ctx->abs($rel);
        $ok  = file_exists($abs);
        return [$ok, ($ok ? 'Exists: ' : 'Not found: ') . $rel];
    }

    public function securityMitigationsDocumented(array $args): array
    {
        $rel = trim((string)($args['path'] ?? 'SECURITY.md'));
        if ($rel === '') {
            return [false, 'security_mitigations_documented requires path'];
        }

        $abs = $this->ctx->abs($rel);
        $evidence = [
            'path' => $rel,
            'exists' => is_file($abs),
            'mitigation_documented' => false,
            'lifecycle_documented' => false,
        ];
        if (!is_file($abs)) {
            return [false, 'Mitigation document not found: ' . $rel, $evidence];
        }

        $content = @file_get_contents($abs);
        if (!is_string($content)) {
            return [null, '[UNKNOWN] Unable to read mitigation document: ' . $rel, $evidence];
        }

        $content = trim($content);
        if ($content === '') {
            return [false, 'Mitigation document is empty: ' . $rel, $evidence];
        }

        $hasMitigation = (bool)preg_match(
            '/\b(mitigation|workaround|temporary\s+(?:control|measure)|compensating\s+control|hotfix)\b/i',
            $content
        );
        $hasLifecycle = (bool)preg_match(
            '/\b(rollback|revert|expiry|expiration|review\s+date|valid\s+until|permanent\s+fix|upgrade\s+to|remove\s+after)\b/i',
            $content
        );
        $evidence['mitigation_documented'] = $hasMitigation;
        $evidence['lifecycle_documented'] = $hasLifecycle;

        $missing = [];
        if (!$hasMitigation) {
            $missing[] = 'mitigation/workaround action';
        }
        if (!$hasLifecycle) {
            $missing[] = 'rollback, review/expiry, or permanent-fix plan';
        }
        if ($missing !== []) {
            return [
                false,
                'Incomplete mitigation documentation in ' . $rel . ': missing ' . implode(' and ', $missing),
                $evidence,
            ];
        }

        return [
            null,
            '[UNKNOWN] Mitigation and lifecycle keywords were observed, but free text does not establish an implemented mitigation or accepted remediation plan; supply structured scoped records for machine validation',
            $evidence + ['scope' => 'Keyword presence only; semantic acceptance is unresolved'],
        ];
    }

    public function pciManualEvidenceDocumented(array $args): array
    {
        $paths = $args['paths'] ?? ['.magebean/pci-evidence.md', 'docs/pci-evidence.md', 'SECURITY.md'];
        if (!is_array($paths)) {
            $paths = ['.magebean/pci-evidence.md', 'docs/pci-evidence.md', 'SECURITY.md'];
        }
        $requiredTopics = $args['required_topics'] ?? ['payment_scope', 'saq_notes', 'access_review', 'incident_response', 'vendor_responsibilities'];
        if (!is_array($requiredTopics)) {
            $requiredTopics = ['payment_scope', 'saq_notes', 'access_review', 'incident_response', 'vendor_responsibilities'];
        }

        $topicPatterns = [
            'payment_scope' => '~\b(?:payment\s+scope|cardholder\s+data\s+environment|\bCDE\b|checkout|payment\s+flow|card\s+data|scope\s+(?:summary|boundary))\b~i',
            'saq_notes' => '~\\b(?:SAQ|self[- ]assessment|merchant\\s+level|attestation|AOC|ROC)\\b~i',
            'access_review' => '~\b(?:access\s+review|user\s+access|privilege\s+review|admin\s+access|MFA|2FA|least\s+privilege|quarterly\s+review)\b~i',
            'incident_response' => '~\b(?:incident\s+response|breach|forensic|containment|escalation|security\s+incident|IR\s+plan|response\s+plan)\b~i',
            'vendor_responsibilities' => '~\b(?:vendor\s+responsibilit(?:y|ies)|service\s+provider|third[- ]party|shared\s+responsibilit(?:y|ies)|processor|gateway|contract|SLA)\b~i',
        ];

        $required = array_values(array_filter(array_map(static fn(mixed $topic): string => (string)$topic, $requiredTopics)));
        $found = array_fill_keys($required, false);
        $documents = [];
        $readable = 0;

        foreach ($paths as $rel) {
            $rel = (string)$rel;
            $abs = $this->ctx->abs($rel);
            $entry = [
                'path' => $rel,
                'exists' => is_file($abs),
                'readable' => false,
                'topics' => [],
            ];
            if (!is_file($abs)) {
                $documents[] = $entry;
                continue;
            }

            $content = @file_get_contents($abs);
            if (!is_string($content)) {
                $documents[] = $entry;
                continue;
            }

            $entry['readable'] = true;
            $readable++;
            $text = trim($content);
            foreach ($required as $topic) {
                $pattern = $topicPatterns[$topic] ?? null;
                $ok = $pattern !== null && $text !== '' && preg_match($pattern, $text) === 1;
                $entry['topics'][$topic] = $ok;
                if ($ok) {
                    $found[$topic] = true;
                }
            }
            $documents[] = $entry;
        }

        $missing = array_values(array_filter($required, static fn(string $topic): bool => empty($found[$topic])));
        $evidence = [
            'paths' => array_values(array_map('strval', $paths)),
            'documents' => $documents,
            'required_topics' => $required,
            'found_topics' => array_keys(array_filter($found)),
            'missing_topics' => $missing,
        ];

        if ($readable === 0) {
            return [false, 'No readable PCI evidence checklist found', $evidence];
        }

        if ($missing !== []) {
            $labels = [
                'payment_scope' => 'payment scope',
                'saq_notes' => 'SAQ/PCI notes',
                'access_review' => 'access review',
                'incident_response' => 'incident response',
                'vendor_responsibilities' => 'vendor responsibilities',
            ];
            $missingLabels = array_map(static fn(string $topic): string => $labels[$topic] ?? $topic, $missing);
            return [
                false,
                'PCI evidence checklist is incomplete: missing ' . implode(', ', $missingLabels),
                $evidence,
            ];
        }

        return [true, 'PCI evidence checklist covers required manual evidence topics', $evidence];
    }
    public function diCompiled(array $args): array
    {
        $metadataRel = (string)($args['metadata_path'] ?? 'generated/metadata');
        $codeRel = (string)($args['code_path'] ?? 'generated/code');
        $minMetadataFiles = max(1, (int)($args['min_metadata_php_files'] ?? 1));
        $minCodeFiles = max(1, (int)($args['min_code_php_files'] ?? 1));

        $metadataAbs = $this->ctx->abs($metadataRel);
        $codeAbs = $this->ctx->abs($codeRel);
        $evidence = [
            'metadata_path' => $metadataRel,
            'code_path' => $codeRel,
            'metadata_present' => is_dir($metadataAbs),
            'code_present' => is_dir($codeAbs),
            'metadata_php_files' => 0,
            'code_php_files' => 0,
        ];

        $missing = [];
        if (!is_dir($metadataAbs)) {
            $missing[] = $metadataRel;
        }
        if (!is_dir($codeAbs)) {
            $missing[] = $codeRel;
        }
        if ($missing !== []) {
            return [false, 'Compiled DI directories missing: ' . implode(', ', $missing), $evidence];
        }

        $metadataCount = $this->countPhpFiles($metadataAbs, $args);
        $codeCount = $this->countPhpFiles($codeAbs, $args);
        if ($metadataCount === null || $codeCount === null) {
            return [null, '[UNKNOWN] Unable to inspect generated DI directories', $evidence];
        }

        $evidence['metadata_php_files'] = $metadataCount;
        $evidence['code_php_files'] = $codeCount;
        $evidence['min_metadata_php_files'] = $minMetadataFiles;
        $evidence['min_code_php_files'] = $minCodeFiles;

        $failures = [];
        if ($metadataCount < $minMetadataFiles) {
            $failures[] = "{$metadataRel} has {$metadataCount} PHP files";
        }
        if ($codeCount < $minCodeFiles) {
            $failures[] = "{$codeRel} has {$codeCount} PHP files";
        }
        if ($failures !== []) {
            return [false, 'Compiled DI output is incomplete: ' . implode('; ', $failures), $evidence];
        }

        return [true, 'Generated DI metadata and code contain compiled PHP output', $evidence];
    }

    public function staticContentDeployed(array $args): array
    {
        if (!empty($args['strict_scope'])) return $this->strictStaticContentPresence($args);
        $staticRel = (string)($args['static_path'] ?? 'pub/static');
        $preprocessedRel = (string)($args['preprocessed_path'] ?? 'var/view_preprocessed');
        $minStaticFiles = max(1, (int)($args['min_static_files'] ?? 1));
        $minPreprocessedFiles = max(1, (int)($args['min_preprocessed_files'] ?? 1));

        $staticAbs = $this->ctx->abs($staticRel);
        $preprocessedAbs = $this->ctx->abs($preprocessedRel);
        $evidence = [
            'static_path' => $staticRel,
            'preprocessed_path' => $preprocessedRel,
            'static_present' => is_dir($staticAbs),
            'preprocessed_present' => is_dir($preprocessedAbs),
            'static_files' => 0,
            'preprocessed_files' => 0,
        ];

        $missing = [];
        if (!is_dir($staticAbs)) {
            $missing[] = $staticRel;
        }
        if (!is_dir($preprocessedAbs)) {
            $missing[] = $preprocessedRel;
        }
        if ($missing !== []) {
            return [false, 'Static content directories missing: ' . implode(', ', $missing), $evidence];
        }

        $staticCount = $this->countFiles($staticAbs, ['.htaccess']);
        $preprocessedCount = $this->countFiles($preprocessedAbs, []);
        if ($staticCount === null || $preprocessedCount === null) {
            return [null, '[UNKNOWN] Unable to inspect static content directories', $evidence];
        }

        $evidence['static_files'] = $staticCount;
        $evidence['preprocessed_files'] = $preprocessedCount;
        $evidence['min_static_files'] = $minStaticFiles;
        $evidence['min_preprocessed_files'] = $minPreprocessedFiles;

        $failures = [];
        if ($staticCount < $minStaticFiles) {
            $failures[] = "{$staticRel} has {$staticCount} deployed files";
        }
        if ($preprocessedCount < $minPreprocessedFiles) {
            $failures[] = "{$preprocessedRel} has {$preprocessedCount} preprocessed files";
        }
        if ($failures !== []) {
            return [false, 'Static content output is incomplete: ' . implode('; ', $failures), $evidence];
        }

        return [true, 'Static content directories contain deployed output', $evidence];
    }


    private function strictStaticContentPresence(array $args): array
    {
        $rel = (string)($args['static_path'] ?? 'pub/static');
        $root = $this->ctx->abs($rel);
        if (!is_dir($root)) return [false, 'Published static directory is missing', ['path' => $rel]];
        [$paths, $gaps] = $this->strictPathInventory([$root], $args);
        $checked = []; $unknown = $gaps;
        foreach ($paths as $path) {
            $this->collectors->session->checkpoint();
            $relative = substr($path, strlen($root) + 1);
            if (!preg_match('~^(?:frontend|adminhtml)/.+\.(?:css|js|woff2?|ttf|svg|png|jpe?g|gif|webp)$~i', $relative)) continue;
            if (!is_file($path) || !is_readable($path)) { $unknown[] = $relative; continue; }
            if (filesize($path) > 0) $checked[] = $relative;
        }
        if ($checked !== []) return [true, 'Nonempty published frontend/admin static artifacts are present', ['path' => $rel, 'artifacts' => array_slice($checked, 0, 20), 'count' => count($checked), 'coverage_gaps' => $gaps]];
        if ($unknown !== []) return [null, '[UNKNOWN] Static artifact inventory is incomplete or cannot be read', ['coverage_gaps' => $unknown]];
        return [false, 'No nonempty published frontend/admin static artifacts found', ['path' => $rel]];
    }

    public function indexersReady(array $args): array
    {
        $rel = (string)($args['file'] ?? 'var/.indexer_status');
        $abs = $this->ctx->abs($rel);
        if (!is_file($abs)) {
            return [null, '[UNKNOWN] Indexer status file not found', ['file' => $rel]];
        }

        $content = @file_get_contents($abs);
        if ($content === false) {
            return [null, '[UNKNOWN] Unable to read indexer status file', ['file' => $rel]];
        }

        $statuses = [];
        foreach (preg_split("~\r?\n~", trim($content)) as $line) {
            $line = trim((string)$line);
            if ($line === '') {
                continue;
            }

            if (str_contains($line, ':')) {
                [$name, $status] = array_map('trim', explode(':', $line, 2));
            } else {
                $parts = preg_split('~\s+~', $line);
                $status = (string)array_pop($parts);
                $name = trim(implode(' ', $parts));
            }

            $normalizedStatus = strtoupper(str_replace([' ', '-'], '_', $status));
            $statuses[] = [
                'indexer' => $name !== '' ? $name : null,
                'status' => $status,
                'normalized_status' => $normalizedStatus,
                'ready' => $normalizedStatus === 'READY',
                'line' => $line,
            ];
        }

        if ($statuses === []) {
            return [null, '[UNKNOWN] Indexer status file is empty', ['file' => $rel]];
        }

        $failures = array_values(array_filter($statuses, static fn(array $entry): bool => empty($entry['ready'])));
        $evidence = ['file' => $rel, 'statuses' => $statuses];
        if ($failures !== []) {
            return [false, 'Some indexers are not READY', $evidence + ['failures' => $failures]];
        }

        return [true, 'All observed indexers are READY', $evidence];
    }

    public function mtimeMaxAge(array $args): array
    {
        $rel = (string)($args['file'] ?? '');
        $max = (int)($args['seconds'] ?? 0);
        if ($rel === '' || $max <= 0) return [false, 'fs_mtime_max_age requires file & seconds'];

        $abs = $this->ctx->abs($rel);
        if (!is_file($abs)) return [false, "$rel not found"];

        $mtime = @filemtime($abs);
        if ($mtime === false) return [false, "Cannot stat $rel"];
        $age = time() - $mtime;

        $ok = ($age <= $max);
        return [$ok, "mtime age {$age}s (max {$max}s) for $rel"];
    }

    private function countPhpFiles(string $root, array $args = []): ?int
    {
        [$paths, $gaps] = $this->strictPathInventory([$root], $args);
        $count = 0;
        foreach ($paths as $path) {
            $this->collectors->session->checkpoint();
            if (!is_file($path) || strtolower(pathinfo($path, PATHINFO_EXTENSION)) !== 'php') continue;
            if (!is_readable($path)) return null;
            ++$count;
        }
        return $gaps === [] ? $count : null;
    }

    private function countFiles(string $root, array $ignoredBasenames): ?int
    {
        try {
            $ignored = array_flip($ignoredBasenames);
            $count = 0;
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::LEAVES_ONLY,
                \RecursiveIteratorIterator::CATCH_GET_CHILD
            );
            foreach ($iterator as $file) {
                if (!$file->isFile()) {
                    continue;
                }
                if (isset($ignored[$file->getFilename()])) {
                    continue;
                }
                $count++;
            }
            return $count;
        } catch (\UnexpectedValueException) {
            return null;
        }
    }

    /** A concrete counterexample disproves the policy; incomplete traversal never proves it. */
    private function strictNoWorldWritable(array $args): array
    {
        $root = $this->ctx->abs($args['path'] ?? '.');
        [$paths, $inventoryGaps] = $this->strictPathInventory([$root], $args);
        $gaps = array_map(static fn(string $path):array => ['path'=>$path,'reason'=>'inventory_incomplete'], $inventoryGaps);
        $count = 0;
        foreach ($paths as $path) {
            $this->collectors->session->checkpoint();
            clearstatcache(true, $path);
            $stat = @lstat($path);
            if ($stat === false) { $gaps[] = ['path' => $path, 'reason' => 'stat_unavailable']; continue; }
            $type = $stat['mode'] & 0170000;
            if ($type === 0120000) { $gaps[] = ['path' => $path, 'reason' => 'symlink_target_not_assessed']; continue; }
            ++$count;
            if (($stat['mode'] & 0002) !== 0) return [false, 'World-writable entry found: ' . $path, ['path' => $path, 'mode' => sprintf('%o', $stat['mode'] & 0777), 'entries_assessed' => $count, 'coverage_gaps' => $gaps]];
        }
        if ($gaps !== []) return [null, '[UNKNOWN] Filesystem permission assessment is incomplete', ['entries_assessed' => $count, 'gaps' => $gaps]];
        return [true, 'No world-writable entries found in the fully traversed deployment path', ['entries_assessed' => $count, 'root' => $root]];
    }

    private function collectWorldWritableOffender(string $path, array &$offenders, int $max, bool &$truncated): void
    {
        if ($truncated || is_link($path)) {
            return;
        }

        $perm = @fileperms($path);
        if ($perm === false) {
            return;
        }

        $perm = $perm & 0777;
        if (($perm & 0002) !== 0002) {
            return;
        }

        if (count($offenders) >= $max) {
            $truncated = true;
            return;
        }

        $offenders[] = [
            'path' => $path,
            'mode' => sprintf('%o', $perm),
            'type' => is_dir($path) ? 'dir' : 'file',
        ];
    }

    private function formatIdentity(int $id, bool $user): string
    {
        $lookup = $user ? 'posix_getpwuid' : 'posix_getgrgid';
        if (function_exists($lookup)) {
            $info = $lookup($id);
            if (is_array($info) && isset($info['name']) && is_string($info['name']) && $info['name'] !== '') {
                return $info['name'] . " ({$id})";
            }
        }

        return (string)$id;
    }

    private function collectForbiddenWebrootArtifact(string $path, array $patterns, array &$matches, int $max, bool &$truncated): void
    {
        if ($truncated) {
            return;
        }

        $name = basename($path);
        $matchedPattern = null;
        foreach ($patterns as $pattern) {
            if ($this->matchesForbiddenArtifact($name, (string)$pattern)) {
                $matchedPattern = (string)$pattern;
                break;
            }
        }
        if ($matchedPattern === null) {
            return;
        }

        if (count($matches) >= $max) {
            $truncated = true;
            return;
        }

        $matches[] = [
            'path' => $path,
            'pattern' => $matchedPattern,
            'type' => is_link($path) ? 'link' : (is_dir($path) ? 'dir' : 'file'),
        ];
    }

    private function matchesForbiddenArtifact(string $name, string $pattern): bool
    {
        return fnmatch($pattern, $name, \FNM_PERIOD);
    }

    private function collectWritableCodePath(string $path, array &$offenders, int $max, bool &$truncated): void
    {
        if ($truncated) {
            return;
        }

        $statPath = $path;
        $target = null;
        if (is_link($path)) {
            $target = realpath($path);
            if ($target === false) {
                return;
            }
            $statPath = $target;
        }

        $perm = @fileperms($statPath);
        if ($perm === false) {
            return;
        }

        $perm = $perm & 0777;
        if (($perm & 0222) === 0) {
            return;
        }

        if (count($offenders) >= $max) {
            $truncated = true;
            return;
        }

        $entry = [
            'path' => $path,
            'mode' => sprintf('%o', $perm),
            'type' => is_link($path) ? 'link' : (is_dir($statPath) ? 'dir' : 'file'),
        ];
        if ($target !== null) {
            $entry['target'] = $target;
        }

        $offenders[] = $entry;
    }
}
