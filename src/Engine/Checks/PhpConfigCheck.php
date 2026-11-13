<?php

declare(strict_types=1);

namespace Magebean\Engine\Checks;

use Magebean\Engine\Context;
use Magebean\Engine\Collectors\CollectorSet;

final class PhpConfigCheck
{
    private Context $ctx;
    private CollectorSet $collectors;

    public function __construct(Context $ctx, ?CollectorSet $collectors = null)
    {
        $this->ctx = $ctx;
        $this->collectors = $collectors ?? new CollectorSet();
    }

    // Router
    public function dispatch(string $name, array $args): array
    {
        return match ($name) {
            'php_array_exists'          => $this->arrayExists($args),
            'php_array_eq'              => $this->arrayEquals($args),
            'php_array_neq'             => $this->arrayNotEquals($args),
            'php_array_numeric_compare' => $this->arrayNumericCompare($args),
            'php_array_absent'          => $this->arrayAbsent($args),
            default => [false, 'Unknown PhpConfigCheck: ' . $name],
        };
    }

    private function loadArray(string $relativeFile): array
    {
        $file = $this->ctx->abs($relativeFile);
        // Keep the legacy include scope and evaluation frequency for executable configs.
        return $this->collectors->php->load($file, $relativeFile, function () use ($file, $relativeFile): mixed {
            return @include $file;
        });
    }

    /** Restored deployment predicates read literal arrays without executing application code. */
    private function loadStaticArray(string $relativeFile): array
    {
        $inventory=(new \Magebean\Engine\Collectors\BoundedSourceInventory($this->collectors->session))->collect($this->ctx,[
            'paths'=>[$relativeFile], 'include_ext'=>['php'], 'max_files'=>1, 'verify_stable'=>true,
        ]);
        if (!$inventory['complete'] || count($inventory['files'])!==1) return ['__ERROR__'=>'Static configuration scope unavailable: '.$relativeFile];
        return $this->collectors->php->literal($this->ctx->abs($relativeFile))
            ?? ['__ERROR__'=>'Static configuration scope unavailable or unsupported: '.$relativeFile];
    }

    private function getByDotPath(array $arr, string $path, mixed $default = null): mixed
    {
        if ($path === '' || $path === '.') return $arr;
        $keys = explode('.', $path);
        $cur = $arr;
        foreach ($keys as $k) {
            if (!is_array($cur) || !array_key_exists($k, $cur)) {
                return $default;
            }
            $cur = $cur[$k];
        }
        return $cur;
    }

    private function arrayExists(array $args): array
    {
        $file = (string)($args['file'] ?? '');
        $path = (string)($args['path'] ?? '');
        if ($file === '' || $path === '') return [false, 'php_array_exists requires file & path'];

        $arr = $this->loadArray($file);
        if (isset($arr['__ERROR__'])) return [false, $arr['__ERROR__']];

        $val = $this->getByDotPath($arr, $path, '__NOT_FOUND__');
        if ($val === '__NOT_FOUND__') return [false, "Path '$path' not found in $file"];
        return [true, "Found '$path' in $file"];
    }

    private function arrayEquals(array $args): array
    {
        $file = (string)($args['file'] ?? '');
        $path = (string)($args['path'] ?? '');
        $expect = $args['equals'] ?? null;
        if ($file === '' || $path === '') return [false, 'php_array_eq requires file & path'];

        $arr = $this->loadArray($file);
        if (isset($arr['__ERROR__'])) return [false, $arr['__ERROR__']];

        $val = $this->getByDotPath($arr, $path, '__NOT_FOUND__');
        if ($val === '__NOT_FOUND__') return [false, "Path '$path' not found in $file"];

        $ok = ($val == $expect); // lỏng hơn === để tiện số/chuỗi
        return [$ok, "Value at '$path' == " . var_export($expect, true) . " (actual: " . var_export($val, true) . ")"];
    }

    private function arrayNotEquals(array $args): array
    {
        $file = (string)($args['file'] ?? '');
        $path = (string)($args['path'] ?? '');
        $not = $args['not_equals'] ?? null;
        if ($file === '' || $path === '') return [false, 'php_array_neq requires file & path'];

        $arr = $this->loadArray($file);
        if (isset($arr['__ERROR__'])) return [false, $arr['__ERROR__']];

        $val = $this->getByDotPath($arr, $path, '__NOT_FOUND__');
        if ($val === '__NOT_FOUND__') return [false, "Path '$path' not found in $file"];

        $ok = ($val != $not);
        return [$ok, "Value at '$path' != " . var_export($not, true) . " (actual: " . var_export($val, true) . ")"];
    }

    private function arrayNumericCompare(array $args): array
    {
        $file = (string)($args['file'] ?? '');
        $path = (string)($args['path'] ?? '');
        $op   = (string)($args['op'] ?? '');
        $rhs  = $args['value'] ?? null;

        if ($file === '' || $path === '' || $op === '' || $rhs === null) {
            return [false, 'php_array_numeric_compare requires file, path, op, value'];
        }

        $arr = $this->loadArray($file);
        if (isset($arr['__ERROR__'])) return [false, $arr['__ERROR__']];

        $val = $this->getByDotPath($arr, $path, '__NOT_FOUND__');
        if ($val === '__NOT_FOUND__') return [false, "Path '$path' not found in $file"];
        if (!is_numeric($val)) return [false, "Value at '$path' is not numeric (actual: " . var_export($val, true) . ")"];

        $lv = (float)$val;
        $rv = (float)$rhs;
        $ok = match ($op) {
            '<=' => $lv <= $rv,
            '<'  => $lv <  $rv,
            '>=' => $lv >= $rv,
            '>'  => $lv >  $rv,
            '==' => $lv == $rv,
            '!=' => $lv != $rv,
            default => false
        };
        return [$ok, "Numeric compare: $lv $op $rv at '$path'"];
    }

    public function keySearch(array $args): array
    {
        $file = (string)($args['file'] ?? '');
        $keyRe = (string)($args['key_regex'] ?? '');
        $minFound = (int)($args['min_found'] ?? 1);

        if ($file === '' || $keyRe === '') {
            return [false, 'php_array_key_search requires file & key_regex'];
        }
        $arr = $this->loadArray($file);
        if (isset($arr['__ERROR__'])) return [false, $arr['__ERROR__']];

        // duyệt đệ qui và đếm số key khớp regex
        $count = $this->countKeysByRegex($arr, $keyRe);
        $ok = ($count >= $minFound);
        return [$ok, "php_array_key_search '$keyRe' matches=$count (min $minFound) in $file"];
    }

    public function xdebugDisabled(array $args): array
    {
        $files = $args['files'] ?? null;
        if ($files === null && isset($args['file'])) {
            $files = [$args['file']];
        }
        if (!is_array($files)) {
            $files = ['php.ini', '.user.ini'];
        }

        $checked = [];
        $findings = [];
        foreach ($files as $file) {
            if (!is_scalar($file)) {
                continue;
            }
            $relative = (string)$file;
            $path = $this->ctx->abs($relative);
            if (!is_file($path)) {
                $checked[] = ['file' => $relative, 'present' => false];
                continue;
            }

            $content = $this->collectors->files->read($path);
            if ($content === false) {
                $checked[] = ['file' => $relative, 'present' => true, 'readable' => false];
                continue;
            }

            $checked[] = ['file' => $relative, 'present' => true, 'readable' => true];
            foreach (preg_split("~\r?\n~", $content) as $idx => $line) {
                $trimmed = trim((string)$line);
                if ($trimmed === '' || str_starts_with($trimmed, ';') || str_starts_with($trimmed, '#')) {
                    continue;
                }

                if (preg_match('~^\s*zend_extension\s*=.*xdebug(?:\.so|\.dll)?\b~i', $line) === 1) {
                    $findings[] = ['file' => $relative, 'line' => $idx + 1, 'directive' => 'zend_extension', 'text' => trim((string)$line)];
                    continue;
                }

                if (preg_match('~^\s*xdebug\.mode\s*=\s*(?P<mode>[^;\s#]+)~i', $line, $m) === 1) {
                    $mode = strtolower(trim((string)$m['mode'], "\"'"));
                    if ($mode !== '' && $mode !== 'off') {
                        $findings[] = ['file' => $relative, 'line' => $idx + 1, 'directive' => 'xdebug.mode', 'mode' => $mode, 'text' => trim((string)$line)];
                    }
                }
            }
        }

        if ($findings !== []) {
            return [false, 'Xdebug configuration detected', ['checked' => $checked, 'findings' => $findings]];
        }

        $readable = array_values(array_filter($checked, static fn(array $entry): bool => !empty($entry['readable'])));
        if ($readable === []) {
            return [null, '[UNKNOWN] No readable PHP ini files found for Xdebug check', ['checked' => $checked]];
        }

        return [true, 'No Xdebug configuration detected in PHP ini files', ['checked' => $checked]];
    }

    public function displayErrorsDisabled(array $args): array
    {
        $files = $args['files'] ?? (isset($args['file']) ? [$args['file']] : ['php.ini', '.user.ini']);
        if (!is_array($files) || $files === []) return [null, '[UNKNOWN] PHP ini paths are required'];
        $observed = []; $gaps = []; $enabled = [];
        foreach ($files as $file) {
            if (!is_string($file) || $file === '') { $gaps[] = 'invalid_ini_path'; continue; }
            if (!file_exists($this->ctx->abs($file)) && !is_link($this->ctx->abs($file))) continue;
            $inventory = (new \Magebean\Engine\Collectors\BoundedSourceInventory($this->collectors->session))->collect($this->ctx, [
                'paths'=>[$file], 'include_ext'=>['ini'], 'max_files'=>1, 'verify_stable'=>true,
            ]);
            if (!$inventory['complete'] || count($inventory['files']) !== 1) { $gaps[] = $file; continue; }
            $ini = @parse_ini_string($inventory['files'][0]['content'], false, INI_SCANNER_RAW);
            if (!is_array($ini) || !array_key_exists('display_errors', $ini) || !is_string($ini['display_errors'])) { $gaps[] = $file; continue; }
            $value = strtolower(trim($ini['display_errors']));
            $off = in_array($value, ['off','0','false','no','none',''], true);
            $on = in_array($value, ['on','1','true','yes','stdout','stderr'], true);
            $observed[] = ['file'=>$file, 'value'=>$value, 'scope'=>'last display_errors declaration in this supplied ini file'];
            if ($on) $enabled[] = $file;
            elseif (!$off) $gaps[] = $file;
        }
        $evidence = ['observed'=>$observed, 'collection_gaps'=>$gaps, 'scope'=>'declared ini values; web worker effective runtime is not assessed'];
        if ($enabled !== []) return [false, 'display_errors is enabled in supplied PHP ini configuration', $evidence];
        if ($gaps !== [] || $observed === []) return [null, '[UNKNOWN] display_errors declaration is missing, malformed or unreadable', $evidence];
        return [true, 'display_errors is explicitly disabled in inspected PHP ini files', $evidence];
    }

    public function templateHintsDisabled(array $args): array
    {
        $paths = $args['paths'] ?? (isset($args['path']) ? [$args['path']] : ['system.default.dev/debug/template_hints']);
        return $this->declaredFlagsDisabled((string)($args['file'] ?? 'app/etc/env.php'), $paths);
    }

    public function devDebugConfigDisabled(array $args): array
    {
        return $this->declaredFlagsDisabled((string)($args['file'] ?? 'app/etc/env.php'), $args['paths'] ?? [
            'system.default.dev/translate_inline/active', 'system.default.dev/debug/template_hints_storefront',
        ]);
    }

    private function declaredFlagsDisabled(string $file, mixed $paths): array
    {
        if (!is_array($paths) || $paths === []) return [null, '[UNKNOWN] Explicit nonempty debug setting paths are required'];
        $arr = $this->loadStaticArray($file);
        if (isset($arr['__ERROR__'])) return [null, '[UNKNOWN] '.$arr['__ERROR__'], ['file'=>$file]];
        $observed = []; $failures = []; $gaps = [];
        foreach ($paths as $path) {
            if (!is_string($path) || $path === '') { $gaps[] = 'invalid_setting_path'; continue; }
            $value = $this->configurationValue($arr, $path);
            if (is_string($value) && $value !== '__NOT_FOUND__') $value = strtolower(trim($value));
            $enabled = in_array($value, [true, 1, '1', 'on', 'yes', 'true'], true);
            $disabled = in_array($value, [false, 0, '0', 'off', 'no', 'false'], true);
            $observed[] = ['path'=>$path, 'present'=>$value!=='__NOT_FOUND__', 'recognized'=>$enabled||$disabled, 'enabled'=>$enabled];
            if ($enabled) $failures[] = $path;
            elseif (!$disabled) $gaps[] = $path;
        }
        $evidence = ['file'=>$file, 'scope'=>'named literal project declaration paths only', 'observed'=>$observed, 'collection_gaps'=>$gaps];
        if ($failures !== []) return [false, 'Declared project debug flag is enabled: '.implode(', ', $failures), $evidence];
        if ($gaps !== []) return [null, '[UNKNOWN] Named debug declarations are missing or malformed', $evidence];
        return [true, 'All named project debug declarations are explicitly disabled', $evidence];
    }

    public function thirdPartyDebugDisabled(array $args): array
    {
        $files = $args['files'] ?? null;
        if ($files === null && isset($args['file'])) {
            $files = [$args['file']];
        }
        if (!is_array($files)) {
            $files = ['app/etc/env.php', 'app/etc/config.php'];
        }

        $keyRegex = (string)($args['key_regex'] ?? '~(?:^|_)(?:debug|debug_logging|verbose|logging|log_enabled|enable_log|enable_logs)(?:_|$)~i');
        $contextRegex = (string)($args['context_regex'] ?? '~(?:dev[./]debug|payment|paypal|braintree|authorizenet|authorize|stripe|adyen|klarna|shipping|carrier|gateway|webhook|integration|connector|api|service|third[_-]?party)~i');

        $checked = [];
        $findings = [];
        foreach ($files as $file) {
            if (!is_scalar($file)) {
                continue;
            }

            $relative = (string)$file;
            $path = $this->ctx->abs($relative);
            if (!is_file($path)) {
                $checked[] = ['file' => $relative, 'present' => false];
                continue;
            }

            $arr = $this->loadStaticArray($relative);
            if (isset($arr['__ERROR__'])) {
                $checked[] = ['file' => $relative, 'present' => true, 'readable' => false, 'error' => $arr['__ERROR__']];
                continue;
            }

            $checked[] = ['file' => $relative, 'present' => true, 'readable' => true];
            foreach ($this->thirdPartyDebugFindings($arr, [], $relative, $keyRegex, $contextRegex) as $finding) {
                $findings[] = $finding;
            }
        }

        $evidence = ['checked' => $checked, 'findings' => $findings];
        if ($findings !== []) {
            $lines = ['Third-party debug/verbose settings enabled:'];
            foreach ($findings as $finding) {
                $lines[] = sprintf(
                    '    - %s:%s = %s',
                    $finding['file'],
                    $finding['path'],
                    var_export($finding['value'], true)
                );
            }

            return [false, implode("\n", $lines), $evidence];
        }

        $readable = array_values(array_filter($checked, static fn(array $entry): bool => !empty($entry['readable'])));
        if ($readable === []) {
            return [null, '[UNKNOWN] No readable Magento PHP config files found for third-party debug check', $evidence];
        }

        return [true, 'Third-party debug/verbose settings are disabled or absent', $evidence];
    }
    public function fullPageCacheConfigured(array $args): array
    {
        $file = (string)($args['file'] ?? 'app/etc/env.php');
        $path = (string)($args['path'] ?? 'system.default.system/full_page_cache/caching_application');
        $allowed = $args['allowed_values'] ?? [$args['equals'] ?? 2];
        if (!is_array($allowed)) {
            $allowed = [$allowed];
        }

        $arr = $this->loadArray($file);
        if (isset($arr['__ERROR__'])) {
            return [null, '[UNKNOWN] ' . $arr['__ERROR__'], ['file' => $file, 'path' => $path]];
        }

        $normPath = str_replace('/', '.', $path);
        $value = $this->configurationValue($arr, $path);
        if ($value === '__NOT_FOUND__') {
            return [null, "[UNKNOWN] Path '{$path}' not found in {$file}", [
                'file' => $file,
                'path' => $path,
                'normalized_path' => $normPath,
                'allowed_values' => $allowed,
            ]];
        }

        $ok = false;
        foreach ($allowed as $expected) {
            if ($value == $expected) {
                $ok = true;
                break;
            }
        }

        $evidence = [
            'file' => $file,
            'path' => $path,
            'normalized_path' => $normPath,
            'observed' => $value,
            'allowed_values' => $allowed,
        ];

        if ($ok) {
            return [true, 'Full Page Cache is configured for the required backend', $evidence];
        }

        return [false, 'Full Page Cache backend is not configured as required', $evidence];
    }

    public function cacheBackendConfigured(array $args): array
    {
        $file = (string)($args['file'] ?? 'app/etc/env.php');
        $paths = $args['paths'] ?? [
            'cache.frontend.default.backend',
            'cache.frontend.page_cache.backend',
            'cache.backend',
            'system.default.system/full_page_cache/caching_application',
        ];
        if (!is_array($paths)) {
            $paths = ['cache.frontend.default.backend', 'cache.backend'];
        }

        $arr = $this->loadArray($file);
        if (isset($arr['__ERROR__'])) {
            return [null, '[UNKNOWN] ' . $arr['__ERROR__'], ['file' => $file, 'paths' => $paths]];
        }

        $observed = [];
        foreach ($paths as $path) {
            if (!is_scalar($path)) {
                continue;
            }
            $rawPath = (string)$path;
            $normPath = str_replace('/', '.', $rawPath);
            $value = $this->configurationValue($arr, $rawPath);
            if ($value === '__NOT_FOUND__') {
                $observed[] = ['path' => $rawPath, 'normalized_path' => $normPath, 'present' => false, 'ok' => false];
                continue;
            }

            $ok = $this->isProductionCacheBackend($normPath, $value);
            $observed[] = [
                'path' => $rawPath,
                'normalized_path' => $normPath,
                'present' => true,
                'value' => $value,
                'ok' => $ok,
            ];
        }

        $matches = array_values(array_filter($observed, static fn(array $entry): bool => !empty($entry['ok'])));
        $present = array_values(array_filter($observed, static fn(array $entry): bool => !empty($entry['present'])));
        $evidence = ['file' => $file, 'observed' => $observed];

        if ($matches !== []) {
            return [true, 'Production cache backend signal found', $evidence + ['matches' => $matches]];
        }
        if ($present === []) {
            return [false, 'No production cache backend configuration found; Magento defaults to file cache', $evidence];
        }

        return [false, 'Cache backend is not configured for Redis or Varnish', $evidence + ['failures' => $present]];
    }

    public function sessionStorageHardened(array $args): array
    {
        $file = (string)($args['file'] ?? 'app/etc/env.php');
        $savePath = (string)($args['save_path'] ?? 'session.save');
        $passwordPath = (string)($args['password_path'] ?? 'session.redis.password');

        $arr = $this->loadArray($file);
        if (isset($arr['__ERROR__'])) {
            return [null, '[UNKNOWN] ' . $arr['__ERROR__'], [
                'file' => $file,
                'save_path' => $savePath,
                'password_path' => $passwordPath,
            ]];
        }

        $saveNorm = str_replace('/', '.', $savePath);
        $passwordNorm = str_replace('/', '.', $passwordPath);
        $save = $this->getByDotPath($arr, $saveNorm, '__NOT_FOUND__');
        $password = $this->getByDotPath($arr, $passwordNorm, '__NOT_FOUND__');

        $saveOk = is_string($save) && strtolower(trim($save)) === 'redis';
        $passwordPresent = $password !== '__NOT_FOUND__';
        $passwordOk = $passwordPresent && is_string($password) && $password !== '';

        $evidence = [
            'file' => $file,
            'session_save' => [
                'path' => $savePath,
                'normalized_path' => $saveNorm,
                'present' => $save !== '__NOT_FOUND__',
                'value' => $save !== '__NOT_FOUND__' ? $save : null,
                'ok' => $saveOk,
            ],
            'redis_password' => [
                'path' => $passwordPath,
                'normalized_path' => $passwordNorm,
                'present' => $passwordPresent,
                'ok' => $passwordOk,
            ],
        ];

        $failures = [];
        if (!$saveOk) {
            $failures[] = $save === '__NOT_FOUND__'
                ? 'session.save is missing'
                : "session.save is '" . (string)$save . "'";
        }
        if (!$passwordOk) {
            $failures[] = $passwordPresent ? 'session.redis.password is empty or disabled' : 'session.redis.password is missing';
        }
        if ($failures !== []) {
            return [false, 'Session storage is not hardened', $evidence + ['failures' => $failures]];
        }

        return [true, 'Sessions are stored in Redis with authentication configured', $evidence];
    }

    public function noFileCacheBackend(array $args): array
    {
        $file = (string)($args['file'] ?? 'app/etc/env.php');
        $paths = $args['paths'] ?? [
            'cache.frontend.default.backend',
            'cache.frontend.page_cache.backend',
            'cache.backend',
        ];
        if (!is_array($paths)) {
            $paths = ['cache.frontend.default.backend', 'cache.backend'];
        }

        $arr = $this->loadStaticArray($file);
        if (isset($arr['__ERROR__'])) {
            return [null, '[UNKNOWN] ' . $arr['__ERROR__'], ['file' => $file, 'paths' => $paths]];
        }

        $observed = [];
        foreach ($paths as $path) {
            if (!is_scalar($path)) {
                continue;
            }
            $rawPath = (string)$path;
            $normPath = str_replace('/', '.', $rawPath);
            $value = $this->configurationValue($arr, $rawPath);
            if ($value === '__NOT_FOUND__') {
                $observed[] = ['path' => $rawPath, 'normalized_path' => $normPath, 'present' => false, 'file_backend' => false];
                continue;
            }

            $observed[] = [
                'path' => $rawPath,
                'normalized_path' => $normPath,
                'present' => true,
                'value' => $value,
                'file_backend' => $this->isFileCacheBackend($value),
            ];
        }

        $fileBackends = array_values(array_filter($observed, static fn(array $entry): bool => !empty($entry['file_backend'])));
        $present = array_values(array_filter($observed, static fn(array $entry): bool => !empty($entry['present'])));
        $evidence = ['file' => $file, 'observed' => $observed];

        if ($fileBackends !== []) {
            return [false, 'File-based cache backend detected', $evidence + ['failures' => $fileBackends]];
        }
        $shared = $this->getByDotPath($arr, 'cache.backend', '__NOT_FOUND__');
        foreach (['default', 'page_cache'] as $frontend) {
            $backend = $this->getByDotPath($arr, 'cache.frontend.' . $frontend . '.backend', $shared);
            if ($backend === '__NOT_FOUND__') {
                // Varnish replaces the page cache frontend only when explicitly declared.
                $varnish = $this->configurationValue($arr, 'system.default.system/full_page_cache/caching_application');
                if ($frontend === 'page_cache' && in_array($varnish, [2, '2'], true)) continue;
                return [false, 'Cache frontend ' . $frontend . ' has no declared backend; Magento falls back to file storage', $evidence + ['frontend' => $frontend]];
            }
            if (!is_string($backend) || trim($backend) === '') return [null, '[UNKNOWN] Cache backend declaration is malformed; inspect cache.frontend.' . $frontend . '.backend in ' . $file, $evidence];
            if (!$this->isProductionCacheBackend('cache.frontend.' . $frontend . '.backend', $backend)) return [false, 'Cache frontend ' . $frontend . ' does not declare a supported Redis backend', $evidence + ['frontend' => $frontend]];
        }
        if ($present === []) {
            return [false, 'No cache backend configuration found; Magento defaults to file cache', $evidence];
        }

        return [true, 'No file-based cache backend detected', $evidence];
    }

    private function thirdPartyDebugFindings(array $arr, array $path, string $file, string $keyRegex, string $contextRegex): array
    {
        $findings = [];
        foreach ($arr as $key => $value) {
            $keyString = (string)$key;
            $nextPath = [...$path, $keyString];
            if (is_array($value)) {
                array_push($findings, ...$this->thirdPartyDebugFindings($value, $nextPath, $file, $keyRegex, $contextRegex));
                continue;
            }

            $dotPath = implode('.', $nextPath);
            if (@preg_match($keyRegex, $keyString) !== 1 && @preg_match($keyRegex, $dotPath) !== 1) {
                continue;
            }
            if (@preg_match($contextRegex, $dotPath) !== 1) {
                continue;
            }
            if (!$this->configTruthy($value)) {
                continue;
            }

            $findings[] = [
                'file' => $file,
                'path' => $dotPath,
                'key' => $keyString,
                'value' => $value,
            ];
        }

        return $findings;
    }

    private function configTruthy(mixed $value): bool
    {
        if ($value === true) {
            return true;
        }
        if (is_int($value) || is_float($value)) {
            return (float)$value !== 0.0;
        }
        $normalized = strtolower(trim((string)$value));
        return in_array($normalized, ['1', 'true', 'on', 'yes', 'enabled', 'enable'], true);
    }
    private function countKeysByRegex(array $arr, string $keyRe): int
    {
        $cnt = 0;
        foreach ($arr as $k => $v) {
            if (@preg_match('/' . $keyRe . '/i', (string)$k)) {
                $cnt++;
            }
            if (is_array($v)) {
                $cnt += $this->countKeysByRegex($v, $keyRe);
            }
        }
        return $cnt;
    }

    private function configFalsey(mixed $value): bool
    {
        if ($value === false || $value === null) {
            return true;
        }
        if (is_int($value) || is_float($value)) {
            return (float)$value === 0.0;
        }
        $normalized = strtolower(trim((string)$value));
        return in_array($normalized, ['', '0', 'false', 'off', 'no', 'null'], true);
    }

    /** Preserve Magento slash-delimited keys below system.default. */
    private function configurationValue(array $arr, string $path): mixed
    {
        if (str_starts_with($path, 'system.default.')) {
            $key = substr($path, strlen('system.default.'));
            $default = $arr['system']['default'] ?? [];
            if (is_array($default) && array_key_exists($key, $default)) return $default[$key];
        }
        return $this->getByDotPath($arr, str_replace('/', '.', $path), '__NOT_FOUND__');
    }

    private function isProductionCacheBackend(string $path, mixed $value): bool
    {
        $normalized = strtolower(trim((string)$value, " \t\n\r\0\x0B\\"));
        if ($normalized === '') {
            return false;
        }
        if (str_ends_with($path, 'full_page_cache.caching_application')) {
            return ((string)$value) === '2' || $value === 2;
        }
        return str_contains($normalized, 'redis') || $normalized === 'cm_cache_backend_redis';
    }

    private function isFileCacheBackend(mixed $value): bool
    {
        $normalized = strtolower(trim((string)$value, " \t\n\r\0\x0B\\"));
        return $normalized === 'file'
            || $normalized === 'cm_cache_backend_file'
            || str_contains($normalized, 'cache_backend_file');
    }

    private function arrayAbsent(array $args): array
    {
        $file = (string)($args['file'] ?? '');
        $path = (string)($args['path'] ?? '');
        if ($file === '' || $path === '') {
            return [false, 'php_array_absent requires file & path'];
        }

        // Chuẩn hoá để hỗ trợ cả “system.default.dev/debug/template_hints”
        // lẫn dot-path thuần: getByDotPath dùng dấu chấm.
        $normPath = str_replace('/', '.', $path);

        $arr = $this->loadStaticArray($file);
        if (isset($arr['__ERROR__'])) {
            return [false, $arr['__ERROR__']];
        }

        $val = $this->getByDotPath($arr, $normPath, '__NOT_FOUND__');
        if ($val === '__NOT_FOUND__') {
            return [true, "Path '$normPath' not present in $file"];
        }
        return [false, "Path '$normPath' exists in $file (value: " . var_export($val, true) . ")"];
    }
}
