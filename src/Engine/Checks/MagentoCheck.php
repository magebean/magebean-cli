<?php

declare(strict_types=1);

namespace Magebean\Engine\Checks;

use Magebean\Engine\Context;

final class MagentoCheck
{
    private Context $ctx;
    public function __construct(Context $ctx)
    {
        $this->ctx = $ctx;
    }
    public function stub(array $args): array
    {
        return [true, 'MagentoCheck stub PASS'];
    }

    public function adminFrontNameStrong(array $args): array
    {
        $file = (string)($args['file'] ?? 'app/etc/env.php');
        $path = (string)($args['path'] ?? 'backend.frontName');
        $minLength = max(1, (int)($args['min_length'] ?? 8));
        $denylist = $args['denylist'] ?? [
            'admin',
            'backend',
            'administrator',
            'adminpanel',
            'magento',
            'manage',
            'cms',
            'dashboard',
        ];
        if (!is_array($denylist)) {
            $denylist = [];
        }
        $denylist = array_values(array_filter(array_map(
            static fn(mixed $value): string => strtolower(trim((string)$value)),
            $denylist
        )));

        $arr = $this->loadArray($file);
        if (isset($arr['__ERROR__'])) {
            return [false, $arr['__ERROR__']];
        }

        $value = $this->getByDotPath($arr, $path, '__NOT_FOUND__');
        if ($value === '__NOT_FOUND__') {
            return [false, "Path '$path' not found in $file"];
        }

        $evidence = [
            'file' => $file,
            'path' => $path,
            'observed' => $value,
            'min_length' => $minLength,
            'denylist' => $denylist,
        ];

        if (!is_string($value)) {
            $evidence['reason'] = 'not_string';
            return [false, "Admin frontName must be a string", $evidence];
        }

        $frontName = trim($value);
        $normalized = strtolower($frontName);
        $evidence['observed'] = $frontName;
        $evidence['length'] = strlen($frontName);

        if ($frontName === '') {
            $evidence['reason'] = 'empty';
            return [false, "Admin frontName is empty", $evidence];
        }

        if (strlen($frontName) < $minLength) {
            $evidence['reason'] = 'too_short';
            return [false, "Admin frontName is shorter than {$minLength} characters", $evidence];
        }

        if (in_array($normalized, $denylist, true)) {
            $evidence['reason'] = 'denylisted';
            return [false, "Admin frontName uses a predictable route: {$frontName}", $evidence];
        }

        if (preg_match('/^admin(?:[\W_]*\d*)?$/i', $frontName) === 1 || preg_match('/^admin[\W_\d]+/i', $frontName) === 1) {
            $evidence['reason'] = 'admin_variant';
            return [false, "Admin frontName is too close to the default /admin route", $evidence];
        }

        if (preg_match('/^[a-z0-9][a-z0-9_-]*$/i', $frontName) !== 1) {
            $evidence['reason'] = 'invalid_format';
            return [false, "Admin frontName contains unsupported characters", $evidence];
        }

        return [true, "Admin frontName is non-default and not trivially guessable", $evidence];
    }

    public function adminTwoFactorAuthEnabled(array $args): array
    {
        $file = (string)($args['file'] ?? 'app/etc/config.php');
        $coreModule = (string)($args['core_module'] ?? 'Magento_TwoFactorAuth');
        $providerModules = $args['provider_modules'] ?? [
            'Magento_GoogleAuthenticator',
            'Magento_DuoSecurity',
            'Magento_U2fKey',
            'Magento_AdminAdobeImsTwoFactorAuth',
        ];
        if (!is_array($providerModules)) {
            $providerModules = [];
        }
        $providerModules = array_values(array_filter(array_map(
            static fn(mixed $value): string => trim((string)$value),
            $providerModules
        )));

        $arr = $this->loadArray($file);
        if (isset($arr['__ERROR__'])) {
            return [false, $arr['__ERROR__']];
        }

        $modules = $this->getByDotPath($arr, 'modules', []);
        if (!is_array($modules)) {
            return [false, "Path 'modules' in $file is not an array"];
        }

        $coreEnabled = $this->moduleEnabled($modules, $coreModule);
        $enabledProviders = [];
        $disabledProviders = [];
        foreach ($providerModules as $module) {
            if ($this->moduleEnabled($modules, $module)) {
                $enabledProviders[] = $module;
            } else {
                $disabledProviders[] = $module;
            }
        }

        $evidence = [
            'file' => $file,
            'core_module' => $coreModule,
            'core_enabled' => $coreEnabled,
            'provider_modules' => $providerModules,
            'enabled_providers' => $enabledProviders,
            'disabled_or_missing_providers' => $disabledProviders,
        ];

        if (!$coreEnabled) {
            return [false, "{$coreModule} is disabled or missing", $evidence];
        }

        if ($enabledProviders === []) {
            return [false, "No enabled Magento admin 2FA provider modules found", $evidence];
        }

        return [true, "Admin 2FA core module and provider are enabled", $evidence];
    }

    public function adminPasswordPolicyStrong(array $args): array
    {
        $file = (string)($args['file'] ?? 'app/etc/config.php');
        $basePath = (string)($args['base_path'] ?? 'system.default.admin.security');
        $minLength = (int)($args['min_password_length'] ?? 12);
        $maxLockoutFailures = (int)($args['max_lockout_failures'] ?? 10);
        $maxPasswordLifetimeDays = (int)($args['max_password_lifetime_days'] ?? 90);

        $arr = $this->loadArray($file);
        if (isset($arr['__ERROR__'])) {
            return [false, $arr['__ERROR__']];
        }

        $checks = [
            'min_password_length' => [
                'paths' => $this->policyPaths($basePath, ['min_password_length', 'minimum_password_length']),
                'op' => '>=',
                'value' => $minLength,
            ],
            'lockout_failures' => [
                'paths' => $this->policyPaths($basePath, ['lockout_failures', 'max_login_failures']),
                'op' => '<=',
                'value' => $maxLockoutFailures,
            ],
            'lockout_threshold' => [
                'paths' => $this->policyPaths($basePath, ['lockout_threshold', 'lockout_time', 'lockout_duration']),
                'op' => 'present_positive',
            ],
            'password_lifetime' => [
                'paths' => $this->policyPaths($basePath, ['password_lifetime', 'password_lifetime_days']),
                'op' => '<=',
                'value' => $maxPasswordLifetimeDays,
            ],
            'password_is_forced' => [
                'paths' => $this->policyPaths($basePath, ['password_is_forced', 'force_password_change']),
                'op' => 'truthy',
            ],
        ];

        $evidence = [
            'file' => $file,
            'base_path' => $basePath,
            'requirements' => [
                'min_password_length' => $minLength,
                'max_lockout_failures' => $maxLockoutFailures,
                'max_password_lifetime_days' => $maxPasswordLifetimeDays,
            ],
            'observed' => [],
            'failures' => [],
        ];

        foreach ($checks as $name => $check) {
            [$foundPath, $value] = $this->firstExistingPath($arr, $check['paths']);
            $evidence['observed'][$name] = [
                'path' => $foundPath,
                'value' => $value,
            ];

            if ($foundPath === null) {
                $evidence['failures'][] = "{$name} missing";
                continue;
            }

            $ok = match ($check['op']) {
                '>=' => is_numeric($value) && (float)$value >= (float)$check['value'],
                '<=' => is_numeric($value) && (float)$value <= (float)$check['value'],
                'truthy' => $this->truthy($value),
                'present_positive' => is_numeric($value) && (float)$value > 0,
                default => false,
            };

            if (!$ok) {
                $evidence['failures'][] = "{$name} weak";
            }
        }

        if ($evidence['failures'] !== []) {
            return [false, "Admin password policy is weak or incomplete", $evidence];
        }

        return [true, "Admin password policy meets minimum strength requirements", $evidence];
    }

    public function adminSessionTimeout(array $args): array
    {
        $file = (string)($args['file'] ?? 'app/etc/config.php');
        $basePath = (string)($args['base_path'] ?? 'system.default.admin.security');
        $maxSeconds = (int)($args['max_seconds'] ?? 900);

        $arr = $this->loadArray($file);
        if (isset($arr['__ERROR__'])) {
            return [false, $arr['__ERROR__']];
        }

        $paths = $this->policyPaths($basePath, ['session_lifetime', 'session_timeout']);
        [$foundPath, $value] = $this->firstExistingPath($arr, $paths);
        $evidence = [
            'file' => $file,
            'base_path' => $basePath,
            'path' => $foundPath,
            'observed' => $value,
            'max_seconds' => $maxSeconds,
        ];

        if ($foundPath === null) {
            return [false, "Admin session lifetime is not configured", $evidence];
        }

        if (!is_numeric($value)) {
            $evidence['reason'] = 'not_numeric';
            return [false, "Admin session lifetime is not numeric", $evidence];
        }

        $seconds = (int)$value;
        $evidence['observed_seconds'] = $seconds;
        if ($seconds <= 0) {
            $evidence['reason'] = 'non_positive';
            return [false, "Admin session lifetime must be positive", $evidence];
        }

        if ($seconds > $maxSeconds) {
            $evidence['reason'] = 'too_long';
            return [false, "Admin session lifetime exceeds {$maxSeconds} seconds", $evidence];
        }

        return [true, "Admin session lifetime is at or below {$maxSeconds} seconds", $evidence];
    }

    public function adminExposureRestricted(array $args): array
    {
        $envFile = (string)($args['env_file'] ?? 'app/etc/env.php');
        $timeout = (int)($args['timeout_ms'] ?? 8000);
        $frontName = null;
        $frontNameError = null;

        $env = $this->loadArray($envFile);
        if (isset($env['__ERROR__'])) {
            $frontNameError = $env['__ERROR__'];
        } else {
            $value = $this->getByDotPath($env, 'backend.frontName', '__NOT_FOUND__');
            if (is_string($value) && trim($value) !== '') {
                $frontName = trim($value);
            } elseif ($value === '__NOT_FOUND__') {
                $frontNameError = "Path 'backend.frontName' not found in {$envFile}";
            } else {
                $frontNameError = 'backend.frontName is not a non-empty string';
            }
        }

        $aclFiles = $args['acl_files'] ?? ['nginx.conf', 'pub/.htaccess', '.htaccess'];
        if (!is_array($aclFiles)) {
            $aclFiles = [];
        }
        $aclEvidence = $this->detectAdminAclHints($aclFiles, $frontName);

        $paths = $args['paths'] ?? ['/admin/', '/index.php/admin/', '/backend/'];
        if (!is_array($paths)) {
            $paths = [];
        }
        $paths = array_values(array_filter(array_map(
            static fn(mixed $path): string => '/' . trim((string)$path, '/') . '/',
            $paths
        )));
        if ($frontName !== null) {
            $paths[] = '/' . trim($frontName, '/') . '/';
            $paths[] = '/index.php/' . trim($frontName, '/') . '/';
        }
        $paths = array_values(array_unique($paths));

        $evidence = [
            'front_name' => $frontName,
            'front_name_error' => $frontNameError,
            'acl_hints' => $aclEvidence,
            'http_probes' => [],
        ];

        $base = $this->baseUrl();
        if ($base !== '') {
            foreach ($paths as $path) {
                [$ok, $msg, $response] = $this->fetch($base . $path, 'GET', [], $timeout, true);
                if ($ok === null || $ok === false) {
                    $evidence['http_probes'][] = [
                        'path' => $path,
                        'status' => null,
                        'reason' => $msg,
                    ];
                    continue;
                }

                $status = (int)($response['status'] ?? 0);
                $body = strtolower(substr((string)($response['body'] ?? ''), 0, 12000));
                $adminLogin = $this->looksLikeAdminLogin($body);
                $probe = [
                    'path' => $path,
                    'status' => $status,
                    'final_url' => $response['final_url'] ?? null,
                    'admin_login_signal' => $adminLogin,
                ];
                $evidence['http_probes'][] = $probe;

                if ($status === 200 && $adminLogin) {
                    return [false, "Admin login appears publicly reachable at {$path}", $evidence];
                }
            }
        }

        if ($aclEvidence !== []) {
            return [true, 'Admin exposure appears restricted by web server ACL hints', $evidence];
        }

        if ($base !== '') {
            return [true, 'No public admin login exposure detected on probed paths', $evidence];
        }

        return [false, 'Could not verify admin exposure restriction: no URL or web server ACL hints found', $evidence];
    }

    public function adminCaptchaOrRateLimit(array $args): array
    {
        $file = (string)($args['file'] ?? 'app/etc/config.php');
        $maxLockoutFailures = (int)($args['max_lockout_failures'] ?? 10);
        $captchaPaths = $args['captcha_enabled_paths'] ?? [
            'system.default.admin.captcha.enable',
            'system.default.admin/captcha.enable',
            'system.default.admin/captcha/enable',
        ];
        $captchaFormPaths = $args['captcha_form_paths'] ?? [
            'system.default.admin.captcha.forms',
            'system.default.admin/captcha.forms',
            'system.default.admin/captcha/forms',
        ];
        $recaptchaPaths = $args['recaptcha_enabled_paths'] ?? [
            'system.default.recaptcha_backend.type_recaptcha.enabled',
            'system.default.recaptcha_backend/type_recaptcha.enabled',
            'system.default.recaptcha_backend/type_recaptcha/enabled',
            'system.default.msp_securitysuite_recaptcha.backend.enabled',
            'system.default.msp_securitysuite_recaptcha/backend.enabled',
            'system.default.msp_securitysuite_recaptcha/backend/enabled',
        ];
        foreach (['captchaPaths', 'captchaFormPaths', 'recaptchaPaths'] as $var) {
            if (!is_array($$var)) {
                $$var = [];
            }
        }

        $arr = $this->loadArray($file);
        if (isset($arr['__ERROR__'])) {
            return [false, $arr['__ERROR__']];
        }

        [$captchaPath, $captchaEnabled] = $this->firstExistingPath($arr, $captchaPaths);
        [$captchaFormsPath, $captchaForms] = $this->firstExistingPath($arr, $captchaFormPaths);
        [$recaptchaPath, $recaptchaEnabled] = $this->firstExistingPath($arr, $recaptchaPaths);

        $lockoutPaths = $this->policyPaths('system.default.admin.security', ['lockout_failures', 'max_login_failures']);
        $thresholdPaths = $this->policyPaths('system.default.admin.security', ['lockout_threshold', 'lockout_time', 'lockout_duration']);
        [$lockoutPath, $lockoutFailures] = $this->firstExistingPath($arr, $lockoutPaths);
        [$thresholdPath, $lockoutThreshold] = $this->firstExistingPath($arr, $thresholdPaths);

        $captchaOk = $this->truthy($captchaEnabled);
        if ($captchaOk && $captchaFormsPath !== null) {
            $captchaOk = $this->valueContainsAny($captchaForms, ['backend_login', 'admin_login', 'backend']);
        }

        $recaptchaOk = $this->truthy($recaptchaEnabled);
        $rateLimitOk = is_numeric($lockoutFailures)
            && (float)$lockoutFailures > 0
            && (float)$lockoutFailures <= $maxLockoutFailures
            && is_numeric($lockoutThreshold)
            && (float)$lockoutThreshold > 0;

        $evidence = [
            'file' => $file,
            'captcha' => [
                'enabled_path' => $captchaPath,
                'enabled_value' => $captchaEnabled,
                'forms_path' => $captchaFormsPath,
                'forms_value' => $captchaForms,
                'ok' => $captchaOk,
            ],
            'recaptcha' => [
                'enabled_path' => $recaptchaPath,
                'enabled_value' => $recaptchaEnabled,
                'ok' => $recaptchaOk,
            ],
            'rate_limit' => [
                'lockout_failures_path' => $lockoutPath,
                'lockout_failures_value' => $lockoutFailures,
                'lockout_threshold_path' => $thresholdPath,
                'lockout_threshold_value' => $lockoutThreshold,
                'max_lockout_failures' => $maxLockoutFailures,
                'ok' => $rateLimitOk,
            ],
        ];

        if ($captchaOk || $recaptchaOk || $rateLimitOk) {
            return [true, 'Admin login CAPTCHA, reCAPTCHA, or lockout protection is enabled', $evidence];
        }

        return [false, 'Admin login CAPTCHA/rate-limit protection is weak or missing', $evidence];
    }

    private function loadArray(string $relativeFile): array
    {
        $file = $this->ctx->abs($relativeFile);
        if (!is_file($file)) {
            return ['__ERROR__' => "$relativeFile not found"];
        }

        $data = @include $file;
        if (!is_array($data)) {
            return ['__ERROR__' => "$relativeFile did not return array"];
        }

        return $data;
    }

    private function getByDotPath(array $arr, string $path, mixed $default = null): mixed
    {
        if ($path === '' || $path === '.') {
            return $arr;
        }

        $keys = explode('.', $path);
        $cur = $arr;
        foreach ($keys as $key) {
            if (!is_array($cur) || !array_key_exists($key, $cur)) {
                return $default;
            }
            $cur = $cur[$key];
        }

        return $cur;
    }

    /**
     * Support both Magento's slash-style config keys and normalized nested keys.
     */
    private function policyPaths(string $basePath, array $keys): array
    {
        $normalizedBase = str_replace('/', '.', $basePath);
        $slashBase = str_replace('.', '/', $basePath);
        $paths = [];
        foreach ($keys as $key) {
            $paths[] = $basePath . '.' . $key;
            $paths[] = $basePath . '/' . $key;
            $paths[] = $normalizedBase . '.' . $key;
            $paths[] = $slashBase . '/' . $key;
        }

        return array_values(array_unique($paths));
    }

    private function firstExistingPath(array $arr, array $paths): array
    {
        foreach ($paths as $path) {
            $value = $this->getByDotPathFlexible($arr, (string)$path, '__NOT_FOUND__');
            if ($value !== '__NOT_FOUND__') {
                return [(string)$path, $value];
            }
        }

        return [null, null];
    }

    private function getByDotPathFlexible(array $arr, string $path, mixed $default = null): mixed
    {
        $value = $this->getByDotPath($arr, $path, '__NOT_FOUND__');
        if ($value !== '__NOT_FOUND__') {
            return $value;
        }

        return $this->getByDotPath($arr, str_replace('/', '.', $path), $default);
    }

    private function truthy(mixed $value): bool
    {
        return $value === 1 || $value === true || $value === '1' || $value === 'true' || $value === 'yes';
    }

    private function baseUrl(): string
    {
        $url = (string)$this->ctx->get('url', '');
        if ($url === '' || !preg_match('~^https?://~i', $url)) {
            return '';
        }

        return rtrim($url, '/');
    }

    private function fetch(string $url, string $method = 'GET', array $headers = [], int $timeoutMs = 8000, bool $follow = true): array
    {
        $ctxHeaders = [];
        foreach ($headers as $key => $value) {
            $ctxHeaders[] = is_int($key) ? $value : ($key . ': ' . $value);
        }

        if (function_exists('curl_init')) {
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_HEADER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT_MS, $timeoutMs);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, $follow);
            curl_setopt($ch, CURLOPT_MAXREDIRS, 5);
            curl_setopt($ch, CURLOPT_USERAGENT, 'Magebean-CLI/1.0');
            if ($ctxHeaders) {
                curl_setopt($ch, CURLOPT_HTTPHEADER, $ctxHeaders);
            }

            $response = curl_exec($ch);
            if ($response === false) {
                $error = curl_error($ch);
                curl_close($ch);
                return [null, '[UNKNOWN] HTTP error: ' . $error, ['url' => $url]];
            }

            $status = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
            $body = substr((string)$response, (int)$headerSize);
            $finalUrl = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
            curl_close($ch);

            return [true, '', ['status' => $status, 'body' => $body, 'final_url' => $finalUrl]];
        }

        $opts = [
            'http' => [
                'method' => $method,
                'header' => implode("\r\n", $ctxHeaders),
                'ignore_errors' => true,
                'timeout' => max(1, (int)ceil($timeoutMs / 1000)),
            ]
        ];
        $body = @file_get_contents($url, false, stream_context_create($opts));
        $status = 0;
        if (isset($http_response_header) && is_array($http_response_header)) {
            if (preg_match('~HTTP/\S+\s+(\d{3})~', $http_response_header[0] ?? '', $match)) {
                $status = (int)$match[1];
            }
        }
        if ($body === false) {
            return [null, '[UNKNOWN] HTTP error (stream)', ['url' => $url]];
        }

        return [true, '', ['status' => $status, 'body' => $body, 'final_url' => $url]];
    }

    private function detectAdminAclHints(array $files, ?string $frontName): array
    {
        $hints = [];
        $adminPattern = $frontName !== null ? preg_quote($frontName, '/') : 'admin|backend';
        $aclRegexes = [
            'nginx_allow_deny' => '/location\s+[^{}]*(?:admin|backend|' . $adminPattern . ')[^{]*\{[^}]*\b(?:allow|deny)\b/is',
            'apache_require_ip' => '/(?:<Location|<Directory|RewriteCond|SetEnvIf)[\s\S]{0,500}(?:admin|backend|' . $adminPattern . ')[\s\S]{0,500}\b(?:Require\s+ip|Require\s+not|Deny\s+from|Allow\s+from)\b/i',
            'generic_acl' => '/(?:admin|backend|' . $adminPattern . ')[\s\S]{0,500}\b(?:allow|deny|Require\s+ip|satisfy)\b/i',
        ];

        foreach ($files as $file) {
            if (!is_scalar($file)) {
                continue;
            }
            $rel = trim((string)$file);
            if ($rel === '') {
                continue;
            }
            $path = $this->ctx->abs($rel);
            if (!is_file($path)) {
                continue;
            }
            $contents = (string)file_get_contents($path);
            foreach ($aclRegexes as $name => $regex) {
                if (preg_match($regex, $contents) === 1) {
                    $hints[] = ['file' => $rel, 'pattern' => $name];
                    break;
                }
            }
        }

        return $hints;
    }

    private function looksLikeAdminLogin(string $body): bool
    {
        return str_contains($body, 'name="login[username]"')
            || str_contains($body, "name='login[username]'")
            || str_contains($body, 'name="login[password]"')
            || str_contains($body, "name='login[password]'")
            || str_contains($body, 'magento admin')
            || preg_match('~<title>[^<]*admin[^<]*</title>~i', $body) === 1;
    }

    private function valueContainsAny(mixed $value, array $needles): bool
    {
        $haystack = '';
        if (is_array($value)) {
            $haystack = strtolower(implode(',', array_map(static fn(mixed $item): string => (string)$item, $value)));
        } elseif ($value !== null) {
            $haystack = strtolower((string)$value);
        }

        foreach ($needles as $needle) {
            if ($needle !== '' && str_contains($haystack, strtolower((string)$needle))) {
                return true;
            }
        }

        return false;
    }

    private function moduleEnabled(array $modules, string $module): bool
    {
        if ($module === '' || !array_key_exists($module, $modules)) {
            return false;
        }

        $value = $modules[$module];
        return $value === 1 || $value === true || $value === '1';
    }
}
