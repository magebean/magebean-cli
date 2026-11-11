<?php

declare(strict_types=1);

namespace Magebean\Engine\Checks;

use Magebean\Engine\Context;
use Magebean\Engine\Collectors\CollectorSet;

final class MagentoCheck
{
    private Context $ctx;
    private CollectorSet $collectors;
    private ?\PDO $primaryDatabase = null;
    private bool $primaryDatabaseAttempted = false;
    public function __construct(Context $ctx, ?CollectorSet $collectors = null)
    {
        $this->ctx = $ctx;
        $this->collectors = $collectors ?? new CollectorSet();
    }
    /** Exact declared route predicate; entropy is not claimed. */
    public function adminFrontNameDeclared(array $args): array
    {
        $file = (string)($args['file'] ?? 'app/etc/env.php');
        $config = $this->loadArray($file);
        if (isset($config['__ERROR__'])) return [null, '[UNKNOWN] Backend route configuration cannot be read'];
        $route = $this->getByDotPath($config, 'backend.frontName', null);
        if (!is_string($route) || trim($route) === '' || preg_match('/^[a-z0-9][a-z0-9_-]*$/i', $route) !== 1) {
            return [null, '[UNKNOWN] backend.frontName is missing or malformed'];
        }
        $ok = !in_array(strtolower($route), ['admin', 'backend'], true);
        return [$ok, $ok ? 'Declared backend route differs from common admin and backend routes' : 'Declared backend route uses a common admin or backend route', ['file' => $file, 'path' => 'backend.frontName', 'observed' => $route, 'scope' => 'declared_configuration']];
    }

    /** Configuration resolver for exact primary predicates; legacy APIs are unchanged. */
    private function primaryConfigValue(string $path): array
    {
        foreach (['app/etc/env.php', 'app/etc/config.php'] as $file) {
            if (!is_file($this->ctx->abs($file))) continue;
            $config = $this->loadArray($file);
            if (isset($config['__ERROR__'])) return [false, null, $file, 'Configuration cannot be read'];
            $system = $config['system'] ?? [];
            if (!is_array($system)) return [false, null, $file, 'System configuration is malformed'];
            $default = $system['default'] ?? [];
            if (!is_array($default)) return [false, null, $file, 'Default configuration is malformed'];
            // Magento supports nested sections and slash-delimited configuration keys.
            if (array_key_exists($path, $default)) return [true, $default[$path], $file, ''];
            $value = $this->getByDotPath($default, str_replace('/', '.', $path), '__NOT_FOUND__');
            if ($value !== '__NOT_FOUND__') return [true, $value, $file, ''];
        }
        // Unlocked values normally live in core_config_data, not config.php.
        $env = $this->loadArray('app/etc/env.php');
        $connection = $env['db']['connection']['default'] ?? null;
        if (is_array($connection)) {
            try {
                $host = $connection['host'] ?? null; $dbname = $connection['dbname'] ?? null;
                if (!is_string($host) || !is_string($dbname) || str_contains($host, ';') || str_contains($dbname, ';')) throw new \RuntimeException('Invalid connection');
                $dsn = 'mysql:host=' . $host . ';dbname=' . $dbname . ';charset=utf8mb4';
                if (isset($connection['port'])) $dsn .= ';port=' . (int)$connection['port'];
                if (!$this->primaryDatabaseAttempted) {
                    $this->primaryDatabaseAttempted = true;
                    $this->primaryDatabase = new \PDO($dsn, (string)($connection['username'] ?? ''), (string)($connection['password'] ?? ''), [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION, \PDO::ATTR_TIMEOUT => 2]);
                }
                if ($this->primaryDatabase === null) throw new \RuntimeException('Connection unavailable');
                $pdo = $this->primaryDatabase;
                $prefix = (string)($env['db']['table_prefix'] ?? '');
                if (preg_match('/^[a-zA-Z0-9_]*$/', $prefix) !== 1) throw new \RuntimeException('Invalid prefix');
                $statement = $pdo->prepare('SELECT value FROM `' . $prefix . 'core_config_data` WHERE scope = ? AND scope_id = ? AND path = ?');
                $statement->execute(['default', 0, $path]);
                $values = $statement->fetchAll(\PDO::FETCH_COLUMN);
                if (count($values) > 1) return [false, null, 'core_config_data', 'Conflicting default configuration'];
                if (count($values) === 1) return [true, $values[0], 'core_config_data', ''];
            } catch (\Throwable $exception) {
                $this->primaryDatabaseAttempted = true;
                $this->primaryDatabase = null;
                // Never disclose DSN, database credentials, SQL exceptions, or config contents.
                return [false, null, 'core_config_data', 'Default configuration database is unavailable'];
            }
        }
        return $this->installedModuleDefault($path);
    }

    /** Read installed Magento module defaults, not scanner-invented fallback values. */
    private function installedModuleDefault(string $path): array
    {
        $moduleFiles = ['Magento_Backend' => 'backend', 'Magento_Captcha' => 'captcha', 'Magento_Developer' => 'developer', 'Magento_Translation' => 'translation', 'Magento_User' => 'user', 'Magento_Security' => 'security', 'Magento_TwoFactorAuth' => 'two-factor-auth'];
        $config = $this->loadArray('app/etc/config.php');
        $modules = $config['modules'] ?? [];
        if (isset($config['__ERROR__']) || !is_array($modules)) return [false, null, 'app/etc/config.php', 'Installed module states are unavailable'];
        $found = false; $value = null; $source = null;
        foreach ($moduleFiles as $module => $package) {
            if (!$this->moduleEnabled($modules, $module)) continue;
            $relative = 'vendor/magento/module-' . $package . '/etc/config.xml';
            $absolute = $this->ctx->abs($relative);
            if (!is_file($absolute)) continue;
            $text = @file_get_contents($absolute);
            if ($text === false || stripos($text, '<!DOCTYPE') !== false || stripos($text, '<!ENTITY') !== false) return [false, null, $relative, 'Installed module defaults cannot be read safely'];
            $previous = libxml_use_internal_errors(true);
            $xml = simplexml_load_string($text, \SimpleXMLElement::class, LIBXML_NONET);
            libxml_clear_errors(); libxml_use_internal_errors($previous);
            if ($xml === false) return [false, null, $relative, 'Installed module defaults are malformed'];
            $cursor = $xml->default;
            foreach (explode('/', $path) as $segment) {
                if (!preg_match('/^[a-zA-Z0-9_]+$/D', $segment) || !isset($cursor->{$segment})) { $cursor = null; break; }
                $cursor = $cursor->{$segment};
            }
            if ($cursor !== null && count($cursor) > 0) { $found = true; $value = (string)$cursor; $source = $relative; }
        }
        return $found ? [true, $value, $source, 'Installed module default'] : [false, null, null, 'Configuration value is not available'];
    }

    /** Bounded deployment policy, not proof of every account/password workflow. */
    public function adminPasswordMinimumConfigured(array $args): array
    {
        $minimum = max(1, (int)($args['min_length'] ?? 8));
        [$found, $value, $source, $reason] = $this->primaryConfigValue('admin/security/minimum_password_length');
        if (!$found && $source === null) [$found, $value, $source, $reason] = $this->primaryConfigValue('admin/security/password_min_length');
        if (!$found && $source !== 'core_config_data') {
            $relative = 'vendor/magento/module-user/Model/UserValidationRules.php';
            if (!is_file($this->ctx->abs($relative))) $relative = 'vendor/magento/module-user/Model/User.php';
            $text = @file_get_contents($this->ctx->abs($relative));
            if (is_string($text)) {
                // Only recognize the installed validator's explicit minimum declaration.
                if (preg_match('/const\s+(?:MIN_PASSWORD_LENGTH|MIN_PASSWORD_LENGTH_ADMIN)\s*=\s*(\d+)\s*;/', $text, $match)) {
                    $found = true; $value = $match[1]; $source = $relative;
                } elseif (preg_match('/new\s+(?:\\\\?[A-Za-z_][A-Za-z0-9_\\\\]*\\\\)?StringLength\s*\(\s*\[\s*[\x27\x22]min[\x27\x22]\s*=>\s*(\d+)\s*\]/', $text, $match)) {
                    $found = true; $value = $match[1]; $source = $relative;
                }
            }
        }
        $evidence = ['source' => $source, 'observed' => $value, 'minimum' => $minimum, 'scope' => 'admin_password_minimum_deployment_policy'];
        if (!$found || !is_scalar($value) || preg_match('/^[0-9]+$/D', (string)$value) !== 1) return [null, '[UNKNOWN] Admin password minimum cannot be resolved from installed configuration or validator', $evidence];
        $ok = (int)$value >= $minimum;
        return [$ok, $ok ? 'Observed admin password minimum meets deployment policy' : 'Observed admin password minimum is below deployment policy', $evidence];
    }

    public function deploymentDebugFlagsDisabled(array $args): array
    {
        $paths = $args['paths'] ?? ['dev/debug/template_hints', 'dev/debug/template_hints_storefront', 'dev/debug/template_hints_admin', 'dev/debug/template_hints_blocks', 'dev/translate_inline/active', 'dev/translate_inline/active_admin'];
        if (!is_array($paths) || $paths === []) return [null, '[UNKNOWN] Project debug flag paths are unavailable'];
        $evidence = []; $unknown = false;
        foreach ($paths as $path) {
            [$found, $value, $source, $reason] = $this->primaryConfigValue((string)$path);
            $evidence[$path] = ['source' => $source, 'observed' => $value, 'available' => $found, 'reason' => $reason, 'scope' => 'declared_project_configuration'];
            if (!$found) { if ($source !== null) $unknown = true; continue; }
            if (!in_array($value, [0, 1, '0', '1', true, false], true)) { $unknown = true; continue; }
            if ($this->truthy($value)) return [false, 'Declared Magento debug flag is enabled: ' . $path, $evidence];
        }
        $result = $unknown ? [null, '[UNKNOWN] Project debug configuration cannot be resolved'] : [true, 'No enabled debug flag is declared in inspected project configuration'];
        foreach (['.user.ini', 'pub/.user.ini', 'php.ini', 'pub/php.ini'] as $relative) {
            $absolute = $this->ctx->abs($relative);
            if (!is_file($absolute)) continue;
            $this->collectors->session->checkpoint();
            $text = @file_get_contents($absolute, false, null, 0, 1048577);
            if (!is_string($text) || strlen($text) > 1048576) return [null, '[UNKNOWN] Project PHP ini cannot be read within bounds', ['file' => $relative]];
            $ini = @parse_ini_string($text, false, INI_SCANNER_RAW);
            if ($ini === false) return [null, '[UNKNOWN] Project PHP ini cannot be read', ['file' => $relative]];
            $xdebugMode = isset($ini['xdebug.mode']) ? strtolower(trim((string)$ini['xdebug.mode'])) : null;
            if ($xdebugMode !== null) {
                $modes = array_map('trim', explode(',', $xdebugMode));
                if ($modes === [] || array_diff($modes, ['off','develop','coverage','debug','gcstats','profile','trace']) !== []) return [null, '[UNKNOWN] Project Xdebug mode declaration is malformed', ['file' => $relative]];
                if (array_diff($modes, ['off']) !== []) return [false, 'Project Xdebug mode enables debugging features', ['file' => $relative, 'modes' => $modes]];
            }
            // zend_extension is repeatable in PHP; parse_ini_string retains only its last occurrence.
            foreach (preg_split('/\R/', $text) ?: [] as $line) {
                if (!preg_match('/^\s*zend_extension\s*=/i', $line)) continue;
                $declaration = @parse_ini_string($line, false, INI_SCANNER_RAW);
                if ($declaration === false) return [null, '[UNKNOWN] Project PHP extension declaration cannot be parsed', ['file' => $relative]];
                if (isset($declaration['zend_extension']) && stripos((string)$declaration['zend_extension'], 'xdebug') !== false && $xdebugMode !== 'off') return [false, 'Project declares Xdebug without an explicit disabled mode', ['file' => $relative]];
            }
            foreach (['display_errors', 'display_startup_errors'] as $flag) {
                if (!array_key_exists($flag, $ini)) continue;
                $normalized = strtolower(trim((string)$ini[$flag]));
                $evidence[$relative . ':' . $flag] = ['source' => $relative, 'observed' => $ini[$flag]];
                if (in_array($normalized, ['1', 'on', 'yes', 'true', 'stdout', 'stderr'], true)) return [false, 'Project PHP error display is enabled: ' . $flag, $evidence];
                if (!in_array($normalized, ['0', 'off', 'no', 'false', 'none', ''], true)) return [null, '[UNKNOWN] Project PHP error display flag is malformed', $evidence];
            }
        }
        return [$result[0], $result[1], $evidence];
    }

    public function adminLoginProtectionConfigured(array $args): array
    {
        $paths = ['admin/captcha/enable', 'admin/captcha/forms', 'admin/security/lockout_failures', 'admin/security/lockout_threshold'];
        $values = []; $evidence = [];
        foreach ($paths as $path) {
            [$found, $value, $source, $reason] = $this->primaryConfigValue($path);
            $values[$path] = [$found, $value];
            $evidence[$path] = ['source' => $source, 'observed' => $value, 'available' => $found, 'reason' => $reason];
        }
        [$captchaKnown, $captcha] = $values['admin/captcha/enable'];
        [$formsKnown, $forms] = $values['admin/captcha/forms'];
        [$failuresKnown, $failures] = $values['admin/security/lockout_failures'];
        [$thresholdKnown, $threshold] = $values['admin/security/lockout_threshold'];
        $boolean = static fn(mixed $value): bool => in_array($value, [0, 1, '0', '1', false, true], true);
        $positive = static fn(mixed $value): bool => is_scalar($value) && preg_match('/^[0-9]+$/D', (string)$value) === 1;
        $captchaValid = $captchaKnown && $boolean($captcha);
        $formsValid = $formsKnown && (is_string($forms) || is_array($forms));
        $formsList = is_string($forms) ? explode(',', $forms) : (is_array($forms) ? $forms : []);
        $loginForm = in_array('backend_login', array_map(static fn($item) => is_scalar($item) ? trim((string)$item) : '', $formsList), true);
        $rateKnown = $failuresKnown && $thresholdKnown && $positive($failures) && $positive($threshold);
        $max = max(1, (int)($args['max_lockout_failures'] ?? 10));
        $rateOk = $rateKnown && (int)$failures > 0 && (int)$failures <= $max && (int)$threshold > 0;
        $captchaOk = $captchaValid && $this->truthy($captcha) && $formsValid && $loginForm;
        if ($rateOk || $captchaOk) return [true, 'Default admin login configuration enables CAPTCHA for backend_login or bounded lockout', $evidence];
        $modules = $this->loadArray('app/etc/config.php');
        $moduleMap = $modules['modules'] ?? null;
        $recaptchaDisabled = is_array($moduleMap) && !$this->moduleEnabled($moduleMap, 'Magento_ReCaptchaAdminUi');
        if (!$recaptchaDisabled) {
            [$found, $type, $source, $reason] = $this->primaryConfigValue('recaptcha_backend/type_for/backend_login');
            $evidence['recaptcha_backend/type_for/backend_login'] = ['source' => $source, 'observed' => $type, 'available' => $found, 'reason' => $reason];
            if ($found && is_string($type) && in_array($type, ['recaptcha_v2', 'recaptcha_v2_invisible', 'recaptcha_v3'], true)) {
                return [true, 'Default admin login configuration enables reCAPTCHA for backend_login', $evidence];
            }
            $recaptchaDisabled = $found && ($type === '' || $type === null || $type === '0' || $type === 0);
        }
        $captchaRejected = $captchaValid && (!$this->truthy($captcha) || ($formsValid && !$loginForm));
        if ($captchaRejected && $rateKnown && $recaptchaDisabled) return [false, 'Default admin login configuration enables neither backend_login CAPTCHA nor bounded lockout', $evidence];
        return [null, '[UNKNOWN] Admin login protection configuration is missing, malformed, or inaccessible', $evidence];
    }

    /** Safe default-scope URL hint for opt-in runtime probes; never exposes DB credentials. */
    public function configuredBaseUrl(): array
    {
        foreach (['web/secure/base_url', 'web/unsecure/base_url'] as $path) {
            [$found, $value, $source, $reason] = $this->primaryConfigValue($path);
            if (!$found || !is_string($value)) continue;
            $parts = parse_url(trim($value));
            if (!is_array($parts) || !in_array(strtolower((string)($parts['scheme'] ?? '')), ['http', 'https'], true) || empty($parts['host']) || isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])) continue;
            return ['url' => rtrim(trim($value), '/'), 'source' => $source, 'reason' => 'Configured default base URL'];
        }
        return ['url' => '', 'source' => null, 'reason' => 'No valid configured default base URL; provide --url'];
    }

    public function httpsConfigurationObserved(array $args): array
    {
        $evidence = []; $unknown = false;
        foreach (['web/secure/use_in_adminhtml', 'web/secure/use_in_frontend', 'web/secure/base_url'] as $path) {
            [$found, $value, $source, $reason] = $this->primaryConfigValue($path);
            $evidence[$path] = ['source' => $source, 'observed' => $value, 'available' => $found, 'reason' => $reason];
            if (!$found) { $unknown = true; continue; }
            if ($path === 'web/secure/base_url') {
                if (!is_string($value) || filter_var($value, FILTER_VALIDATE_URL) === false) { $unknown = true; continue; }
                if (strtolower((string)parse_url($value, PHP_URL_SCHEME)) !== 'https') return [false, 'Declared secure base URL does not use HTTPS', $evidence];
            } else {
                if (!in_array($value, [0, 1, '0', '1', false, true], true)) { $unknown = true; continue; }
                if (!$this->truthy($value)) return [false, 'Magento secure URL flag is explicitly disabled: ' . $path, $evidence];
            }
        }
        if ($unknown) return [null, '[UNKNOWN] Secure URL settings are missing, malformed, or inaccessible', $evidence];
        return [true, 'Default Magento secure URL settings enable HTTPS for admin and storefront', $evidence];
    }

    public function cookieConfigurationObserved(array $args): array
    {
        $evidence = []; $unknown = false;
        foreach (['web/cookie/cookie_secure', 'web/cookie/cookie_httponly', 'web/cookie/cookie_samesite'] as $path) {
            [$found, $value, $source, $reason] = $this->primaryConfigValue($path);
            $evidence[$path] = ['source' => $source, 'observed' => $value, 'available' => $found, 'reason' => $reason];
            if (!$found) { $unknown = true; continue; }
            if ($path === 'web/cookie/cookie_samesite') {
                if (!is_string($value)) { $unknown = true; continue; }
                if (!in_array(strtolower(trim($value)), ['lax', 'strict'], true)) return [false, 'Declared cookie SameSite does not meet Lax/Strict policy', $evidence];
            } else {
                if (!in_array($value, [0, 1, '0', '1', false, true], true)) { $unknown = true; continue; }
                if (!$this->truthy($value)) return [false, 'Declared cookie protection is explicitly disabled: ' . $path, $evidence];
            }
        }
        if ($unknown) return [null, '[UNKNOWN] Cookie settings are missing, malformed, or inaccessible; runtime cookies must be probed', $evidence];
        return [true, 'Declared default cookie settings enable Secure, HttpOnly and Lax/Strict SameSite', $evidence];
    }

    public function effectiveConfigurationValues(array $paths): array
    {
        $result = [];
        foreach ($paths as $path) {
            if (!is_string($path) || $path === '') continue;
            [$found, $value, $source, $reason] = $this->primaryConfigValue($path);
            $result[$path] = ['available' => $found, 'value' => $value, 'source' => $source, 'reason' => $reason];
        }
        return $result;
    }

    public function debugConfigurationObserved(array $args): array
    {
        $paths = $args['paths'] ?? ['dev/debug/template_hints', 'dev/debug/template_hints_storefront', 'dev/translate_inline/active'];
        if (!is_array($paths) || $paths === []) return [null, '[UNKNOWN] Debug configuration paths are unavailable'];
        $observations = $this->effectiveConfigurationValues($paths);
        $unknown = false;
        foreach ($observations as $path => $observation) {
            $value = $observation['value'];
            if (!$observation['available'] || !in_array($value, [0, 1, '0', '1', true, false], true)) { $unknown = true; continue; }
            if ($this->truthy($value)) return [false, 'Default Magento debug or inline translation flag is enabled: ' . $path, $observations];
        }
        if ($unknown || count($observations) !== count($paths)) return [null, '[UNKNOWN] Debug flags are missing, malformed, or inaccessible', $observations];
        return [true, 'Observed default Magento debug and inline translation flags are disabled', $observations];
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

    /** Native provider configuration only; enrollment and IMS MFA remain external evidence. */
    public function adminTwoFactorAuthEnabled(array $args): array
    {
        $file = (string)($args['file'] ?? 'app/etc/config.php');
        $arr = $this->loadArray($file);
        $modules = $arr['modules'] ?? null;
        if (isset($arr['__ERROR__']) || !is_array($modules)) return [null, '[UNKNOWN] Installed authentication module states are unavailable'];
        foreach (['Magento_TwoFactorAuth', 'Magento_AdminAdobeIms', 'Magento_AdminAdobeImsTwoFactorAuth'] as $module) {
            if (array_key_exists($module, $modules) && !in_array($modules[$module], [0, 1, '0', '1', false, true], true)) return [null, '[UNKNOWN] Authentication module state is malformed', ['module' => $module]];
        }
        $evidence = ['file' => $file, 'scope' => 'native_admin_provider_configuration', 'enrollment_verified' => false];
        // Module presence does not establish an active IMS integration or its MFA policy.
        if ($this->moduleEnabled($modules, 'Magento_AdminAdobeIms') || $this->moduleEnabled($modules, 'Magento_AdminAdobeImsTwoFactorAuth')) {
            return [null, '[UNKNOWN] Adobe IMS modules are enabled; active authentication mode and identity-provider MFA require evidence', $evidence + ['authentication_mode' => 'ims_possible']];
        }
        if (!array_key_exists('Magento_TwoFactorAuth', $modules)) return [null, '[UNKNOWN] Native Admin 2FA module state is missing', $evidence];
        if (!$this->moduleEnabled($modules, 'Magento_TwoFactorAuth')) return [false, 'Native Admin 2FA is disabled and no IMS module is declared', $evidence];
        [$found, $value, $source, $reason] = $this->primaryConfigValue('twofactorauth/general/force_providers');
        $evidence += ['source' => $source, 'reason' => $reason];
        if (!$found || (!is_string($value) && !is_array($value))) return [null, '[UNKNOWN] Native Admin 2FA provider configuration cannot be resolved', $evidence];
        $providers = is_string($value) ? explode(',', $value) : $value;
        $normalized = [];
        foreach ($providers as $provider) {
            if (!is_string($provider)) return [null, '[UNKNOWN] Native Admin 2FA provider configuration is malformed', $evidence];
            if (trim($provider) !== '') $normalized[] = trim($provider);
        }
        $normalized = array_values(array_unique($normalized));
        $evidence['providers'] = $normalized;
        if ($normalized === []) return [null, '[UNKNOWN] No providers are forced; available providers and account enrollment require additional evidence', $evidence];
        // These engines belong to Magento_TwoFactorAuth; they are not separate modules.
        if (array_diff($normalized, ['google', 'duo_security', 'authy', 'u2fkey']) !== []) return [null, '[UNKNOWN] Custom or unrecognized 2FA provider requires installed-engine validation', $evidence];
        return [true, 'Native Admin 2FA is enabled with recognized configured provider engines; account enrollment is not verified', $evidence];
    }

    /** Exact default-scope Admin flag; no claim about custom authentication handlers. */
    public function adminSecurityFlagConfigured(array $args): array
    {
        $allowed = ['admin/security/use_form_key' => true, 'admin/security/use_case_sensitive_login' => true, 'admin/security/admin_account_sharing' => false];
        $path = (string)($args['path'] ?? '');
        if (!array_key_exists($path, $allowed)) return [null, '[UNKNOWN] Unsupported Admin security configuration path'];
        [$found, $value, $source, $reason] = $this->primaryConfigValue($path);
        $evidence = ['path' => $path, 'source' => $source, 'observed' => $value, 'reason' => $reason, 'scope' => 'resolved_default_configuration'];
        if (!$found || !in_array($value, [0, 1, '0', '1', false, true], true)) return [null, '[UNKNOWN] Admin security flag cannot be resolved', $evidence];
        $ok = $this->truthy($value) === $allowed[$path];
        return [$ok, $ok ? 'Resolved Admin security flag meets deployment policy' : 'Resolved Admin security flag violates deployment policy', $evidence];
    }

    /** Check independent reset throttles without exercising a real account recovery flow. */
    public function adminPasswordResetProtectionConfigured(array $args): array
    {
        $paths = ['admin/security/password_reset_protection_type', 'admin/security/max_number_password_reset_requests', 'admin/security/min_time_between_password_reset_requests'];
        $values = []; $evidence = ['scope' => 'resolved_default_password_reset_configuration'];
        foreach ($paths as $path) {
            [$found, $value, $source, $reason] = $this->primaryConfigValue($path);
            $evidence[$path] = ['source' => $source, 'observed' => $value, 'reason' => $reason];
            if (!$found || !is_scalar($value) || preg_match('/^[0-9]+$/D', (string)$value) !== 1) return [null, '[UNKNOWN] Admin password reset protection cannot be resolved', $evidence];
            $values[$path] = (int)$value;
        }
        $type = $values[$paths[0]];
        if (!in_array($type, [0, 1, 2, 3], true)) return [null, '[UNKNOWN] Admin password reset protection type is unrecognized', $evidence];
        $maximum = max(1, (int)($args['max_requests_per_hour'] ?? 5));
        $minimum = max(1, (int)($args['min_interval_minutes'] ?? 1));
        $evidence['policy'] = ['max_requests_per_hour' => $maximum, 'min_interval_minutes' => $minimum, 'owner' => 'Magebean'];
        $ok = $type !== 0 && $values[$paths[1]] > 0 && $values[$paths[1]] <= $maximum && $values[$paths[2]] >= $minimum;
        return [$ok, $ok ? 'Resolved Admin password reset protection enables bounded requests and cooldown' : 'Resolved Admin password reset protection lacks required protection or bounded throttles', $evidence];
    }
    public function adminPasswordPolicyStrong(array $args): array
    {
        $file = (string)($args['file'] ?? 'app/etc/config.php');
        $basePath = (string)($args['base_path'] ?? 'system.default.admin.security');
        $minLength = (int)($args['min_password_length'] ?? 8);
        $maxLockoutFailures = isset($args['max_lockout_failures']) ? (int)$args['max_lockout_failures'] : null;
        $maxPasswordLifetimeDays = isset($args['max_password_lifetime_days']) ? (int)$args['max_password_lifetime_days'] : null;

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

        // Authentication throttling belongs to MB-R011. Password expiry and
        // forced changes are optional project policy, not ASVS 5.0 L1
        // password-strength criteria.
        if ($maxLockoutFailures === null) {
            unset($checks['lockout_failures'], $checks['lockout_threshold']);
        }
        if ($maxPasswordLifetimeDays === null) {
            unset($checks['password_lifetime'], $checks['password_is_forced']);
        }

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
            return [false, "Admin password policy does not meet the configured criteria", $evidence];
        }

        return [true, "Admin password policy meets the configured criteria", $evidence];
    }

    public function productionMode(array $args): array
    {
        $file = (string)($args['file'] ?? 'app/etc/env.php');
        $path = (string)($args['path'] ?? 'MAGE_MODE');
        $expected = strtolower(trim((string)($args['equals'] ?? 'production')));

        $arr = $this->loadArray($file);
        if (isset($arr['__ERROR__'])) {
            return [null, '[UNKNOWN] ' . $arr['__ERROR__'], ['file' => $file, 'path' => $path]];
        }

        $value = $this->getByDotPathFlexible($arr, $path, '__NOT_FOUND__');
        if ($value === '__NOT_FOUND__') {
            return [null, "[UNKNOWN] Path '{$path}' not found in {$file}", ['file' => $file, 'path' => $path]];
        }

        $mode = strtolower(trim((string)$value));
        $evidence = [
            'file' => $file,
            'path' => $path,
            'observed' => $value,
            'expected' => $expected,
        ];

        if ($mode === $expected) {
            return [true, 'Magento deploy mode is production', $evidence];
        }

        return [false, "Magento deploy mode is '{$mode}', expected '{$expected}'", $evidence];
    }

    public function adminSessionTimeout(array $args): array
    {
        $maxSeconds = max(1, (int)($args['max_seconds'] ?? 900));
        [$found, $value, $source, $reason] = $this->primaryConfigValue('admin/security/session_lifetime');
        $evidence = ['source' => $source, 'path' => 'admin/security/session_lifetime', 'observed' => $value, 'max_seconds' => $maxSeconds, 'scope' => 'default_configuration'];
        if (!$found) return [null, '[UNKNOWN] Admin session lifetime cannot be resolved: ' . $reason, $evidence];
        if ((!is_int($value) && !is_string($value)) || preg_match('/^[0-9]+$/D', (string)$value) !== 1) return [null, '[UNKNOWN] Admin session lifetime is not a valid integer', $evidence];
        $seconds = (int)$value;
        $evidence['observed_seconds'] = $seconds;
        $ok = $seconds > 0 && $seconds <= $maxSeconds;
        return [$ok, $ok ? 'Configured admin session lifetime is at or below ' . $maxSeconds . ' seconds' : 'Configured admin session lifetime is ' . $seconds . ' seconds; set admin/security/session_lifetime to between 1 and ' . $maxSeconds, $evidence];
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
            $probes = $evidence['http_probes'];
            $unobserved = array_filter($probes, static fn(array $probe): bool => ($probe['status'] ?? null) === null || (int)$probe['status'] < 100 || (int)$probe['status'] >= 500);
            if ($probes === [] || $unobserved !== []) {
                return [null, '[UNKNOWN] Admin exposure could not be verified for all probed paths', $evidence];
            }
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

    public function httpsEnforced(array $args): array
    {
        $files = $args['files'] ?? ['app/etc/config.php', 'app/etc/env.php'];
        if (!is_array($files)) {
            $files = ['app/etc/config.php', 'app/etc/env.php'];
        }
        $timeoutMs = (int)($args['timeout_ms'] ?? 8000);

        [$adminPath, $adminValue, $adminFile] = $this->firstConfigValue($files, $this->httpsConfigPaths('use_in_adminhtml'));
        [$frontPath, $frontValue, $frontFile] = $this->firstConfigValue($files, $this->httpsConfigPaths('use_in_frontend'));
        [$basePath, $baseValue, $baseFile] = $this->firstConfigValue($files, $this->httpsConfigPaths('base_url'));

        $adminOk = $this->truthy($adminValue);
        $frontOk = $this->truthy($frontValue);
        $secureBaseOk = is_string($baseValue) && preg_match('~^https://~i', trim($baseValue)) === 1;

        $redirectEvidence = null;
        $redirectOk = null;
        $base = $this->baseUrl();
        if ($base !== '') {
            $redirectEvidence = $this->httpsRedirectEvidence($base, $timeoutMs);
            $redirectOk = (bool)($redirectEvidence['ok'] ?? false);
        }

        $evidence = [
            'config' => [
                'admin' => ['file' => $adminFile, 'path' => $adminPath, 'value' => $adminValue, 'ok' => $adminOk],
                'frontend' => ['file' => $frontFile, 'path' => $frontPath, 'value' => $frontValue, 'ok' => $frontOk],
                'secure_base_url' => ['file' => $baseFile, 'path' => $basePath, 'value' => $baseValue, 'ok' => $secureBaseOk],
            ],
            'http_redirect' => $redirectEvidence,
        ];

        $configOk = $adminOk && $frontOk && $secureBaseOk;
        if ($configOk && ($redirectOk === null || $redirectOk === true)) {
            return [true, 'HTTPS is enforced by Magento secure URL config' . ($redirectOk === true ? ' and HTTP redirect' : ''), $evidence];
        }

        if (!$configOk) {
            return [false, 'Magento secure URL configuration is incomplete', $evidence];
        }

        return [false, 'HTTP entrypoint does not redirect to HTTPS', $evidence];
    }

    public function cookieFlagsSecure(array $args): array
    {
        $files = $args['files'] ?? ['app/etc/config.php', 'app/etc/env.php'];
        if (!is_array($files)) {
            $files = ['app/etc/config.php', 'app/etc/env.php'];
        }
        $allowedSameSite = $args['allowed_samesite'] ?? ['lax', 'strict'];
        if (!is_array($allowedSameSite)) {
            $allowedSameSite = ['lax', 'strict'];
        }
        $allowedSameSite = array_map(static fn(mixed $value): string => strtolower((string)$value), $allowedSameSite);

        [$securePath, $secureValue, $secureFile] = $this->firstConfigValue($files, $this->cookieConfigPaths('secure'));
        [$httpOnlyPath, $httpOnlyValue, $httpOnlyFile] = $this->firstConfigValue($files, $this->cookieConfigPaths('httponly'));
        [$sameSitePath, $sameSiteValue, $sameSiteFile] = $this->firstConfigValue($files, $this->cookieConfigPaths('samesite'));

        $secureOk = $this->truthy($secureValue);
        $httpOnlyOk = $this->truthy($httpOnlyValue);
        $sameSiteNormalized = strtolower(trim((string)$sameSiteValue));
        $sameSiteOk = $sameSiteNormalized !== '' && in_array($sameSiteNormalized, $allowedSameSite, true);

        $evidence = [
            'secure' => ['file' => $secureFile, 'path' => $securePath, 'value' => $secureValue, 'ok' => $secureOk],
            'httponly' => ['file' => $httpOnlyFile, 'path' => $httpOnlyPath, 'value' => $httpOnlyValue, 'ok' => $httpOnlyOk],
            'samesite' => ['file' => $sameSiteFile, 'path' => $sameSitePath, 'value' => $sameSiteValue, 'allowed' => $allowedSameSite, 'ok' => $sameSiteOk],
        ];

        if ($secureOk && $httpOnlyOk && $sameSiteOk) {
            return [true, 'Cookie Secure, HttpOnly, and SameSite config are enabled', $evidence];
        }

        return [false, 'Cookie Secure, HttpOnly, or SameSite config is incomplete', $evidence];
    }

    private function loadArray(string $relativeFile): array
    {
        $file = $this->ctx->abs($relativeFile);
        // Keep the legacy include scope and evaluation frequency for executable configs.
        return $this->collectors->php->load($file, $relativeFile, function () use ($file, $relativeFile): mixed {
            return @include $file;
        });
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

    private function httpsConfigPaths(string $key): array
    {
        return array_values(array_unique([
            'system.default.web.secure.' . $key,
            'system/default/web/secure/' . $key,
            'web.secure.' . $key,
            'web/secure/' . $key,
            'default.web.secure.' . $key,
            'default/web/secure/' . $key,
        ]));
    }

    private function cookieConfigPaths(string $key): array
    {
        $sessionKey = $key === 'samesite' ? 'samesite' : $key;
        $webCookieKey = $key === 'httponly' ? 'cookie_httponly' : ($key === 'secure' ? 'cookie_secure' : 'cookie_samesite');

        return array_values(array_unique([
            'session.cookie.' . $sessionKey,
            'session/cookie/' . $sessionKey,
            'system.default.session.cookie.' . $sessionKey,
            'system/default/session/cookie/' . $sessionKey,
            'system.default.web.cookie.' . $webCookieKey,
            'system/default/web/cookie/' . $webCookieKey,
            'web.cookie.' . $webCookieKey,
            'web/cookie/' . $webCookieKey,
        ]));
    }

    private function firstConfigValue(array $files, array $paths): array
    {
        foreach ($files as $file) {
            if (!is_scalar($file)) {
                continue;
            }
            $relativeFile = (string)$file;
            $arr = $this->loadArray($relativeFile);
            if (isset($arr['__ERROR__'])) {
                continue;
            }
            [$path, $value] = $this->firstExistingPath($arr, $paths);
            if ($path !== null) {
                return [$path, $value, $relativeFile];
            }
        }

        return [null, null, null];
    }

    private function httpsRedirectEvidence(string $base, int $timeoutMs): array
    {
        $http = preg_replace('~^https://~i', 'http://', $base);
        if (!preg_match('~^http://~i', (string)$http)) {
            $http = 'http://' . preg_replace('~^https?://~i', '', $base);
        }

        [$ok, $msg, $ev] = $this->fetch((string)$http, 'GET', [], $timeoutMs, true);
        if ($ok === null || $ok === false) {
            return ['ok' => false, 'request_url' => $http, 'message' => $msg, 'evidence' => $ev];
        }

        $finalUrl = (string)($ev['final_url'] ?? '');
        $sameHost = parse_url((string)$http, PHP_URL_HOST) === parse_url($finalUrl, PHP_URL_HOST);
        $redirectOk = preg_match('~^https://~i', $finalUrl) === 1 && $sameHost;

        return [
            'ok' => $redirectOk,
            'request_url' => $http,
            'final_url' => $finalUrl,
            'status' => $ev['status'] ?? null,
            'same_host' => $sameHost,
        ];
    }

    private function baseUrl(): string
    {
        if (strtoupper((string)($this->ctx->get('meta',[])['target_mode']??'LOCAL')) !== 'REMOTE'
            && \Magebean\Engine\ScanTargetResolver::isMagentoRoot($this->ctx->path)) {
            return (string)($this->configuredBaseUrl()['url']??'');
        }
        $url = (string)$this->ctx->get('url', '');
        if (($url === '' || $url === '.') && strtoupper((string)($this->ctx->get('meta',[])['target_mode']??'LOCAL')) !== 'REMOTE') {
            $url = (string)($this->configuredBaseUrl()['url'] ?? '');
        }
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
