<?php

declare(strict_types=1);

namespace Magebean\Engine\Checks;

use Magebean\Engine\Context;
use Magebean\Engine\Collectors\CollectorSet;

final class HttpCheck
{
    private Context $ctx;
    private CollectorSet $collectors;
    private int $transportOk = 0;
    private int $transportTotal = 0;
    private bool $strictScope = false;
    private MagentoCheck $magento;
    private ?string $resolvedBaseUrl = null;

    public function __construct(Context $ctx, ?CollectorSet $collectors = null)
    {
        $this->ctx = $ctx;
        $this->collectors = $collectors ?? new CollectorSet();
        $this->magento = new MagentoCheck($ctx, $this->collectors);
    }

    public function stub(array $args): array
    {
        return [true, 'HttpCheck stub PASS'];
    }

    /** Dispatch http_* checks */
    public function dispatch(string $name, array $args): array
    {
        $this->strictScope = !empty($args['strict_scope']);
        return match ($name) {
            'http_force_https_redirect'              => $this->forceHttpsRedirect($args),
            'http_has_hsts'                          => $this->hasHsts($args),
            'http_no_mixed_content'                  => $this->noMixedContent($args),
            'http_cookie_flags'                      => $this->cookieFlags($args),
            'http_no_directory_listing'              => $this->noDirectoryListing($args),
            'http_no_public_artifacts'               => $this->noPublicArtifacts($args),
            'http_no_stacktrace'                     => $this->noStacktrace($args),
            'http_no_xdebug_headers'                 => $this->noXdebugHeaders($args),
            'http_admin_path_heuristics'             => $this->adminPathHeuristics($args),
            'http_magento_fingerprint'               => $this->magentoFingerprint($args),

            'http_header_equals'                     => $this->headerEquals($args),
            'http_header_in'                         => $this->headerIn($args),
            'http_header_absent'                     => $this->headerAbsent($args),

            'http_clickjacking_protection'           => $this->clickjackingProtection($args),
            'http_csp_present_min'                   => $this->cspPresent($args),
            'http_csp_not_overly_permissive'         => $this->cspNotOverlyPermissive($args),

            'http_cors_no_wildcard_with_credentials' => $this->corsNoWildcardWithCreds($args),
            'http_cors_preflight_safe'               => $this->corsPreflightSafe($args),

            'http_tls_min_version'                   => $this->tlsMinVersion($args),
            'http_tls_cert_days_left'                => $this->tlsCertDaysLeft($args),
            'http_hsts_preload_ready'                => $this->hstsPreloadReady($args),

            'http_method_disallowed'                 => $this->methodDisallowed($args),
            'http_options_not_overly_verbose'        => $this->optionsNotVerbose($args),
            'http_server_banner_not_verbose'         => $this->serverBannerNotVerbose($args),

            'http_block_path'                        => $this->blockPath($args),
            'http_graphql_introspection_disabled'    => $this->graphqlIntrospectionDisabled($args),
            'http_rest_sensitive_endpoints_closed'   => $this->restSensitiveEndpointsClosed($args),

            'http_static_assets_deployed'            => $this->staticAssetsDeployed($args),
            'http_cache_signals'                     => $this->cacheSignals($args),
            'http_logs_protected'                    => $this->logsProtected($args),
            'http_csrf_form_key_signal'              => $this->csrfFormKeySignal($args),
            'http_no_vcs_misc'                       => $this->noVcsMisc($args),
            'http_third_party_links_https'           => $this->thirdPartyLinksHttps($args),
            'http_no_debug_endpoints'                => $this->noDebugEndpoints($args),
            'http_payment_tls_min'                   => $this->paymentTlsMin($args),

            default => [false, 'Unknown HttpCheck: ' . $name],
        };
    }

    public function getTransportCounts(): array
    {
        return [
            'ok'    => $this->transportOk,
            'total' => $this->transportTotal,
        ];
    }

    public function runtimeBaseUrl(): string
    {
        return $this->baseUrl();
    }

    private function baseUrl(): string
    {
        if (($this->ctx->get('meta', [])['launch_profile'] ?? null) === 'prelaunch') {
            return $this->ctx->url;
        }
        if (strtoupper((string)($this->ctx->get('meta',[])['target_mode']??'LOCAL')) !== 'REMOTE'
            && \Magebean\Engine\ScanTargetResolver::isMagentoRoot($this->ctx->path)) {
            return $this->resolvedBaseUrl ??= (string)($this->magento->configuredBaseUrl()['url'] ?? '');
        }
        $u = trim($this->ctx->url);
        if ($u === '' || $u === '.') $u = (string)$this->ctx->get('url', '');
        // URL discovery is shared by every local HTTP check, not a policy strictness option.
        if ($u === '.') $u = '';
        if ($u === '' && strtoupper((string)($this->ctx->get('meta',[])['target_mode']??'LOCAL')) !== 'REMOTE') {
            $this->resolvedBaseUrl ??= (string)($this->magento->configuredBaseUrl()['url'] ?? '');
            $u = $this->resolvedBaseUrl;
        }
        if ($u === '') return '';
        if (!preg_match('~^https?://~i', $u)) return '';
        return rtrim($u, '/');
    }

    private function bump(bool $ok): void
    {
        $this->transportTotal++;
        if ($ok) $this->transportOk++;
    }

    private function fetch(string $url, string $method = 'GET', array $headers = [], int $timeoutMs = 8000, bool $follow = true, ?string $requestBody = null): array
    {
        if (($this->ctx->get('meta', [])['launch_profile'] ?? null) === 'prelaunch') $follow = false;
        return $this->collectors->http->fetch($url, $method, $headers, $timeoutMs, $follow, $requestBody, function (bool $ok): void {
            $this->bump($ok);
        });
    }



    /** Safely get header value as string (use last when multiple) */
    private function hget(array $hdrs, string $key): string
    {
        $key = strtolower($key);
        if (!array_key_exists($key, $hdrs)) return '';
        $v = $hdrs[$key];
        if (is_array($v)) {
            $last = end($v);
            return is_string($last) ? $last : (string)$last;
        }
        return (string)$v;
    }

    private function forceHttpsRedirect(array $args): array
    {
        if (!empty($args['strict_scope'])) return $this->strictHttpsRedirect($args);
        $base = $this->baseUrl();
        if ($base === '') return [null, '[UNKNOWN] Runtime URL unavailable; no valid Magento store base URL could be read. Check store configuration and scanner read access'];

        // Always test HTTP entrypoint (no redirect follow)
        $http = preg_replace('~^https://~i', 'http://', $base);
        if (!preg_match('~^http://~i', $http)) {
            $http = 'http://' . preg_replace('~^https?://~i', '', $base);
        }

        [$ok, $msg, $ev] = $this->fetch($http, 'GET', [], (int)($args['timeout_ms'] ?? 8000), true);
        if ($ok === null) return [null, $msg, $ev];
        if (!$ok) return [false, $msg, $ev];

        $status  = (int)($ev['status'] ?? 0);
        $headers = array_change_key_case((array)($ev['headers'] ?? []), CASE_LOWER);
        $loc     = $this->hget($headers, 'location');
        $finalUrl = (string)($ev['final_url'] ?? '');

        $sameHost = parse_url($http, PHP_URL_HOST) === parse_url($finalUrl, PHP_URL_HOST);
        $isRedirect = preg_match('~^https://~i', $finalUrl) === 1 && $sameHost;

        $evidence = [
            'request_url' => $http,
            'status'      => $status,
            'location'    => $loc,
            'final_url'   => $finalUrl,
            'same_host'   => $sameHost,
        ];

        return [$isRedirect, $isRedirect ? 'HTTP redirected to HTTPS' : 'No HTTP→HTTPS redirect', $evidence];
    }

    /** Exact first-hop redirect predicate for explicitly observed storefront/backend entries. */
    private function strictHttpsRedirect(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [null, '[UNKNOWN] Runtime URL unavailable; no valid Magento store base URL could be read. Check store configuration and scanner read access', []];
        $paths = !empty($args['admin_only']) ? [] : ['/'];
        $unknown = false; $adminIssue = null;
        if (!empty($args['include_admin']) || !empty($args['admin_only'])) {
            $route = $args['admin_path'] ?? $this->ctx->get('admin_path');
            if ($route === null) {
                $admin = $this->magento->adminFrontNameDeclared([]);
                $route = $admin[2]['observed'] ?? null;
            }
            if (!is_string($route) || preg_match('~^/?([a-z0-9][a-z0-9_-]*)/?$~iD', $route, $match) !== 1) {
                $unknown = true;
                $adminIssue = 'Provide a single Admin route through admin_path or readable app/etc/env.php backend.frontName.';
            } else {
                $paths[] = '/' . $match[1] . '/';
            }
        }
        $checked = []; $failed = false;
        foreach ($paths as $path) {
            $url = $this->joinUrl(preg_replace('~^https://~i', 'http://', $base), $path);
            [$ok, $msg, $ev] = $this->fetch($url, 'GET', [], (int)($args['timeout_ms'] ?? 8000), false);
            $status = (int)($ev['status'] ?? 0);
            $location = $this->hget(array_change_key_case((array)($ev['headers'] ?? []), CASE_LOWER), 'location');
            $parts = parse_url($location);
            $valid = is_array($parts) && strtolower((string)($parts['scheme'] ?? '')) === 'https' &&
                strtolower((string)($parts['host'] ?? '')) === strtolower((string)parse_url($url, PHP_URL_HOST)) && !isset($parts['user']) && !isset($parts['pass']);
            $checked[] = ['request_url' => $url, 'status' => $status, 'location' => $location, 'https_redirect' => $valid] + ($ok !== true ? ['transport_error' => $msg, 'reason_code' => $ev['reason_code'] ?? 'HTTP_TRANSPORT_FAILED', 'action' => $ev['action'] ?? 'Verify scanner connectivity to this HTTP entrypoint.'] : []);
            if ($ok !== true || $status === 429 || $status >= 500 || $status <= 0) { $unknown = true; continue; }
            if (!in_array($status, [301,302,303,307,308], true) || !$valid) $failed = true;
        }
        $evidence = ['scope' => 'first_hop_observed_entrypoints', 'checked' => $checked, 'admin_route_issue' => $adminIssue];
        if ($failed) return [false, 'Observed HTTP entrypoint does not redirect directly to same-host HTTPS', $evidence];
        if ($unknown) return [null, '[UNKNOWN] HTTP redirect probes are incomplete', $evidence + ['action' => 'Inspect each checked entrypoint/status below; restore HTTP port reachability, resolve rate limiting or server errors, then rerun.']];
        return [true, 'Observed storefront/admin HTTP entrypoints redirect directly to same-host HTTPS', $evidence];
    }

    private function hasHsts(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [null, '[UNKNOWN] Runtime URL unavailable; no valid Magento store base URL could be read. Check store configuration and scanner read access'];
        $url = preg_replace('~^http://~i', 'https://', $base);
        [$ok, $msg, $ev] = $this->fetch((string)$url, 'GET', [], (int)($args['timeout_ms'] ?? 8000), true);
        if ($ok !== true) {
            $error = trim(preg_replace('/\[UNKNOWN\]\s*/i', '', $msg) ?? $msg);
            $message = ($ev['reason_code'] ?? '') === 'HTTP_TLS_TRUST_FAILED'
                ? 'TLS certificate verification failed; HSTS response was not inspected: '.$error
                : 'HSTS response was not inspected: '.$error;
            return [null, $message, $ev];
        }
        $final = (string)($ev['final_url'] ?? $url);
        $status = (int)($ev['status'] ?? 0);
        if ($status < 200 || $status >= 300 || strtolower((string)parse_url($final, PHP_URL_SCHEME)) !== 'https' || strtolower((string)parse_url($final, PHP_URL_HOST)) !== strtolower((string)parse_url((string)$url, PHP_URL_HOST))) return [null, '[UNKNOWN] HSTS probe requires a successful same-host HTTPS page; received HTTP ' . $status . ' at ' . $final . '. Verify the canonical HTTPS storefront in Magento store configuration.', $ev];

        return $this->assessHstsPolicy((array)($ev['headers'] ?? []), (string)$url, $final, $args);
    }

    private function assessHstsPolicy(array $observedHeaders, string $url, string $final, array $args): array
    {
        $headers = array_change_key_case( $observedHeaders, CASE_LOWER);
        $policies = $headers['strict-transport-security'] ?? [];
        $policies = is_array($policies) ? $policies : ($policies === '' ? [] : [$policies]);
        if (count($policies) > 1) return [false, 'Multiple HSTS headers are ambiguous; emit exactly one Strict-Transport-Security header.', ['observed'=>$policies]];
        $h = (string)($policies[0] ?? '');
        $directives = [];
        foreach (explode(';', $h) as $part) {
            $part = trim($part); if ($part === '') continue;
            if (!preg_match('~^([a-zA-Z][a-zA-Z0-9-]*)(?:\s*=\s*(.+))?$~', $part, $directive)) return [false, 'Malformed HSTS directive; configure a valid Strict-Transport-Security header.', ['observed'=>$h]];
            $key = strtolower($directive[1]);
            if (array_key_exists($key, $directives)) return [false, 'Duplicate HSTS directive; emit each directive once.', ['observed'=>$h]];
            $directives[$key] = $directive[2] ?? null;
        }
        foreach (['includesubdomains','preload'] as $flag) if (array_key_exists($flag, $directives) && $directives[$flag] !== null) return [false, 'Malformed HSTS flag; includeSubDomains and preload must not have values.', ['observed'=>$h]];
        $finalUrl = $final;
        $evidence = [
            'request_url' => $url,
            'final_url' => $finalUrl,
            'observed' => $h,
            'max_age' => null,
            'include_subdomains' => array_key_exists('includesubdomains', $directives),
            'preload' => array_key_exists('preload', $directives),
        ];

        if ($h === '') return [false, 'HSTS header missing', $evidence];
        if (preg_match('~^(?:([0-9]+)|\x22([0-9]+)\x22)$~', (string)($directives['max-age'] ?? ''), $m)) {
            $m[1] = ($m[1] ?? '') !== '' ? $m[1] : ($m[2] ?? '');
            $min = (int)($args['min_max_age'] ?? 31536000);
            $evidence['max_age'] = (int)$m[1];
            $evidence['min_max_age'] = $min;
            $maxAgeOk = ((int)$m[1] >= $min);
            $includeSubdomainsOk = !(bool)($args['require_include_subdomains'] ?? false) || $evidence['include_subdomains'];
            $preloadOk = !(bool)($args['require_preload'] ?? false) || $evidence['preload'];
            $ok2 = $maxAgeOk && $includeSubdomainsOk && $preloadOk;
            return [$ok2, $ok2 ? 'HSTS present' : 'HSTS policy is incomplete', $evidence];
        }
        return [false, 'HSTS header missing max-age', $evidence];
    }

    private function noMixedContent(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [null, '[UNKNOWN] Runtime URL unavailable; no valid Magento store base URL could be read. Check store configuration and scanner read access'];
        $paths = $args['paths'] ?? ['/'];
        if (!is_array($paths)) {
            $paths = ['/'];
        }

        $checked = [];
        $offenders = [];
        $successful = 0;
        $incomplete = [];
        foreach ($paths as $path) {
            if (!is_scalar($path)) {
                continue;
            }
            $url = $this->joinUrl($base, (string)$path);
            [$ok, $msg, $ev] = $this->fetch($url, 'GET', [], (int)($args['timeout_ms'] ?? 8000), true);
            if ($ok === null) {
                $entry = ['url' => $url, 'ok' => null, 'message' => $msg, 'evidence' => $ev];
                $checked[] = $entry;
                $incomplete[] = $entry;
                continue;
            }
            if (!$ok) {
                $entry = ['url' => $url, 'ok' => false, 'message' => $msg, 'evidence' => $ev];
                $checked[] = $entry;
                $incomplete[] = $entry;
                continue;
            }

            if (!empty($args['strict_scope']) && ((int)($ev['status'] ?? 0) !== 200 || !str_starts_with(strtolower((string)($ev['final_url'] ?? $url)), 'https://'))) {
                $incomplete[] = ['url' => $url, 'reason' => 'Mixed-content probe requires a successful HTTPS page'];
                continue;
            }
            $successful++;
            $body = (string)($ev['body'] ?? '');
            $pageOffenders = $this->mixedContentInMarkup(!empty($args['strict_scope']) ? (preg_replace('~(<script\b[^>]*>)[\s\S]*?(</script>)~i', '$1$2', $body) ?? $body) : $body);
            $checked[] = ['url' => $url, 'ok' => true, 'status' => $ev['status'] ?? null, 'final_url' => $ev['final_url'] ?? null];
            foreach ($pageOffenders as $offender) {
                $offender['page_url'] = $url;
                $offenders[] = $offender;
            }
        }

        if ($offenders !== []) {
            return [false, 'Mixed content (http://) detected in rendered markup', ['offenders' => $offenders, 'checked' => $checked]];
        }
        if ($checked === []) {
            return [null, '[UNKNOWN] No pages checked for mixed content', []];
        }
        if ($successful === 0) {
            return [null, '[UNKNOWN] Unable to fetch any page for mixed content check', ['checked' => $checked]];
        }
        if ($incomplete !== []) {
            return [null, '[UNKNOWN] Mixed content check had incomplete HTTP coverage', ['checked' => $checked]];
        }

        return [true, 'No mixed content in rendered markup', ['checked' => $checked]];
    }

    private function mixedContentInMarkup(string $body): array
    {
        $offenders = [];
        $body = preg_replace('~<!--[\s\S]*?-->~', '', $body) ?? $body;
        $patterns = [
            'html_attr' => '~<(?:script|img|iframe|frame|link|audio|video|source|track|embed|object|input|form)\b[^>]*?\b(?:href|src|action|data|data-src|formaction|poster|srcset|data-srcset)\s*=\s*([\'"])(?P<url>[^\'"]*http://[^\'"]+)\1~i',
            'css_url' => '~url\(\s*([\'"]?)(?P<url>http://[^\'")\s]+)\1\s*\)~i',
        ];
        foreach ($patterns as $kind => $regex) {
            $count = preg_match_all($regex, $body, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER);
            if ($count === false || $count < 1) {
                continue;
            }
            foreach ($matches as $match) {
                $url = isset($match['url']) && is_array($match['url']) ? (string)$match['url'][0] : '';
                $offenders[] = [
                    'kind' => $kind,
                    'url' => $url,
                    'snippet' => trim(substr((string)$match[0][0], 0, 240)),
                ];
            }
        }

        return $offenders;
    }

    private function joinUrl(string $base, string $path): string
    {
        if (preg_match('~^https?://~i', $path) === 1) {
            return $path;
        }

        return rtrim($base, '/') . '/' . ltrim($path, '/');
    }

    private function assessCookieFlags(string $cookie, array $sensitive, array $allowedSameSite, array $clientReadable): ?array
    {
        $parts = explode(';', $cookie);
        if ($parts === []) {
            return null;
        }
        [$name,] = array_map('trim', explode('=', $parts[0], 2));
        $lname = strtolower($name);
        if (in_array($lname, $clientReadable, true)) {
            return null;
        }
        if (!in_array($lname, $sensitive, true) && !str_contains($lname, 'sess') && !str_contains($lname, 'admin')) {
            return null;
        }

        $attributes = array_map(static fn(string $part): string => strtolower(trim($part)), array_slice($parts, 1));
        $hasSecure = in_array('secure', $attributes, true);
        $hasHttpOnly = in_array('httponly', $attributes, true);
        $sameSite = null;
        foreach ($parts as $part) {
            $part = trim($part);
            if (stripos($part, 'samesite=') === 0) {
                $sameSite = strtolower(substr($part, 9));
                break;
            }
        }

        $sameSiteOk = $sameSite !== null && in_array($sameSite, $allowedSameSite, true);
        $ok = $hasSecure && $hasHttpOnly && $sameSiteOk;
        $missing = [];
        if (!$hasSecure) {
            $missing[] = 'secure';
        }
        if (!$hasHttpOnly) {
            $missing[] = 'httponly';
        }
        if (!$sameSiteOk) {
            $missing[] = 'samesite';
        }

        return [
            'name' => $name,
            'secure' => $hasSecure,
            'httponly' => $hasHttpOnly,
            'samesite' => $sameSite,
            'ok' => $ok,
            'missing' => $missing,
        ];
    }

    private function cookieFlags(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [null, '[UNKNOWN] Runtime URL unavailable; no valid Magento store base URL could be read. Check store configuration and scanner read access', []];
        $paths = $args['paths'] ?? ['/', '/customer/account/login', '/checkout/cart'];
        if (!is_array($paths)) {
            $paths = ['/'];
        }

        // Only enforce flags on sensitive cookies
        $sensitive = $args['sensitive_cookies'] ?? [
            'phpsessid',
            'admin',
            'adminhtml',
            'backend',
            'frontend',
            'frontend_cid',
        ];
        if (!is_array($sensitive)) {
            $sensitive = [];
        }
        $sensitive = array_map(static fn(mixed $value): string => strtolower((string)$value), $sensitive);
        $clientReadable = $args['client_readable_cookies'] ?? [
            'form_key',
            'store',
            'private_content_version',
            'mage-cache-sessid',
            'mage-cache-storage',
            'mage-cache-storage-section-invalidation',
            'section_data_ids',
        ];
        if (!is_array($clientReadable)) {
            $clientReadable = [];
        }
        $clientReadable = array_map(static fn(mixed $value): string => strtolower((string)$value), $clientReadable);
        $allowedSameSite = $args['allowed_samesite'] ?? ['lax', 'strict'];
        if (!is_array($allowedSameSite)) {
            $allowedSameSite = ['lax', 'strict'];
        }
        $allowedSameSite = array_map(static fn(mixed $value): string => strtolower((string)$value), $allowedSameSite);

        $allOk = true;
        $checked = [];
        $successful = 0;
        $incomplete = [];
        $observedSensitive = [];
        $failures = [];

        foreach ($paths as $path) {
            if (!is_scalar($path)) {
                continue;
            }
            $url = $this->joinUrl($base, (string)$path);
            [$ok, $msg, $ev] = $this->fetch($url, 'GET', [], (int)($args['timeout_ms'] ?? 8000), true);
            if ($ok === null || !$ok) {
                $entry = ['url' => $url, 'ok' => $ok, 'message' => $msg, 'evidence' => $ev];
                $checked[] = $entry;
                $incomplete[] = $entry;
                continue;
            }

            if (!empty($args['strict_scope']) && ((int)($ev['status'] ?? 0) !== 200 || strtolower((string)parse_url((string)($ev['final_url'] ?? $url), PHP_URL_SCHEME)) !== 'https' || strtolower((string)parse_url((string)($ev['final_url'] ?? $url), PHP_URL_HOST)) !== strtolower((string)parse_url($url, PHP_URL_HOST)))) {
                $incomplete[] = ['url' => $url, 'reason' => 'Cookie probe needs a successful same-host HTTPS response'];
                continue;
            }
            $successful++;
            $hdrs = array_change_key_case((array)($ev['headers'] ?? []), CASE_LOWER);
            $setCookies = $hdrs['set-cookie'] ?? [];
            if (!is_array($setCookies)) $setCookies = $setCookies !== '' ? [$setCookies] : [];
            $checked[] = ['url' => $url, 'ok' => true, 'status' => $ev['status'] ?? null, 'final_url' => $ev['final_url'] ?? null, 'set_cookie_count' => count($setCookies)];

            foreach ($setCookies as $cookie) {
                $assessment = $this->assessCookieFlags((string)$cookie, $sensitive, $allowedSameSite, $clientReadable);
                if ($assessment === null) {
                    continue;
                }
                $assessment['page_url'] = $url;
                $observedSensitive[] = $assessment;
                if (!$assessment['ok']) {
                    $allOk = false;
                    $failures[] = $assessment;
                }
            }
        }

        $evidence = [
            'checked' => $checked,
            'sensitive_cookies' => $observedSensitive,
            'failures' => $failures,
            'allowed_samesite' => $allowedSameSite,
            'client_readable_cookies' => $clientReadable,
            'incomplete_paths' => $incomplete,
        ];
        if ($successful === 0) {
            return [null, '[UNKNOWN] Unable to inspect cookies. Verify the discovered store URL, network access and the HTTPS trust chain. Probe errors: ' . implode('; ', array_map(static fn(array $entry): string => ($entry['url'] ?? '') . ': ' . ($entry['message'] ?? $entry['reason'] ?? 'Unavailable response'), $incomplete)), $evidence];
        }
        if ($observedSensitive === []) {
            return [null, '[UNKNOWN] No session/authentication cookies observed; provide a reachable session-creating page or inspect declared Magento cookie settings. No Set-Cookie does not prove protection.', $evidence];
        }
        if ($incomplete !== [] && $failures === []) {
            return [null, '[UNKNOWN] Cookie flag check had incomplete HTTP coverage', $evidence];
        }

        return [$allOk, $allOk ? 'Sensitive cookies have Secure/HttpOnly/SameSite' : 'Cookie flags missing on sensitive cookies', $evidence];
    }

    private function noDirectoryListing(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [null, '[UNKNOWN] Runtime URL unavailable; no valid Magento store base URL could be read. Check store configuration and scanner read access'];
        $paths = $args['paths'] ?? ['/media/', '/static/', '/errors/', '/var/'];
        $timeout = (int)($args['timeout_ms'] ?? 8000);
        $probed = 0;
        $unknowns = [];
        $checked = [];

        foreach ($paths as $p) {
            [$ok, $msg, $ev] = $this->fetch($this->joinUrl($base, (string)$p), 'GET', [], $timeout, true);
            if ($ok === null) {
                $unknowns[] = ['path' => $p, 'reason' => $msg, 'evidence' => $ev];
                continue;
            }
            if (!$ok) {
                $unknowns[] = ['path' => $p, 'reason' => $msg, 'evidence' => $ev];
                continue;
            }

            $probed++;
            $checked[] = ['path'=>$p, 'status'=>$ev['status']??null, 'final_url'=>$ev['final_url']??null];
            $status = (int)($ev['status'] ?? 0);
            $headers = array_change_key_case((array)($ev['headers'] ?? []), CASE_LOWER);
            $b = strtolower(substr((string)($ev['body'] ?? ''), 0, 8192));
            $contentType = strtolower($this->hget($headers, 'content-type'));

            $matchedSignature = null;
            if (!empty($args['strict_scope']) && strtolower((string)parse_url((string)($ev['final_url'] ?? $this->joinUrl($base, (string)$p)), PHP_URL_HOST)) !== strtolower((string)parse_url($base, PHP_URL_HOST))) {
                $unknowns[] = ['path'=>$p, 'reason'=>'Directory probe redirected outside the deployment host'];
                continue;
            }
            if (!empty($args['strict_scope']) && !in_array($status, [200, 401, 403, 404, 405, 410], true)) {
                $unknowns[] = ['path' => $p, 'reason' => 'Unassessable HTTP status ' . $status];
                continue;
            }
            if ($status === 200) {
                $signatures = [
                    'index of /',
                    'directory listing for',
                    '<title>index of ',
                    '<h1>index of ',
                    '<pre><a href=',
                ];
                if (!empty($args['strict_scope'])) $signatures = ['<title>index of ', '<h1>index of ', '<title>directory listing for'];
                foreach ($signatures as $signature) {
                    if (str_contains($b, $signature)) {
                        $matchedSignature = $signature;
                        break;
                    }
                }
            }

            if ($matchedSignature !== null) {
                return [
                    false,
                    'Directory listing enabled at ' . $p,
                    [
                        'path' => $p,
                        'status' => $status,
                        'content_type' => $contentType,
                        'final_url' => $ev['final_url'] ?? null,
                        'matched_signature' => $matchedSignature,
                    ]
                ];
            }
        }

        if ($probed === 0) {
            return [null, '[UNKNOWN] Could not verify directory listing on any configured path', $unknowns];
        }

        if ($unknowns !== []) {
            return [null, '[UNKNOWN] Directory listing probes failed: ' . implode('; ', array_map(static fn(array $entry): string => $entry['path'] . ': ' . $entry['reason'], $unknowns)), [
                'probed' => $probed,
                'unknown_paths' => $unknowns,
                'checked' => $checked,
            ]];
        }

        return [true, 'No directory listing detected in common paths', ['probed' => $probed, 'checked' => $checked]];
    }

    private function noPublicArtifacts(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [false, 'Missing URL in context'];

        $paths = $args['paths'] ?? [
            '/.git/HEAD',
            '/.env',
            '/composer.json',
            '/var/report/',
            '/var/log/exception.log',
            '/backup.zip',
            '/dump.sql',
        ];
        $timeout = (int)($args['timeout_ms'] ?? 8000);

        $allowStatuses = [401, 403, 404, 405, 410, 301, 302, 307, 308];

        foreach ($paths as $p) {
            [$ok, $msg, $ev] = $this->fetch($base . $p, 'GET', [], $timeout, false);
            if ($ok === null) continue;
            if (!$ok) continue;

            $status = (int)($ev['status'] ?? 0);
            $hdrs   = array_change_key_case((array)($ev['headers'] ?? []), CASE_LOWER);
            $body   = (string)($ev['body'] ?? '');
            $ctype  = strtolower($this->hget($hdrs, 'content-type'));
            $server = strtolower($this->hget($hdrs, 'server'));

            if (in_array($status, $allowStatuses, true)) continue;

            if ($status === 200) {
                // WAF/CDN challenge -> UNKNOWN (do not count as FAIL)
                if (
                    (str_contains($server, 'cloudflare') || str_contains($server, 'akamai') || str_contains($server, 'fastly'))
                    && stripos($body, 'attention required') !== false
                ) {
                    return [null, '[UNKNOWN] WAF challenge on ' . $p, ['path' => $p, 'status' => $status]];
                }

                // Soft-404: small HTML with not found/forbidden/error
                $soft404 = false;
                if (str_contains($ctype, 'text/html')) {
                    $b = strtolower(substr($body, 0, 4096));
                    $soft404 = (strlen($body) < 8192) && (
                        str_contains($b, 'not found') || str_contains($b, 'forbidden') || str_contains($b, 'error')
                    );
                }
                if ($soft404) continue;

                // Real exposure signatures
                $exposed = false;
                if ($p === '/.git/HEAD') {
                    $exposed = (strncmp($body, 'ref: refs/', 9) === 0);
                } elseif ($p === '/.env') {
                    $lb = strtolower($body);
                    $exposed = (str_contains($lb, 'app_env=') || str_contains($lb, 'db_password=') || str_contains($lb, 'secret='));
                } elseif ($p === '/composer.json') {
                    $exposed = (preg_match('~^\s*\{\s*\"name\"\s*:\s*\"~', $body) === 1);
                } elseif (str_ends_with($p, '/') && stripos($body, 'Index of /') !== false) {
                    $exposed = true; // directory index
                } else {
                    if (preg_match('~^(PK\x03\x04|SQL|-- MySQL dump)~', $body) === 1) $exposed = true;
                }

                if ($exposed) {
                    return [false, 'Public artifact exposed: ' . $p, ['path' => $p, 'status' => $status]];
                }
            }
        }

        return [true, 'No public artifacts exposed', []];
    }

    private function noStacktrace(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [null, '[UNKNOWN] Runtime URL unavailable; no valid Magento store base URL could be read. Check store configuration and scanner read access', []];

        $targets = [];
        $targets[] = rtrim($base, '/'); // home
        // 404 thử nghiệm
        $targets[] = rtrim($base, '/') . '/__mb-not-exist-' . time();
        // (tuỳ chọn) trang search đơn giản
        $targets[] = rtrim($base, '/') . '/search?q=test';

        $pattern = '~(Stack trace:|Fatal error:|Uncaught (?:Exception|Error)|'
            . ' in /[A-Za-z0-9._/\-]+\.php on line \d+|'
            . ' at /[A-Za-z0-9._/\-]+\.php:\d+|'
            . '<b>(?:Warning|Notice)</b>:.{0,240} in /[A-Za-z0-9._/\-]+\.php on line \d+)~i';

        $checked = [];
        $successful = 0;
        foreach ($targets as $u) {
            [$ok, $msg, $ev] = $this->fetch($u, 'GET', ['Accept: text/html'], (int)($args['timeout_ms'] ?? 8000), true);
            if ($ok !== true) {
                $checked[] = ['url' => $u, 'ok' => $ok, 'message' => $msg, 'evidence' => $ev];
                continue;
            }
            $successful++;

            $hdrs = array_change_key_case((array)($ev['headers'] ?? []), CASE_LOWER);
            $ctype = strtolower($this->hget($hdrs, 'content-type'));
            $entry = ['url' => $u, 'ok' => true, 'status' => $ev['status'] ?? null, 'final_url' => $ev['final_url'] ?? null, 'content_type' => $ctype];
            if ($ctype && stripos($ctype, 'text/html') === false) {
                $checked[] = $entry + ['skipped' => 'non_html'];
                continue;
            }

            $body = (string)($ev['body'] ?? '');
            // Loại trừ trang WAF/challenge
            $waf = preg_match('~(cloudflare|akamai|fastly|sucuri|incapsula|varnish|attention required|error reference number)~i', substr($body, 0, 8192)) === 1;
            if ($waf) {
                $checked[] = $entry + ['skipped' => 'waf_challenge'];
                continue;
            }

            $checked[] = $entry;

            if (preg_match($pattern, $body) === 1) {
                return [false, 'Error/stack trace visible on pages', ['url' => $u, 'checked' => $checked]];
            }
        }

        if ($successful === 0) {
            return [null, '[UNKNOWN] Unable to fetch any page for stack trace check', ['checked' => $checked]];
        }

        return [true, 'No error traces observed', ['checked' => $checked]];
    }


    private function noXdebugHeaders(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [null, '[UNKNOWN] Runtime URL unavailable; no valid Magento store base URL could be read. Check store configuration and scanner read access', []];
        [$ok, $msg, $ev] = $this->fetch($base, 'GET', [], (int)($args['timeout_ms'] ?? 8000), false);
        if ($ok === null) return [null, $msg, $ev];
        if (!$ok) return [false, $msg, $ev];
        $h = array_change_key_case((array)($ev['headers'] ?? []), CASE_LOWER);
        $keys = is_array($h) ? array_keys($h) : [];
        $badKeys = array_filter($keys, static function ($key): bool {
            $key = strtolower((string)$key);
            return in_array($key, [
                'x-debug-token',
                'x-debug-token-link',
                'x-phpdebug',
            ], true) || str_contains($key, 'xdebug');
        });
        $ok2 = empty($badKeys);
        return [
            $ok2,
            $ok2 ? 'No debug headers' : 'Debug headers present: ' . implode(', ', $badKeys),
            $ok2 ? [] : ['debug_headers' => array_values($badKeys)],
        ];
    }

    private function adminPathHeuristics(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [false, 'Missing URL in context'];
        $candidates = $args['paths'] ?? ['/admin/', '/backend/', '/index.php/admin/'];
        foreach ($candidates as $p) {
            [$ok, $msg, $ev] = $this->fetch($base . rtrim($p, '/') . '/', 'GET', [], (int)($args['timeout_ms'] ?? 8000), false);
            if ($ok === null) continue;
            if (!$ok) continue;

            $status = (int)($ev['status'] ?? 0);
            $b = strtolower((string)($ev['body'] ?? ''));

            // 401/403 -> treated as protected
            if (in_array($status, [401, 403], true)) continue;

            // Consider exposed only when 200 + strong admin login signals
            $strong =
                (str_contains($b, 'name="login[username]"') || str_contains($b, 'name="login[password]"')) ||
                preg_match('~<title>.*admin.*</title>~i', $b) === 1 ||
                str_contains($b, 'Magento Admin');

            if ($status === 200 && $strong) {
                return [false, 'Admin path appears exposed: ' . $p, ['path' => $p, 'status' => $status]];
            }
        }
        return [true, 'No obvious admin path exposure', []];
    }

    private function magentoFingerprint(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') {
            return [null, '[UNKNOWN] Missing URL in context', []];
        }

        $timeout = (int)($args['timeout_ms'] ?? 8000);
        [$ok, $msg, $ev] = $this->fetch($base, 'GET', [], $timeout, true);
        if ($ok === null) {
            return [null, $msg, $ev];
        }
        if (!$ok) {
            return [false, $msg, $ev];
        }

        $hdrs = array_change_key_case((array)($ev['headers'] ?? []), CASE_LOWER);
        $body = (string)($ev['body'] ?? '');
        $normalizedBody = html_entity_decode($body, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $normalizedBody = str_replace(['\\/', '&#x2F;', '&#47;'], '/', $normalizedBody);

        $cloudflareMitigation = strtolower($this->hget($hdrs, 'cf-mitigated'));
        $cloudflareChallenge = $cloudflareMitigation === 'challenge'
            || str_contains($normalizedBody, '/cdn-cgi/challenge-platform/')
            || str_contains($normalizedBody, 'Enable JavaScript and cookies to continue');
        if ($cloudflareChallenge) {
            return [
                null,
                '[UNKNOWN] Cloudflare managed challenge blocked Magento 2 fingerprinting',
                [
                    'request_url' => $base,
                    'final_url' => (string)($ev['final_url'] ?? $base),
                    'status' => (int)($ev['status'] ?? 0),
                    'blocked_by' => 'cloudflare_managed_challenge',
                    'cf_ray' => $this->hget($hdrs, 'cf-ray'),
                ],
            ];
        }

        $signals = [];
        foreach (['x-magento-tags', 'x-magento-cache-debug', 'x-magento-vary'] as $header) {
            if (array_key_exists($header, $hdrs)) {
                $signals[] = 'response_header:' . $header;
            }
        }
        if (preg_match('~mage-cache-storage|mage-cache-sessid|Magento_Customer/js/customer-data~i', $normalizedBody) === 1) {
            $signals[] = 'magento_frontend_markup';
        }
        if (preg_match('~text/x-magento-init|data-mage-init|Magento_Ui/js|Magento_Theme/js~i', $normalizedBody) === 1) {
            $signals[] = 'magento_js_bootstrap';
        }
        if (preg_match('~/static/version\\d+/|/static/_cache/merged/|Luma-Icons\\.(?:woff2|woff|ttf)~i', $normalizedBody) === 1) {
            $signals[] = 'magento_static_asset';
        }
        if (preg_match('~/static/(?:version\\d+/)?frontend/[^"\'<>\\s?]+/(?:[a-z]{2}_[a-z]{2})/~i', $normalizedBody) === 1) {
            $signals[] = 'magento_frontend_theme';
        }
        if (preg_match('~/static/(?:version\\d+/)?frontend/[^"\'<>\\s?]+/[a-z]{2}_[a-z]{2}/css/[^"\'<>\\s?]+\\.css~i', $normalizedBody) === 1) {
            $signals[] = 'magento_css_asset_path';
        }
        if (
            preg_match(
                '~(?:src|href)=["\'][^"\']*(?:requirejs/require(?:\\.min)?\\.js|requirejs-config\\.js|mage/requirejs/mixins\\.js|mage/bootstrap\\.js|Magento_[A-Za-z0-9_]+/js/[^"\']+\\.js)~i',
                $normalizedBody
            ) === 1
        ) {
            $signals[] = 'magento_js_asset_path';
        }
        $signals = array_values(array_unique($signals));

        $version = null;
        $versionPattern = '~Magento(?:\\s+(?:Open Source|Commerce))?[/\\s:]+(2\\.\\d+\\.\\d+(?:-p\\d+)?)~i';
        $versionHeader = $this->hget($hdrs, 'x-magento-version');
        if ($versionHeader !== '' && preg_match('~(2\\.\\d+\\.\\d+(?:-p\\d+)?)~', $versionHeader, $matches) === 1) {
            $version = $matches[1];
            $signals[] = 'response_header:x-magento-version';
        } elseif (preg_match($versionPattern, $body, $matches) === 1) {
            $version = $matches[1];
            $signals[] = 'public_version_markup';
        }

        if ($version === null) {
            $versionUrl = $this->joinUrl($base, '/magento_version');
            [$versionOk, , $versionEvidence] = $this->fetch($versionUrl, 'GET', [], $timeout, true);
            $versionBody = (string)($versionEvidence['body'] ?? '');
            if (
                $versionOk === true
                && (int)($versionEvidence['status'] ?? 0) === 200
                && preg_match($versionPattern, $versionBody, $matches) === 1
            ) {
                $version = $matches[1];
                $signals[] = 'public_endpoint:/magento_version';
            }
        }

        $confirmed = $signals !== [];
        $evidence = [
            'request_url' => $base,
            'final_url' => (string)($ev['final_url'] ?? $base),
            'status' => (int)($ev['status'] ?? 0),
            'signals' => array_values(array_unique($signals)),
            'version' => $version,
        ];

        if (!$confirmed) {
            return [false, 'Magento 2 fingerprint not found in the public response', $evidence];
        }

        $message = $version !== null
            ? 'Magento 2 confirmed (version ' . $version . ')'
            : 'Magento 2 confirmed; version is not publicly exposed';

        return [true, $message, $evidence];
    }

    // === Additional generic header checks ===
    private function headerEquals(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [false, 'Missing URL in context'];
        $header = strtolower((string)($args['header'] ?? ''));
        $expected = (string)($args['equals'] ?? '');
        if ($header === '' || $expected === '') return [null, '[UNKNOWN] Missing header/equals', []];
        [$ok, $msg, $ev] = $this->fetch($base, 'GET', [], (int)($args['timeout_ms'] ?? 8000), false);
        if ($ok === null) return [null, $msg, $ev];
        if (!$ok) return [false, $msg, $ev];
        $hdrs = array_change_key_case((array)($ev['headers'] ?? []), CASE_LOWER);
        $val = $this->hget($hdrs, $header);
        $pass = strcasecmp($val, $expected) === 0;
        return [$pass, $pass ? "{$header}={$expected}" : "Header {$header} is '" . ($val !== '' ? $val : '<absent>') . "'", $ev];
    }

    private function headerIn(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [null, '[UNKNOWN] Runtime URL unavailable; no valid Magento store base URL could be read. Check store configuration and scanner read access', []];
        $header = strtolower((string)($args['header'] ?? ''));
        $allowed = (array)($args['allowed'] ?? []);
        if ($header === '' || !$allowed) return [null, '[UNKNOWN] Missing header/allowed', []];
        [$ok, $msg, $ev] = $this->fetch($base, 'GET', [], (int)($args['timeout_ms'] ?? 8000), false);
        if ($ok === null) return [null, $msg, $ev];
        if (!$ok) return [false, $msg, $ev];
        $hdrs = array_change_key_case((array)($ev['headers'] ?? []), CASE_LOWER);
        if (!array_key_exists($header, $hdrs)) return [false, "Header {$header} absent", $ev];
        $val = $this->hget($hdrs, $header);
        $pass = false;
        foreach ($allowed as $a) {
            if (strcasecmp($val, (string)$a) === 0) {
                $pass = true;
                break;
            }
        }
        return [$pass, $pass ? "Header ok: {$header}={$val}" : "Header {$header} not in allowed list ({$val})", $ev];
    }

    private function headerAbsent(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [false, 'Missing URL in context'];
        $header = strtolower((string)($args['header'] ?? ''));
        if ($header === '') return [null, '[UNKNOWN] Missing header', []];
        [$ok, $msg, $ev] = $this->fetch($base, 'GET', [], (int)($args['timeout_ms'] ?? 8000), false);
        if ($ok === null) return [null, $msg, $ev];
        if (!$ok) return [false, $msg, $ev];
        $hdrs = array_change_key_case((array)($ev['headers'] ?? []), CASE_LOWER);
        $absent = !array_key_exists($header, $hdrs);
        return [$absent, $absent ? "Header {$header} absent" : "Header {$header} present", $ev];
    }

    /** A transport response or redirect is not evidence about application headers. */
    private function responseAssessmentIssue(?bool $ok, string $message, array $evidence, string $url, string $purpose, bool $httpsRequired = false): ?array
    {
        if ($ok !== true) {
            $evidence['action'] ??= 'Check scanner DNS/network connectivity and certificate trust for the resolved URL, then rerun.';
            return [null, '[UNKNOWN] Cannot inspect ' . $purpose . ': ' . $message, $evidence];
        }
        $final = (string)($evidence['final_url'] ?? $url);
        $status = (int)($evidence['status'] ?? 0);
        $sameHost = strtolower((string)parse_url($final, PHP_URL_HOST)) === strtolower((string)parse_url($url, PHP_URL_HOST));
        if ($status < 200 || $status >= 300 || !$sameHost || ($httpsRequired && strtolower((string)parse_url($final, PHP_URL_SCHEME)) !== 'https')) {
            $evidence['action'] = 'Use the canonical ' . ($httpsRequired ? 'HTTPS ' : '') . 'storefront URL returning a successful page from this scanner; resolve redirects, access challenges or server errors first.';
            return [null, '[UNKNOWN] Cannot inspect ' . $purpose . ': HTTP ' . $status . ' at ' . $final . ' is not an assessable same-host ' . ($httpsRequired ? 'HTTPS ' : '') . 'application response.', $evidence];
        }
        return null;
    }

    // === Security headers / policies ===
    private function clickjackingProtection(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [null, '[UNKNOWN] Runtime URL unavailable; no valid Magento store base URL could be read. Check store configuration and scanner read access', []];
        [$ok, $msg, $ev] = $this->fetch($base, 'GET', [], (int)($args['timeout_ms'] ?? 8000), false);
        $issue = $this->responseAssessmentIssue($ok, $msg, $ev, $base, 'clickjacking headers', false);
        if ($issue !== null) return $issue;

        [$pass, $reason] = $this->assessClickjackingPolicy((array)($ev['headers'] ?? []));
        return [$pass, $reason, $ev + ['scope' => 'observed_response_framing_headers']];
    }

    private function assessClickjackingPolicy(array $headers): array
    {
        $headers = array_change_key_case($headers, CASE_LOWER);
        $xfo = $headers['x-frame-options'] ?? [];
        $xfo = is_array($xfo) ? $xfo : [$xfo];
        $xfoValid = count($xfo) === 1 && in_array(strtolower(trim((string)$xfo[0])), ['deny', 'sameorigin'], true);
        $policies = $headers['content-security-policy'] ?? [];
        $policies = is_array($policies) ? $policies : [$policies];
        if ($policies === []) return [$xfoValid, $xfoValid ? 'Valid X-Frame-Options protects the observed response' : 'Framing protection is missing'];
        if (count($policies) !== 1 || !is_string($policies[0])) return [false, 'A single unambiguous framing policy is required'];
        $ancestors = [];
        foreach (explode(';', $policies[0]) as $directive) {
            if (preg_match('~^\s*frame-ancestors(?:\s+(.*))?\s*$~iD', $directive, $match)) $ancestors[] = trim($match[1] ?? '');
        }
        if ($ancestors === []) return [$xfoValid, $xfoValid ? 'Valid X-Frame-Options protects the observed response' : 'Framing protection is missing'];
        if (count($ancestors) !== 1 || $ancestors[0] === '') return [false, 'CSP frame-ancestors is missing, empty or duplicated'];
        $tokens = preg_split('/\s+/', $ancestors[0]);
        if ($tokens === ["'none'"]) return [true, 'CSP frame-ancestors denies framing'];
        foreach ($tokens as $token) {
            if ($token === "'self'") continue;
            if (str_contains($token, '*') || !preg_match('~^https?://[a-z0-9.-]+(?::[0-9]{1,5})?/?$~iD', $token)) return [false, 'CSP frame-ancestors must name explicit origins or self; wildcard and scheme-wide sources are disallowed'];
            $parts = parse_url($token);
            if (!is_array($parts) || empty($parts['host']) || isset($parts['user']) || isset($parts['pass']) || (isset($parts['port']) && ($parts['port'] < 1 || $parts['port'] > 65535))) return [false, 'CSP frame-ancestors origin is malformed'];
        }
        return [true, 'CSP frame-ancestors limits framing to explicit origins'];
    }
    private function cspPresent(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [false, 'Missing URL in context'];
        [$ok, $msg, $ev] = $this->fetch($base, 'GET', [], (int)($args['timeout_ms'] ?? 8000), false);
        if ($ok === null) return [null, $msg, $ev];
        if (!$ok) return [false, $msg, $ev];
        $h = array_change_key_case((array)($ev['headers'] ?? []), CASE_LOWER);
        $csp = trim($this->hget($h, 'content-security-policy'));
        $pass = ($csp !== '');
        return [$pass, $pass ? 'CSP present' : 'CSP header absent', $ev];
    }

    private function cspNotOverlyPermissive(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [null, '[UNKNOWN] Runtime URL unavailable; no valid Magento store base URL could be read. Check store configuration and scanner read access', []];
        [$ok, $msg, $ev] = $this->fetch($base, 'GET', [], (int)($args['timeout_ms'] ?? 8000), false);
        $issue = $this->responseAssessmentIssue($ok, $msg, $ev, $base, 'Content-Security-Policy', false);
        if ($issue !== null) return $issue;

        $h = array_change_key_case((array)($ev['headers'] ?? []), CASE_LOWER);
        $csp = strtolower($this->hget($h, 'content-security-policy'));
        if ($csp === '') return [false, 'CSP header absent', $ev];

        $hasNonce = str_contains($csp, 'nonce-') || str_contains($csp, 'sha256-') || str_contains($csp, 'sha384-');
        $bad = (str_contains($csp, "default-src *")
            || (substr_count($csp, "unsafe-inline") > 0 && !$hasNonce)
            || substr_count($csp, "unsafe-eval") > 0);

        return [!$bad, !$bad ? 'CSP looks reasonable' : 'CSP overly permissive', $ev];
    }

    private function corsNoWildcardWithCreds(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [null, '[UNKNOWN] Runtime URL unavailable; no valid Magento store base URL could be read. Check store configuration and scanner read access', []];
        [$ok, $msg, $ev] = $this->fetch($base, 'GET', [], (int)($args['timeout_ms'] ?? 8000), false);
        $issue = $this->responseAssessmentIssue($ok, $msg, $ev, $base, 'CORS headers', false);
        if ($issue !== null) return $issue;

        $h = array_change_key_case((array)($ev['headers'] ?? []), CASE_LOWER);
        $acao = strtolower($this->hget($h, 'access-control-allow-origin'));
        $acac = strtolower($this->hget($h, 'access-control-allow-credentials'));
        $bad = ($acao == '*' && $acac == 'true');
        return [!$bad, !$bad ? 'CORS ok' : 'CORS wildcard with credentials=true', $ev];
    }

    private function corsPreflightSafe(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [null, '[UNKNOWN] Runtime URL unavailable; no valid Magento store base URL could be read. Check store configuration and scanner read access', []];
        // Real preflight with Origin + Access-Control-Request-Method
        $headers = [
            'Origin: https://example.com',
            'Access-Control-Request-Method: POST',
            'Access-Control-Request-Headers: Content-Type'
        ];
        [$ok, $msg, $ev] = $this->fetch($base, 'OPTIONS', $headers, (int)($args['timeout_ms'] ?? 8000), false);
        if ($ok === null) return [null, $msg, $ev];
        if (!$ok) return [null, '[UNKNOWN] OPTIONS not allowed', $ev];

        $h = array_change_key_case((array)($ev['headers'] ?? []), CASE_LOWER);
        $allow = strtolower($this->hget($h, 'access-control-allow-methods'));
        $bad = ($allow == '*');
        return [!$bad, !$bad ? 'OPTIONS looks safe' : 'OPTIONS allows * methods', $ev];
    }

    // === TLS / cert ===
    private function tlsMinVersion(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [null, '[UNKNOWN] Runtime URL unavailable; no valid Magento store base URL could be read. Check store configuration and scanner read access', []];

        $host = (string)parse_url($base, PHP_URL_HOST);
        if ($host === '') return [null, '[UNKNOWN] Invalid host', []];
        $port = (int)(parse_url($base, PHP_URL_PORT) ?: 443);
        $timeout = $this->timeoutSeconds($args, 10);

        $streamProbe = !empty($args['strict_scope']) ? $this->strictTlsVersions($host, $port, $timeout) : $this->probeTlsVersionsWithStreams($host, $port, $timeout);
        $nmapProbe = $this->probeTlsWithNmap($host, $port, $timeout);

        $accepted = $streamProbe['accepted'] ?? [];
        if (!empty($nmapProbe['ok'])) {
            $legacy = (array)($nmapProbe['legacy'] ?? []);
            foreach (['tls1.0', 'tls1.1'] as $version) {
                if (!empty($legacy[$version])) {
                    $accepted[$version] = true;
                }
            }
        }

        $hasLegacy = !empty($accepted['tls1.0']) || !empty($accepted['tls1.1']);
        $hasModern = !empty($accepted['tls1.2']) || !empty($accepted['tls1.3']) || !empty($nmapProbe['modern']);
        $evidence = [
            'host' => $host,
            'port' => $port,
            'stream_probe' => $streamProbe,
            'nmap_probe' => $nmapProbe,
            'accepted' => $accepted,
        ];

        if (!$hasModern && empty($nmapProbe['ok']) && empty($streamProbe['ok'])) {
            return [null, '[UNKNOWN] TLS probing failed for ' . $host . ':' . $port, $evidence + ['action' => 'Verify TCP reachability to the TLS endpoint from the scanner and inspect stream_probe.errors / nmap_probe; install nmap if the local OpenSSL client cannot enumerate legacy protocols.']];
        }
        if (!$hasModern) {
            return [false, 'TLS 1.2+ could not be negotiated', $evidence];
        }

        if (!empty($args['strict_scope'])) {
            if ($hasLegacy) return [false, 'Endpoint accepts TLS below 1.2', $evidence];
            if (empty($nmapProbe['ok']) && empty($streamProbe['legacy_rejection_verified'])) return [null, '[UNKNOWN] Modern TLS accepted but legacy-protocol rejection is unverified; install nmap for active protocol enumeration', $evidence];
        }

        $pass = !$hasLegacy;
        $msg  = $pass ? 'TLS < 1.2 disabled (nmap)' : 'Legacy TLS (1.0/1.1) still accepted (nmap)';

        return [$pass, $pass ? 'TLS < 1.2 disabled and TLS 1.2+ accepted' : $msg, $evidence];
    }


    private function tlsCertDaysLeft(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [null, '[UNKNOWN] Runtime URL unavailable; no valid Magento store base URL could be read. Check store configuration and scanner read access', []];
        $host = (string)parse_url($base, PHP_URL_HOST);
        if ($host === '') return [null, '[UNKNOWN] Invalid host', []];

        $port = (int)(parse_url($base, PHP_URL_PORT) ?: 443);
        $context = stream_context_create(['ssl' => ['capture_peer_cert' => true, 'SNI_enabled' => true, 'peer_name' => $host, 'verify_peer' => true, 'verify_peer_name' => true, 'allow_self_signed' => false]]);
        $client = @stream_socket_client("ssl://{$host}:{$port}", $errno, $errstr, $this->timeoutSeconds($args, 10), STREAM_CLIENT_CONNECT, $context);
        if (!$client) return [null, '[UNKNOWN] Cannot collect certificate from ' . $host . ':' . $port . ': ' . $errstr, ['host' => $host, 'port' => $port, 'transport_error' => true, 'action' => 'Verify scanner DNS/network access and trusted CA chain for this TLS endpoint; configure openssl.cafile for private CAs, then rerun.']];
        $params = stream_context_get_params($client);
        @fclose($client);
        $x = $params['options']['ssl']['peer_certificate'] ?? null;
        if (!$x) return [null, '[UNKNOWN] No certificate', []];
        $arr = openssl_x509_parse($x);
        if (!is_array($arr)) return [null, '[UNKNOWN] Certificate validity fields cannot be parsed', ['host'=>$host,'port'=>$port]];
        return $this->assessCertificateValidity($arr, $args, ['host'=>$host, 'port'=>$port, 'trust_chain_verified'=>true, 'hostname_verified'=>true, 'scope'=>'verified_tls_endpoint']);
    }

    private function assessCertificateValidity(array $certificate, array $args, array $evidence): array
    {
        $validTo = (int)($certificate['validTo_time_t'] ?? 0);
        $validFrom = (int)($certificate['validFrom_time_t'] ?? 0);
        if ($validTo <= 0 || $validFrom <= 0 || $validTo < $validFrom) return [null, '[UNKNOWN] Certificate validity interval is unavailable or malformed', $evidence];
        $now = time();
        $days = (int)floor(($validTo - $now) / 86400);
        $minDays = max(0, (int)($args['min_days'] ?? 15));
        $evidence += ['valid_from'=>$validFrom, 'valid_to'=>$validTo, 'days_remaining'=>$days, 'minimum_days'=>$minDays, 'currently_valid'=>$validFrom <= $now && $validTo >= $now];
        $pass = $evidence['currently_valid'] && $days >= $minDays;
        return [$pass, $pass ? "Verified TLS certificate has approximately {$days} days remaining" : 'TLS certificate validity or remaining lifetime violates deployment policy', $evidence];
    }
    private function hstsPreloadReady(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [null, '[UNKNOWN] Runtime URL unavailable; no valid Magento store base URL could be read. Check store configuration and scanner read access', []];
        [$ok, $msg, $ev] = $this->fetch($base, 'GET', [], (int)($args['timeout_ms'] ?? 8000), false);
        $issue = $this->responseAssessmentIssue($ok, $msg, $ev, $base, 'HSTS preload policy', true);
        if ($issue !== null) return $issue;

        $h = array_change_key_case((array)($ev['headers'] ?? []), CASE_LOWER);
        $hst = strtolower($this->hget($h, 'strict-transport-security'));
        $hasSub = str_contains($hst, 'includesubdomains');
        $hasPre = str_contains($hst, 'preload');
        preg_match('~max-age=(\d+)~', $hst, $m);
        $maxAge = (int)($m[1] ?? 0);
        $min = (int)($args['min_max_age'] ?? 31536000);
        $reqSub = (bool)($args['require_include_subdomains'] ?? true);
        $reqPre = (bool)($args['require_preload'] ?? true);
        $pass = ($maxAge >= $min) && (!$reqSub || $hasSub) && (!$reqPre || $hasPre);
        return [$pass, $pass ? 'HSTS preload-ready' : 'HSTS not preload-ready', $ev];
    }

    // === Methods & misc ===
    private function methodDisallowed(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [null, '[UNKNOWN] Runtime URL unavailable; no valid Magento store base URL could be read. Check store configuration and scanner read access', []];
        $method = strtoupper((string)($args['method'] ?? 'TRACE'));
        [$ok, $msg, $ev] = $this->fetch($base, $method, [], (int)($args['timeout_ms'] ?? 8000), false);
        if ($ok === null) return [null, $msg, $ev];
        if (!$ok) return [null, '[UNKNOWN] Method not allowed', $ev];
        $status = (int)($ev['status'] ?? 0);
        $pass = !in_array($status, [200, 202], true);
        return [$pass, $pass ? "{$method} not allowed" : "{$method} allowed", $ev];
    }

    private function optionsNotVerbose(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [null, '[UNKNOWN] Runtime URL unavailable; no valid Magento store base URL could be read. Check store configuration and scanner read access', []];
        [$ok, $msg, $ev] = $this->fetch($base, 'OPTIONS', [], (int)($args['timeout_ms'] ?? 8000), false);
        if ($ok === null) return [null, $msg, $ev];
        if (!$ok) return [null, '[UNKNOWN] OPTIONS not allowed', $ev];
        $h = array_change_key_case((array)($ev['headers'] ?? []), CASE_LOWER);
        $allow = strtolower($this->hget($h, 'allow'));
        $bad = (bool)preg_match('~\b(put|delete|trace)\b~', $allow);
        return [!$bad, !$bad ? 'OPTIONS ok' : 'OPTIONS reveals unsafe methods', $ev];
    }

    private function serverBannerNotVerbose(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [null, '[UNKNOWN] Runtime URL unavailable; no valid Magento store base URL could be read. Check store configuration and scanner read access', []];
        [$ok, $msg, $ev] = $this->fetch($base, 'GET', [], (int)($args['timeout_ms'] ?? 8000), false);
        if ($ok === null) return [null, $msg, $ev];
        if (!$ok) return [false, $msg, $ev];
        $h = array_change_key_case((array)($ev['headers'] ?? []), CASE_LOWER);
        $srv = $this->hget($h, 'server');
        $bad = (bool)preg_match('~/\d~', $srv);
        return [!$bad, !$bad ? 'Server banner ok' : "Server banner verbose: {$srv}", $ev];
    }

    private function blockPath(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [null, '[UNKNOWN] Runtime URL unavailable; no valid Magento store base URL could be read. Check store configuration and scanner read access', []];
        $paths = (array)($args['paths'] ?? []);
        $allowed = (array)($args['allowed_status'] ?? [404, 403, 401, 302, 301]);
        $timeout = (int)($args['timeout_ms'] ?? 8000);
        if (!$paths) return [null, '[UNKNOWN] No paths', []];
        foreach ($paths as $p) {
            $url = rtrim($base, '/') . $p;
            [$ok, $msg, $ev] = $this->fetch($url, 'GET', [], $timeout, false);
            if ($ok === null) continue;
            if (!$ok) continue;
            $st = (int)($ev['status'] ?? 0);
            if (!in_array($st, $allowed, true)) {
                return [false, "Path {$p} status {$st}", $ev];
            }
        }
        return [true, 'Paths blocked/hidden', []];
    }

    private function graphqlIntrospectionDisabled(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [null, '[UNKNOWN] Runtime URL unavailable; no valid Magento store base URL could be read. Check store configuration and scanner read access', []];
        $path = (string)($args['path'] ?? '/graphql');
        $url = rtrim($base, '/') . $path;
        $query = '{"query":"query IntrospectionQuery { __schema { types { name } } }"}';
        $headers = ['Content-Type: application/json'];
        [$ok, $msg, $ev] = $this->fetch($url, 'POST', $headers, (int)($args['timeout_ms'] ?? 8000), false, $query);
        if ($ok === null) return [null, $msg, $ev];
        if (!$ok) return [null, '[UNKNOWN] GraphQL endpoint not responding', $ev];
        $body = (string)($ev['body'] ?? '');
        $decoded = json_decode($body, true);
        $hasSchema = is_array($decoded) && isset($decoded['data']['__schema']);
        return [!$hasSchema, !$hasSchema ? 'Introspection disabled' : 'Introspection enabled', $ev];
    }

    private function restSensitiveEndpointsClosed(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [null, '[UNKNOWN] Runtime URL unavailable; no valid Magento store base URL could be read. Check store configuration and scanner read access', []];
        $paths = (array)($args['paths'] ?? []);
        $timeout = (int)($args['timeout_ms'] ?? 8000);
        if (!$paths) return [null, '[UNKNOWN] No paths', []];
        foreach ($paths as $p) {
            $url = rtrim($base, '/') . $p;
            [$ok, $msg, $ev] = $this->fetch($url, 'GET', [], $timeout, false);
            if ($ok === null) continue;
            if (!$ok) continue;
            $st = (int)($ev['status'] ?? 0);
            if ($st === 200) {
                return [false, "Sensitive endpoint {$p} accessible (200)", $ev];
            }
        }
        return [true, 'Sensitive endpoints not publicly accessible', []];
    }

    // === Hygiene & assets ===
    private function staticAssetsDeployed(array $args): array
    {
        if (!empty($args['strict_scope'])) return $this->strictStaticAssets($args);
        $base = $this->baseUrl();
        if ($base === '') return [null, '[UNKNOWN] Runtime URL unavailable; no valid Magento store base URL could be read. Check store configuration and scanner read access', []];
        [$ok, $msg, $ev] = $this->fetch($base, 'GET', [], (int)($args['timeout_ms'] ?? 8000), true);
        if ($ok === null) return [null, $msg, $ev];
        if (!$ok) return [null, '[UNKNOWN] Unable to fetch homepage for static asset check', $ev];
        $body = strtolower((string)($ev['body'] ?? ''));
        $hits = 0;
        if (preg_match('~/static/version\d+/~', $body)) $hits++;
        if (preg_match('~/static/_cache/merged/~', $body)) $hits++;
        if (preg_match('~/static/frontend/[^"]+/(en_[a-z]{2}|[a-z]{2}_[A-Z]{2})/~', $body)) $hits++;
        if (preg_match('~luma-icons\.(woff2|woff|ttf)~', $body)) $hits++;
        $pass = $hits >= 2; // cần >=2 tín hiệu để chắc hơn
        if (!$pass) {
            return [null, '[UNKNOWN] No strong static asset signals on homepage', ['hits' => $hits, 'response' => $ev]];
        }
        return [true, 'Static assets deployed/versioned', ['hits' => $hits, 'response' => $ev]];
    }


    private function strictStaticAssets(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [null, '[UNKNOWN] Runtime URL unavailable; no valid Magento store base URL could be read. Check store configuration and scanner read access', []];
        [$ok, $msg, $page] = $this->fetch($base, 'GET', [], (int)($args['timeout_ms'] ?? 8000), true);
        if ($ok !== true || (int)($page['status'] ?? 0) !== 200) return [null, '[UNKNOWN] Cannot retrieve storefront for static asset assessment', $page];
        $html = preg_replace('~<!--[\s\S]*?-->~', '', (string)($page['body'] ?? '')) ?? '';
        preg_match_all('~<(?:script|link)\b[^>]*\b(?:src|href)\s*=\s*([\'"])([^\'"]+)\1~i', $html, $matches, PREG_SET_ORDER);
        $urls = [];
        $final = (string)($page['final_url'] ?? $base);
        $origin = (string)parse_url($final, PHP_URL_SCHEME) . '://' . (string)parse_url($final, PHP_URL_HOST);
        $port = parse_url($final, PHP_URL_PORT); if ($port) $origin .= ':' . $port;
        foreach ($matches as $m) {
            $ref = html_entity_decode($m[2], ENT_QUOTES | ENT_HTML5);
            if (!preg_match('~\.(?:css|js)(?:[?#]|$)~i', $ref)) continue;
            if (str_starts_with($ref, '//')) $url = (string)parse_url($final, PHP_URL_SCHEME) . ':' . $ref;
            elseif (preg_match('~^https?://~i', $ref)) $url = $ref;
            elseif (str_starts_with($ref, '/')) $url = $origin . $ref;
            else $url = preg_replace('~/[^/]*$~', '/', $final) . $ref;
            if (parse_url($url, PHP_URL_HOST) !== parse_url($final, PHP_URL_HOST) || parse_url($url, PHP_URL_PORT) !== parse_url($final, PHP_URL_PORT)) continue;
            if (!str_contains((string)parse_url($url, PHP_URL_PATH), '/static/')) continue;
            $urls[$url] = true;
        }
        if ($urls === []) return [null, '[UNKNOWN] Storefront references no same-origin Magento static CSS/JS assets', ['page_url' => $final]];
        $checked = []; $unknown = false; $failed = false;
        foreach (array_keys($urls) as $url) {
            [$ok, $msg, $ev] = $this->fetch($url, 'GET', [], (int)($args['timeout_ms'] ?? 8000), true);
            $status = (int)($ev['status'] ?? 0); $body = (string)($ev['body'] ?? '');
            $type = strtolower($this->hget((array)($ev['headers'] ?? []), 'content-type'));
            $checked[] = ['url' => $url, 'status' => $status, 'bytes' => strlen($body), 'content_type' => $type];
            if ($ok !== true || $status >= 500 || $status === 429) { $unknown = true; continue; }
            if ($status !== 200 || $body === '' || str_contains($type, 'text/html') || preg_match('~^\s*(?:<!doctype|<html)~i', $body)) $failed = true;
        }
        if ($failed) return [false, 'Storefront references missing or invalid static assets', ['checked' => $checked]];
        if ($unknown) return [null, '[UNKNOWN] Static asset retrieval incomplete', ['checked' => $checked]];
        return [true, 'Referenced same-origin static CSS/JS assets are deployed and retrievable', ['checked' => $checked]];
    }

    private function cacheSignals(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [null, '[UNKNOWN] Runtime URL unavailable; no valid Magento store base URL could be read. Check store configuration and scanner read access', []];
        // First fetch
        [$ok1, $msg1, $ev1] = $this->fetch($base, 'GET', [], (int)($args['timeout_ms'] ?? 8000), true);
        if ($ok1 === null) return [null, $msg1, $ev1];
        if (!$ok1) return [null, '[UNKNOWN] Unable to fetch homepage for cache signal check', $ev1];

        $h1 = array_change_key_case((array)($ev1['headers'] ?? []), CASE_LOWER);
        $age1 = (int)preg_replace('~\D+~', '', $this->hget($h1, 'age')) ?: 0;
        $xc1 = $this->hget($h1, 'x-cache');
        $via1 = $this->hget($h1, 'via');

        // Second fetch
        [$ok2, $msg2, $ev2] = $this->fetch($base, 'GET', [], (int)($args['timeout_ms'] ?? 8000), true);
        if ($ok2 === null) return [null, $msg2, ['first_response' => $ev1, 'second_response' => $ev2]];
        if (!$ok2) return [null, '[UNKNOWN] Unable to repeat homepage fetch for cache signal check', ['first_response' => $ev1, 'second_response' => $ev2]];

        $h2 = array_change_key_case((array)($ev2['headers'] ?? []), CASE_LOWER);
        $age2 = (int)preg_replace('~\D+~', '', $this->hget($h2, 'age')) ?: 0;
        $xc2 = $this->hget($h2, 'x-cache');
        $via2 = $this->hget($h2, 'via');

        $hits = 0;
        if ($age1 > 0 || $age2 > 0) $hits++;
        if ($age2 > $age1) $hits++;
        if (stripos($xc1 . $xc2, 'hit') !== false) $hits++;
        if (stripos($via1 . $via2, 'varnish') !== false) $hits++;

        $pass = $hits >= 1;
        $evidence = [
            'hits' => $hits,
            'first' => [
                'status' => $ev1['status'] ?? null,
                'final_url' => $ev1['final_url'] ?? null,
                'age' => $age1,
                'x_cache' => $xc1,
                'via' => $via1,
            ],
            'second' => [
                'status' => $ev2['status'] ?? null,
                'final_url' => $ev2['final_url'] ?? null,
                'age' => $age2,
                'x_cache' => $xc2,
                'via' => $via2,
            ],
        ];
        return [$pass, $pass ? 'Cache/FPC signals present' : 'No cache/FPC signals', $evidence];
    }

    private function logsProtected(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [null, '[UNKNOWN] Runtime URL unavailable; no valid Magento store base URL could be read. Check store configuration and scanner read access', []];

        $paths = ['/var/log/', '/var/report/'];
        $allowStatuses = [401, 403, 404, 405, 410, 301, 302, 307, 308];
        $timeout = (int)($args['timeout_ms'] ?? 8000);

        $attempted = 0;
        $reachable = 0;
        $evidence  = [];

        foreach ($paths as $p) {
            $url = rtrim($base, '/') . $p;
            [$ok, $msg, $ev] = $this->fetch($url, 'GET', [], $timeout, false);
            $attempted++;

            if ($ok === null) { // lỗi transport (UNKNOWN)
                $evidence[] = ['path' => $p, 'status' => 'unknown'];
                continue;
            }
            if (!$ok) { // fetch lỗi (timeout, TLS, v.v.)
                $evidence[] = ['path' => $p, 'status' => 'error'];
                continue;
            }

            $reachable++;
            $st = (int)($ev['status'] ?? 0);
            $hdrs = array_change_key_case((array)($ev['headers'] ?? []), CASE_LOWER);
            $ctype = strtolower($this->hget($hdrs, 'content-type'));
            $body  = (string)($ev['body'] ?? '');

            $evidence[] = ['path' => $p, 'status' => $st];

            // Các status coi như đã được bảo vệ
            if (in_array($st, $allowStatuses, true)) continue;

            if ($st === 200) {
                // Soft-404/forbidden dạng HTML nhỏ => coi như bảo vệ
                if (str_contains($ctype, 'text/html')) {
                    $b = strtolower(substr($body, 0, 4096));
                    $soft404 = (strlen($body) < 8192) && (
                        str_contains($b, 'not found') || str_contains($b, 'forbidden') || str_contains($b, 'error')
                    );
                    if ($soft404) continue;

                    // Directory index
                    if (stripos($body, 'Index of /') !== false) {
                        return [false, "{$p} directory index accessible", $ev];
                    }
                }

                // Heuristic: body có link/định danh file log/report
                if (preg_match('~\.(log|xml|txt|html|csv)(\?|")?~i', substr($body, 0, 8192)) === 1) {
                    return [false, "{$p} appears to expose logs/reports", $ev];
                }
            }
            // Các status khác: tiếp tục thử path khác
        }

        // Không path nào phản hồi được -> UNKNOWN chứ không PASS
        if ($reachable === 0) {
            return [null, '[UNKNOWN] Unable to verify logs/report paths (no HTTP response)', [
                'attempted' => $attempted,
                'evidence'  => $evidence
            ]];
        }

        return [true, 'Application logs/reports not publicly accessible', [
            'attempted' => $attempted,
            'evidence'  => $evidence
        ]];
    }


    private function csrfFormKeySignal(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [false, 'Missing URL in context'];
        [$ok, $msg, $ev] = $this->fetch($base, 'GET', [], (int)($args['timeout_ms'] ?? 8000), true);
        if ($ok === null) return [null, $msg, $ev];
        if (!$ok) return [false, $msg, $ev];
        $body = strtolower((string)($ev['body'] ?? ''));
        $has = (bool)preg_match('~name=["\\\']form_key["\\\']~i', $body);
        return [$has, $has ? 'form_key present in forms' : 'No form_key signal on homepage', $ev];
    }

    private function noVcsMisc(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [false, 'Missing URL in context'];
        $paths = ['/.git/HEAD', '/.svn/entries', '/.hg/', '/.DS_Store', '/composer.json', '/app/etc/env.php'];
        $allowStatuses = [401, 403, 404, 405, 410, 301, 302, 307, 308];

        foreach ($paths as $p) {
            $url = rtrim($base, '/') . $p;
            [$ok, $msg, $ev] = $this->fetch($url, 'GET', [], (int)($args['timeout_ms'] ?? 8000), false);
            if ($ok === null) continue;
            if (!$ok) continue;

            $st = (int)($ev['status'] ?? 0);
            if (in_array($st, $allowStatuses, true)) continue;

            if ($st === 200) {
                $body  = (string)($ev['body'] ?? '');
                if ($p === '/composer.json' && preg_match('~^\s*\{\s*\"name\"\s*:\s*\"~', $body) === 1) {
                    return [false, "Artifact exposed: {$p}", $ev];
                }
                if (stripos($body, 'Index of /') !== false) {
                    return [false, "Artifact exposed: {$p}", $ev];
                }
            }
        }
        return [true, 'No VCS/misc artifacts exposed', []];
    }

    private function thirdPartyLinksHttps(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [false, 'Missing URL in context'];
        [$ok, $msg, $ev] = $this->fetch($base, 'GET', [], (int)($args['timeout_ms'] ?? 8000), true);
        if ($ok === null) return [null, $msg, $ev];
        if (!$ok) return [false, $msg, $ev];
        $body = (string)($ev['body'] ?? '');
        $clean = preg_replace('~<!--.*?-->~s', '', $body) ?? $body;
        $bad = (bool)preg_match('~\b(?:href|src|action)\s*=\s*["\']http://~i', $clean);
        return [!$bad, !$bad ? '3rd-party links use HTTPS' : 'Found http:// link in markup', $ev];
    }

    private function noDebugEndpoints(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [false, 'Missing URL in context'];
        $paths = ['/phpinfo.php', '/debug', '/adminer.php', '/errors/', '/setup/'];
        foreach ($paths as $p) {
            $url = rtrim($base, '/') . $p;
            [$ok, $msg, $ev] = $this->fetch($url, 'GET', [], (int)($args['timeout_ms'] ?? 8000), false);
            if ($ok === null) continue;
            if (!$ok) continue;
            $st = (int)($ev['status'] ?? 0);
            if ($st === 200) return [false, "Debug/diagnostic path open: {$p}", $ev];
        }
        return [true, 'No debug endpoints publicly accessible', []];
    }

    private function paymentTlsMin(array $args): array
    {
        $base = $this->baseUrl();
        if ($base === '') return [null, '[UNKNOWN] Runtime URL unavailable; no valid Magento store base URL could be read. Check store configuration and scanner read access', []];

        [$ok, $msg, $ev] = $this->fetch($base, 'GET', [], 8000, true);
        if ($ok === null) return [null, $msg, $ev];
        if (!$ok) return [null, '[UNKNOWN] Unable to fetch homepage', $ev];

        $html = (string)($ev['body'] ?? '');
        $origin = (string)parse_url($base, PHP_URL_HOST);

        $hosts = [];
        if (preg_match_all('#https?://([a-z0-9\.\-]+)(?:[:/][^\s"\'<]*)?#i', $html, $m)) {
            foreach ($m[1] as $h) {
                $h = strtolower($h);
                if ($h !== strtolower($origin)) $hosts[] = $h;
            }
        }
        $hosts = array_values(array_unique($hosts));
        if (empty($hosts)) return [true, 'No third-party endpoints to audit for TLS', []];

        // Yêu cầu có nmap
        $which = @trim((string)@shell_exec('command -v nmap 2>/dev/null'));
        if ($which === '') {
            return [null, '[UNKNOWN] TLS probing third-parties requires nmap', ['hosts' => $hosts]];
        }

        $weak = [];
        $evidences = [];
        foreach ($hosts as $h) {
            $probe = $this->probeTlsWithNmap($h, 443, (int)($args['timeout_s'] ?? 10));
            if (empty($probe['ok'])) {
                $evidences[$h] = ['err' => $probe['err'] ?? 'n/a'];
                continue;
            }
            $legacy = (array)$probe['legacy'];
            $evidences[$h] = $legacy;
            if (!empty($legacy['tls1.0']) || !empty($legacy['tls1.1'])) $weak[] = $h;
        }

        if (empty($evidences)) return [null, '[UNKNOWN] No evidence collected', ['hosts' => $hosts]];

        $pass = empty($weak);
        $msg  = $pass ? 'Payment/3rd-party endpoints enforce TLS ≥ 1.2' : ('Legacy TLS accepted by: ' . implode(', ', $weak));
        return [$pass, $msg, ['hosts_checked' => $evidences]];
    }


    private function strictTlsVersions(string $host, int $port, int $timeout): array
    {
        $accepted = []; $errors = []; $rejected = [];
        foreach (['tls1.0' => 'STREAM_CRYPTO_METHOD_TLSv1_0_CLIENT', 'tls1.1' => 'STREAM_CRYPTO_METHOD_TLSv1_1_CLIENT', 'tls1.2' => 'STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT', 'tls1.3' => 'STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT'] as $version => $constant) {
            $this->collectors->session->checkpoint();
            if (!defined($constant)) { $errors[$version] = 'Client does not support protocol'; continue; }
            $ctx = stream_context_create(['ssl' => ['SNI_enabled' => true, 'peer_name' => $host, 'verify_peer' => false, 'verify_peer_name' => false, 'ciphers' => 'ALL:@SECLEVEL=0']]);
            $socket = @stream_socket_client("tcp://{$host}:{$port}", $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, $ctx);
            if (!is_resource($socket)) { $errors[$version] = 'TCP connection failed: ' . $errstr; continue; }
            stream_set_timeout($socket, $timeout);
            $warnings = [];
            set_error_handler(static function (int $severity, string $message) use (&$warnings): bool { $warnings[] = $message; return true; });
            try { $ok = stream_socket_enable_crypto($socket, true, constant($constant)); }
            finally { restore_error_handler(); fclose($socket); }
            $accepted[$version] = $ok === true;
            $errors[$version] = implode('; ', $warnings);
            // A peer protocol-version alert is a rejection; local cipher/client errors and timeouts prove nothing.
            $rejected[$version] = $ok === false && preg_match('~alert protocol version|unsupported protocol.*alert~i', $errors[$version]) === 1;
        }
        return ['ok' => in_array(true, $accepted, true), 'accepted' => $accepted, 'errors' => $errors, 'legacy_rejection_verified' => !empty($rejected['tls1.0']) && !empty($rejected['tls1.1'])];
    }

    private function probeTlsVersionsWithStreams(string $host, int $port, int $timeout = 10): array
    {
        $constants = [
            'tls1.0' => defined('STREAM_CRYPTO_METHOD_TLSv1_0_CLIENT') ? constant('STREAM_CRYPTO_METHOD_TLSv1_0_CLIENT') : null,
            'tls1.1' => defined('STREAM_CRYPTO_METHOD_TLSv1_1_CLIENT') ? constant('STREAM_CRYPTO_METHOD_TLSv1_1_CLIENT') : null,
            'tls1.2' => defined('STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT') ? constant('STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT') : null,
            'tls1.3' => defined('STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT') ? constant('STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT') : null,
        ];

        $accepted = [];
        $errors = [];
        foreach ($constants as $version => $method) {
            if ($method === null) {
                $errors[$version] = 'unsupported_by_php';
                continue;
            }

            $ctx = stream_context_create([
                'ssl' => [
                    'crypto_method' => $method,
                    'SNI_enabled' => true,
                    'peer_name' => $host,
                    'verify_peer' => false,
                    'verify_peer_name' => false,
                    'allow_self_signed' => true,
                    'capture_peer_cert' => false,
                ],
            ]);
            $errno = 0;
            $errstr = '';
            $client = @stream_socket_client(
                "tls://{$host}:{$port}",
                $errno,
                $errstr,
                $timeout,
                STREAM_CLIENT_CONNECT,
                $ctx
            );
            if (is_resource($client)) {
                $accepted[$version] = true;
                @fclose($client);
            } else {
                $accepted[$version] = false;
                $errors[$version] = $errstr !== '' ? $errstr : (string)$errno;
            }
        }

        return [
            'ok' => in_array(true, $accepted, true),
            'accepted' => $accepted,
            'errors' => $errors,
        ];
    }

    private function probeTlsWithNmap(string $host, int $port = 443, int $timeout = 10): array
    {
        $host = trim($host);
        if ($host === '') return ['ok' => false, 'err' => 'empty host'];

        $which = @trim((string)@shell_exec('command -v nmap 2>/dev/null'));
        if ($which === '') return ['ok' => false, 'err' => 'nmap not found'];

        $cmd = sprintf(
            '%s --host-timeout %ds --script ssl-enum-ciphers -p %d %s 2>&1',
            escapeshellcmd($which),
            max(1, $timeout),
            $port,
            escapeshellarg($host)
        );
        $out = @shell_exec($cmd);
        if ($out === null || $out === '') return ['ok' => false, 'err' => 'empty nmap output'];

        if (preg_match('/\b(?:host seems down|failed to connect|couldn\'t connect|no route to host|connection refused|timed out|timeout)\b/i', $out)) {
            return ['ok' => false, 'err' => 'nmap could not connect', 'raw' => $out];
        }
        if (!preg_match('/\bTLSv?1\.[0-3]\s*:/i', $out)) {
            return ['ok' => false, 'err' => 'nmap output has no TLS protocol sections', 'raw' => $out];
        }



        // Helper: rút block cho 1 version, rồi xác định có cipher thật không
        $hasLegacy = function (string $out, string $verRegex): bool {
            // Lấy block từ "TLSvX.Y:" đến ngay trước dòng bắt đầu bằng "|   TLS" kế tiếp hoặc hết file
            if (!preg_match('/' . $verRegex . ':(.*?)(?:(?:\r?\n)\|\s*TLS|$)/si', $out, $m)) {
                // Không có section => coi như tắt version này
                return false;
            }
            $blk = $m[1];

            // Nếu block chứa câu "No supported ciphers found" -> không legacy
            if (stripos($blk, 'No supported ciphers found') !== false) return false;

            // Có cipher thực khi thấy "ciphers:" hoặc ít nhất một dòng cipher bắt đầu bằng "|       TLS_"
            if (preg_match('/\|\s*ciphers\s*:/i', $blk)) return true;
            if (preg_match('/\|\s+TLS[_A-Z0-9\-]+/i', $blk)) return true;

            // Nếu block hoàn toàn rỗng/không có chỉ dấu cipher -> không coi là legacy
            return false;
        };

        $has10 = $hasLegacy($out, 'TLSv?1\\.0');
        $has11 = $hasLegacy($out, 'TLSv?1\\.1');

        return ['ok' => true, 'modern' => preg_match('/\bTLSv?1\.[23]\s*:/i', $out) === 1, 'legacy' => ['tls1.0' => $has10, 'tls1.1' => $has11], 'raw' => $out];
    }

    private function timeoutSeconds(array $args, int $default): int
    {
        if (isset($args['timeout_s'])) {
            return max(1, (int)$args['timeout_s']);
        }
        if (isset($args['timeout_ms'])) {
            return max(1, (int)ceil(((int)$args['timeout_ms']) / 1000));
        }
        return $default;
    }
}
