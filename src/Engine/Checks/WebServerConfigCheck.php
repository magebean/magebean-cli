<?php declare(strict_types=1);

namespace Magebean\Engine\Checks;

use Magebean\Engine\Context;

final class WebServerConfigCheck
{
    private Context $ctx;

    public function __construct(Context $ctx) { $this->ctx = $ctx; }

    /**
     * nginx_directive:
     *  args: { file: "nginx.conf", directive: "regex-or-literal", expects_regex: true|false }
     */
    public function nginxDirective(array $args): array
    {
        $file = (string)($args['file'] ?? 'nginx.conf');
        $path = $this->ctx->abs($file);
        if (!is_file($path)) return [null, "$file not found"]; 
        $needle = (string)($args['directive'] ?? '');
        $isRe   = (bool)($args['expects_regex'] ?? false);
        $txt = (string)file_get_contents($path);
        if ($txt === '') return [null, "$file is empty or unreadable"];

        if ($isRe) {
            if (@preg_match('/'.$needle.'/m', '') === false) {
                return [false, "Invalid regex: /$needle/"];
            }
            return [ (bool)preg_match('/'.$needle.'/m', $txt), "nginx matched /$needle/" ];
        }
        return [ str_contains($txt, $needle), "nginx contains '$needle'" ];
    }

    /**
     * apache_htaccess_directive:
     *  args: { file: "pub/.htaccess", directive: "regex-or-literal", expects_regex: true|false }
     */
    public function apacheDirective(array $args): array
    {
        $file = (string)($args['file'] ?? 'pub/.htaccess');
        $path = $this->ctx->abs($file);
        if (!is_file($path)) return [null, "$file not found"];
        $needle = (string)($args['directive'] ?? '');
        $isRe   = (bool)($args['expects_regex'] ?? false);
        $txt = (string)file_get_contents($path);
        if ($txt === '') return [null, "$file is empty or unreadable"];

        if ($isRe) {
            if (@preg_match('/'.$needle.'/m', '') === false) {
                return [false, "Invalid regex: /$needle/"];
            }
            return [ (bool)preg_match('/'.$needle.'/m', $txt), ".htaccess matched /$needle/" ];
        }
        return [ str_contains($txt, $needle), ".htaccess contains '$needle'" ];
    }

    public function tlsCiphers(array $args): array
    {
        $files = $args['files'] ?? ['nginx.conf', 'pub/.htaccess', '.htaccess', 'apache.conf'];
        if (!is_array($files)) {
            $files = ['nginx.conf', 'pub/.htaccess', '.htaccess', 'apache.conf'];
        }
        $requireProtocols = (bool)($args['require_protocols'] ?? true);
        $requireCiphers = (bool)($args['require_ciphers'] ?? true);

        $checked = [];
        $failures = [];
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

            $content = @file_get_contents($path);
            if ($content === false || $content === '') {
                $checked[] = ['file' => $relative, 'present' => true, 'readable' => false];
                continue;
            }

            $analysis = $this->tlsCipherConfigEvidence($relative, $content, $requireProtocols, $requireCiphers);
            $checked[] = $analysis;
            if (!empty($analysis['configured']) && $analysis['ok'] === false) {
                $failures[] = $analysis;
            }
        }

        $evidence = ['checked' => $checked, 'failures' => $failures];
        if ($failures !== []) {
            $lines = ['Weak TLS protocol/cipher configuration detected:'];
            foreach ($failures as $failure) {
                $lines[] = sprintf(
                    '    - %s missing %s',
                    $failure['file'],
                    implode('+', $failure['missing'] ?? ['strong_tls_config'])
                );
            }
            return [false, implode("\n", $lines), $evidence];
        }

        foreach ($checked as $analysis) {
            if ((!empty($analysis['present']) && empty($analysis['readable'])) || (array_key_exists('ok', $analysis) && $analysis['ok'] === null)) return [null, '[UNKNOWN] TLS configuration collection or cipher interpretation is incomplete', $evidence];
        }
        $configured = array_filter($checked, static fn(array $entry): bool => !empty($entry['configured']));
        if ($configured === []) return [null, '[UNKNOWN] No explicit TLS protocol/cipher declarations were collected; effective gateway policy is unresolved', $evidence];
        return [true, 'Collected explicit TLS declarations satisfy the source configuration policy; effective gateway binding was not verified', $evidence + ['scope' => 'readable repository TLS declarations only']];
    }
    private function tlsCipherConfigEvidence(string $file, string $content, bool $requireProtocols, bool $requireCiphers): array
    {
        $protocols = $this->firstDirectiveValue($content, '~^\s*(?:ssl_protocols|SSLProtocol)\s+(?P<value>[^;\r\n]+)~im');
        $ciphers = $this->firstDirectiveValue($content, '~^\s*(?:ssl_ciphers|SSLCipherSuite)\s+(?P<value>[^;\r\n]+)~im');

        if (preg_match_all('~^\s*(?:ssl_protocols|SSLProtocol)\s+~im', $content) > 1 || preg_match_all('~^\s*(?:ssl_ciphers|SSLCipherSuite)\s+~im', $content) > 1) return ['file'=>$file,'present'=>true,'readable'=>true,'configured'=>true,'ok'=>null,'reason'=>'multiple TLS scopes require effective configuration binding'];
        $protocolEvidence = $this->tlsProtocolEvidence($protocols);
        $cipherEvidence = $this->cipherSuiteEvidence($ciphers);

        $missing = [];
        if ($requireProtocols && empty($protocolEvidence['ok'])) {
            $missing[] = 'strong_protocols';
        }
        if ($requireCiphers && empty($cipherEvidence['ok'])) {
            $missing[] = 'strong_ciphers';
        }

        return [
            'file' => $file,
            'present' => true,
            'readable' => true,
            'configured' => $protocols !== null || $ciphers !== null,
            'protocols' => $protocolEvidence,
            'ciphers' => $cipherEvidence,
            'missing' => $missing,
            'ok' => $requireCiphers && $cipherEvidence['ok'] === null && (!$requireProtocols || $protocolEvidence['ok']) ? null : $missing === [],
        ];
    }

    private function firstDirectiveValue(string $content, string $regex): ?string
    {
        if (preg_match($regex, $content, $match) !== 1) {
            return null;
        }

        return trim((string)$match['value'], " \t\n\r\0\x0B\"'");
    }

    private function tlsProtocolEvidence(?string $value): array
    {
        if ($value === null || $value === '') {
            return ['present' => false, 'ok' => false, 'missing' => ['protocol_directive']];
        }

        $normalized = strtolower($value);
        $hasStrong = preg_match('~\bTLSv1\.[23]\b~i', $value) === 1;
        $usesAll = preg_match('~(?:^|\s)all(?:\s|$)~', $normalized) === 1;
        $weakEnabled = [];
        foreach (['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.0', 'TLSv1.1'] as $proto) {
            if ($this->tlsProtocolEnabled($normalized, strtolower($proto))) {
                $weakEnabled[] = $proto;
            }
        }

        return [
            'present' => true,
            'value' => $value,
            'has_strong_protocol' => $hasStrong || ($usesAll && $weakEnabled === []),
            'weak_enabled' => $weakEnabled,
            'ok' => ($hasStrong || ($usesAll && $weakEnabled === [])) && $weakEnabled === [],
        ];
    }

    private function tlsProtocolEnabled(string $normalized, string $proto): bool
    {
        $quoted = preg_quote($proto, '~');
        if (preg_match('~(?:^|\s)-' . $quoted . '(?:\s|$)~', $normalized) === 1) {
            return false;
        }
        if (preg_match('~(?:^|\s)\+' . $quoted . '(?:\s|$)~', $normalized) === 1) {
            return true;
        }
        if (preg_match('~(?:^|\s)' . $quoted . '(?:\s|$)~', $normalized) === 1) {
            return true;
        }
        if ($proto === 'tlsv1' && preg_match('~(?:^|\s)all(?:\s|$)~', $normalized) === 1) {
            return true;
        }

        return false;
    }

    private function cipherSuiteEvidence(?string $value): array
    {
        if ($value === null || $value === '') return ['present' => false, 'ok' => false, 'missing' => ['cipher_directive']];
        $enabled = []; $excluded = []; $uncertain = false;
        foreach (preg_split('~[:\s,]+~', trim($value)) ?: [] as $token) {
            if ($token === '') continue;
            $operator = $token[0]; $name = strtoupper(ltrim($token, '!+-'));
            if ($operator === '!' || $operator === '-') {
                unset($enabled[$name]);
                if ($operator === '!') $excluded[$name] = true;
                // Intersections, aliases and wildcard exclusions need OpenSSL expansion.
                if (str_contains($name, '+') || !preg_match('~^(?:RC4|3DES|DES|MD5|NULL|ANULL|ENULL|EXPORT|LOW|ADH|ECDHE-(?:RSA|ECDSA)-[A-Z0-9_-]+|TLS_AES_[A-Z0-9_]+|TLS_CHACHA20_[A-Z0-9_]+)$~', $name)) $uncertain = true;
                continue;
            }
            if ($operator === '+') continue; // Reorders existing ciphers; never enables one.
            if (!isset($excluded[$name])) $enabled[$name] = true;
        }
        $weak = []; $strong = false;
        foreach (array_keys($enabled) as $name) {
            if (preg_match('~(?:RC4|3DES|(?:^|-)DES(?:-|$)|MD5|NULL|EXPORT|LOW|ADH)~', $name)) {
                $removed = false;
                foreach (array_keys($excluded) as $exclude) if ($exclude === $name || (in_array($exclude, ['RC4', '3DES', 'DES', 'MD5', 'NULL', 'ANULL', 'ENULL', 'EXPORT', 'LOW', 'ADH'], true) && ($exclude === 'DES' ? preg_match('~(?:^|-)DES(?:-|$)~', $name) === 1 : str_contains($name, $exclude)))) $removed = true;
                if (!$removed) $weak[] = $name;
            } elseif (preg_match('~^(?:ECDHE-(?:RSA|ECDSA)-(?:AES(?:128|256)-(?:GCM-)?SHA(?:256|384)?|CHACHA20-POLY1305)|TLS_AES_(?:128_GCM_SHA256|256_GCM_SHA384)|TLS_CHACHA20_POLY1305_SHA256)$~', $name)) {
                $strong = true;
            } else {
                $uncertain = true;
            }
        }
        return ['present' => true, 'value' => $value, 'has_strong_cipher' => $strong,
            'weak_enabled' => $weak, 'ok' => $weak !== [] ? false : ($uncertain ? null : $strong),
            'reason' => $uncertain ? 'Cipher aliases require effective OpenSSL expansion' : ''];
    }
    public function hstsConfig(array $args): array
    {
        $files = $args['files'] ?? ['nginx.conf', 'pub/.htaccess', '.htaccess'];
        if (!is_array($files)) {
            $files = ['nginx.conf', 'pub/.htaccess', '.htaccess'];
        }
        $min = (int)($args['min_max_age'] ?? 15552000);
        $requireIncludeSubdomains = (bool)($args['require_include_subdomains'] ?? false);
        $requirePreload = (bool)($args['require_preload'] ?? false);

        $checked = [];
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

            $txt = (string)file_get_contents($path);
            if (!preg_match_all('~(?:Strict-Transport-Security|strict-transport-security)[^"\']*["\'](?P<policy>[^"\']+)["\']|(?:Strict-Transport-Security|strict-transport-security)\s+(?P<bare>[^\r\n;]+(?:;[^\r\n;]+)*)~i', $txt, $matches, PREG_SET_ORDER)) {
                $checked[] = ['file' => $relative, 'present' => true, 'hsts' => false];
                continue;
            }

            foreach ($matches as $match) {
                $policy = trim((string)($match['policy'] ?? $match['bare'] ?? ''));
                if (!preg_match('~max-age\s*=\s*(\d+)~i', $policy, $ageMatch)) {
                    $checked[] = ['file' => $relative, 'present' => true, 'hsts' => true, 'policy' => $policy, 'ok' => false];
                    continue;
                }

                $maxAge = (int)$ageMatch[1];
                $includeSubdomains = stripos($policy, 'includesubdomains') !== false;
                $preload = stripos($policy, 'preload') !== false;
                $ok = $maxAge >= $min
                    && (!$requireIncludeSubdomains || $includeSubdomains)
                    && (!$requirePreload || $preload);
                $evidence = [
                    'file' => $relative,
                    'policy' => $policy,
                    'max_age' => $maxAge,
                    'min_max_age' => $min,
                    'include_subdomains' => $includeSubdomains,
                    'preload' => $preload,
                    'ok' => $ok,
                ];
                if ($ok) {
                    return [true, 'HSTS configured in web server config', $evidence];
                }
                $checked[] = $evidence;
            }
        }

        return [null, 'No passing HSTS web server config found', ['checked' => $checked]];
    }
}
