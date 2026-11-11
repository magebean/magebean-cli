<?php
declare(strict_types=1);
namespace Magebean\Engine\Collectors;
/** Always fresh: repeated probes and transport counts retain their semantics. */
final class HttpCollector
{
    private const MAX_BODY_BYTES = 1048576;
    private const MAX_HEADER_BYTES = 65536;

    public function __construct(private readonly ?CollectionSession $session = null) {}
    public function fetch(string $url, string $method = 'GET', array $headers = [], int $timeoutMs = 8000, bool $follow = true, ?string $requestBody = null, ?callable $observe = null): array
    {
        $this->session?->checkpoint();
        $deadline = $this->session?->deadline();
        if ($deadline !== null) {
            $remaining = $deadline->remainingMilliseconds();
            if ($remaining === 0) throw new \Magebean\Engine\ScanDeadlineExceeded('Scan deadline exceeded before HTTP request.');
            $timeoutMs = $timeoutMs > 0 ? min($timeoutMs, $remaining) : $remaining;
        }
        $observe ??= static function (bool $ok): void {};
        $ctxHeaders = [];
        foreach ($headers as $k => $v) $ctxHeaders[] = is_int($k) ? $v : ($k . ': ' . $v);

        // Prefer curl (if available) to capture headers + redirects
        if (function_exists('curl_init')) {
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
            $body = ''; $headerRaw = ''; $headerBytes = 0; $limit = null;
            curl_setopt($ch, CURLOPT_HEADERFUNCTION, function ($handle, string $line) use (&$headerRaw, &$headerBytes, &$body, &$limit): int {
                $this->session?->checkpoint();
                $headerBytes += strlen($line);
                if ($headerBytes > self::MAX_HEADER_BYTES) { $limit = 'headers'; return 0; }
                // Discard the previous response body and headers when a redirect/informational response ends.
                if (preg_match('~^HTTP/\S+\s+\d{3}\b~i', $line)) { $headerRaw = ''; $body = ''; }
                $headerRaw .= $line;
                return strlen($line);
            });
            curl_setopt($ch, CURLOPT_WRITEFUNCTION, function ($handle, string $chunk) use (&$body, &$limit): int {
                $this->session?->checkpoint();
                if (strlen($body) + strlen($chunk) > self::MAX_BODY_BYTES) { $limit = 'body'; return 0; }
                $body .= $chunk;
                return strlen($chunk);
            });
            curl_setopt($ch, CURLOPT_TIMEOUT_MS, $timeoutMs);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, $follow);
            curl_setopt($ch, CURLOPT_MAXREDIRS, 5);
            curl_setopt($ch, CURLOPT_USERAGENT, 'Magebean-CLI/1.0');
            if ($ctxHeaders) curl_setopt($ch, CURLOPT_HTTPHEADER, $ctxHeaders);
            if ($requestBody !== null) curl_setopt($ch, CURLOPT_POSTFIELDS, $requestBody);
            try {
                $resp = curl_exec($ch);
                $error = curl_error($ch);
                $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
                $finalUrl = (string)curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
            } finally { curl_close($ch); }
            if ($limit !== null) {
                $observe(false);
                return $this->responseLimit($url, $limit, 'curl');
            }
            if ($resp === false) {
                $observe(false);
                return $this->transportFailure($url, $error, 'curl');
            }
            $observe(true);
            return [true, '', ['status' => $status, 'headers' => $this->parseHeaders($headerRaw), 'body' => $body, 'final_url' => $finalUrl, 'body_complete' => true, 'headers_complete' => true]];
        }

        // Fallback streams
        $opts = [
            'http' => [
                'method'        => $method,
                'header'        => implode("\r\n", $ctxHeaders),
                'ignore_errors' => true,
                'follow_location' => $follow ? 1 : 0,
                'max_redirects' => 5,
                'timeout'       => max(1, (int)ceil($timeoutMs / 1000)),
                'content'       => $requestBody ?? '',
            ]
        ];
        $context = stream_context_create($opts);
        error_clear_last();
        $stream = @fopen($url, 'rb', false, $context);
        $streamError = error_get_last();
        if ($stream === false) {
            $observe(false);
            return $this->transportFailure($url, (string)($streamError['message'] ?? 'Stream request failed'), 'stream');
        }
        $body = ''; $limit = null; $readFailed = false;
        try {
            $metadata = stream_get_meta_data($stream);
            $responseHeaders = (array)($metadata['wrapper_data'] ?? []);
            $headerBytes = 0;
            foreach ($responseHeaders as $line) {
                $headerBytes += strlen($line) + 2;
                if ($headerBytes > self::MAX_HEADER_BYTES) { $limit = 'headers'; break; }
            }
            while ($limit === null && !feof($stream)) {
                $this->session?->checkpoint();
                $chunk = @fread($stream, min(8192, self::MAX_BODY_BYTES + 1 - strlen($body)));
                if ($chunk === false) { $readFailed = true; break; }
                $body .= $chunk;
                if (strlen($body) > self::MAX_BODY_BYTES) { $limit = 'body'; break; }
                if ($chunk === '') break;
            }
            $metadata = stream_get_meta_data($stream);
            $readFailed = $readFailed || !empty($metadata['timed_out']) || ($limit === null && !feof($stream));
        } finally { fclose($stream); }
        if ($limit !== null) {
            $observe(false);
            return $this->responseLimit($url, $limit, 'stream');
        }
        if ($readFailed) {
            $observe(false);
            return $this->transportFailure($url, 'Stream response incomplete or timed out', 'stream');
        }
        $hdrs = [];
        $status = 0;
        $finalUrl = $url;
        if ($responseHeaders !== []) {
            $hdrs = $this->parseHeaders(implode("\r\n", $responseHeaders));
            foreach ($responseHeaders as $line) {
                if (preg_match('~^HTTP/\S+\s+(\d{3})~', $line, $m)) $status = (int)$m[1];
                elseif ($follow && $status >= 300 && $status < 400 && stripos($line, 'Location:') === 0) {
                    $finalUrl = $this->redirectUrl($finalUrl, trim(substr($line, 9)));
                }
            }
        }
        $observe(true);
        return [true, '', ['status' => $status, 'headers' => $hdrs, 'body' => $body, 'final_url' => $finalUrl, 'body_complete' => true, 'headers_complete' => true]];
    }
    private function responseLimit(string $url, string $part, string $backend): array
    {
        $failure = $this->transportFailure($url, 'Response '.$part.' exceeded the bounded collection budget', $backend);
        $failure[2]['reason_code'] = 'HTTP_RESPONSE_LIMIT_EXCEEDED';
        $failure[2]['limit_part'] = $part;
        $failure[2]['max_body_bytes'] = self::MAX_BODY_BYTES;
        $failure[2]['max_header_bytes'] = self::MAX_HEADER_BYTES;
        $failure[2]['body_complete'] = false;
        $failure[2]['headers_complete'] = false;
        $failure[2]['action'] = 'Inspect the endpoint response size and rerun against a representative bounded page. No clean result is available from the incomplete response.';
        return $failure;
    }

    private function transportFailure(string $url, string $error, string $backend): array
    {
        $kind = 'HTTP_TRANSPORT_FAILED';
        $action = 'Verify that the resolved URL is reachable from the scanner and retry; inspect proxy/firewall routing if the site works only from your browser.';
        if (preg_match('~certificate|peer verification|self.signed~i', $error)) {
            $kind = 'HTTP_TLS_TRUST_FAILED';
            $steps = \Magebean\Engine\TlsCollectionGuidance::steps();
            $action = implode(' ', $steps);
        } elseif (preg_match('~SSL|crypto|TLS~i', $error)) {
            $kind = 'HTTP_TLS_FAILED';
            $action = 'Verify that the resolved HTTPS port serves TLS and supports modern protocols/ciphers accepted by the scanner OpenSSL/cURL client; inspect the negotiation error before rerunning.';
        } elseif (preg_match('~resolve|name resolution|getaddrinfo|php_network_getaddresses~i', $error)) {
            $kind = 'HTTP_DNS_FAILED';
            $action = 'Resolve the storefront hostname from the scanner environment (including WSL/container DNS or hosts mapping), then retry the same URL.';
        } elseif (preg_match('~timed? ?out|timeout~i', $error)) {
            $kind = 'HTTP_TIMEOUT';
            $action = 'Check endpoint latency and firewall routing from the scanner; increase this check timeout only after connectivity is confirmed.';
        }
        // Errors may include URL credentials/query secrets; never retain them in diagnostics.
        $safeUrl = preg_replace('~^(https?://)[^/@]+@~i', '$1', $url) ?? $url;
        $safeUrl = preg_replace('~[?#].*$~', '', $safeUrl) ?? $safeUrl;
        $safeError = str_replace($url, $safeUrl, $error);
        return [null, '[UNKNOWN] HTTP error: ' . $safeError, ['url' => $safeUrl, 'transport_error' => true, 'reason_code' => $kind, 'backend' => $backend, 'action' => $action] + (isset($steps) ? ['steps'=>$steps] : [])];
    }
    /** Resolve each redirect hop, including relative Location values, for stream evidence. */
    private function redirectUrl(string $base, string $location): string
    {
        if (preg_match('~^https?://~i', $location)) return $location;
        $parts = parse_url($base);
        if (!is_array($parts) || !isset($parts['host'])) return $base;
        $scheme = (string)($parts['scheme'] ?? 'http');
        if (str_starts_with($location, '//')) return $scheme . ':' . $location;
        $origin = $scheme . '://' . $parts['host'] . (isset($parts['port']) ? ':' . $parts['port'] : '');
        $basePath = (string)($parts['path'] ?? '/');
        if (str_starts_with($location, '?')) return $origin . $basePath . $location;
        if (str_starts_with($location, '#')) return preg_replace('~#.*$~', '', $base) . $location;
        $relative = parse_url($location);
        if (!is_array($relative)) return $base;
        $path = (string)($relative['path'] ?? '');
        if (!str_starts_with($path, '/')) $path = substr($basePath, 0, (int)strrpos($basePath, '/') + 1) . $path;
        $segments = [];
        foreach (explode('/', $path) as $segment) {
            if ($segment === '..') array_pop($segments);
            elseif ($segment !== '.' && $segment !== '') $segments[] = $segment;
        }
        $path = '/' . implode('/', $segments) . (str_ends_with($path, '/') && $segments !== [] ? '/' : '');
        return $origin . $path . (isset($relative['query']) ? '?' . $relative['query'] : '') . (isset($relative['fragment']) ? '#' . $relative['fragment'] : '');
    }
    private function parseHeaders(string $raw): array
    {
        // Combine duplicate headers; keep 'set-cookie' as array of all values.
        $out = [];
        foreach (preg_split("~\r?\n~", $raw) as $line) {
            if (preg_match('~^HTTP/\S+\s+\d{3}\b~i', $line)) {
                $out = [];
                continue;
            }
            if (strpos($line, ':') !== false) {
                [$k, $v] = array_map('trim', explode(':', $line, 2));
                $lk = strtolower($k);
                if ($lk === 'set-cookie') {
                    if (!isset($out[$lk])) $out[$lk] = [];
                    if (is_array($out[$lk])) $out[$lk][] = $v;
                    else $out[$lk] = [$out[$lk], $v];
                } else {
                    if (isset($out[$lk])) {
                        if (is_array($out[$lk])) $out[$lk][] = $v;
                        else $out[$lk] = [$out[$lk], $v];
                    } else {
                        $out[$lk] = $v;
                    }
                }
            }
        }
        return $out;
    }
}
