<?php
declare(strict_types=1);
namespace Magebean\Engine\Checks\Families;
use Magebean\Engine\Context;
use Magebean\Engine\Collectors\CollectorSet;

/** Internal shared primitives for compatible check families. */
abstract class ComposerSupport
{
    protected Context $ctx;
    protected CollectorSet $collectors;
    public function __construct(Context $ctx, ?CollectorSet $collectors = null)
    {
        $this->ctx = $ctx;
        $this->collectors = $collectors ?? new CollectorSet();
    }
    protected function unsupportedBranchMessage(array $response, string $installedVersion): string
    {
        $branch = trim((string)($response['branch'] ?? $installedVersion));
        $reason = (string)($response['reason'] ?? 'lifecycle_not_covered');
        $supportEnd = trim((string)($response['lifecycle']['security_support_end'] ?? ''));
        $recommended = trim((string)($response['recommended_latest_branch'] ?? ''));
        $supportedBranches = array_values(array_filter(array_map(
            static function (mixed $candidate): string {
                if (is_scalar($candidate)) return trim((string)$candidate);
                if (!is_array($candidate)) return '';
                return trim((string)($candidate['branch'] ?? $candidate['name'] ?? $candidate['version'] ?? ''));
            },
            is_array($response['supported_branches'] ?? null) ? $response['supported_branches'] : []
        )));
        $recommendationIsDifferent = $recommended !== '' && strcasecmp($recommended, $branch) !== 0;
        $recommendationIsSupported = $supportedBranches === []
            || in_array(strtolower($recommended), array_map('strtolower', $supportedBranches), true);

        $message = 'Magento branch ' . $branch
            . ($reason === 'security_support_ended'
                ? ' no longer receives Adobe security fixes'
                : ' is not covered by the current Adobe lifecycle dataset');
        if ($supportEnd !== '') $message .= ' (security support ended ' . $supportEnd . ')';
        if ($recommendationIsDifferent && $recommendationIsSupported) {
            return $message . '; upgrade to a supported release line such as ' . $recommended;
        }

        return $message . '. No supported upgrade recommendation is currently available.';
    }

    protected function isAdobeCorePackage(string $package): bool
    {
        $package = strtolower($package);

        if (str_starts_with($package, 'adobe-commerce/')) {
            return true;
        }

        if (!str_starts_with($package, 'magento/')) {
            return false;
        }

        $name = substr($package, strlen('magento/'));
        if (str_starts_with($name, 'module-')) {
            return true;
        }

        return in_array($name, [
            'framework',
            'magento2-base',
            'product-community-edition',
            'product-enterprise-edition',
            'security-package',
        ], true);
    }

    protected function evaluateOsvAdvisories(array $vulns, array $installedVers, array $sourceEvidence): array
    {
        $auditor = new \Magebean\Engine\Cve\CveAuditor($this->ctx);
        $sus = [];
        $unassessed = [];
        $remediated = [];
        $hotfixVerifier = new \Magebean\Engine\Cve\HotfixVerifier();
        $usableAdvisories = 0;

        foreach ($vulns as $vuln) {
            if (!is_array($vuln) || empty($vuln['affected']) || !is_array($vuln['affected'])) {
                continue;
            }
            $usableAdvisories++;

            $id = (string)($vuln['id'] ?? ($vuln['aliases'][0] ?? 'CVE'));
            $knownExploited = $this->isKnownExploitedAdvisory($vuln);

            foreach ($vuln['affected'] as $aff) {
                $pkg = $aff['package']['name'] ?? null;
                $eco = strtolower((string)($aff['package']['ecosystem'] ?? ''));
                if (!$pkg || !isset($installedVers[$pkg])) {
                    continue;
                }
                if ($eco !== 'packagist' && $eco !== 'composer') {
                    continue;
                }

                [$sevLabel, $cvssScore, $cvssVector] = $this->extractSeveritySafe($vuln, $aff);
                $current = $installedVers[$pkg];
                $hit = false;
                $fixed = null;
                $hasVersionEvidence = false;

                if (!empty($aff['versions']) && is_array($aff['versions'])) {
                    $hasVersionEvidence = true;
                    foreach ($aff['versions'] as $version) {
                        $version = ltrim((string)$version, 'vV');
                        if ($version !== '' && version_compare($current, $version, '==')) {
                            $hit = true;
                            break;
                        }
                    }
                }

                if (!empty($aff['ranges']) && is_array($aff['ranges'])) {
                    foreach ($aff['ranges'] as $range) {
                        $events = is_array($range['events'] ?? null) ? $range['events'] : [];
                        $rangeType = strtoupper((string)($range['type'] ?? 'SEMVER'));
                        $validEvents = $events !== [] && in_array($rangeType, ['SEMVER', 'ECOSYSTEM'], true);
                        foreach ($events as $event) {
                            if (!is_array($event) || count($event) !== 1
                                || !in_array(array_key_first($event), ['introduced', 'fixed', 'last_affected', 'limit'], true)
                                || !is_string(reset($event)) || trim(reset($event)) === '') {
                                $validEvents = false;
                            }
                        }
                        if (!$validEvents) {
                            $unassessed[strtolower((string)$pkg) . '@' . $current . '|' . $id . '|range'] = [
                                'package' => (string)$pkg, 'version' => $current,
                                'advisory' => $id, 'reason' => 'unsupported_or_malformed_range',
                            ];
                            continue;
                        }
                        $hasVersionEvidence = true;
                        $fixedCandidate = null;
                        $intervals = $this->eventsToIntervalsSafe($auditor, $events, $fixedCandidate);
                        foreach ($intervals as [$start, $end, $inclusive, $kind]) {
                            if ($this->inRangeSafe($auditor, $current, $start, $end, $inclusive)) {
                                $hit = true;
                                if ($end !== null && $kind === 'fixed') {
                                    $fixed = $this->minVersionLocal($fixed, $end);
                                }
                            }
                        }
                    }
                }

                if (!$hasVersionEvidence) {
                    $unassessedKey = strtolower((string)$pkg) . '@' . $current . '|' . $id;
                    $unassessed[$unassessedKey] = [
                        'package' => (string)$pkg,
                        'version' => $current,
                        'advisory' => $id,
                        'reason' => 'missing_versions_or_ranges',
                    ];
                    continue;
                }

                if (!$hit) {
                    continue;
                }

                $findingKey = strtolower((string)$pkg) . '@' . $current . '|' . $id;
                $hotfix = null;
                $hotfixRules = $aff['database_specific']['magebean_hotfixes'] ?? [];
                if (is_array($hotfixRules) && $hotfixRules !== []) {
                    // Only rules explicitly bound to this advisory may suppress this package finding.
                    $ids = array_map('strtoupper', array_merge([$id],
                        array_filter((array)($vuln['aliases'] ?? []), 'is_string')));
                    $hotfixRules = array_values(array_filter($hotfixRules, static fn($rule): bool =>
                        is_array($rule) && array_intersect($ids, array_map('strtoupper',
                            array_filter((array)($rule['advisories'] ?? []), 'is_string'))) !== []));
                    $hotfix = $hotfixVerifier->verify($this->ctx->path, (string)$pkg, $current, $hotfixRules);
                    if ($hotfix['status'] === 'verified_fixed') {
                        $remediated[$findingKey] = [
                            'package' => (string)$pkg, 'version' => $current,
                            'advisory' => $id, 'hotfix_verification' => $hotfix,
                        ];
                        continue;
                    }
                }
                $sus[$findingKey] = [
                    'package' => (string)$pkg,
                    'version' => $current,
                    'advisory' => $id,
                    ...(is_string($vuln['summary']??null)&&trim($vuln['summary'])!==''?['summary'=>$vuln['summary']]:[]),
                    ...(!empty($vuln['references'])&&is_array($vuln['references'])?['references'=>array_values(array_filter($vuln['references'],static fn($reference):bool=>is_array($reference)&&is_string($reference['url']??null)))]:[]),
                    'published' => is_string($vuln['published'] ?? null)
                        ? $vuln['published']
                        : null,
                    'severity' => $sevLabel,
                    'cvss' => $cvssScore,
                    'cvss_vector' => $cvssVector,
                    'fixed' => $fixed,
                    'known_exploited' => $knownExploited,
                    'hotfix_verification' => $hotfix,
                ];
            }
        }

        $evidence = $sourceEvidence + [
            'advisories' => count($vulns),
            'usable_advisories' => $usableAdvisories,
            'remediated_findings' => array_values($remediated),
            'unassessed_affected_packages' => array_values($unassessed),
        ];
        if ($vulns !== [] && $usableAdvisories === 0) {
            return [null, '[UNKNOWN] No usable OSV advisories found in response', $evidence];
        }

        $sus = array_values($sus);
        if ($sus !== []) {
            $vulnerablePackages = array_values(array_unique(array_map(
                static fn(array $item): string => (string)$item['package'],
                $sus
            )));
            $vulnerablePackageCount = count($vulnerablePackages);
            $findingCount = count($sus);
            $packageLabel = $vulnerablePackageCount === 1 ? 'package' : 'packages';
            $findingLabel = $findingCount === 1 ? 'advisory match' : 'advisory matches';
            $msg = sprintf(
                '%d vulnerable %s found (%d %s):',
                $vulnerablePackageCount,
                $packageLabel,
                $findingCount,
                $findingLabel
            ) . "\n    - " . implode("\n    - ", array_map(
                static function (array $item): string {
                    $message = $item['package'] . '@' . $item['version']
                        . ' -> ' . $item['advisory']
                        . ' (' . $item['severity'];
                    if (is_string($item['cvss'] ?? null) && $item['cvss'] !== '') {
                        $message .= ' · CVSS ' . $item['cvss'];
                    }
                    $message .= ')';
                    if (is_string($item['fixed'] ?? null) && $item['fixed'] !== '') {
                        $message .= ', fix >= ' . $item['fixed'];
                    }
                    if (is_array($item['hotfix_verification'] ?? null)) {
                        $message .= '; hotfix not verified (version match remains)';
                    }
                    return $message;
                },
                $sus
            ));
            if ($unassessed !== []) {
                $unassessedDetails = array_map(
                    static fn(array $item): string => $item['package'] . '@' . $item['version']
                        . ' -> ' . $item['advisory'] . ' (' . $item['reason'] . ')',
                    array_values($unassessed)
                );
                $msg .= "\n    Version evidence unavailable for:\n    - "
                    . implode("\n    - ", $unassessedDetails);
            }
            return [false, $msg, $evidence + [
                'findings' => $sus,
                'vulnerable_packages' => $vulnerablePackages,
                'vulnerable_packages_count' => $vulnerablePackageCount,
                'advisory_matches_count' => $findingCount,
            ]];
        }

        if ($unassessed !== []) {
            $details = array_map(
                static fn(array $item): string => $item['package'] . '@' . $item['version']
                    . ' -> ' . $item['advisory'] . ' (' . $item['reason'] . ')',
                array_values($unassessed)
            );
            return [
                null,
                "[UNKNOWN] Installed packages have advisories without version evidence:\n    - "
                    . implode("\n    - ", $details),
                $evidence,
            ];
        }

        return [
            true,
            'No unresolved vulnerable packages according to OSV advisories (' . count($installedVers) . ' pkgs, ' . count($vulns) . ' advisories; ' . count($remediated) . ' package/advisory matches verified fixed by hotfix)',
            $evidence,
        ];
    }

    protected function isKnownExploitedAdvisory(array $advisory): bool
    {
        if (($advisory['database_specific']['known_exploited'] ?? false) === true) {
            return true;
        }
        if (!empty($advisory['source']['kev'])) {
            return true;
        }

        foreach ((array)($advisory['references'] ?? []) as $reference) {
            $url = strtolower((string)($reference['url'] ?? ''));
            if ($url !== ''
                && str_contains($url, 'cisa.gov')
                && (str_contains($url, 'known-exploited') || str_contains($url, '/kev'))
            ) {
                return true;
            }
        }
        return false;
    }

    protected function isAllowedAdvisoryEndpoint(string $endpoint): bool
    {
        $parts = parse_url($endpoint);
        if (!is_array($parts) || empty($parts['scheme']) || empty($parts['host'])) {
            return false;
        }

        $scheme = strtolower((string)$parts['scheme']);
        if ($scheme === 'https') {
            return true;
        }

        $host = strtolower(trim((string)$parts['host'], '[]'));
        return $scheme === 'http' && in_array($host, ['localhost', '127.0.0.1', '::1'], true);
    }

    protected function canFallbackToPrivateHttp(string $endpoint): bool
    {
        $parts = parse_url($endpoint);
        if (
            !is_array($parts)
            || strtolower((string)($parts['scheme'] ?? '')) !== 'https'
            || empty($parts['host'])
        ) {
            return false;
        }

        $host = strtolower(trim((string)$parts['host'], '[]'));
        if (in_array($host, ['localhost', '127.0.0.1', '::1'], true)) {
            return true;
        }

        $addresses = gethostbynamel($host);
        if (!is_array($addresses) || $addresses === []) {
            return false;
        }

        foreach ($addresses as $address) {
            if ($this->isPrivateOrLoopbackIpv4($address)) {
                return true;
            }
        }

        return false;
    }

    protected function isPrivateOrLoopbackIpv4(string $address): bool
    {
        $ip = ip2long($address);
        if ($ip === false) {
            return false;
        }
        $ip = (int)sprintf('%u', $ip);

        foreach ([
            ['10.0.0.0', '10.255.255.255'],
            ['127.0.0.0', '127.255.255.255'],
            ['169.254.0.0', '169.254.255.255'],
            ['172.16.0.0', '172.31.255.255'],
            ['192.168.0.0', '192.168.255.255'],
        ] as [$start, $end]) {
            $rangeStart = (int)sprintf('%u', ip2long($start));
            $rangeEnd = (int)sprintf('%u', ip2long($end));
            if ($ip >= $rangeStart && $ip <= $rangeEnd) {
                return true;
            }
        }

        return false;
    }

    protected function postJson(string $url, array $payload, int $timeoutMs, string $token = ''): array
    {
        $loaded=null;
        $key='dependency-api:'.hash('sha256',serialize([$url,$payload,$timeoutMs,$token]));
        $cached=$this->collectors->session->remember($key,function () use ($url,$payload,$timeoutMs,$token,&$loaded): ?array {
            $loaded=$this->postJsonFresh($url,$payload,$timeoutMs,$token);
            $decoded=json_decode((string)($loaded[2]['body']??''),true);
            $valid=($loaded[0]??false) && ($loaded[2]['status']??null)===200 && is_array($decoded);
            if (($payload['schema_version']??'')==='magebean-osv-request-v1') $valid=$valid && ($decoded['schema_version']??'')==='magebean-osv-response-v1' && is_array($decoded['advisories']??null) && array_is_list($decoded['advisories']);
            if (($payload['schema_version']??'')==='magebean-osv-request-v1' && $valid) {
                foreach ($decoded['advisories'] as $advisory) if (!is_array($advisory) || !is_array($advisory['affected']??null) || $advisory['affected']===[]) $valid=false;
            }
            if (($payload['schema_version']??'')==='magebean-package-status-request-v1') $valid=$valid && ($decoded['schema_version']??'')==='magebean-package-status-response-v1' && is_array($decoded['packages']??null);
            return $valid?$loaded:null;
        });
        return $cached??$loaded;
    }

    private function postJsonFresh(string $url, array $payload, int $timeoutMs, string $token = ''): array
    {
        $json = json_encode($payload, JSON_UNESCAPED_SLASHES);
        if (!is_string($json)) {
            return [false, 'Unable to encode request JSON', []];
        }

        $headers = [
            'Accept: application/json',
            'Content-Type: application/json',
            'User-Agent: Magebean-CLI/1.0',
        ];
        if ($token !== '') {
            $headers[] = 'Authorization: Bearer ' . $token;
        }

        return $this->collectors->http->fetch($url, 'POST', $headers, $timeoutMs, false, $json);
    }

    protected function eventsToIntervals(array $events): array
    {
        return \Magebean\Engine\Cve\OsvRange::intervals($events);
    }

    protected function inRange(string $cur, ?string $a, ?string $b, bool $inclusive = false): bool
    {
        return \Magebean\Engine\Cve\OsvRange::contains($cur, $a, $b, $inclusive);
    }

    protected function extractSeverity(array $vuln): ?string
    {
        $sev = $vuln['severity'][0]['score'] ?? null;
        return is_string($sev) ? $sev : null;
    }

    protected function fetchPackageStatuses(array $args, array $packages): array
    {
        $endpoint = trim((string)($args['status_endpoint'] ?? $this->ctx->get(
            'package_status_api_url',
            'https://api.magebean.com/v1/packages/status'
        )));
        if (!$this->isAllowedAdvisoryEndpoint($endpoint)) {
            return [false, 'Invalid package status API endpoint; HTTPS is required', []];
        }

        $timeoutMs = max(1000, (int)($args['timeout_ms'] ?? 10000));
        $batchSize = max(1, min(1000, (int)($args['status_batch_size'] ?? $args['batch_size'] ?? 500)));
        $token = trim((string)($args['token'] ?? $this->ctx->get(
            'package_status_api_token',
            getenv('MAGEBEAN_PACKAGE_STATUS_API_TOKEN') ?: ''
        )));

        $byName = []; $batchGaps=[];
        foreach (array_chunk($packages, $batchSize) as $batchIndex => $batch) {
            $requestEndpoint = $endpoint;
            [$ok, $message, $response] = $this->postJson(
                $requestEndpoint,
                [
                    'schema_version' => 'magebean-package-status-request-v1',
                    'packages' => $batch,
                ],
                $timeoutMs,
                $token
            );
            if (!$ok
                && !empty($args['allow_private_http_fallback'])
                && $token === ''
                && $this->canFallbackToPrivateHttp($endpoint)
            ) {
                $requestEndpoint = 'http://' . substr($endpoint, strlen('https://'));
                [$ok, $message, $response] = $this->postJson(
                    $requestEndpoint,
                    [
                        'schema_version' => 'magebean-package-status-request-v1',
                        'packages' => $batch,
                    ],
                    $timeoutMs,
                    $token
                );
            }
            $status=(int)($response['status']??0);
            $decoded=json_decode((string)($response['body']??''),true);
            if (!$ok || $status!==200 || !is_array($decoded)
                || ($decoded['schema_version']??null)!=='magebean-package-status-response-v1'
                || !is_array($decoded['packages']??null)) {
                $batchGaps[]=$batchIndex+1;
                continue;
            }

            foreach ((array)($decoded['packages'] ?? []) as $package) {
                if (is_array($package) && is_string($package['name'] ?? null)) {
                    $package['_status_observation']=['endpoint'=>$requestEndpoint,'identity'=>hash('sha256',json_encode($package,JSON_INVALID_UTF8_SUBSTITUTE|JSON_THROW_ON_ERROR)), 'dataset_revision'=>$decoded['meta']['dataset_revision']??null];
                    $byName[strtolower($package['name'])] = $package;
                }
            }
        }
        if ($byName===[] && $batchGaps!==[]) return [false,'Package status response unavailable or invalid',[]];
        return [true, ($batchGaps!==[]?'Partial package status; missing batches '.implode(',',$batchGaps).'. ':'').'Package status loaded (' . count($packages) . ' packages in '
            . (int)ceil(count($packages) / $batchSize) . ' batch(es))', $byName];
    }

    protected function absPath(string $p): string
    {
        $p = trim($p);
        if ($p === '') return getcwd();
        // expand relative
        if ($p[0] !== '/') {
            $p = rtrim(getcwd(), '/') . '/' . ltrim($p, '/');
        }
        return rtrim($p, '/');
    }

    protected function loadJsonSafe(string $path): ?array
    {
        return $this->collectors->composer->json($path);
    }

    protected function applyAdobeFingerprintEvidence(array $response, array $localEvidence = []): array
    {
        $remaining = [];
        $satisfied = is_array($response['satisfied_by_alternatives'] ?? null)
            ? $response['satisfied_by_alternatives']
            : [];

        foreach ((array)($response['missing_patches'] ?? []) as $patch) {
            if (!is_array($patch)) continue;
            $proof = null;

            foreach ((array)($patch['alternative_rules'] ?? []) as $rule) {
                if (!is_array($rule)) continue;
                $type = (string)($rule['type'] ?? '');

                if ($type === 'package_constraint') {
                    $package = strtolower(trim((string)($rule['package'] ?? '')));
                    $constraint = trim((string)($rule['constraint'] ?? ''));
                    $version = $localEvidence['packages'][$package] ?? null;
                    if (is_string($version) && $constraint !== '') {
                        try {
                            if (\Composer\Semver\Semver::satisfies($version, $constraint)) {
                                $proof = [
                                    'type' => $type,
                                    'label' => $rule['label'] ?? null,
                                    'package' => $package,
                                    'version' => $version,
                                    'constraint' => $constraint,
                                    'verification' => 'installed package constraint matched locally',
                                    'source_url' => $rule['source_url'] ?? null,
                                ];
                                break;
                            }
                        } catch (\Throwable) {
                            // Invalid constraints cannot satisfy an alternative.
                        }
                    }
                    continue;
                }

                if ($type === 'patch_identifier') {
                    $pattern = strtolower(trim((string)($rule['pattern'] ?? '')));
                    foreach ((array)($localEvidence['patch_artifacts'] ?? []) as $artifact) {
                        if (!is_array($artifact) || empty($artifact['applied']) || $pattern === '') continue;
                        $haystack = strtolower(implode(' ', array_merge(
                            [(string)($artifact['path'] ?? '')],
                            array_map('strval', (array)($artifact['identifiers'] ?? []))
                        )));
                        if ($haystack !== '' && str_contains($haystack, $pattern)) {
                            $proof = [
                                'type' => $type,
                                'label' => $rule['label'] ?? null,
                                'identifier' => $pattern,
                                'verification' => 'applied patch identifier matched locally',
                                'source_url' => $rule['source_url'] ?? null,
                            ];
                            break 2;
                        }
                    }
                    continue;
                }

                if ($type !== 'file_sha256') continue;
                $relative = str_replace('\\', '/', trim((string)($rule['path'] ?? '')));
                $expected = strtolower((string)($rule['patched_sha256'] ?? $rule['sha256'] ?? ''));
                if ($relative === '' || str_starts_with($relative, '/') || str_contains($relative, '../')
                    || !preg_match('/^[a-f0-9]{64}$/', $expected)) {
                    continue;
                }
                $absolute = $this->ctx->abs($relative);
                if (!is_file($absolute)) continue;
                $actual = hash_file('sha256', $absolute);
                if (is_string($actual) && hash_equals($expected, strtolower($actual))) {
                    $proof = [
                        'type' => $type,
                        'label' => $rule['label'] ?? null,
                        'path' => $relative,
                        'sha256' => $actual,
                        'verification' => 'patched file fingerprint matched locally',
                        'source_url' => $rule['source_url'] ?? null,
                    ];
                    break;
                }
            }

            if ($proof === null) {
                $remaining[] = $patch;
                continue;
            }
            $advisory = (string)($patch['advisory'] ?? 'unknown');
            $satisfied[$advisory] = $proof;
        }

        $response['missing_patches'] = $remaining;
        $response['satisfied_by_alternatives'] = $satisfied;
        if (($response['status'] ?? null) === 'outdated' && $remaining === []) {
            $response['status'] = 'current';
        }
        return $response;
    }

    /** Strict inventory completeness before narrowing an API query to a package subset. */
    protected function strictInventoryProblem(array $args, bool $rootRequired = false): ?array
    {
        if (empty($args['strict_scope'])) return null;
        $path = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        $raw = $this->collectors->files->read($path);
        $data = is_string($raw) ? json_decode($raw, true) : null;
        $bad = !is_array($data) || !isset($data['packages']) || !is_array($data['packages']) || !array_is_list($data['packages']);
        $seen = [];
        foreach (['packages','packages-dev'] as $section) {
            if (isset($data[$section]) && (!is_array($data[$section]) || !array_is_list($data[$section]))) { $bad = true; continue; }
            foreach ($data[$section] ?? [] as $package) {
                if (!is_array($package) || !is_string($package['name'] ?? null) || preg_match('~^[a-z0-9_.-]+/[a-z0-9_.-]+$~iD', $package['name']) !== 1 || !is_string($package['version'] ?? null) || trim($package['version']) === '') { $bad = true; continue; }
                $name = strtolower($package['name']);
                if (isset($seen[$name])) $bad = true;
                $seen[$name] = true;
                if (isset($package['require']) && !is_array($package['require'])) $bad = true;
            }
        }
        if ($bad) return [null, '[UNKNOWN] composer.lock inventory is missing or malformed; restore a complete lock file before querying package status.', ['file'=>'composer.lock']];
        if (!$rootRequired) return null;
        $rootPath = $this->ctx->abs($args['composer_file'] ?? $args['json_file'] ?? 'composer.json');
        $raw = $this->collectors->files->read($rootPath);
        $data = is_string($raw) ? json_decode($raw, true) : null;
        $bad = !is_array($data);
        foreach (['require','require-dev'] as $section) {
            if (isset($data[$section]) && !is_array($data[$section])) { $bad = true; continue; }
            foreach ($data[$section] ?? [] as $name => $constraint) if (!is_string($name) || !is_string($constraint) || trim($constraint) === '') $bad = true;
        }
        if ($bad) return [null, '[UNKNOWN] composer.json dependency declarations are missing or malformed; restore the project manifest.', ['file'=>'composer.json']];
        return null;
    }

    protected function dependencySelection(array $args): array
    {
        $inventory=$this->collectors->dependencies->collect($this->ctx,$args);
        return $this->collectors->dependencies->select($inventory,(string)($args['dependency_scope']??'current'));
    }

    protected function withDependencyProvenance(array $result, array $selection): array
    {
        $evidence=is_array($result[2]??null)?$result[2]:[];
        $evidence['dependency_inventory']=array_diff_key($selection,['packages'=>true]);
        $evidence['package_observations']=array_map(static fn(array $p): array=>$p['dependency_observation'],$selection['packages']);
        foreach (['findings','unassessed','unassessed_affected_packages','remediated_findings'] as $field) {
            foreach ($evidence[$field]??[] as $index=>$finding) {
                $name=$finding['package']??'';
                if (isset($selection['packages'][$name])) $evidence[$field][$index]['dependency_observation']=$selection['packages'][$name]['dependency_observation'];
            }
        }
        $message=(string)($result[1]??'');
        if ($selection['scope']==='locked_dependency') {
            $message=str_replace(['installed package','Installed package','installed version'],['locked package','Locked package','locked version'],$message);
            if (!str_contains($message,'[Scope: locked dependency declarations;')) $message.=' [Scope: locked dependency declarations; installation and runtime exposure unverified.]';
        }
        if ((!$selection['complete'] || !empty($evidence['feed_gaps'])) && ($result[0]??null)===true) {
            $result[0]=null; $message='[UNKNOWN] Dependency inventory coverage incomplete; no clean conclusion can be established.';
        }
        if (!$selection['complete'] && ($result[0]??null)!==false) $evidence['reason_code']='COMPOSER_LOCK_SCOPE_INVALID';
        if (!$selection['complete']) $message.=' [Inventory: composer.lock or installed metadata coverage incomplete.]';
        return [$result[0]??null,$message,$evidence];
    }

    protected function readLockPackages(string $lockPath): ?array
    {
        return $this->collectors->composer->packages($lockPath);
    }

    protected function metaPath(array $args, string $metaKey, string $argKey, string $defaultRel): ?string
    {
        $metaBag = $this->ctx->get('meta', []);
        if (is_array($metaBag) && !empty($metaBag[$metaKey]) && is_string($metaBag[$metaKey])) {
            $p = $metaBag[$metaKey];
            if ($this->safeIsFile($p)) return $p;
        }
        $root = (string)($this->ctx->path ?? getcwd());
        $cand = $this->safeJoin($root, is_string($args[$argKey] ?? null) ? $args[$argKey] : $defaultRel);
        return $this->safeIsFile($cand) ? $cand : null;
    }

    protected function safeIsFile($p): bool
    {
        return is_string($p) && $p !== '' && is_file($p);
    }

    protected function safeJoin($base, $rel): ?string
    {
        if (!is_string($base)) $base = '';
        if (!is_string($rel))  return null;
        $base = rtrim($base, '/');
        if ($rel === '' || $rel === '.') return $base;
        if ($rel[0] === '/' || preg_match('#^[A-Za-z]:[\\\\/]#', $rel)) return $rel;
        return $base . '/' . ltrim($rel, '/');
    }

    protected function findCveBundleCandidate(?string $explicit): array
    {
        $cands = [];
        if ($explicit) $cands[] = $explicit;

        // vài vị trí thường gặp
        $cands[] = $this->ctx->abs('magebean-known-cve-data-202510.zip');
        $cands[] = $this->ctx->abs('magebean-known-cve-data.zip');
        $cands[] = $this->ctx->abs('cve-data.zip');
        $cands[] = $this->ctx->abs('.'); // bundle đã giải nén ngay trong project

        // /tmp loader patterns (nếu bạn có cơ chế giải nén tạm)
        foreach (glob('/tmp/magebean-cve-*') ?: [] as $d) $cands[] = $d;

        foreach ($cands as $p) {
            if (is_file($p) && str_ends_with(strtolower($p), '.zip')) {
                $z = new \ZipArchive();
                if ($z->open($p) !== true) {
                    // zip hỏng -> tiếp tục dò candidate khác
                    continue;
                }
                // đếm VULNS/*.json
                $count = 0;
                for ($i = 0; $i < $z->numFiles; $i++) {
                    $name = $z->getNameIndex($i);
                    if (!$name) continue;
                    $ln = strtolower($name);
                    if (str_starts_with($ln, 'vulns/') && str_ends_with($ln, '.json')) $count++;
                }
                $z->close();
                return ['status' => 'ok', 'type' => 'zip', 'path' => $p, 'vuln_count' => $count];
            }
            if (is_dir($p)) {
                $vdir = rtrim($p, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'VULNS';
                if (!is_dir($vdir)) {
                    // không coi là ok vì thiếu VULNS
                    continue;
                }
                $files = glob($vdir . DIRECTORY_SEPARATOR . '*.json') ?: [];
                return ['status' => 'ok', 'type' => 'dir', 'path' => $p, 'vuln_count' => count($files)];
            }
        }
        return ['status' => 'err', 'reason' => 'CVE bundle not found (zip or VULNS dir)'];
    }

    protected function loadVulnsViaAuditor(\Magebean\Engine\Cve\CveAuditor $auditor, string $cveDataPath): array
    {
        $ref = new \ReflectionClass($auditor);
        if ($ref->hasMethod('readCveFile')) {
            $m = $ref->getMethod('readCveFile');
            $m->setAccessible(true);
            $v = $m->invoke($auditor, $cveDataPath);
            return is_array($v) ? $v : [];
        }
        return [];
    }

    protected function extractSeveritySafe(array $vuln, ?array $affected = null): array
    {
        $severity = \Magebean\Engine\Cve\OsvSeverity::resolve($vuln, $affected);
        return [$severity['label'], $severity['score'], $severity['vector']];
    }

    protected function eventsToIntervalsSafe($auditor, array $events, ?string &$minFixedCandidate = null): array
    {
        return \Magebean\Engine\Cve\OsvRange::intervals($events, $minFixedCandidate);
    }

    protected function inRangeSafe($auditor, string $cur, ?string $a, ?string $b, bool $inclusive = false): bool
    {
        return \Magebean\Engine\Cve\OsvRange::contains($cur, $a, $b, $inclusive);
    }

    protected function minVersionLocal(?string $cur, string $cand): string
    {
        if ($cur === null) return ltrim($cand, 'v');
        return version_compare(ltrim($cand, 'v'), $cur, '<') ? ltrim($cand, 'v') : $cur;
    }

    protected function packageStatusApiFailureEvidence(array $packages, array $extra = []): array
    {
        return array_merge([
            'packages_checked' => count($packages),
            'package_list_omitted' => true,
        ], $extra);
    }
}
