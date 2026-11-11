<?php
declare(strict_types=1);
namespace Magebean\Engine\Checks\Families;
use Magebean\Engine\Context;
use Magebean\Engine\Collectors\CollectorSet;

final class ComposerAdvisoryChecks extends ComposerSupport
{
    /** Validate before collectors normalize or omit malformed dependency records. */
    private function validateLockScope(string $lockFile): ?string
    {
        $raw = $this->collectors->files->read($lockFile);
        $lock = is_string($raw) ? json_decode($raw, true) : null;
        if (!is_array($lock) || !array_key_exists('packages', $lock)) {
            return 'composer.lock dependency scope is missing or invalid';
        }
        $names = [];
        foreach (['packages', 'packages-dev'] as $section) {
            if (!array_key_exists($section, $lock) && $section === 'packages-dev') continue;
            $packages = $lock[$section] ?? null;
            if (!is_array($packages) || !array_is_list($packages)) {
                return 'composer.lock ' . $section . ' must be a dependency list';
            }
            foreach ($packages as $package) {
                if (!is_array($package) || !is_string($package['name'] ?? null)
                    || !preg_match('/^[a-z0-9_.-]+\/[a-z0-9_.-]+$/D', $package['name'])
                    || !is_string($package['version'] ?? null)
                    || trim($package['version']) === '' || trim($package['version']) !== $package['version']) {
                    return 'composer.lock contains an invalid dependency name or version';
                }
                if (isset($names[$package['name']])) {
                    return 'composer.lock contains duplicate dependency records';
                }
                $names[$package['name']] = true;
            }
        }
        return null;
    }

    public function auditApi(array $args): array
    {
        $lockFile = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        if (!is_file($lockFile)) {
            return [null, '[UNKNOWN] composer.lock not found'];
        }

        if (!empty($args['strict_scope'])) {
            $scopeError = $this->validateLockScope($lockFile);
            if ($scopeError !== null) {
                return [null, '[UNKNOWN] ' . $scopeError];
            }
        }

        $installed = $this->readLockPackages($lockFile);
        if (!$installed || !is_array($installed)) {
            return [null, '[UNKNOWN] Unable to parse composer.lock'];
        }

        $installedVers = [];
        foreach ($installed as $name => $info) {
            $version = $info['version'] ?? null;
            if (is_string($version) && $version !== '') {
                $installedVers[(string)$name] = ltrim($version, 'vV');
            }
        }
        $packageScope = (string)($args['package_scope'] ?? 'all');
        if ($packageScope === 'adobe_core') {
            $installedVers = array_filter(
                $installedVers,
                fn(string $version, string $name): bool => $this->isAdobeCorePackage($name),
                ARRAY_FILTER_USE_BOTH
            );
        }
        if (is_array($args['package_names'] ?? null)) {
            $allowedPackages = array_fill_keys(array_map(
                static fn(mixed $name): string => strtolower((string)$name),
                $args['package_names']
            ), true);
            $installedVers = array_filter(
                $installedVers,
                static fn(string $version, string $name): bool => isset($allowedPackages[strtolower($name)]),
                ARRAY_FILTER_USE_BOTH
            );
        }
        if ($installedVers === []) {
            $message = $packageScope === 'adobe_core'
                ? 'No Adobe/Magento core packages found in composer.lock'
                : 'No packages in composer.lock (nothing to audit)';
            return [null, '[UNKNOWN] ' . $message . '; advisory scope could not be established', ['package_scope' => $packageScope, 'packages' => 0]];
        }

        $endpoint = trim((string)($args['endpoint'] ?? $this->ctx->get(
            'osv_api_url',
            'https://api.magebean.com/v1/osv/advisories'
        )));
        if (!$this->isAllowedAdvisoryEndpoint($endpoint)) {
            return [null, '[UNKNOWN] Invalid OSV API endpoint; HTTPS is required', ['endpoint' => $endpoint]];
        }

        $timeoutMs = max(1000, (int)($args['timeout_ms'] ?? 10000));
        $batchSize = max(1, min(1000, (int)($args['batch_size'] ?? 500)));
        $allowPrivateHttpFallback = !empty($args['allow_private_http_fallback']);
        $token = trim((string)($args['token'] ?? $this->ctx->get(
            'osv_api_token',
            getenv('MAGEBEAN_OSV_API_TOKEN') ?: ''
        )));

        $packages = [];
        foreach ($installedVers as $name => $version) {
            $packages[] = ['name' => $name, 'version' => $version];
        }

        $advisories = [];
        $responses = [];
        foreach (array_chunk($packages, $batchSize) as $batchIndex => $batch) {
            $payload = [
                'schema_version' => 'magebean-osv-request-v1',
                'ecosystem' => 'Packagist',
                'packages' => $batch,
                'client' => [
                    'name' => 'magebean-cli',
                    'version' => (string)($args['client_version'] ?? 'dev'),
                ],
            ];

            [$transportOk, $transportMessage, $response] = $this->postJson(
                $endpoint,
                $payload,
                $timeoutMs,
                $token
            );
            $requestEndpoint = $endpoint;
            if (
                !$transportOk
                && $allowPrivateHttpFallback
                && $token === ''
                && $this->canFallbackToPrivateHttp($endpoint)
            ) {
                $requestEndpoint = 'http://' . substr($endpoint, strlen('https://'));
                [$transportOk, $transportMessage, $response] = $this->postJson(
                    $requestEndpoint,
                    $payload,
                    $timeoutMs,
                    $token
                );
            }
            if (!$transportOk) {
                return [
                    null,
                    '[UNKNOWN] OSV API request failed: ' . $transportMessage,
                    [
                        'endpoint' => $endpoint,
                        'request_endpoint' => $requestEndpoint,
                        'batch' => $batchIndex + 1,
                    ],
                ];
            }

            $status = (int)($response['status'] ?? 0);
            $body = (string)($response['body'] ?? '');
            $decoded = json_decode($body, true);
            if ($status !== 200) {
                $apiMessage = is_array($decoded)
                    ? (string)($decoded['error']['message'] ?? $decoded['message'] ?? '')
                    : '';
                $suffix = $apiMessage !== '' ? ': ' . $apiMessage : '';
                return [
                    null,
                    '[UNKNOWN] OSV API returned HTTP ' . $status . $suffix,
                    [
                        'endpoint' => $endpoint,
                        'request_endpoint' => $requestEndpoint,
                        'status' => $status,
                        'batch' => $batchIndex + 1,
                    ],
                ];
            }

            if (!is_array($decoded)) {
                return [
                    null,
                    '[UNKNOWN] OSV API returned invalid JSON',
                    ['endpoint' => $endpoint, 'batch' => $batchIndex + 1],
                ];
            }
            if (($decoded['schema_version'] ?? null) !== 'magebean-osv-response-v1') {
                return [
                    null,
                    '[UNKNOWN] Unsupported OSV API response schema',
                    [
                        'endpoint' => $endpoint,
                        'schema_version' => $decoded['schema_version'] ?? null,
                        'batch' => $batchIndex + 1,
                    ],
                ];
            }
            if (!array_key_exists('advisories', $decoded) || !is_array($decoded['advisories'])) {
                return [
                    null,
                    '[UNKNOWN] OSV API response is missing advisories array',
                    ['endpoint' => $endpoint, 'batch' => $batchIndex + 1],
                ];
            }

            foreach ($decoded['advisories'] as $advisory) {
                if (!is_array($advisory) || !is_array($advisory['affected'] ?? null) || $advisory['affected'] === []) {
                    return [null, '[UNKNOWN] OSV API returned a malformed advisory', ['endpoint' => $endpoint, 'batch' => $batchIndex + 1]];
                }
                $key = (string)($advisory['id'] ?? hash('sha256', json_encode($advisory)));
                if (!isset($advisories[$key])) {
                    $advisories[$key] = $advisory;
                    continue;
                }

                $existingAffected = is_array($advisories[$key]['affected'] ?? null)
                    ? $advisories[$key]['affected']
                    : [];
                $newAffected = is_array($advisory['affected'] ?? null)
                    ? $advisory['affected']
                    : [];
                $advisories[$key]['affected'] = array_merge($existingAffected, $newAffected);
            }
            $responses[] = [
                'batch' => $batchIndex + 1,
                'request_endpoint' => $requestEndpoint,
                'packages' => count($batch),
                'advisories' => count($decoded['advisories']),
                'dataset_revision' => $decoded['meta']['dataset_revision'] ?? null,
            ];
        }

        $sourceEvidence = [
            'source' => 'magebean_osv_api',
            'package_scope' => $packageScope,
            'endpoint' => $endpoint,
            'packages' => count($installedVers),
            'responses' => $responses,
        ];

        if ($advisories === []) {
            return [
                true,
                'No vulnerable packages according to Magebean OSV API (' . count($installedVers) . ' pkgs)',
                $sourceEvidence,
            ];
        }

        return $this->evaluateOsvAdvisories(
            array_values($advisories),
            $installedVers,
            $sourceEvidence
        );
    }

    public function adobeSecurityPatchesApi(array $args): array
    {
        $lockFile = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        if (!is_file($lockFile)) {
            return [null, '[UNKNOWN] composer.lock not found'];
        }

        if (!empty($args['strict_scope'])) {
            $scopeError = $this->validateLockScope($lockFile);
            if ($scopeError !== null) {
                return [null, '[UNKNOWN] ' . $scopeError];
            }
        }

        $installed = $this->readLockPackages($lockFile);
        if (!$installed) {
            return [null, '[UNKNOWN] Unable to parse composer.lock'];
        }

        $product = null;
        $version = null;
        foreach ([
            'magento/product-enterprise-edition' => 'adobe-commerce',
            'magento/product-community-edition' => 'magento-open-source',
        ] as $package => $candidateProduct) {
            if (!empty($installed[$package]['version'])) {
                $product = $candidateProduct;
                $version = ltrim((string)$installed[$package]['version'], 'vV');
                break;
            }
        }
        if ($version === null && !empty($installed['magento/magento2-base']['version'])) {
            $product = 'magento-open-source';
            $version = ltrim((string)$installed['magento/magento2-base']['version'], 'vV');
        }
        if ($product === null || $version === null) {
            return [null, '[UNKNOWN] Magento product version was not found in composer.lock'];
        }

        $endpoint = trim((string)($args['endpoint'] ?? $this->ctx->get(
            'adobe_patch_api_url',
            'https://api.magebean.com/v1/adobe/security-patches'
        )));
        if (!$this->isAllowedAdvisoryEndpoint($endpoint)) {
            return [null, '[UNKNOWN] Invalid Adobe patch API endpoint; HTTPS is required', ['endpoint' => $endpoint]];
        }

        $localPatchEvidence = $this->collectAdobePatchEvidence($installed);
        $payload = [
            'schema_version' => 'magebean-adobe-patch-request-v1',
            'product' => $product,
            'installed_version' => $version,
            'evidence' => [
                'packages' => (object)[],
                'patch_artifacts' => [],
            ],
            'client' => ['name' => 'magebean-cli', 'version' => (string)($args['client_version'] ?? 'dev')],
        ];
        $timeoutMs = max(1000, (int)($args['timeout_ms'] ?? 10000));
        $token = trim((string)($args['token'] ?? $this->ctx->get(
            'adobe_patch_api_token',
            getenv('MAGEBEAN_ADOBE_PATCH_API_TOKEN') ?: ''
        )));
        [$ok, $message, $response] = $this->postJson($endpoint, $payload, $timeoutMs, $token);
        $requestEndpoint = $endpoint;
        if (!$ok && !empty($args['allow_private_http_fallback']) && $token === ''
            && $this->canFallbackToPrivateHttp($endpoint)) {
            $requestEndpoint = 'http://' . substr($endpoint, strlen('https://'));
            [$ok, $message, $response] = $this->postJson($requestEndpoint, $payload, $timeoutMs, $token);
        }
        if (!$ok) {
            return [null, '[UNKNOWN] Adobe patch API request failed: ' . $message, [
                'endpoint' => $endpoint,
                'request_endpoint' => $requestEndpoint,
                'product' => $product,
                'installed_version' => $version,
            ]];
        }

        $statusCode = (int)($response['status'] ?? 0);
        $decoded = json_decode((string)($response['body'] ?? ''), true);
        if ($statusCode !== 200 || !is_array($decoded)) {
            return [null, '[UNKNOWN] Adobe patch API returned HTTP ' . $statusCode, [
                'endpoint' => $endpoint,
                'status' => $statusCode,
            ]];
        }
        if (in_array($decoded['status'] ?? null, ['current', 'outdated'], true)) {
            if (!is_array($decoded['missing_patches'] ?? null)) {
                return [null, '[UNKNOWN] Adobe patch API missing required patch evidence', ['endpoint' => $endpoint]];
            }
            foreach ($decoded['missing_patches'] as $patch) {
                if (!is_array($patch) || !is_string($patch['advisory'] ?? null)
                    || trim($patch['advisory']) === '') {
                    return [null, '[UNKNOWN] Adobe patch API returned malformed patch evidence', ['endpoint' => $endpoint]];
                }
            }
        }
        if (($decoded['schema_version'] ?? null) === 'magebean-adobe-patch-response-v1') {
            $decoded = $this->applyAdobeFingerprintEvidence($decoded, $localPatchEvidence);
        }
        if (($decoded['schema_version'] ?? null) !== 'magebean-adobe-patch-response-v1') {
            return [null, '[UNKNOWN] Unsupported Adobe patch API response schema', [
                'endpoint' => $endpoint,
                'schema_version' => $decoded['schema_version'] ?? null,
            ]];
        }

        $evidence = [
            'source' => 'magebean_adobe_patch_api',
            'endpoint' => $endpoint,
            'request_endpoint' => $requestEndpoint,
            'product' => $product,
            'installed_version' => $version,
            'branch' => $decoded['branch'] ?? null,
            'latest_security_version' => $decoded['latest_security_version'] ?? null,
            'missing_patches' => is_array($decoded['missing_patches'] ?? null)
                ? $decoded['missing_patches']
                : [],
            'satisfied_by_alternatives' => is_array($decoded['satisfied_by_alternatives'] ?? null)
                ? $decoded['satisfied_by_alternatives']
                : [],
            'dataset_generated_at' => $decoded['dataset_generated_at'] ?? null,
            'lifecycle' => $decoded['lifecycle'] ?? null,
            'recommended_latest_branch' => $decoded['recommended_latest_branch'] ?? null,
            'local_patch_evidence' => $localPatchEvidence,
        ];

        if (($decoded['status'] ?? null) === 'unsupported_branch') {
            $evidence['supported_branches'] = $decoded['supported_branches'] ?? [];
            return [false, $this->unsupportedBranchMessage($decoded, $version), $evidence];
        }
        if (($decoded['status'] ?? null) === 'current'
            && (!array_key_exists('missing_patches', $decoded)
                || !is_array($decoded['missing_patches']) || $decoded['missing_patches'] !== []
                || !is_string($decoded['latest_security_version'] ?? null)
                || trim($decoded['latest_security_version']) === '')) {
            return [null, '[UNKNOWN] Adobe patch API current status lacks complete patch evidence', $evidence];
        }
        if (($decoded['status'] ?? null) === 'current') {
            $latest = (string)($decoded['latest_security_version'] ?? $version);
            $satisfiedCount = count((array)($decoded['satisfied_by_alternatives'] ?? []));
            $notApplied = array_values(array_filter(
                (array)($localPatchEvidence['patch_artifacts'] ?? []),
                static fn(mixed $artifact): bool => is_array($artifact)
                    && ($artifact['status'] ?? null) === 'not applied'
            ));
            $message = 'Adobe security patch status: installed ' . $version
                . '; latest for branch ' . $latest . '; no missing security release patches';
            if ($satisfiedCount > 0) {
                $message .= '; ' . $satisfiedCount . ' advisory patch(es) verified by alternative evidence';
            }
            if ($notApplied !== []) {
                $ids = [];
                foreach (array_slice($notApplied, 0, 10) as $artifact) {
                    $ids[] = (string)(($artifact['identifiers'][0] ?? 'unknown-patch'));
                }
                $message .= "\nQuality Patches Tool also reports " . count($notApplied)
                    . " optional/unmapped patch(es) as Not applied (not scored by R050): "
                    . implode(', ', $ids);
                if (count($notApplied) > 10) $message .= ', ...';
            }
            return [true, $message, $evidence];
        }
        if (($decoded['status'] ?? null) !== 'outdated' || $evidence['missing_patches'] === []) {
            return [null, '[UNKNOWN] Adobe patch API returned an incomplete status', $evidence];
        }

        $items = [];
        foreach ($evidence['missing_patches'] as $patch) {
            if (!is_array($patch)) continue;
            $advisory = (string)($patch['advisory'] ?? 'Adobe security patch');
            $fixed = (string)($patch['fixed_version'] ?? 'unknown');
            $items[] = $advisory . ' (update to ' . $fixed . ')';
        }

        $satisfiedItems = [];
        foreach ((array)$evidence['satisfied_by_alternatives'] as $advisory => $proof) {
            if (!is_array($proof)) continue;
            $label = (string)($proof['label'] ?? $proof['verification'] ?? $proof['type'] ?? 'verified evidence');
            $satisfiedItems[] = $advisory . ' via ' . $label;
        }
        $message = 'Adobe security patch status: installed ' . $version
            . '; latest for branch ' . (string)($evidence['latest_security_version'] ?? 'unknown')
            . "\nMissing:\n - " . implode("\n - ", $items);
        if ($satisfiedItems !== []) {
            $message .= "\nAlready satisfied by alternative evidence:\n - "
                . implode("\n - ", $satisfiedItems);
        }

        return [false, $message, $evidence];
    }

    public function coreAdvisoriesApi(array $args): array
    {
        return $this->adobeSecurityPatchesApi($args);
    }

    public function fixVersionApi(array $args): array
    {
        $result = $this->auditApi($args);
        $status = $result[0] ?? null;
        if ($status !== false) {
            return $result;
        }

        $evidence = is_array($result[2] ?? null) ? $result[2] : [];
        $findings = is_array($evidence['findings'] ?? null) ? $evidence['findings'] : [];
        if ($findings === []) {
            return [
                null,
                '[UNKNOWN] Vulnerable packages were reported without usable fix evidence',
                $evidence,
            ];
        }

        $messages = [];
        foreach ($findings as $finding) {
            if (!is_array($finding)) {
                continue;
            }
            $package = (string)($finding['package'] ?? 'unknown-package');
            $version = (string)($finding['version'] ?? 'unknown-version');
            $advisory = (string)($finding['advisory'] ?? 'unknown-advisory');
            $fixed = (string)($finding['fixed'] ?? '');
            $message = $package . '@' . $version . ' -> ' . $advisory;
            $message .= $fixed !== ''
                ? ', upgrade >= ' . $fixed
                : ', no fixed version published';
            $messages[] = $message;
        }

        if ($messages === []) {
            return [
                null,
                '[UNKNOWN] Vulnerable packages were reported without usable fix evidence',
                $evidence,
            ];
        }

        $visible = $messages;
        $message = "Vulnerable packages require updates:\n    - "
            . implode("\n    - ", $visible);

        return [false, $message, $evidence];
    }

    public function auditOffline(array $args): array
    {
        $lockFile = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        if (!is_file($lockFile)) {
            return [null, "[UNKNOWN] composer.lock not found"];
        }

        if (!empty($args['require_explicit_snapshot']) || !empty($args['strict_scope'])) {
            $scopeError = $this->validateLockScope($lockFile);
            if ($scopeError !== null) {
                return [null, '[UNKNOWN] '.$scopeError, ['reason_code' => 'COMPOSER_LOCK_SCOPE_INVALID']];
            }
        }

        $installed = $this->readLockPackages($lockFile);
        if (!$installed || !is_array($installed)) {
            return [null, "[UNKNOWN] Unable to parse composer.lock"];
        }

        $installedVers = [];
        foreach ($installed as $name => $info) {
            $ver = $info['version'] ?? null;
            if (is_string($ver) && $ver !== '') {
                $installedVers[$name] = ltrim($ver, 'vV');
            }
        }
        if (!$installedVers) {
            return [true, "No packages in composer.lock (nothing to audit)"];
        }

        if (!empty($args['require_explicit_snapshot'])) {
            $relative = (string) ($args['cve_data'] ?? '');
            $path = $this->ctx->abs($relative);
            $text = $relative !== '' && is_file($path) ? @file_get_contents($path, false, null, 0, 33554433) : false;
            $snapshot = is_string($text) && strlen($text) <= 33554432 ? json_decode($text, true, 128) : null;
            if (!is_array($snapshot) || !array_is_list($snapshot) || $snapshot === []) {
                return [null, '[UNKNOWN] Local advisory snapshot unavailable or invalid. Supply an OSV JSON advisory list at '.$relative.'.',
                    ['reason_code' => 'OFFLINE_ADVISORY_SNAPSHOT_UNAVAILABLE']];
            }
            $advisories = [];
            $composerRecords = 0;
            foreach ($snapshot as $row) {
                if (!is_array($row) || !is_string($row['id'] ?? null) || !is_array($row['affected'] ?? null) || $row['affected'] === []) {
                    return [null, '[UNKNOWN] Local advisory snapshot contains an invalid advisory.',
                        ['reason_code' => 'OFFLINE_ADVISORY_SNAPSHOT_INVALID']];
                }
                foreach ($row['affected'] as $affected) {
                    $name = $affected['package']['name'] ?? null;
                    $ecosystem = $affected['package']['ecosystem'] ?? null;
                    if (!is_string($name) || $name === '' || !is_string($ecosystem) || $ecosystem === '') {
                        return [null, '[UNKNOWN] Local advisory snapshot contains an invalid affected package.',
                            ['reason_code' => 'OFFLINE_ADVISORY_SNAPSHOT_INVALID']];
                    }
                    if (in_array(strtolower($ecosystem), ['packagist', 'composer'], true)) ++$composerRecords;
                }
                if (empty($row['withdrawn'])) $advisories[] = $row;
            }
            if ($composerRecords === 0) {
                return [null, '[UNKNOWN] Local advisory snapshot has no Composer package records.',
                    ['reason_code' => 'OFFLINE_ADVISORY_SNAPSHOT_INVALID']];
            }
            $evidence = ['source' => 'offline_dataset', 'dataset' => $relative, 'snapshot_records' => count($snapshot)];
            return $advisories === [] ? [true, 'No active advisories in the local snapshot.', $evidence]
                : $this->evaluateOsvAdvisories($advisories, $installedVers, $evidence);
        }

        $meta = $this->ctx->get('meta', []);
        $pathCandidates = [];
        foreach (['cve_data', 'cve_db', 'osv_db', 'osv'] as $key) {
            if (is_string($args[$key] ?? null) && $args[$key] !== '') {
                $pathCandidates[] = (string)$args[$key];
            }
        }
        if (is_string($this->ctx->cveData ?? null) && $this->ctx->cveData !== '') {
            $pathCandidates[] = $this->ctx->cveData;
        }
        if (is_array($meta)) {
            foreach (['osv_db', 'osv', 'cve_data'] as $key) {
                if (is_string($meta[$key] ?? null) && $meta[$key] !== '') {
                    $pathCandidates[] = (string)$meta[$key];
                }
            }
        }

        $datasetPath = null;
        $tried = [];
        foreach (array_values(array_unique($pathCandidates)) as $candidate) {
            $path = $this->ctx->abs((string)$candidate);
            $tried[] = $path;
            if (is_file($path) || is_dir($path)) {
                $datasetPath = $path;
                break;
            }
        }

        if ($datasetPath === null) {
            $bundle = $this->findCveBundleCandidate($args['cve_data'] ?? ($this->ctx->cveData ?: null));
            if (($bundle['status'] ?? '') === 'ok') {
                $datasetPath = (string)$bundle['path'];
                $tried[] = $datasetPath;
            }
        }

        if ($datasetPath === null) {
            return [null, "[UNKNOWN] CVE dataset not found (supply --cve-data bundle or osv-db.json)", ['tried' => $tried]];
        }

        $auditor = new \Magebean\Engine\Cve\CveAuditor($this->ctx);
        $vulns = $this->loadVulnsViaAuditor($auditor, $datasetPath);
        if ($vulns === []) {
            return [null, "[UNKNOWN] No advisories parsed from CVE dataset", ['dataset' => $datasetPath, 'packages' => count($installedVers)]];
        }

        return $this->evaluateOsvAdvisories(
            $vulns,
            $installedVers,
            ['source' => 'offline_dataset', 'dataset' => $datasetPath]
        );
    }

    public function kevAdvisoriesApi(array $args): array
    {
        $result = $this->auditApi($args);
        $status = $result[0] ?? null;
        if ($status === null || $status === true) {
            return $result;
        }

        $evidence = is_array($result[2] ?? null) ? $result[2] : [];
        $findings = array_values(array_filter(
            is_array($evidence['findings'] ?? null) ? $evidence['findings'] : [],
            static fn(mixed $finding): bool => is_array($finding)
                && !empty($finding['known_exploited'])
        ));

        $evidence['kev_findings'] = $findings;
        $evidence['kev_findings_count'] = count($findings);
        if ($findings === []) {
            return [
                true,
                'No installed package versions match CISA Known Exploited Vulnerabilities',
                $evidence,
            ];
        }

        $visible = $findings;
        $message = "CISA KEV package matches:\n    - "
            . implode("\n    - ", array_map(
            static function (array $finding): string {
                $text = (string)($finding['package'] ?? 'unknown-package')
                    . '@' . (string)($finding['version'] ?? 'unknown-version')
                    . ' -> ' . (string)($finding['advisory'] ?? 'unknown-advisory');
                if (is_string($finding['fixed'] ?? null) && $finding['fixed'] !== '') {
                    $text .= ', fix >= ' . $finding['fixed'];
                } else {
                    $text .= ', no fixed version published';
                }
                return $text;
            },
            $visible
        ));

        return [false, $message, $evidence];
    }

    public function advisoryLatencyApi(array $args): array
    {
        if (($problem = $this->strictInventoryProblem($args, false)) !== null) return $problem;
        $audit = $this->auditApi($args);
        $status = $audit[0] ?? null;
        $evidence = is_array($audit[2] ?? null) ? $audit[2] : [];
        if ($status === null) {
            return $audit;
        }
        if ($status === true) {
            return [
                true,
                'No unresolved advisories affect installed package versions',
                $evidence + [
                    'sla_days' => max(1, (int)($args['latency_days'] ?? 30)),
                    'open_advisories' => [],
                ],
            ];
        }

        $slaDays = max(1, (int)($args['latency_days'] ?? 30));
        $now = time();
        $open = [];
        $overdue = [];
        $missingPublished = [];
        foreach ((array)($evidence['findings'] ?? []) as $finding) {
            if (!is_array($finding)) {
                continue;
            }

            $published = is_string($finding['published'] ?? null)
                ? trim($finding['published'])
                : '';
            $publishedAt = $published !== '' ? strtotime($published) : false;
            if ($publishedAt === false) {
                $finding['open_days'] = null;
                $finding['sla_days'] = $slaDays;
                $missingPublished[] = $finding;
                continue;
            }

            $finding['open_days'] = max(0, (int)floor(($now - $publishedAt) / 86400));
            $finding['sla_days'] = $slaDays;
            $finding['overdue'] = $finding['open_days'] > $slaDays;
            $open[] = $finding;
            if ($finding['overdue']) {
                $overdue[] = $finding;
            }
        }

        $latencyEvidence = $evidence + [
            'sla_days' => $slaDays,
            'open_advisories' => $open,
            'overdue_advisories' => $overdue,
            'missing_published_date' => $missingPublished,
        ];

        if ($overdue !== []) {
            $visible = $overdue;
            $details = array_map(static function (array $finding): string {
                $text = (string)($finding['package'] ?? 'unknown-package')
                    . '@' . (string)($finding['version'] ?? 'unknown-version')
                    . ' -> ' . (string)($finding['advisory'] ?? 'unknown-advisory')
                    . ' open ' . (string)($finding['open_days'] ?? '?') . ' days';
                if (is_string($finding['fixed'] ?? null) && $finding['fixed'] !== '') {
                    $text .= ', update to >= ' . $finding['fixed'];
                }
                return $text;
            }, $visible);
            $message = 'Affected advisories exceed the ' . $slaDays . "-day publication-age threshold:\n    - "
                . implode("\n    - ", $details);
            if ($missingPublished !== []) {
                $missingDetails = array_map(
                    static fn(array $finding): string => (string)($finding['package'] ?? 'unknown-package')
                        . '@' . (string)($finding['version'] ?? 'unknown-version')
                        . ' -> ' . (string)($finding['advisory'] ?? 'unknown-advisory'),
                    $missingPublished
                );
                $message .= "\n    Published date unavailable for:\n    - "
                    . implode("\n    - ", $missingDetails);
            }
            return [false, $message, $latencyEvidence];
        }

        if ($missingPublished !== []) {
            $visible = $missingPublished;
            $details = array_map(
                static fn(array $finding): string => (string)($finding['package'] ?? 'unknown-package')
                    . '@' . (string)($finding['version'] ?? 'unknown-version')
                    . ' -> ' . (string)($finding['advisory'] ?? 'unknown-advisory'),
                $visible
            );
            $message = "[UNKNOWN] Published date unavailable for unresolved advisories:\n    - "
                . implode("\n    - ", $details);
            return [null, $message, $latencyEvidence];
        }

        return [
            true,
            count($open) . ' unresolved advisory match(es) remain within the '
                . $slaDays . '-day remediation SLA',
            $latencyEvidence,
        ];
    }

    public function transitiveAuditApi(array $args): array
    {
        if (($problem = $this->strictInventoryProblem($args, true)) !== null) return $problem;
        $lockFile = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        $composerFile = $this->ctx->abs($args['composer_file'] ?? 'composer.json');
        if (!is_file($lockFile)) {
            return [null, '[UNKNOWN] composer.lock not found'];
        }
        if (!is_file($composerFile)) {
            return [null, '[UNKNOWN] composer.json not found; cannot distinguish direct and transitive dependencies'];
        }

        $lock = $this->loadJsonSafe($lockFile);
        $composer = $this->loadJsonSafe($composerFile);
        if (!is_array($lock)) {
            return [null, '[UNKNOWN] Unable to parse composer.lock'];
        }
        if (!is_array($composer)) {
            return [null, '[UNKNOWN] Unable to parse composer.json'];
        }

        $direct = [];
        foreach (['require', 'require-dev'] as $section) {
            foreach ((array)($composer[$section] ?? []) as $name => $_constraint) {
                $name = strtolower((string)$name);
                if (str_contains($name, '/')) {
                    $direct[$name] = true;
                }
            }
        }

        $installed = [];
        $requiredBy = [];
        foreach (['packages', 'packages-dev'] as $section) {
            foreach ((array)($lock[$section] ?? []) as $package) {
                if (!is_array($package) || !is_string($package['name'] ?? null)) {
                    continue;
                }
                $name = strtolower($package['name']);
                $installed[$name] = true;
                foreach ((array)($package['require'] ?? []) as $dependency => $_constraint) {
                    $dependency = strtolower((string)$dependency);
                    if (!str_contains($dependency, '/')) {
                        continue;
                    }
                    $requiredBy[$dependency][] = $name;
                }
            }
        }

        $transitive = array_values(array_diff(array_keys($installed), array_keys($direct)));
        sort($transitive, SORT_STRING);
        if ($transitive === []) {
            return [
                true,
                'No transitive Composer dependencies found',
                [
                    'direct_packages' => array_keys($direct),
                    'transitive_packages' => [],
                ],
            ];
        }

        $args['package_names'] = $transitive;
        $args['package_scope'] = 'transitive';
        $result = $this->auditApi($args);
        $evidence = is_array($result[2] ?? null) ? $result[2] : [];
        $evidence['direct_packages'] = array_keys($direct);
        $evidence['transitive_packages'] = $transitive;

        if (is_array($evidence['findings'] ?? null)) {
            foreach ($evidence['findings'] as &$finding) {
                if (!is_array($finding)) {
                    continue;
                }
                $package = strtolower((string)($finding['package'] ?? ''));
                $parents = array_values(array_unique($requiredBy[$package] ?? []));
                sort($parents, SORT_STRING);
                $finding['required_by'] = $parents;
            }
            unset($finding);

            $visible = $evidence['findings'];
            $message = "Vulnerable transitive dependencies:\n    - "
                . implode("\n    - ", array_map(
                static function (array $finding): string {
                    $text = (string)($finding['package'] ?? 'unknown-package')
                        . '@' . (string)($finding['version'] ?? 'unknown-version')
                        . ' -> ' . (string)($finding['advisory'] ?? 'unknown-advisory');
                    $parents = (array)($finding['required_by'] ?? []);
                    if ($parents !== []) {
                        $text .= ', required by ' . implode(', ', $parents);
                    }
                    if (is_string($finding['fixed'] ?? null) && $finding['fixed'] !== '') {
                        $text .= ', fix >= ' . $finding['fixed'];
                    }
                    return $text;
                },
                $visible
            ));
            return [false, $message, $evidence];
        }

        return [$result[0] ?? null, (string)($result[1] ?? ''), $evidence];
    }

    public function constraintsConflictApi(array $args): array
    {
        if (($problem = $this->strictInventoryProblem($args, true)) !== null) return $problem;
        $composerFile = $this->ctx->abs($args['json_file'] ?? 'composer.json');
        $lockFile = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        if (!is_file($composerFile)) {
            return [null, '[UNKNOWN] composer.json not found'];
        }
        if (!is_file($lockFile)) {
            return [null, '[UNKNOWN] composer.lock not found'];
        }

        $composer = $this->loadJsonSafe($composerFile);
        $lock = $this->loadJsonSafe($lockFile);
        if (!is_array($composer)) {
            return [null, '[UNKNOWN] Unable to parse composer.json'];
        }
        if (!is_array($lock)) {
            return [null, '[UNKNOWN] Unable to parse composer.lock'];
        }

        $audit = $this->auditApi($args);
        if (($audit[0] ?? null) !== false) {
            return $audit;
        }

        $evidence = is_array($audit[2] ?? null) ? $audit[2] : [];
        $findings = is_array($evidence['findings'] ?? null) ? $evidence['findings'] : [];
        $constraintsByPackage = [];

        foreach (['require', 'require-dev'] as $section) {
            foreach ((array)($composer[$section] ?? []) as $package => $constraint) {
                $package = strtolower((string)$package);
                if (!str_contains($package, '/') || !is_string($constraint)) {
                    continue;
                }
                $constraintsByPackage[$package][] = [
                    'source' => 'root:' . $section,
                    'constraint' => $constraint,
                ];
            }
        }

        foreach (['packages', 'packages-dev'] as $section) {
            foreach ((array)($lock[$section] ?? []) as $parent) {
                if (!is_array($parent) || !is_string($parent['name'] ?? null)) {
                    continue;
                }
                $parentName = strtolower($parent['name']);
                foreach ((array)($parent['require'] ?? []) as $package => $constraint) {
                    $package = strtolower((string)$package);
                    if (!str_contains($package, '/') || !is_string($constraint)) {
                        continue;
                    }
                    $constraintsByPackage[$package][] = [
                        'source' => $parentName,
                        'constraint' => $constraint,
                    ];
                }
            }
        }

        $parser = new \Composer\Semver\VersionParser();
        $blocked = [];
        $allowed = [];
        $notApplicable = [];
        $errors = [];

        foreach ($findings as $finding) {
            if (!is_array($finding)) {
                continue;
            }
            $package = strtolower((string)($finding['package'] ?? ''));
            $fixed = ltrim((string)($finding['fixed'] ?? ''), 'vV');
            if ($package === '' || $fixed === '') {
                $notApplicable[] = $finding + [
                    'reason' => 'no fixed version published; no available security update can be blocked',
                ];
                continue;
            }

            $requirements = $constraintsByPackage[$package] ?? [];
            if ($requirements === []) {
                $notApplicable[] = $finding + [
                    'reason' => 'no requiring constraint found; no blocking constraint identified',
                    'required_safe_range' => '>=' . $fixed,
                ];
                continue;
            }

            try {
                $parsed = [];
                foreach ($requirements as $requirement) {
                    $parsed[] = $parser->parseConstraints($requirement['constraint']);
                }
                $combined = count($parsed) === 1
                    ? $parsed[0]
                    : new \Composer\Semver\Constraint\MultiConstraint($parsed, true);
                $safeRange = $parser->parseConstraints('>=' . $fixed);
                $allowsSafeVersion = \Composer\Semver\Intervals::haveIntersections($combined, $safeRange);
            } catch (\Throwable $exception) {
                $errors[] = $finding + [
                    'reason' => 'unable to parse constraint: ' . $exception->getMessage(),
                    'requirements' => $requirements,
                ];
                continue;
            }

            $item = $finding + [
                'requirements' => $requirements,
                'required_safe_range' => '>=' . $fixed,
            ];
            if ($allowsSafeVersion) {
                $allowed[] = $item;
            } else {
                $blocked[] = $item;
            }
        }

        $evidence['blocked'] = $blocked;
        $evidence['allowed'] = $allowed;
        $evidence['not_applicable'] = $notApplicable;
        $evidence['errors'] = $errors;

        if ($blocked !== []) {
            $visible = $blocked;
            $message = "Composer constraints block security updates:\n    - "
                . implode("\n    - ", array_map(
                static function (array $item): string {
                    $requirements = array_map(
                        static fn(array $requirement): string => $requirement['source']
                            . ' requires ' . $requirement['constraint'],
                        (array)($item['requirements'] ?? [])
                    );
                    return (string)($item['package'] ?? 'unknown-package')
                        . '@' . (string)($item['version'] ?? 'unknown-version')
                        . ' needs ' . (string)($item['required_safe_range'] ?? '')
                        . ' but ' . implode(', ', $requirements);
                },
                $visible
            ));
            return [false, $message, $evidence];
        }

        if ($errors !== []) {
            $visible = $errors;
            return [
                null,
                "[UNKNOWN] Unable to evaluate Composer constraints:\n    - "
                    . implode("\n    - ", array_map(
                    static fn(array $item): string => (string)($item['package'] ?? 'unknown-package')
                        . '@' . (string)($item['version'] ?? 'unknown-version')
                        . ' (' . (string)($item['reason'] ?? 'unknown error') . ')',
                    $visible
                )),
                $evidence,
            ];
        }

        $suffix = $notApplicable !== []
            ? '; ' . count($notApplicable) . ' finding(s) had no applicable blocking constraint'
            : '';
        return [
            true,
            'Composer constraints allow the required security update ranges' . $suffix,
            $evidence,
        ];
    }

    public function coreAdvisoriesOffline(array $args): array
    {
        // ===== 0) Load composer.lock (giống yankedOffline) =====
        $lockPath = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        if (!is_file($lockPath)) {
            return [null, "[UNKNOWN] composer.lock not found at {$lockPath}"];
        }
        $installed = $this->readLockPackages($lockPath);
        if (!$installed || !is_array($installed)) {
            return [null, "[UNKNOWN] Unable to parse composer.lock"];
        }

        // Map: package(lc) => version (bỏ tiền tố v/V)
        $installedVers = [];
        foreach ($installed as $name => $info) {
            $v = $info['version'] ?? null;
            if (is_string($v) && $v !== '') {
                $installedVers[strtolower((string)$name)] = ltrim((string)$v, 'vV');
            }
        }
        if (!$installedVers) {
            return [true, "No packages in composer.lock (nothing to check); lock={$lockPath}"];
        }

        // ===== 1) Xác định root & vendor-dir =====
        // Root tiêu chuẩn: thư mục chứa lock
        $root = rtrim(str_replace('\\', '/', dirname($lockPath)), '/');
        $composerJsonPath = $root . '/composer.json';
        $vendorDirCfg = null;
        if (is_file($composerJsonPath)) {
            $composerJson = @json_decode((string)$this->collectors->files->read($composerJsonPath), true) ?: [];
            $vendorDirCfg = $composerJson['config']['vendor-dir'] ?? null;
        }
        $vendor = $vendorDirCfg ? ($root . '/' . ltrim((string)$vendorDirCfg, '/')) : ($root . '/vendor');
        $vendor = rtrim($vendor, '/');
        if (!is_dir($vendor)) {
            // Theo yêu cầu: chỉ dựa lock + vendor ⇒ thiếu vendor thì UNKNOWN
            return [null, "[UNKNOWN] vendor directory not found at {$vendor}; lock={$lockPath}"];
        }

        // ===== 2) Định nghĩa nhóm core =====
        $patterns = $args['core_patterns'] ?? [
            '#^magento/#i',
            '#^adobe\-commerce/#i',
            '#^magento\/module\-#i',
        ];
        $isCore = static function (string $pkg, array $pats): bool {
            foreach ($pats as $re) {
                if (@preg_match($re, $pkg) && preg_match($re, $pkg)) return true;
            }
            return false;
        };

        // ===== 3) Helpers =====
        $readFile = static function (string $fp, int $max = 256 * 1024) {
            if (!is_file($fp) || !is_readable($fp)) return null;
            $size = filesize($fp);
            if ($size === false) return null;
            $limit = min($size, $max);
            $h = @fopen($fp, 'rb');
            if (!$h) return null;
            $data = @fread($h, $limit);
            @fclose($h);
            return is_string($data) ? $data : null;
        };
        $isSecurityLine = static function (string $line): bool {
            return (bool)preg_match('/\b(cve|security|vulnerab|advisory|hotfix|patch|sec\-)\b/i', $line);
        };
        $extractFixedFromLine = static function (string $line): ?string {
            $line = strtolower($line);
            // ưu tiên >= / ≥
            if (preg_match('/(?:>=|≥)\s*v?([0-9][0-9a-z\.\-\+]*?)\b/i', $line, $m)) {
                return ltrim($m[1], 'v');
            }
            // "fixed in / update to / patch to / use ..."
            if (preg_match('/(?:fixed\s+in|update\s+to|patch\s+to|use\s+)\s*v?([0-9][0-9a-z\.\-\+]*?)\b/i', $line, $m)) {
                return ltrim($m[1], 'v');
            }
            // ">=2.4.6" (không khoảng)
            if (preg_match('/(?:>=|≥)v?([0-9][0-9a-z\.\-\+]*?)\b/i', $line, $m)) {
                return ltrim($m[1], 'v');
            }
            // "2.4.7-p1 or later/and later/and above"
            if (preg_match('/\bv?([0-9][0-9a-z\.\-\+]*?)\b\s+(?:or\s+later|and\s+later|and\s+above)/i', $line, $m)) {
                return ltrim($m[1], 'v');
            }
            return null;
        };

        // ===== 4) Quét từng core package trong vendor =====
        $hits = [];
        $coreCount = 0;

        foreach ($installedVers as $pkgLc => $installedVer) {
            if (!$isCore($pkgLc, $patterns)) continue;
            $coreCount++;

            $pkgPath = $vendor . '/' . $pkgLc; // composer cài theo dạng lowercase "vendor/name"
            if (!is_dir($pkgPath)) {
                // không có thư mục vendor tương ứng → không có dữ liệu changelog ⇒ bỏ qua
                continue;
            }

            // Tập fixed-version candidates từ các file nhỏ thông dụng
            $cands = [
                'SECURITY.md',
                'SECURITY.txt',
                'SECURITY.adoc',
                'SECURITY',
                'CHANGELOG.md',
                'CHANGELOG.txt',
                'CHANGELOG',
                'RELEASE_NOTES.md',
                'RELEASE_NOTES.txt',
                'README.md',
            ];
            $bestFixed = null;

            foreach ($cands as $rel) {
                $fp = $pkgPath . '/' . $rel;
                $txt = $readFile($fp);
                if (!$txt) continue;

                foreach (preg_split('/\r?\n/', $txt) as $line) {
                    if ($line === '' || !$isSecurityLine($line)) continue;
                    $fx = $extractFixedFromLine($line);
                    if (!$fx) continue;

                    // chỉ xét fixed >= installed
                    if (version_compare($fx, $installedVer, '<')) continue;

                    // giữ fixed nhỏ nhất nhưng ≥ installed
                    if ($bestFixed === null || version_compare($fx, $bestFixed, '<')) {
                        $bestFixed = $fx;
                    }
                }
            }

            // Nếu tìm thấy fixed và installed < fixed ⇒ flag
            if ($bestFixed !== null && version_compare($installedVer, $bestFixed, '<')) {
                // tên hiển thị: ưu tiên tên gốc nếu còn
                $disp = $pkgLc;
                if (isset($installed[$pkgLc]['name']) && is_string($installed[$pkgLc]['name'])) {
                    $disp = $installed[$pkgLc]['name'];
                }
                $hits[] = sprintf('%s %s -> >= %s', $disp, $installedVer, $bestFixed);
            }
        }

        // ===== 5) Kết quả + evidence =====
        if ($hits) {
            return [false, "Core advisories flagged:\n    - " . implode("\n    - ", $hits)
                . "\n    lock={$lockPath}; vendor={$vendor}; core_pkgs_scanned={$coreCount}"];
        }

        return [true, "No core advisories found (offline scan). lock={$lockPath}; vendor={$vendor}; core_pkgs_scanned={$coreCount}"];
    }

    public function fixVersion(array $args): array
    {
        // ---- composer.lock -> installed packages
        $lock = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        if (!is_file($lock)) return [null, "[UNKNOWN] composer.lock not found"];
        $installed = $this->readLockPackages($lock);
        if (!$installed || !is_array($installed)) return [null, "[UNKNOWN] Unable to parse composer.lock"];

        $installedVers = [];
        foreach ($installed as $name => $info) {
            $v = $info['version'] ?? null;
            if (is_string($v) && $v !== '') $installedVers[$name] = ltrim($v, 'vV');
        }
        if (!$installedVers) return [true, "No packages in composer.lock (nothing to suggest)"];

        // ---- resolve bundle input (zip / dir / file-inside-dir)
        $candidates = [];
        if (!empty($args['cve_data'])) $candidates[] = (string)$args['cve_data'];
        if (!empty($this->ctx->cveData)) $candidates[] = (string)$this->ctx->cveData;
        $candidates = array_values(array_unique(array_filter($candidates, fn($p) => is_string($p) && $p !== '')));

        // Normalize to absolute without creating bogus concatenations
        $normalize = function (string $p): string {
            // If already absolute, keep; else relativize to CWD
            if (preg_match('#^/|^[A-Za-z]:[\\\\/]#', $p)) return $p;
            $abs = $this->ctx->abs($p);
            return is_string($abs) && $abs !== '' ? $abs : (getcwd() . '/' . $p);
        };

        // Find a usable "bundle root": either ['zip', zipPath] or ['dir', dirPath]
        $tried = [];
        $resolveBundleRoot = function (string $raw) use ($normalize, &$tried) {
            $p = $normalize($raw);
            $tried[] = $p;

            // case 1: ZIP file
            if (is_file($p) && preg_match('/\.zip$/i', $p)) return ['zip', $p];

            // case 2: Directory bundle root (contains INDEX/ or DATA/ etc.)
            $asDir = is_dir($p) ? $p : dirname($p); // if it's a file inside bundle, go up 1
            // climb up a few levels to find a dir that has INDEX or DATA
            $cur = $asDir;
            for ($i = 0; $i < 5; $i++) {
                if (is_dir($cur . '/INDEX') || is_dir($cur . '/DATA') || is_dir($cur . '/VULNS') || is_file($cur . '/INDEX/packages-index.json')) {
                    return ['dir', $cur];
                }
                $parent = dirname($cur);
                if ($parent === $cur) break;
                $cur = $parent;
            }

            // case 3: If input was a JSON inside DATA/, try up-two-levels explicitly
            if (preg_match('#/(DATA|VULNS|INDEX)/#', $p)) {
                $root = preg_replace('#/(DATA|VULNS|INDEX)/.*$#', '', $p);
                if (is_dir($root)) return ['dir', $root];
            }

            return null;
        };

        $root = null;
        foreach ($candidates as $cand) {
            $root = $resolveBundleRoot($cand);
            if ($root !== null) break;
        }
        if ($root === null) {
            $msgTried = $tried ? implode(' | ', $tried) : '(no candidates)';
            return [null, "[UNKNOWN] CVE bundle not found/openable; tried: " . $msgTried];
        }

        // ---- read packages-index.json from bundle (zip or dir)
        $pkg2vuln = null;
        if ($root[0] === 'zip') {
            $zip = new \ZipArchive();
            if ($zip->open($root[1]) !== true) {
                return [null, "[UNKNOWN] Unable to open CVE bundle zip: " . $root[1]];
            }
            $i = $zip->locateName('INDEX/packages-index.json', \ZipArchive::FL_NOCASE);
            if ($i === false) {
                $zip->close();
                return [true, "No vulnerable packages index found in bundle (INDEX/packages-index.json missing)"];
            }
            $raw = $zip->getFromIndex($i);
            $pkg2vuln = is_string($raw) ? json_decode($raw, true) : null;
            $zip->close();
        } else { // dir
            $idxPath = $root[1] . '/INDEX/packages-index.json';
            if (!is_file($idxPath)) {
                return [true, "No vulnerable packages index found in bundle dir (INDEX/packages-index.json missing at " . $idxPath . ")"];
            }
            $raw = $this->collectors->files->read($idxPath);
            $pkg2vuln = $raw !== false ? json_decode($raw, true) : null;
        }

        if (!is_array($pkg2vuln) || !$pkg2vuln) {
            return [true, "No vulnerable packages index found in bundle (index empty at root " . $root[1] . ")"];
        }

        // ---- ensure composer CLI available (for available versions)
        @exec('composer --version 2>&1', $outV, $codeV);
        if ($codeV !== 0) {
            return [null, "[UNKNOWN] composer CLI not available for version discovery (install composer or add it to PATH)"];
        }

        $parseVersionsFromComposerShow = static function (string $text): array {
            $vers = [];
            foreach (preg_split('/\r?\n/', $text) as $line) {
                if (stripos($line, 'versions') === 0 || preg_match('/^\s*versions\s*:/i', $line)) {
                    [$l, $r] = array_pad(explode(':', $line, 2), 2, '');
                    $r = preg_replace('/^\*\s*/', '', trim($r));
                    foreach (explode(',', $r) as $tok) {
                        $tok = trim($tok);
                        if ($tok === '' || stripos($tok, 'dev') !== false) continue;
                        $vers[] = ltrim($tok, 'vV');
                    }
                    break;
                }
            }
            $vers = array_values(array_unique($vers));
            usort($vers, static fn($a, $b) => version_compare($a, $b)); // ascending (min >= current)
            return $vers;
        };
        $isStable = static fn(string $v) => !preg_match('/(?:alpha|beta|rc)\d*$/i', $v);

        $cwd = $args['path'] ?? getcwd();
        $suggest = [];
        $checked = 0;

        foreach ($installedVers as $pkg => $curVer) {
            if (!isset($pkg2vuln[$pkg])) continue; // only consider packages known in index
            $checked++;

            $cmd = sprintf('cd %s && composer show %s -a 2>&1', escapeshellarg($cwd), escapeshellarg($pkg));
            $out = [];
            $code = 0;
            @exec($cmd, $out, $code);
            if ($code !== 0) continue;

            $versions = $parseVersionsFromComposerShow(implode("\n", $out));
            if (!$versions) continue;

            $candidates = array_values(array_filter($versions, $isStable));
            if (!$candidates) $candidates = $versions;

            $target = null;
            foreach ($candidates as $v) {
                if (version_compare($v, $curVer, '>=')) {
                    $target = $v;
                    break;
                }
            }
            if ($target && version_compare($target, $curVer, '>')) {
                $suggest[$pkg] = [$curVer, $target];
            }
        }

        if (!$suggest) {
            $msg = $checked > 0
                ? "No upgrade suggestions found from composer (checked {$checked} packages; root " . $root[1] . ")"
                : "No vulnerable packages from bundle index match installed packages (root " . $root[1] . ")";
            return [true, $msg];
        }

        $parts = [];
        foreach ($suggest as $pkg => [$cur, $tgt]) $parts[] = "{$pkg} {$cur} -> >= {$tgt}";
        return [false, "Suggest fixed versions:\n    - " . implode("\n    - ", $parts)];
    }

    public function advisoryLatency(array $args): array
    {
        // ---- 0) Guard: composer.lock (để biết project path), nhưng rule không bắt buộc phải match installed
        $root = $args['path'] ?? getcwd();

        // ---- 1) Resolve bundle root (zip/dir/file-inside-bundle)
        $candidates = [];
        if (!empty($args['cve_data']))   $candidates[] = (string)$args['cve_data'];
        if (!empty($this->ctx->cveData)) $candidates[] = (string)$this->ctx->cveData;
        $candidates = array_values(array_unique(array_filter($candidates, fn($p) => is_string($p) && $p !== '')));

        $normalize = function (string $p): string {
            if (preg_match('#^/|^[A-Za-z]:[\\\\/]#', $p)) return $p;
            $abs = $this->ctx->abs($p);
            return is_string($abs) && $abs !== '' ? $abs : (getcwd() . '/' . $p);
        };
        $tried = [];
        $resolveRoot = function (string $raw) use ($normalize, &$tried) {
            $p = $normalize($raw);
            $tried[] = $p;
            if (is_file($p) && preg_match('/\.zip$/i', $p)) return ['zip', $p];
            $asDir = is_dir($p) ? $p : dirname($p);
            $cur = $asDir;
            for ($i = 0; $i < 5; $i++) {
                if (is_dir($cur . '/INDEX') || is_dir($cur . '/DATA') || is_dir($cur . '/VULNS') || is_file($cur . '/INDEX/packages-index.json')) {
                    return ['dir', $cur];
                }
                $parent = dirname($cur);
                if ($parent === $cur) break;
                $cur = $parent;
            }
            if (preg_match('#/(DATA|VULNS|INDEX)/#', $p)) {
                $root = preg_replace('#/(DATA|VULNS|INDEX)/.*$#', '', $p);
                if (is_dir($root)) return ['dir', $root];
            }
            return null;
        };

        $bundle = null;
        foreach ($candidates as $cand) {
            if (($bundle = $resolveRoot($cand)) !== null) break;
        }
        if (!$bundle) {
            $msg = $tried ? implode(' | ', $tried) : '(no candidates)';
            return [null, "[UNKNOWN] Bundle not found/openable; tried: " . $msg];
        }

        // ---- 2) Helpers load text from bundle
        $loadText = function (string $rel) use ($bundle) {
            if ($bundle[0] === 'zip') {
                $zip = new \ZipArchive();
                if ($zip->open($bundle[1]) !== true) return null;
                $idx = $zip->locateName($rel, \ZipArchive::FL_NOCASE);
                if ($idx === false) {
                    $zip->close();
                    return null;
                }
                $raw = $zip->getFromIndex($idx);
                $zip->close();
                return is_string($raw) ? $raw : null;
            } else {
                $path = rtrim($bundle[1], '/') . '/' . $rel;
                if (!is_file($path)) return null;
                $raw = $this->collectors->files->read($path);
                return $raw === false ? null : $raw;
            }
        };

        // ---- 3) Load index + release-history
        $rawIdx = $loadText('INDEX/packages-index.json');
        if ($rawIdx === null) return [null, "[UNKNOWN] packages-index.json missing in bundle"];
        $pkg2vuln = json_decode($rawIdx, true);
        if (!is_array($pkg2vuln) || !$pkg2vuln) return [null, "[UNKNOWN] packages-index.json invalid/empty"];

        $rawRel = $loadText('release-history.json') ?? $loadText('rules/release-history.json');
        if ($rawRel === null) return [null, "[UNKNOWN] release-history.json missing"];
        $relJ = json_decode($rawRel, true);
        if (!is_array($relJ)) return [null, "[UNKNOWN] release-history.json invalid JSON"];

        // ---- 4) Normalize release-history → map: pkg => (version => timestamp)
        $releaseMap = []; // 'vendor/pkg' => ['1.2.3' => '2024-01-02T..Z', ...]
        $isAssoc = static function (array $a): bool {
            return array_keys($a) !== range(0, count($a) - 1);
        };
        $normRel = isset($relJ['packages']) && is_array($relJ['packages']) ? $relJ['packages'] : $relJ;

        if ($isAssoc($normRel)) {
            // Map form: "pkg" => ["x.y.z", ...] OR "pkg" => { "versions":[...]} OR "pkg" => { "timeline":[{"version":"..","date":".."}] } OR "pkg" => {"map": {"x.y.z":"2024-..."}}
            foreach ($normRel as $pkg => $row) {
                if (!is_string($pkg)) continue;
                if (is_array($row)) {
                    // timeline/map first (preferred if available)
                    if (isset($row['map']) && is_array($row['map'])) {
                        foreach ($row['map'] as $ver => $ts) {
                            if (!is_string($ver) || !is_string($ts)) continue;
                            $releaseMap[$pkg][ltrim($ver, 'vV')] = $ts;
                        }
                    }
                    if (isset($row['timeline']) && is_array($row['timeline'])) {
                        foreach ($row['timeline'] as $it) {
                            $ver = $it['version'] ?? null;
                            $ts = $it['date'] ?? null;
                            if (!is_string($ver) || !is_string($ts)) continue;
                            $releaseMap[$pkg][ltrim($ver, 'vV')] = $ts;
                        }
                    }
                    // plain versions list without dates → still useful to know existence (but latency needs date)
                    $vers = $row['versions'] ?? (is_array($row) ? $row : null);
                    if (is_array($vers)) {
                        foreach ($vers as $ver) {
                            if (!is_string($ver) || $ver === '') continue;
                            $v = ltrim($ver, 'vV');
                            if (!isset($releaseMap[$pkg][$v])) $releaseMap[$pkg][$v] = null;
                        }
                    }
                }
            }
        } else {
            // List form: [{"package":"pkg","versions":[...]}, {"package":"pkg","timeline":[{"version":"..","date":".."}]}]
            foreach ($normRel as $row) {
                if (!is_array($row)) continue;
                $pkg = $row['package'] ?? null;
                if (!is_string($pkg) || $pkg === '') continue;
                if (isset($row['map']) && is_array($row['map'])) {
                    foreach ($row['map'] as $ver => $ts) {
                        if (!is_string($ver) || !is_string($ts)) continue;
                        $releaseMap[$pkg][ltrim($ver, 'vV')] = $ts;
                    }
                }
                if (isset($row['timeline']) && is_array($row['timeline'])) {
                    foreach ($row['timeline'] as $it) {
                        $ver = $it['version'] ?? null;
                        $ts = $it['date'] ?? null;
                        if (!is_string($ver) || !is_string($ts)) continue;
                        $releaseMap[$pkg][ltrim($ver, 'vV')] = $ts;
                    }
                }
                if (isset($row['versions']) && is_array($row['versions'])) {
                    foreach ($row['versions'] as $ver) {
                        if (!is_string($ver) || $ver === '') continue;
                        $v = ltrim($ver, 'vV');
                        if (!isset($releaseMap[$pkg][$v])) $releaseMap[$pkg][$v] = null;
                    }
                }
            }
        }

        if (!$releaseMap) {
            return [null, "[UNKNOWN] release-history.json has no version→date mapping"];
        }

        // ---- 5) Iterate vulnerabilities & compute latency
        $eventsToIntervals = static fn(array $events): array => \Magebean\Engine\Cve\OsvRange::intervals($events);

        $parseDate = static function (?string $s): ?\DateTimeImmutable {
            if (!is_string($s) || $s === '') return null;
            try {
                return new \DateTimeImmutable($s);
            } catch (\Exception $e) {
                return null;
            }
        };

        $thresholdDays = isset($args['latency_days']) && is_numeric($args['latency_days']) ? (int)$args['latency_days'] : 30;

        $rows = []; // collected report lines
        $worst = 0;

        // read each vuln json on demand
        $readVulnJson = function (string $vid) use ($bundle) {
            if ($bundle[0] === 'zip') {
                $zip = new \ZipArchive();
                if ($zip->open($bundle[1]) !== true) return null;
                $idx = $zip->locateName("VULNS/{$vid}.json", \ZipArchive::FL_NOCASE);
                if ($idx === false) {
                    $zip->close();
                    return null;
                }
                $raw = $zip->getFromIndex($idx);
                $zip->close();
                return is_string($raw) ? json_decode($raw, true) : null;
            } else {
                $p = rtrim($bundle[1], '/') . "/VULNS/{$vid}.json";
                if (!is_file($p)) return null;
                $raw = $this->collectors->files->read($p);
                return $raw === false ? null : json_decode($raw, true);
            }
        };

        foreach ($pkg2vuln as $pkg => $ids) {
            if (!is_array($ids)) continue;
            foreach ($ids as $vid) {
                $vj = $readVulnJson((string)$vid);
                if (!is_array($vj)) continue;

                // advisory publish date
                $pub = $vj['published'] ?? ($vj['database_specific']['published'] ?? ($vj['database_specific']['advisory_date'] ?? null));
                $pubDt = $parseDate(is_string($pub) ? $pub : null);

                $aff = $vj['affected'] ?? null;
                if (!is_array($aff)) continue;

                // Collect fixed versions for this package (Packagist only)
                $fixedVers = [];
                foreach ($aff as $a) {
                    $pname = $a['package']['name'] ?? null;
                    $eco   = $a['package']['ecosystem'] ?? null;
                    if (!is_string($pname) || $pname !== $pkg) continue;
                    if ($eco && is_string($eco) && !preg_match('/^packagist$/i', $eco)) continue;

                    $ranges = is_array($a['ranges'] ?? null) ? $a['ranges'] : [];
                    foreach ($ranges as $rng) {
                        $events = is_array($rng['events'] ?? null) ? $rng['events'] : [];
                        $intervals = $eventsToIntervals($events);
                        foreach ($intervals as [, $to, , $kind]) {
                            if ($kind !== 'fixed') continue;
                            if ($to !== null && $to !== '') $fixedVers[] = ltrim((string)$to, 'vV');
                        }
                    }
                    // fallback database_specific.fixed
                    if (isset($a['database_specific']['fixed']) && is_string($a['database_specific']['fixed']) && $a['database_specific']['fixed'] !== '') {
                        $fixedVers[] = ltrim($a['database_specific']['fixed'], 'vV');
                    }
                }

                $fixedVers = array_values(array_unique($fixedVers));
                if (!$fixedVers) {
                    // không có fixed version nào để tính latency
                    // $rows[] = "{$pkg} — {$vid} — no fixed version found";
                    continue;
                }

                // Find earliest fixed version release date among available mappings
                $bestLatency = null;
                $bestFixed = null;
                $bestFixedDate = null;
                $pubStr = $pubDt ? $pubDt->format(DATE_ATOM) : 'unknown';
                foreach ($fixedVers as $fv) {
                    $ts = $releaseMap[$pkg][$fv] ?? null;
                    if (!is_string($ts) || $ts === '') continue; // không có timestamp → không tính được
                    $fixDt = $parseDate($ts);
                    if (!$fixDt || !$pubDt) continue;
                    $latDays = (int)$fixDt->diff($pubDt)->format('%r%a'); // days (can be negative if dates inverted)
                    // latency = fix - advisory
                    $latency = ($fixDt->getTimestamp() - $pubDt->getTimestamp()) / 86400.0;
                    $latencyDays = (int)floor($latency + 0.00001);
                    if ($bestLatency === null || $latencyDays < $bestLatency) {
                        $bestLatency = $latencyDays;
                        $bestFixed = $fv;
                        $bestFixedDate = $fixDt->format(DATE_ATOM);
                    }
                }

                if ($bestLatency === null) {
                    $rows[] = "{$pkg} — {$vid} — publish={$pubStr} — fixed_date=unknown (no version→date mapping)";
                    continue;
                }

                $worst = max($worst, $bestLatency);
                $rows[] = "{$pkg} — {$vid} — publish={$pubStr} — fixed={$bestFixed} @ {$bestFixedDate} — latency_days={$bestLatency}";
            }
        }

        if (!$rows) {
            return [true, "No advisory timelines computed (no records or missing data)"];
        }

        // Kết luận theo threshold
        $failRows = array_filter($rows, function ($line) use ($thresholdDays) {
            if (preg_match('/latency_days=([\-]?\d+)/', $line, $m)) {
                return ((int)$m[1]) > $thresholdDays;
            }
            return false;
        });

        // In nhiều dòng cho dễ đọc (phần renderDetails đã hỗ trợ nl2br)
        $msg = "Advisory timeline (publish → fixed):\n - " . implode("\n - ", $rows);

        if (!empty($failRows)) {
            return [false, $msg . "\nThreshold: {$thresholdDays} days — flagged entries marked above"];
        }
        return [true, $msg . "\nThreshold: {$thresholdDays} days — all within limit"];
    }

    private function collectAdobePatchEvidence(array $installed): array
    {
        $packages = [];
        foreach ($installed as $name => $info) {
            if (is_string($info['version'] ?? null) && $info['version'] !== '') {
                $packages[strtolower((string)$name)] = ltrim((string)$info['version'], 'vV');
            }
        }

        $artifacts = $this->qualityPatchArtifacts();
        foreach (array_merge($this->composerPatchArtifacts(), $this->localPatchArtifacts()) as $artifact) {
            $artifacts[] = $artifact;
        }

        return [
            'packages' => $packages,
            'patch_artifacts' => $artifacts,
        ];
    }

    private function qualityPatchArtifacts(): array
    {
        $binary = $this->ctx->abs('vendor/bin/magento-patches');
        if (!is_file($binary) || !function_exists('proc_open')) {
            return [];
        }

        [$exitCode, $output] = $this->runReadOnlyProcess([PHP_BINARY, $binary, 'status'], $this->ctx->path);
        if ($exitCode !== 0 || $output === '') {
            return [];
        }

        $artifacts = [];
        foreach (preg_split('/\R/', $output) ?: [] as $line) {
            if (!preg_match('/\b([A-Z][A-Z0-9]+(?:-[A-Z0-9]+)+)\b.*\b(Applied|Not applied|N\/A)\b/i', $line, $match)) {
                continue;
            }
            $status = strtolower($match[2]);
            $artifacts[] = [
                'path' => 'vendor/bin/magento-patches',
                'identifiers' => [strtoupper($match[1])],
                'applied' => $status === 'applied',
                'verification' => 'magento-patches status',
                'status' => $status,
            ];
        }
        return $artifacts;
    }

    private function composerPatchArtifacts(): array
    {
        $lockPath = $this->ctx->abs('patches.lock.json');
        if (!is_file($lockPath)) return [];
        $document = json_decode((string)$this->collectors->files->read($lockPath), true);
        if (!is_array($document)) return [];

        $artifacts = [];
        $walk = function (mixed $node) use (&$walk, &$artifacts): void {
            if (!is_array($node)) return;
            $description = (string)($node['description'] ?? '');
            $url = (string)($node['url'] ?? '');
            $sha256 = strtolower((string)($node['sha256'] ?? ''));
            if ($description !== '' || $url !== '' || $sha256 !== '') {
                preg_match_all(
                    '/\b(?:APSB\d{2}-\d+|(?:ACSD|MDVA|MC|MAGETWO|MAGECLOUD|MCLOUD|VULN)-?[A-Z0-9-]+)\b/i',
                    $description . ' ' . $url,
                    $matches
                );
                $artifacts[] = [
                    'path' => $url !== '' ? $url : 'patches.lock.json',
                    'identifiers' => array_values(array_unique(array_map('strtoupper', $matches[0] ?? []))),
                    'sha256' => preg_match('/^[a-f0-9]{64}$/', $sha256) ? $sha256 : null,
                    'applied' => true,
                    'verification' => 'cweagans patches.lock.json',
                ];
            }
            foreach ($node as $child) {
                if (is_array($child)) $walk($child);
            }
        };
        $walk($document['patches'] ?? $document);
        return $artifacts;
    }

    private function localPatchArtifacts(): array
    {
        $paths = [];
        foreach (glob($this->ctx->abs('*.patch')) ?: [] as $path) {
            if (is_file($path)) $paths[$path] = true;
        }

        $hotfixDir = $this->ctx->abs('m2-hotfixes');
        if (is_dir($hotfixDir)) {
            try {
                $iterator = new \RecursiveIteratorIterator(
                    new \RecursiveDirectoryIterator($hotfixDir, \FilesystemIterator::SKIP_DOTS)
                );
                foreach ($iterator as $file) {
                    if ($file->isFile() && strtolower($file->getExtension()) === 'patch') {
                        $paths[$file->getPathname()] = true;
                    }
                }
            } catch (\Throwable) {
                // Unreadable patch directories produce no evidence.
            }
        }

        $artifacts = [];
        foreach (array_keys($paths) as $path) {
            $size = @filesize($path);
            if (!is_int($size) || $size <= 0 || $size > 10 * 1024 * 1024) continue;
            $content = (string)$this->collectors->files->read($path);
            preg_match_all(
                '/\b(?:APSB\d{2}-\d+|(?:ACSD|MDVA|MC|MAGETWO|MAGECLOUD|MCLOUD|VULN)-?[A-Z0-9-]+)\b/i',
                basename($path) . "\n" . substr($content, 0, 1024 * 1024),
                $matches
            );
            $identifiers = array_values(array_unique(array_map('strtoupper', $matches[0] ?? [])));
            [$exitCode] = $this->runReadOnlyProcess(
                ['patch', '--dry-run', '--reverse', '--silent', '-p1', '-i', $path],
                $this->ctx->path
            );
            if ($exitCode !== 0) {
                [$exitCode] = $this->runReadOnlyProcess(
                    ['patch', '--dry-run', '--reverse', '--silent', '-p2', '-i', $path],
                    $this->ctx->path
                );
            }
            $relative = str_starts_with($path, $this->ctx->path . DIRECTORY_SEPARATOR)
                ? substr($path, strlen($this->ctx->path) + 1)
                : basename($path);
            $artifacts[] = [
                'path' => $relative,
                'identifiers' => $identifiers,
                'sha256' => hash_file('sha256', $path) ?: null,
                'applied' => $exitCode === 0,
                'verification' => $exitCode === 0
                    ? 'reverse patch dry-run succeeded'
                    : 'patch file present but applied state was not proven',
            ];
        }
        return $artifacts;
    }

    private function runReadOnlyProcess(array $command, string $cwd): array
    {
        if (!function_exists('proc_open')) return [127, ''];
        $pipes = [];
        $process = @proc_open(
            $command,
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
            $cwd,
            null,
            ['bypass_shell' => true]
        );
        if (!is_resource($process)) return [127, ''];
        fclose($pipes[0]);
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);
        $stdout = '';
        $stderr = '';
        $deadline = microtime(true) + 15.0;
        $exitCode = null;
        do {
            $stdout .= (string)stream_get_contents($pipes[1]);
            $stderr .= (string)stream_get_contents($pipes[2]);
            $status = proc_get_status($process);
            if (!$status['running']) {
                $exitCode = (int)$status['exitcode'];
                break;
            }
            if (microtime(true) >= $deadline) {
                proc_terminate($process);
                $exitCode = 124;
                break;
            }
            usleep(20000);
        } while (true);
        $stdout .= (string)stream_get_contents($pipes[1]);
        $stderr .= (string)stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $closedExitCode = proc_close($process);
        if ($exitCode === null || $exitCode < 0) $exitCode = $closedExitCode;
        return [$exitCode, trim($stdout . "\n" . $stderr)];
    }
}
