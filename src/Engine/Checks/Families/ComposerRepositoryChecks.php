<?php
declare(strict_types=1);
namespace Magebean\Engine\Checks\Families;
use Magebean\Engine\Context;
use Magebean\Engine\Collectors\CollectorSet;

final class ComposerRepositoryChecks extends ComposerSupport
{
    private function observedPackageRecords(array $selection): array
    {
        return array_map(static function (array $record): array {
            foreach (['source','dist'] as $field) if (is_array($record[$field]??null)) $record[$field]=$record[$field]['url']??null;
            return $record;
        },$selection['packages']);
    }

    public function vendorSupportApi(array $args): array
    {
        $selection=$this->dependencySelection($args);
        return $this->withDependencyProvenance($this->vendorSupportApiObserved($args,$selection),$selection);
    }

    private function vendorSupportApiObserved(array $args, array $selection): array
    {
        $lockFile = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        if ($selection['packages']===[]) {
            return [null, '[UNKNOWN] composer.lock not found'];
        }

        $lock=['packages'=>array_values($selection['packages'])];

        $packages = [];
        foreach (array_merge($lock['packages'] ?? [], $lock['packages-dev'] ?? []) as $package) {
            if (!is_array($package)
                || ($package['type'] ?? '') !== 'magento2-module'
                || !is_string($package['name'] ?? null)
                || !is_string($package['version'] ?? null)
                || $this->isAdobeCorePackage($package['name'])
            ) {
                continue;
            }

            $version = ltrim(trim($package['version']), 'vV');
            if ($version !== '') {
                $packages[] = [
                    'name' => strtolower($package['name']),
                    'version' => $version,
                ];
            }
        }

        if ($packages === []) {
            return [
                true,
                'No third-party Magento Composer modules found in composer.lock',
                ['packages_checked' => 0],
            ];
        }

        [$ok, $message, $statuses] = $this->fetchPackageStatuses($args, $packages);
        if (!$ok) {
            return [
                null,
                '[UNKNOWN] Package status API request failed: ' . $message,
                $this->packageStatusApiFailureEvidence($packages),
            ];
        }

        $supported = [];
        $unsupported = [];
        $unknown = [];
        $excluded = [];
        foreach ($packages as $package) {
            $status = $statuses[$package['name']] ?? null;
            if (!is_array($status) || empty($status['classification_known'])) {
                $unknown[] = $package + ['reason' => 'classification_unavailable'];
                continue;
            }
            if (empty($status['marketplace'])) {
                $excluded[] = $package + ['category' => $status['category'] ?? 'other'];
                continue;
            }

            $item = [
                'name' => $package['name'],
                'installed' => $package['version'],
                'status' => (string)($status['vendor_support_status'] ?? 'unknown'),
                'reasons' => array_values(array_map(
                    'strval',
                    (array)($status['vendor_support_reasons'] ?? [])
                )),
            ];
            if ($item['status'] === 'unsupported') {
                $unsupported[] = $item;
            } elseif ($item['status'] === 'active') {
                $supported[] = $item;
            } else {
                $unknown[] = $item;
            }
        }

        $evidence = [
            'scope' => 'API-classified Marketplace magento2-module packages',
            'packages_checked' => count($packages),
            'packages_supported' => $supported,
            'packages_unsupported' => $unsupported,
            'packages_unknown' => $unknown,
            'packages_excluded_by_category' => $excluded,
        ];

        if ($unsupported !== []) {
            $visible = $unsupported;
            $details = array_map(static function (array $item): string {
                $reasons = $item['reasons'] !== [] ? implode(', ', $item['reasons']) : 'unsupported';
                return $item['name'] . '@' . $item['installed'] . ' [' . $reasons . ']';
            }, $visible);
            $resultMessage = "Marketplace extensions without active vendor support:\n    - "
                . implode("\n    - ", $details);
            if ($unknown !== []) {
                $unknownDetails = array_map(
                    static fn(array $item): string => (string)($item['name'] ?? 'unknown-package')
                        . '@' . (string)($item['installed'] ?? $item['version'] ?? 'unknown-version'),
                    $unknown
                );
                $resultMessage .= "\n    Vendor support evidence unavailable for:\n    - "
                    . implode("\n    - ", $unknownDetails);
            }
            return [false, $resultMessage, $evidence];
        }

        if ($unknown !== []) {
            $visible = $unknown;
            $details = array_map(
                static fn(array $item): string => (string)($item['name'] ?? 'unknown-package')
                    . '@' . (string)($item['installed'] ?? $item['version'] ?? 'unknown-version'),
                $visible
            );
            $resultMessage = "[UNKNOWN] Vendor support evidence unavailable for:\n    - "
                . implode("\n    - ", $details);
            return [null, $resultMessage, $evidence];
        }

        if ($supported === []) {
            return [
                true,
                'No API-classified Marketplace extensions found in composer.lock',
                $evidence,
            ];
        }

        return [
            true,
            count($supported) . ' Marketplace extension(s) have active vendor support evidence',
            $evidence,
        ];
    }

    public function abandonedApi(array $args): array
    {
        $selection=$this->dependencySelection($args);
        return $this->withDependencyProvenance($this->abandonedApiObserved($args,$selection),$selection);
    }

    private function abandonedApiObserved(array $args, array $selection): array
    {
        $lockFile = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        if ($selection['packages']===[]) {
            return [null, '[UNKNOWN] composer.lock not found'];
        }

        $installed = $this->observedPackageRecords($selection);
        if (!is_array($installed) || $installed === []) {
            return [null, '[UNKNOWN] Unable to parse composer.lock'];
        }

        $packageTypes = is_array($args['package_types'] ?? null)
            ? array_values(array_filter(array_map(
                static fn(mixed $type): string => strtolower(trim((string)$type)),
                $args['package_types']
            )))
            : [];
        $packages = [];
        foreach ($installed as $name => $info) {
            $type = strtolower(trim((string)($info['type'] ?? '')));
            if ($packageTypes !== [] && !in_array($type, $packageTypes, true)) {
                continue;
            }
            $version = ltrim(trim((string)($info['version'] ?? '')), 'vV');
            if ($version !== '') {
                $packages[] = [
                    'name' => strtolower((string)$name),
                    'version' => $version,
                    'type' => $type,
                ];
            }
        }
        if ($packages === []) {
            return [
                true,
                $packageTypes === []
                    ? 'No packages in composer.lock (nothing to check)'
                    : 'No installed packages match the requested Composer package types',
                ['package_types' => $packageTypes, 'packages_checked' => 0],
            ];
        }

        [$ok, $message, $statuses] = $this->fetchPackageStatuses($args, $packages);
        if (!$ok) {
            return [
                null,
                '[UNKNOWN] Package status API request failed: ' . $message,
                $this->packageStatusApiFailureEvidence($packages, [
                    'package_types' => $packageTypes,
                ]),
            ];
        }

        $abandoned = [];
        $unknown = [];
        foreach ($packages as $package) {
            $status = $statuses[$package['name']] ?? null;
            if (!is_array($status) || empty($status['abandoned_status_known'])) {
                $unknown[] = $package;
                continue;
            }
            if (empty($status['abandoned'])) {
                continue;
            }

            $abandoned[] = [
                'status_observation'=>$status['_status_observation']??null,
                'name' => $package['name'],
                'installed' => $package['version'],
                'replacement' => is_string($status['replacement'] ?? null)
                    && trim($status['replacement']) !== ''
                        ? trim($status['replacement'])
                        : null,
            ];
        }

        $evidence = [
            'package_types' => $packageTypes,
            'packages_checked' => count($packages),
            'abandoned_packages' => $abandoned,
            'packages_unknown' => $unknown,
        ];
        if ($abandoned !== []) {
            $details = array_map(static function (array $item): string {
                $text = $item['name'] . '@' . $item['installed'];
                if (is_string($item['replacement']) && $item['replacement'] !== '') {
                    $text .= ' -> replace with ' . $item['replacement'];
                }
                return $text;
            }, $abandoned);
            $resultMessage = "Packages marked abandoned on Packagist:\n    - "
                . implode("\n    - ", $details);
            if ($unknown !== []) {
                $unknownDetails = array_map(
                    static fn(array $package): string => $package['name'] . '@' . $package['version'],
                    $unknown
                );
                $resultMessage .= "\n    Packages not assessed for abandoned status:\n    - "
                    . implode("\n    - ", $unknownDetails);
            }
            return [false, $resultMessage, $evidence];
        }

        if ($unknown !== []) {
            $details = array_map(
                static fn(array $package): string => $package['name'] . '@' . $package['version'],
                $unknown
            );
            $resultMessage = "[UNKNOWN] Packagist abandoned status unavailable for:\n    - "
                . implode("\n    - ", $details);
            return [null, $resultMessage, $evidence];
        }

        return [
            true,
            $packageTypes === []
                ? 'No installed packages are marked abandoned in the Packagist snapshot'
                : 'No installed packages in the requested Composer type scope are marked abandoned',
            $evidence,
        ];
    }

    public function releaseRecencyApi(array $args): array
    {
        $selection=$this->dependencySelection($args);
        return $this->withDependencyProvenance($this->releaseRecencyApiObserved($args,$selection),$selection);
    }

    private function releaseRecencyApiObserved(array $args, array $selection): array
    {
        $lockFile = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        if ($selection['packages']===[]) {
            return [null, '[UNKNOWN] composer.lock not found'];
        }

        $installed = $this->observedPackageRecords($selection);
        if (!is_array($installed) || $installed === []) {
            return [null, '[UNKNOWN] Unable to parse composer.lock'];
        }

        $packages = [];
        foreach ($installed as $name => $info) {
            $version = ltrim(trim((string)($info['version'] ?? '')), 'vV');
            if ($version !== '') {
                $packages[] = [
                    'name' => strtolower((string)$name),
                    'version' => $version,
                ];
            }
        }
        if ($packages === []) {
            return [true, 'No packages in composer.lock (nothing to check)'];
        }

        [$ok, $message, $statuses] = $this->fetchPackageStatuses($args, $packages);
        if (!$ok) {
            return [
                null,
                '[UNKNOWN] Package status API request failed: ' . $message,
                $this->packageStatusApiFailureEvidence($packages),
            ];
        }

        return $this->assessReleaseRecencyStatuses($packages, $statuses, $args);
    }

    private function assessReleaseRecencyStatuses(array $packages, array $statuses, array $args): array
    {
        $months = max(1, (int)($args['months'] ?? 24));
        $cutoff = (new \DateTimeImmutable('now'))->modify('-' . $months . ' months');
        $now = time();
        $tracked = [];
        $stale = [];
        $unknown = [];
        $excluded = [];

        foreach ($packages as $package) {
            $status = $statuses[$package['name']] ?? null;
            if (!is_array($status)) {
                $unknown[] = $package + ['reason' => 'missing_status'];
                continue;
            }
            if (($status['release_history_known'] ?? null) !== true) {
                $unknown[] = $package + ['reason' => 'release_history_unavailable'];
                continue;
            }

            $latestDate = is_string($status['latest_date'] ?? null)
                ? trim($status['latest_date'])
                : '';
            $latestAt = \Magebean\Engine\Checks\AbsoluteTimestamp::parse($latestDate);
            if ($latestAt === null || $latestAt->getTimestamp() > $now) {
                $unknown[] = $package + ['reason' => 'latest_date_invalid'];
                continue;
            }

            $item = [
                'name' => $package['name'],
                'installed' => $package['version'],
                'latest' => is_string($status['latest'] ?? null) ? $status['latest'] : null,
                'latest_date' => $latestAt->format(DATE_ATOM),
                'age_days' => max(0, (int)floor(($now - $latestAt->getTimestamp()) / 86400)),
            ];
            $tracked[] = $item;
            if ($latestAt < $cutoff) {
                $stale[] = $item;
            }
        }

        $evidence = [
            'months' => $months,
            'cutoff' => $cutoff->format(DATE_ATOM),
            'packages_checked' => count($packages),
            'packages_tracked' => $tracked,
            'packages_stale' => $stale,
            'packages_unknown' => $unknown,
            'packages_excluded_no_release_history' => $excluded,
        ];

        if ($stale !== []) {
            $visible = $stale;
            $details = array_map(static function (array $item): string {
                $latest = is_string($item['latest'] ?? null) && $item['latest'] !== ''
                    ? ' latest ' . $item['latest']
                    : '';
                return $item['name'] . '@' . $item['installed']
                    . $latest
                    . ', last release ' . $item['age_days'] . ' days ago';
            }, $visible);
            $resultMessage = 'Packagist-tracked packages without a release in the last '
                . $months . " months:\n    - " . implode("\n    - ", $details);
            // Unavailable release data is diagnostic evidence, not an actionable package issue.
            return [false, $resultMessage, $evidence];
        }

        if ($unknown !== []) {
            $resultMessage = '[UNKNOWN] Release recency could not be assessed for '.count($unknown).' package(s).';
            return [null, $resultMessage, $evidence];
        }

        if ($tracked === []) {
            return [
                true,
                'No Packagist release history is available for installed packages; nothing to assess',
                $evidence,
            ];
        }

        return [
            true,
            'Packagist-tracked packages have a release within the last ' . $months . ' months',
            $evidence,
        ];
    }

    public function repoArchivedApi(array $args): array
    {
        $selection=$this->dependencySelection($args);
        return $this->withDependencyProvenance($this->repoArchivedApiObserved($args,$selection),$selection);
    }

    private function repoArchivedApiObserved(array $args, array $selection): array
    {
        $lockFile = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        if ($selection['packages']===[]) {
            return [null, '[UNKNOWN] composer.lock not found'];
        }

        $installed = $this->observedPackageRecords($selection);
        if (!is_array($installed) || $installed === []) {
            return [null, '[UNKNOWN] Unable to parse composer.lock'];
        }

        $packages = [];
        foreach ($installed as $name => $info) {
            $version = ltrim(trim((string)($info['version'] ?? '')), 'vV');
            if ($version !== '') {
                $packages[] = [
                    'name' => strtolower((string)$name),
                    'version' => $version,
                    'repository_url' => is_string($info['source'] ?? null)
                        ? trim($info['source'])
                        : '',
                ];
            }
        }
        if ($packages === []) {
            return [true, 'No packages in composer.lock (nothing to check)'];
        }

        [$ok, $message, $statuses] = $this->fetchPackageStatuses($args, $packages);
        if (!$ok) {
            return [
                null,
                '[UNKNOWN] Package status API request failed: ' . $message,
                $this->packageStatusApiFailureEvidence($packages),
            ];
        }

        return $this->assessRepositoryStatuses($packages, $statuses, $args);
    }

    private function assessRepositoryStatuses(array $packages, array $statuses, array $args): array
    {
        $findings = [];
        $unknown = [];
        $unassessed = [];
        $excluded = [];
        $active = [];
        foreach ($packages as $package) {
            $status = $statuses[$package['name']] ?? null;
            if (!is_array($status)) {
                $unassessed[] = $package + [
                    'installed' => $package['version'],
                    'reason' => 'missing_status',
                    'repository_url' => $package['repository_url'],
                ];
                continue;
            }

            if (!empty($args['strict_scope']) && (($status['repository_status_known'] ?? null) === true)
                && (!is_bool($status['repository_archived'] ?? null) || !is_bool($status['repository_disabled'] ?? null))) {
                $unassessed[] = $package + ['reason' => 'repository_flags_invalid'];
                continue;
            }
            if (empty($status['repository_status_known'])) {
                $reason = trim((string)($status['repository_status_reason'] ?? ''));
                $item = $package + [
                    'installed' => $package['version'],
                    'reason' => $reason !== '' ? $reason : 'repository_status_unavailable',
                    'repository_url' => is_string($status['repository_url'] ?? null)
                        ? $status['repository_url']
                        : null,
                ];
                if ($item['reason'] === 'repository_missing') {
                    $findings[] = $item + [
                        'archived' => false,
                        'disabled' => false,
                        'missing' => true,
                    ];
                } elseif ($item['reason'] === 'repository_not_collected') {
                    $unassessed[] = $item;
                } elseif (in_array($item['reason'], [
                    'repository_not_applicable',
                    'repository_provider_unsupported',
                ], true)) {
                    if (!empty($args['strict_scope']) && $item['reason'] === 'repository_provider_unsupported') $unassessed[] = $item;
                    else $excluded[] = $item;
                } else {
                    $unassessed[] = $item;
                }
                continue;
            }

            $item = [
                'name' => $package['name'],
                'installed' => $package['version'],
                'repository_url' => is_string($status['repository_url'] ?? null)
                    ? trim($status['repository_url'])
                    : '',
                'provider' => is_string($status['repository_provider'] ?? null)
                    ? trim($status['repository_provider'])
                    : null,
                'archived' => !empty($status['repository_archived']),
                'disabled' => !empty($status['repository_disabled']),
                'missing' => false,
                'checked_at' => is_string($status['repository_checked_at'] ?? null)
                    ? $status['repository_checked_at']
                    : null,
            ];
            if ($item['archived'] || $item['disabled']) {
                $findings[] = $item;
            } else {
                $active[] = $item;
            }
        }

        $evidence = [
            'packages_checked' => count($packages),
            'repositories_active' => $active,
            'repository_findings' => $findings,
            'packages_unknown' => $unknown,
            'packages_unassessed' => $unassessed,
            'packages_excluded' => $excluded,
        ];

        if ($findings !== []) {
            $details = array_map(static function (array $item): string {
                $states = [];
                if ($item['archived']) {
                    $states[] = 'archived';
                }
                if ($item['disabled']) {
                    $states[] = 'disabled';
                }
                if ($item['missing']) {
                    $states[] = 'missing';
                }
                $detail = $item['name'] . '@' . $item['installed'] . ' (' . implode(', ', $states) . ')';
                if ($item['repository_url'] !== '') {
                    $detail .= "\n      Repository: " . $item['repository_url'];
                }
                return $detail;
            }, $findings);
            $resultMessage = "Packages from archived, disabled, or missing repositories:\n    - "
                . implode("\n    - ", $details);
            // Keep coverage gaps and scope exclusions in structured evidence, not issue text.
            return [false, $resultMessage, $evidence];
        }

        $coverageParts = [count($active) . ' repositories assessed'];
        if ($unassessed !== []) {
            $coverageParts[] = count($unassessed) . ' awaiting collection or unavailable';
        }
        if ($excluded !== []) {
            $coverageParts[] = count($excluded) . ' not applicable or unsupported';
        }
        $coverage = implode(', ', $coverageParts);

        if ($unassessed !== [] && (!empty($args['strict_scope']) || $active === [])) {
            return [
                null,
                '[UNKNOWN] Repository status coverage is insufficient to assess archived or disabled repositories ('
                    . $coverage . ')',
                $this->repositoryCoverageEvidence($evidence),
            ];
        }

        if ($active === []) {
            return [
                true,
                'No installed packages have an applicable GitHub or GitLab source repository (' . $coverage . ')',
                $evidence,
            ];
        }

        return [
            true,
            'No assessed packages come from archived, disabled, or missing repositories ('
                . $coverage . ')',
            $evidence,
        ];
    }

    public function riskyForkApi(array $args): array
    {
        $selection=$this->dependencySelection($args);
        return $this->withDependencyProvenance($this->riskyForkApiObserved($args,$selection),$selection);
    }

    private function riskyForkApiObserved(array $args, array $selection): array
    {
        $lockFile = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        if ($selection['packages']===[]) {
            return [null, '[UNKNOWN] composer.lock not found'];
        }
        $installed = $this->observedPackageRecords($selection);
        if (!is_array($installed) || $installed === []) {
            return [null, '[UNKNOWN] Unable to parse composer.lock'];
        }

        $packages = [];
        foreach ($installed as $name => $info) {
            $version = ltrim(trim((string)($info['version'] ?? '')), 'vV');
            if ($version === '') {
                continue;
            }
            $replaces = [];
            foreach ((array)($info['replace'] ?? []) as $replacement => $_constraint) {
                $replacement = strtolower(trim((string)$replacement));
                if ($replacement !== ''
                    && $replacement !== strtolower((string)$name)
                    && str_contains($replacement, '/')
                    && !str_ends_with($replacement, '-implementation')
                ) {
                    $replaces[] = $replacement;
                }
            }
            $packages[] = [
                'name' => strtolower((string)$name),
                'version' => $version,
                'repository_url' => is_string($info['source'] ?? null)
                    ? trim($info['source'])
                    : '',
                'type' => is_string($info['type'] ?? null) ? $info['type'] : null,
                'replaces' => array_values(array_unique($replaces)),
            ];
        }
        if ($packages === []) {
            return [true, 'No packages in composer.lock (nothing to check)'];
        }

        [$ok, $message, $statuses] = $this->fetchPackageStatuses($args, $packages);
        if (!$ok) {
            return [null, '[UNKNOWN] Package status API request failed: ' . $message, $this->packageStatusApiFailureEvidence($packages)];
        }

        $findings = [];
        $safe = [];
        $unknown = [];
        $excluded = [];
        foreach ($packages as $package) {
            $status = $statuses[$package['name']] ?? null;
            if (!is_array($status)) {
                if ($package['replaces'] !== []) {
                    $unknown[] = $package + ['installed' => $package['version'], 'reason' => 'missing_status'];
                } else {
                    $excluded[] = $package + ['reason' => 'not_a_replacement_candidate'];
                }
                continue;
            }

            $sourceOverride = !empty($status['repository_source_override_known'])
                && !empty($status['repository_source_override']);
            if ($package['replaces'] === [] && !$sourceOverride) {
                $excluded[] = $package + ['reason' => 'not_a_replacement_candidate'];
                continue;
            }
            if ($package['type'] === 'metapackage' || $package['repository_url'] === '') {
                $excluded[] = $package + ['reason' => 'repository_not_applicable'];
                continue;
            }

            $reason = trim((string)($status['repository_status_reason'] ?? ''));
            $item = [
                'name' => $package['name'],
                'installed' => $package['version'],
                'repository_url' => (string)($status['repository_url'] ?? $package['repository_url']),
                'package_repository_url' => is_string($status['package_repository_url'] ?? null)
                    ? $status['package_repository_url']
                    : null,
                'upstream_url' => is_string($status['repository_upstream_url'] ?? null)
                    ? $status['repository_upstream_url']
                    : null,
                'replaces' => $package['replaces'],
                'source_override' => $sourceOverride,
                'is_fork' => !empty($status['repository_is_fork']),
                'trusted' => !empty($status['repository_trusted']),
            ];

            if ($reason === 'repository_missing') {
                $findings[] = $item + ['reason' => 'replacement_repository_missing'];
                continue;
            }
            if ($item['trusted']) {
                $safe[] = $item + ['reason' => 'trusted_repository'];
                continue;
            }
            if ($sourceOverride) {
                $findings[] = $item + ['reason' => 'untrusted_source_override'];
                continue;
            }
            if (empty($status['repository_status_known']) || empty($status['fork_status_known'])) {
                $unknown[] = $item + [
                    'reason' => $reason !== '' ? $reason : 'fork_status_unavailable',
                ];
                continue;
            }
            if ($item['is_fork']) {
                $findings[] = $item + [
                    'reason' => $item['upstream_url'] === null || $item['upstream_url'] === ''
                        ? 'fork_upstream_missing'
                        : 'unverified_fork_replacing_upstream',
                ];
                continue;
            }
            $safe[] = $item + ['reason' => 'replacement_not_from_fork'];
        }

        $evidence = [
            'packages_checked' => count($packages),
            'replacement_candidates_safe' => $safe,
            'risky_replacements' => $findings,
            'replacement_candidates_unknown' => $unknown,
            'packages_excluded' => $excluded,
        ];

        if ($findings !== []) {
            $details = array_map(static function (array $item): string {
                $detail = $item['name'] . '@' . $item['installed'] . ' (' . $item['reason'] . ')';
                if ($item['replaces'] !== []) {
                    $detail .= "\n      Replaces: " . implode(', ', $item['replaces']);
                }
                $detail .= "\n      Repository: " . $item['repository_url'];
                if (is_string($item['upstream_url']) && $item['upstream_url'] !== '') {
                    $detail .= "\n      Upstream: " . $item['upstream_url'];
                }
                return $detail;
            }, $findings);
            $resultMessage = "Risky replacement repositories detected:\n    - "
                . implode("\n    - ", $details);
            if ($unknown !== []) {
                $unknownDetails = array_map(static function (array $item): string {
                    return $item['name'] . '@' . $item['installed']
                        . ' (' . $item['reason'] . ')';
                }, $unknown);
                $resultMessage .= "\n    Fork evidence unavailable for:\n    - "
                    . implode("\n    - ", $unknownDetails);
            }
            return [false, $resultMessage, $evidence];
        }

        if ($unknown !== []) {
            $details = array_map(static function (array $item): string {
                return $item['name'] . '@' . $item['installed'] . ' (' . $item['reason'] . ')';
            }, $unknown);
            return [
                null,
                "[UNKNOWN] Fork evidence unavailable for replacement candidates:\n    - "
                    . implode("\n    - ", $details),
                $evidence,
            ];
        }

        return [
            true,
            $safe === []
                ? 'No installed packages replace upstream libraries from alternate repositories'
                : 'No risky forks detected among ' . count($safe) . ' replacement candidate(s)',
            $evidence,
        ];
    }

    public function vendorSupportOffline(array $args): array
    {
        // 0) Load composer.lock
        $lock = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        if (!is_file($lock)) return [null, "[UNKNOWN] composer.lock not found"];
        $pkgs = $this->readLockPackages($lock);
        if (!$pkgs || !is_array($pkgs)) return [null, "[UNKNOWN] Unable to parse composer.lock"];

        $installed = [];
        foreach ($pkgs as $name => $info) {
            $v = $info['version'] ?? null;
            if (is_string($v) && $v !== '') $installed[strtolower($name)] = ltrim($v, 'vV');
        }
        if (!$installed) return [true, "No packages in composer.lock (nothing to check)"];

        // Prefer Context->meta (resolved from extracted bundle) before falling back to bundle root detection.
        $metaPath = $this->metaPath($args, 'vendor_support', 'vendor_support_meta', 'vendor-support.json')
            ?? $this->metaPath($args, 'vendor_support', 'vendor_support_meta', 'rules/vendor-support.json');
        $raw = null;
        if ($metaPath) {
            $raw = $this->collectors->files->read($metaPath);
            if ($raw === false) $raw = null;
        }

        // 1) Resolve bundle root (zip/dir/path-inside-bundle)
        if ($raw === null) {
            $candidates = [];
            if (!empty($args['vendor_support_meta'])) $candidates[] = (string)$args['vendor_support_meta'];
            if (!empty($args['cve_data']))           $candidates[] = (string)$args['cve_data'];
            if (!empty($this->ctx->cveData))         $candidates[] = (string)$this->ctx->cveData;
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
                return [null, "[UNKNOWN] Vendor-support metadata not found; bundle root unresolved; tried: " . $msg];
            }

            // 2) Load DATA/vendor-support.json (fallback rules/)
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

            $raw = $loadText('vendor-support.json') ?? $loadText('rules/vendor-support.json');
            if ($raw === null) {
                return [true, "Vendor-support metadata not provided; skipping check (add vendor-support.json in CVE bundle to enable)"];
            }
        }

        // 2.1) Loose JSON decode: strip BOM, comments, trailing commas; retry decode
        $looseDecode = static function (string $s) {
            // strip UTF-8 BOM
            if (substr($s, 0, 3) === "\xEF\xBB\xBF") $s = substr($s, 3);
            // remove //... and /* ... */
            $s = preg_replace('#//[^\r\n]*#', '', $s);
            $s = preg_replace('#/\*.*?\*/#s', '', $s);
            // remove trailing commas before } or ]
            $s = preg_replace('#,\s*(}|\])#', '$1', $s);
            // collapse repeated commas
            $s = preg_replace('#,\s*,+#', ',', $s);
            // trim
            $s = trim($s);
            $j = json_decode($s, true);
            if (is_array($j)) return $j;
            // final fallback: try to decode as empty container aliases
            if ($s === '' || $s === '{}' || $s === '[]') return [];
            return null;
        };

        $j = $looseDecode($raw);
        if (!is_array($j)) return [null, "[UNKNOWN] Invalid vendor-support metadata JSON"];

        // 3) Normalize payload → rules[pkg][] = ['versions'[], 'constraint', 'eol', 'seol', 'status']
        $payload = $j;
        if (isset($j['support']) && (is_array($j['support']) || $j['support'] === [])) $payload = $j['support'];
        if (isset($j['vendor_support']) && (is_array($j['vendor_support']) || $j['vendor_support'] === [])) $payload = $j['vendor_support'];
        if (isset($j['vendorSupport']) && (is_array($j['vendorSupport']) || $j['vendorSupport'] === [])) $payload = $j['vendorSupport'];

        $isAssoc = static function (array $a): bool {
            return array_keys($a) !== range(0, count($a) - 1);
        };
        $rules = []; // pkg => list of rule rows

        $addRule = static function (string $pkg, ?array $versions, ?string $constraint, ?string $eol, ?string $seol, ?string $status) use (&$rules) {
            $pkg = strtolower($pkg);
            $row = [
                'versions'   => $versions ?: null,
                'constraint' => $constraint ?: null,
                'eol'        => $eol ?: null,
                'seol'       => $seol ?: null,
                'status'     => $status ? strtolower($status) : null,
            ];
            $rules[$pkg][] = $row;
        };
        $canonSeol = static function (?array $row): ?string {
            if (!$row) return null;
            foreach (['security_eol', 'securityEOL', 'security-end', 'security_end'] as $k) {
                if (isset($row[$k]) && is_string($row[$k]) && $row[$k] !== '') return $row[$k];
            }
            return null;
        };

        if ((is_array($payload) && empty($payload)) || ($payload instanceof \stdClass && !get_object_vars($payload))) {
            return [true, "No vendor-support entries (empty list)"];
        }


        if ($isAssoc((array)$payload)) {
            foreach ($payload as $pkg => $row) {
                if (!is_string($pkg)) continue;
                if (!is_array($row)) continue;

                $eol  = is_string($row['eol'] ?? null) ? $row['eol'] : null;
                $seol = $canonSeol($row);
                $status = is_string($row['status'] ?? null) ? $row['status'] : null;
                if ($eol || $seol || $status) $addRule($pkg, null, null, $eol, $seol, $status);

                if (isset($row['tracks']) && is_array($row['tracks'])) {
                    foreach ($row['tracks'] as $t) {
                        if (!is_array($t)) continue;
                        $vers = null;
                        if (isset($t['versions']) && is_array($t['versions'])) {
                            $vers = array_values(array_filter(array_map(fn($v) => is_string($v) ? ltrim($v, 'vV') : '', $t['versions']), fn($v) => $v !== ''));
                        }
                        $constraint = is_string($t['constraint'] ?? null) ? $t['constraint'] : null;
                        $teol  = is_string($t['eol'] ?? null) ? $t['eol'] : null;
                        $tseol = $canonSeol($t);
                        $tstat = is_string($t['status'] ?? null) ? $t['status'] : null;
                        if ($vers || $constraint || $teol || $tseol || $tstat) {
                            $addRule($pkg, $vers, $constraint, $teol, $tseol, $tstat);
                        }
                    }
                }
                if (isset($row['versions']) && is_array($row['versions'])) {
                    foreach ($row['versions'] as $expr => $meta) {
                        if (!is_array($meta)) continue;
                        $teol  = is_string($meta['eol'] ?? null) ? $meta['eol'] : null;
                        $tseol = $canonSeol($meta);
                        $tstat = is_string($meta['status'] ?? null) ? $meta['status'] : null;
                        $vlist = null;
                        if (isset($meta['versions']) && is_array($meta['versions'])) {
                            $vlist = array_values(array_filter(array_map(fn($v) => is_string($v) ? ltrim($v, 'vV') : '', $meta['versions']), fn($v) => $v !== ''));
                        }
                        $addRule($pkg, $vlist, is_string($expr) ? $expr : null, $teol, $tseol, $tstat);
                    }
                }
            }
        } else {
            foreach ((array)$payload as $row) {
                if (!is_array($row)) continue;
                $pkg = $row['package'] ?? null;
                if (!is_string($pkg) || $pkg === '') continue;

                $eol  = is_string($row['eol'] ?? null) ? $row['eol'] : null;
                $seol = $canonSeol($row);
                $status = is_string($row['status'] ?? null) ? $row['status'] : null;
                if ($eol || $seol || $status) $addRule($pkg, null, null, $eol, $seol, $status);

                if (isset($row['tracks']) && is_array($row['tracks'])) {
                    foreach ($row['tracks'] as $t) {
                        if (!is_array($t)) continue;
                        $vers = null;
                        if (isset($t['versions']) && is_array($t['versions'])) {
                            $vers = array_values(array_filter(array_map(fn($v) => is_string($v) ? ltrim($v, 'vV') : '', $t['versions']), fn($v) => $v !== ''));
                        }
                        $constraint = is_string($t['constraint'] ?? null) ? $t['constraint'] : null;
                        $teol  = is_string($t['eol'] ?? null) ? $t['eol'] : null;
                        $tseol = $canonSeol($t);
                        $tstat = is_string($t['status'] ?? null) ? $t['status'] : null;
                        if ($vers || $constraint || $teol || $tseol || $tstat) {
                            $addRule($pkg, $vers, $constraint, $teol, $tseol, $tstat);
                        }
                    }
                }
            }
        }

        if (!$rules) {
            return [true, "No vendor-support entries (empty or no usable rules)"];
        }

        // 4) Version matching (Composer-like, tối giản + các toán tử phổ biến)
        $cmp = static fn(string $a, string $b, string $op) => version_compare(ltrim($a, 'vV'), ltrim($b, 'vV'), $op);

        $expandCaret = static function (string $v): array {
            $v = ltrim($v, 'vV');
            $parts = array_map('intval', explode('.', $v) + [0, 0, 0]);
            if ($parts[0] > 0)        $upper = ($parts[0] + 1) . ".0.0";
            elseif ($parts[1] > 0)    $upper = "0." . ($parts[1] + 1) . ".0";
            else                      $upper = "0.0." . ($parts[2] + 1);
            return [">=" . $v, "<" . $upper];
        };
        $expandTilde = static function (string $v): array {
            $v = ltrim($v, 'vV');
            $parts = explode('.', $v);
            if (count($parts) === 1) {
                $upper = ((int)$parts[0] + 1) . ".0.0";
                $vmin = $parts[0] . ".0.0";
            } elseif (count($parts) === 2) {
                $upper = $parts[0] . "." . ((int)$parts[1] + 1) . ".0";
                $vmin = $parts[0] . "." . $parts[1] . ".0";
            } else {
                $upper = $parts[0] . "." . ((int)$parts[1] + 1) . ".0";
                $vmin = $v;
            }
            return [">=" . $vmin, "<" . $upper];
        };
        $expandWildcard = static function (string $v): array {
            $v = ltrim($v, 'vV');
            $parts = explode('.', str_replace(['x', 'X', '*'], '*', $v));
            if (count($parts) === 1 || ($parts[1] ?? '') === '*') {
                $lower = $parts[0] . ".0.0";
                $upper = ((int)$parts[0] + 1) . ".0.0";
            } elseif (($parts[2] ?? '') === '*') {
                $lower = $parts[0] . "." . $parts[1] . ".0";
                $upper = $parts[0] . "." . ((int)$parts[1] + 1) . ".0";
            } else {
                $lower = $v;
                $upper = null;
            }
            return $upper ? [">=" . $lower, "<" . $upper] : [">=" . $lower];
        };

        $matchExpr = null; // forward decl for recursion
        $matchExpr = static function (string $iv, string $expr) use (&$matchExpr, $cmp, $expandCaret, $expandTilde, $expandWildcard): bool {
            foreach (preg_split('/\s*\|\|\s*/', trim($expr)) as $orPart) {
                if ($orPart === '') continue;
                $ok = true;
                $tokens = preg_split('/\s*,\s*|\s+/', trim($orPart));
                foreach ($tokens as $t) {
                    if ($t === '') continue;
                    if ($t[0] === '^') {
                        foreach ($expandCaret(substr($t, 1)) as $c) if (!$matchExpr($iv, $c)) {
                            $ok = false;
                            break;
                        }
                        if (!$ok) break;
                        continue;
                    }
                    if ($t[0] === '~') {
                        foreach ($expandTilde(substr($t, 1)) as $c) if (!$matchExpr($iv, $c)) {
                            $ok = false;
                            break;
                        }
                        if (!$ok) break;
                        continue;
                    }
                    if (preg_match('/[*xX]/', $t)) {
                        foreach ($expandWildcard($t) as $c) if (!$matchExpr($iv, $c)) {
                            $ok = false;
                            break;
                        }
                        if (!$ok) break;
                        continue;
                    }
                    if (preg_match('/^(<=|>=|==|=|!=|<|>)\s*([vV]?\d[\w\.\-\+]*)$/', $t, $m)) {
                        $op = $m[1] === '=' ? '==' : $m[1];
                        if (!$cmp($iv, $m[2], $op)) {
                            $ok = false;
                            break;
                        }
                    } else {
                        if (!$cmp($iv, $t, '==')) {
                            $ok = false;
                            break;
                        }
                    }
                }
                if ($ok) return true;
            }
            return false;
        };

        $now = new \DateTimeImmutable('now');
        $parseDate = static function (?string $s): ?\DateTimeImmutable {
            if (!is_string($s) || $s === '') return null;
            try {
                return new \DateTimeImmutable($s);
            } catch (\Exception $e) {
                return null;
            }
        };

        // 5) Evaluate
        $hits = [];
        foreach ($installed as $pkg => $cur) {
            if (empty($rules[$pkg])) continue;

            foreach ($rules[$pkg] as $r) {
                $matched = false;
                if (is_array($r['versions'])) {
                    $matched = in_array($cur, $r['versions'], true);
                }
                if (!$matched && is_string($r['constraint']) && $r['constraint'] !== '') {
                    $matched = $matchExpr(ltrim($cur, 'vV'), $r['constraint']);
                }
                if (!$matched && !$r['versions'] && !$r['constraint']) {
                    $matched = true; // apply to all versions
                }
                if (!$matched) continue;

                $eol  = $parseDate($r['eol']);
                $seol = $parseDate($r['seol']);
                $status = $r['status'] ?? null;

                if ($status && in_array($status, ['eol', 'end_of_life', 'unsupported', 'security_eol', 'security-end'], true)) {
                    $label = ($status === 'security_eol' || $status === 'security-end') ? 'SECURITY-EOL' : 'EOL';
                    $dateStr = $eol ? $eol->format(DATE_ATOM) : ($seol ? $seol->format(DATE_ATOM) : 'n/a');
                    $hits[] = "{$pkg} {$cur} — {$label} (since {$dateStr})";
                    continue;
                }
                if ($eol && $now > $eol) {
                    $hits[] = "{$pkg} {$cur} — EOL on " . $eol->format(DATE_ATOM);
                    continue;
                }
                if ($seol && $now > $seol) {
                    $hits[] = "{$pkg} {$cur} — SECURITY-EOL on " . $seol->format(DATE_ATOM);
                    continue;
                }
            }
        }

        if ($hits) {
            $lines = array_map(fn($s) => ' - ' . $s, $hits);
            return [false, "Vendor support issues (offline):\n" . implode(PHP_EOL, $lines)];
        }
        return [true, "All installed packages are within vendor support"];
    }

    public function composer_vendor_support_offline(array $args): array
    {
        return $this->composerVendorSupportOffline($args);
    }

    public function abandonedOffline(array $args): array
    {
        // 0) Read composer.lock
        $root = $args['path'] ?? getcwd();
        $lock = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        if (!is_file($lock)) return [null, "[UNKNOWN] composer.lock not found"];
        $pkgs = $this->readLockPackages($lock);
        if (!$pkgs || !is_array($pkgs)) return [null, "[UNKNOWN] Unable to parse composer.lock"];

        $installed = [];
        foreach ($pkgs as $name => $info) {
            $v = $info['version'] ?? null;
            if (is_string($v) && $v !== '') $installed[$name] = ltrim($v, 'vV');
        }
        if (!$installed) return [true, "No packages in composer.lock (nothing to check)"];

        // 1) Resolve bundle root (zip/dir/path-inside-bundle)
        $candidates = [];
        if (!empty($args['abandoned_meta'])) $candidates[] = (string)$args['abandoned_meta'];
        if (!empty($args['cve_data']))       $candidates[] = (string)$args['cve_data'];
        if (!empty($this->ctx->cveData))     $candidates[] = (string)$this->ctx->cveData;
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
            return [null, "[UNKNOWN] Abandoned metadata not found; bundle root unresolved; tried: " . $msg];
        }

        // 2) Load DATA/packagist-abandoned.json (fallback rules/)
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

        $raw = $loadText('packagist-abandoned.json') ?? $loadText('rules/packagist-abandoned.json');
        if ($raw === null) return [null, "[UNKNOWN] Abandoned metadata not found"];

        $j = json_decode($raw, true);
        if (!is_array($j)) {
            return [null, "[UNKNOWN] Invalid abandoned metadata JSON: " . ($bundle[0] === 'zip' ? 'zip://' . $bundle[1] . '!/DATA/packagist-abandoned.json' : (rtrim($bundle[1], '/') . '/DATA/packagist-abandoned.json'))];
        }

        // 3) Normalize abandoned map: name => replacement|null  (replacement: string|null)
        // Hỗ trợ container { "abandoned": [...] }
        $payload = isset($j['abandoned']) && is_array($j['abandoned']) ? $j['abandoned'] : $j;

        $isAssoc = static function (array $a): bool {
            return array_keys($a) !== range(0, count($a) - 1);
        };
        $abandoned = []; // 'vendor/pkg' => 'replacement/pkg' | null

        if ($isAssoc($payload)) {
            // Map form:
            // - "vendor/pkg": true
            // - "vendor/pkg": "replacement/pkg"
            // - "vendor/pkg": {"replacement": "alt/pkg"}  (hoặc {"abandoned":true})
            foreach ($payload as $pkg => $val) {
                if (!is_string($pkg) || $pkg === '') continue;
                $rep = null;
                if ($val === true) {
                    $rep = null;
                } elseif (is_string($val) && $val !== '') {
                    $rep = $val;
                } elseif (is_array($val)) {
                    if (isset($val['replacement']) && is_string($val['replacement']) && $val['replacement'] !== '') {
                        $rep = $val['replacement'];
                    } elseif (isset($val['abandoned']) && ($val['abandoned'] === true || is_string($val['abandoned']))) {
                        $rep = is_string($val['abandoned']) ? $val['abandoned'] : null;
                    }
                }
                // Chỉ thêm khi thực sự đánh dấu bỏ (true hoặc có replacement)
                if ($val === true || is_string($val) || (is_array($val) && (isset($val['replacement']) || isset($val['abandoned'])))) {
                    $abandoned[$pkg] = $rep ? (string)$rep : null;
                }
            }
        } else {
            // List form:
            // [{"package":"vendor/pkg","abandoned":true},{"package":"foo/bar","replacement":"alt/pkg"}]
            foreach ($payload as $row) {
                if (!is_array($row)) continue;
                $pkg = $row['package'] ?? null;
                if (!is_string($pkg) || $pkg === '') continue;
                $rep = null;
                if (isset($row['replacement']) && is_string($row['replacement']) && $row['replacement'] !== '') {
                    $rep = $row['replacement'];
                } elseif (array_key_exists('abandoned', $row)) {
                    if ($row['abandoned'] === true) $rep = null;
                    elseif (is_string($row['abandoned']) && $row['abandoned'] !== '') $rep = $row['abandoned'];
                }
                if (array_key_exists('abandoned', $row)) {
                    // chỉ ghi nhận nếu có cờ 'abandoned'
                    $abandoned[$pkg] = $rep;
                }
            }
        }

        // Nếu metadata rỗng có chủ đích: PASS
        if (!$abandoned) {
            if (isset($j['abandoned']) && is_array($j['abandoned']) && $j['abandoned'] === []) {
                return [true, "No abandoned entries (empty list)"];
            }
            // Không có entries usable → UNKNOWN
            return [null, "[UNKNOWN] Invalid abandoned metadata JSON (no usable entries)"];
        }

        // 4) Match against installed
        $hits = [];
        foreach ($installed as $name => $ver) {
            if (isset($abandoned[$name])) {
                $rep = $abandoned[$name];
                if ($rep) {
                    $hits[] = "{$name} {$ver} — abandoned; replacement: {$rep}";
                } else {
                    $hits[] = "{$name} {$ver} — abandoned";
                }
            }
        }

        if ($hits) {
            // Multiline output
            $lines = array_map(fn($s) => ' - ' . $s, $hits);
            return [false, "Abandoned packages (offline):\n" . implode(PHP_EOL, $lines)];
        }

        return [true, "No abandoned packages installed"];
    }

    public function releaseRecencyOffline(array $args): array
    {
        $lock = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        if (!is_file($lock)) return [null, "[UNKNOWN] composer.lock not found"];

        $metaPath = $this->metaPath($args, 'release_history', 'release_meta', 'release-history.json')
            ?? $this->metaPath($args, 'release_history', 'release_meta', 'rules/release-history.json');
        if (!$metaPath) return [null, "[UNKNOWN] Release-history metadata not found"];

        $pkgs = $this->readLockPackages($lock);
        if (!$pkgs) return [null, "[UNKNOWN] Unable to parse composer.lock"];

        $meta = $this->loadJsonSafe($metaPath);
        if (!$meta) return [null, "[UNKNOWN] Invalid release-history metadata JSON"];

        $maxAgeDays = (int)($args['max_age_days'] ?? 365);
        $today = strtotime('today');

        $stale = [];
        foreach ($pkgs as $name => $p) {
            $info = $meta[$name] ?? null;
            if (!$info || empty($info['latest_date'])) continue;
            $latestDate = strtotime((string)$info['latest_date']);
            if ($latestDate === false) continue;

            $ageDays = (int)floor(($today - $latestDate) / 86400);
            if ($ageDays > $maxAgeDays) {
                $latestVer = (string)($info['latest_version'] ?? '?');
                $stale[] = "{$name} (latest {$latestVer}, {$ageDays} days old)";
            }
        }

        if ($stale) return [false, "Stale releases:\n    - " . implode("\n    - ", $stale)];
        return [true, "No stale releases over {$maxAgeDays} days"];
    }

    public function repoArchivedOffline(array $args): array
    {
        $lock = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        if (!is_file($lock)) return [null, "[UNKNOWN] composer.lock not found"];

        $metaPath = $this->metaPath($args, 'repo_status', 'repo_meta', 'repo-status.json')
            ?? $this->metaPath($args, 'repo_status', 'repo_meta', 'rules/repo-status.json');
        if (!$metaPath) return [null, "[UNKNOWN] Repo-status metadata not found"];

        $pkgs = $this->readLockPackages($lock);
        if (!$pkgs) return [null, "[UNKNOWN] Unable to parse composer.lock"];

        $meta = $this->loadJsonSafe($metaPath);
        if (!$meta) return [null, "[UNKNOWN] Invalid repo-status metadata JSON"];

        $archived = [];
        foreach ($pkgs as $name => $_) {
            $st = $meta[$name] ?? null;
            if ($st && !empty($st['archived'])) $archived[] = $name;
        }

        if ($archived) return [false, "Archived repositories detected: " . implode(', ', $archived)];
        return [true, "No archived repositories"];
    }

    public function riskyForkOffline(array $args): array
    {
        $lock = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        if (!is_file($lock)) return [null, "[UNKNOWN] composer.lock not found"];

        $metaPath = $this->metaPath($args, 'repo_status', 'repo_meta', 'repo-status.json')
            ?? $this->metaPath($args, 'repo_status', 'repo_meta', 'rules/repo-status.json');
        if (!$metaPath) return [null, "[UNKNOWN] Repo-status metadata not found"];

        $pkgs = $this->readLockPackages($lock);
        if (!$pkgs) return [null, "[UNKNOWN] Unable to parse composer.lock"];

        $meta = $this->loadJsonSafe($metaPath);
        if (!$meta) return [null, "[UNKNOWN] Invalid repo-status metadata JSON"];

        $risky = [];
        foreach ($pkgs as $name => $_) {
            $st = $meta[$name] ?? null;
            if ($st && !empty($st['is_fork']) && empty($st['upstream'])) {
                $risky[] = $name;
            }
        }

        if ($risky) return [false, "Risky forks without upstream detected: " . implode(', ', $risky)];
        return [true, "No risky forks"];
    }

    private function repositoryCoverageEvidence(array $evidence): array
    {
        return [
            'packages_checked' => (int)($evidence['packages_checked'] ?? 0),
            'repositories_assessed' => count((array)($evidence['repositories_active'] ?? [])),
            'repository_findings' => count((array)($evidence['repository_findings'] ?? [])),
            'packages_unassessed' => count((array)($evidence['packages_unassessed'] ?? [])),
            'packages_excluded' => count((array)($evidence['packages_excluded'] ?? [])),
            'package_list_omitted' => true,
        ];
    }
}
