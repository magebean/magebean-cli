<?php
declare(strict_types=1);
namespace Magebean\Engine\Checks\Families;
use Magebean\Engine\Context;
use Magebean\Engine\Collectors\CollectorSet;

final class ComposerVersionChecks extends ComposerSupport
{
    public function yankedOffline(array $args): array
    {
        // 0) Load composer.lock
        $lock = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        if (!is_file($lock)) {
            return [null, "[UNKNOWN] composer.lock not found"];
        }
        $installed = $this->readLockPackages($lock);
        if (!$installed || !is_array($installed)) {
            return [null, "[UNKNOWN] Unable to parse composer.lock"];
        }
        $installedVers = [];
        foreach ($installed as $name => $info) {
            $v = $info['version'] ?? null;
            if (is_string($v) && $v !== '') $installedVers[$name] = ltrim($v, 'vV');
        }
        if (!$installedVers) {
            return [true, "No packages in composer.lock (nothing to check)"];
        }

        // 1) Resolve yanked metadata path (zip/dir/file-inside-dir)
        $candidates = [];
        if (!empty($args['yanked_meta'])) $candidates[] = (string)$args['yanked_meta'];
        $candidates[] = 'packagist-yanked.json';
        $candidates[] = 'rules/packagist-yanked.json';      // legacy rules/ fallback

        $metaPath = null;
        $openedZip = null;
        $tried = [];

        $tryResolve = function (string $hint) use (&$openedZip, &$metaPath, &$tried) {
            $tried[] = $hint;

            // absolute file on disk
            if (is_file($hint)) {
                $metaPath = $hint;
                return true;
            }

            // try from ctx->cveData as zip/dir or file-inside-dir
            $cve = $this->ctx->cveData ?? '';
            if (is_string($cve) && $cve !== '') {
                // zip
                if (is_file($cve) && preg_match('/\.zip$/i', $cve)) {
                    $zip = new \ZipArchive();
                    if ($zip->open($cve) === true) {
                        $idx = $zip->locateName($hint, \ZipArchive::FL_NOCASE);
                        if ($idx !== false) {
                            $raw = $zip->getFromIndex($idx);
                            if (is_string($raw)) {
                                $tmp = tempnam(sys_get_temp_dir(), 'mb-yanked-');
                                @file_put_contents($tmp, $raw);
                                $openedZip = $zip;  // keep open until end
                                $metaPath = $tmp;
                                return true;
                            }
                        }
                        $zip->close();
                    }
                }
                // dir (or file inside dir → walk up)
                $dir = is_dir($cve) ? $cve : dirname($cve);
                $cur = $dir;
                for ($i = 0; $i < 5; $i++) {
                    $p = rtrim($cur, '/') . '/' . $hint;
                    if (is_file($p)) {
                        $metaPath = $p;
                        return true;
                    }
                    $parent = dirname($cur);
                    if ($parent === $cur) break;
                    $cur = $parent;
                }
            }

            // cwd fallback
            $p2 = getcwd() . '/' . $hint;
            if (is_file($p2)) {
                $metaPath = $p2;
                return true;
            }

            return false;
        };

        foreach ($candidates as $rel) {
            if ($tryResolve($rel)) break;
        }
        if (!$metaPath) {
            return [null, "[UNKNOWN] Yanked metadata not found; tried: " . implode(' | ', $tried)];
        }

        // 2) Load JSON (accept container form { "yanked": [...] })
        $raw = $this->collectors->files->read($metaPath);
        if ($raw === false) {
            if ($openedZip instanceof \ZipArchive) @$openedZip->close();
            return [null, "[UNKNOWN] Failed to read yanked metadata at " . $metaPath];
        }
        $j = json_decode($raw, true);

        if (!is_array($j)) {
            if ($openedZip instanceof \ZipArchive) @$openedZip->close();
            return [null, "[UNKNOWN] Invalid yanked metadata JSON (not an array/object) at " . $metaPath];
        }

        // Support container shape: { "yanked": [...] }
        $payload = $j;
        if (array_key_exists('yanked', $j)) {
            // If the key exists but is not an array, treat as invalid
            if (!is_array($j['yanked'])) {
                if ($openedZip instanceof \ZipArchive) @$openedZip->close();
                return [null, "[UNKNOWN] Invalid yanked metadata JSON ('yanked' is not an array) at " . $metaPath];
            }
            // Empty yanked array => PASS (your requested behavior)
            if ($j['yanked'] === []) {
                if ($openedZip instanceof \ZipArchive) @$openedZip->close();
                return [true, "No yanked entries (empty list) (meta: {$metaPath})"];
            }
            $payload = $j['yanked'];
        }

        // 3) Normalize to map: name => set of yanked versions
        $isAssoc = static function (array $a): bool {
            return array_keys($a) !== range(0, count($a) - 1);
        };

        $yanked = []; // name => [ver => true]
        if ($isAssoc($payload)) {
            // Map form: { "vendor/pkg": ["1.2.3", ...], ... }
            foreach ($payload as $pkg => $vers) {
                if (!is_string($pkg) || !is_array($vers)) continue;
                foreach ($vers as $v) {
                    if (!is_string($v) || $v === '') continue;
                    $yanked[$pkg][ltrim($v, 'vV')] = true;
                }
            }
        } else {
            // List form: [ {"package":"vendor/pkg","versions":[...]}, ... ]
            foreach ($payload as $row) {
                if (!is_array($row)) continue;
                $pkg  = $row['package']  ?? null;
                $vers = $row['versions'] ?? null;
                if (!is_string($pkg) || !is_array($vers)) continue;
                foreach ($vers as $v) {
                    if (!is_string($v) || $v === '') continue;
                    $yanked[$pkg][ltrim($v, 'vV')] = true;
                }
            }
        }

        if ($openedZip instanceof \ZipArchive) {
            @$openedZip->close();
        }

        // Nếu vẫn không có entry sau khi normalize → coi như “không có yanked” → PASS
        if (!$yanked) {
            return [true, "No yanked entries (normalized empty) (meta: {$metaPath})"];
        }

        // 4) Match against installed
        $hits = [];
        foreach ($installedVers as $name => $ver) {
            if (isset($yanked[$name][$ver])) {
                $hits[] = "{$name} {$ver}";
            }
        }

        if ($hits) {
            return [false, "Yanked versions installed:\n    - "
                . implode("\n    - ", $hits) . "\n    Metadata: {$metaPath}"];
        }
        return [true, "No yanked versions installed (meta: {$metaPath})"];
    }

    public function yankedApi(array $args): array
    {
        // These compatibility predicates assess locked build declarations, not installed runtime bytes.
        $selection=$this->dependencySelection(array_replace($args,['dependency_scope'=>'locked']));
        return $this->withDependencyProvenance($this->yankedApiLocked($args),$selection);
    }

    private function yankedApiLocked(array $args): array
    {
        if (($problem = $this->strictInventoryProblem($args, false)) !== null) return $problem;
        $lockFile = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        if (!is_file($lockFile)) {
            return [null, '[UNKNOWN] composer.lock not found'];
        }

        $installed = $this->readLockPackages($lockFile);
        if (!is_array($installed) || $installed === []) {
            return [null, '[UNKNOWN] Unable to parse composer.lock'];
        }

        $packages = [];
        foreach ($installed as $name => $info) {
            $version = ltrim((string)($info['version'] ?? ''), 'vV');
            if ($version !== '') {
                $packages[] = ['name' => (string)$name, 'version' => $version];
            }
        }
        if ($packages === []) {
            return [true, 'No packages in composer.lock (nothing to check)'];
        }

        [$ok, $message, $statuses] = $this->fetchPackageStatuses($args, $packages);
        if (!$ok) {
            return [null, '[UNKNOWN] Package status API request failed: ' . $message];
        }

        if (!empty($args['strict_scope'])) return $this->assessCompleteYankedStatuses($packages, $statuses);

        $hits = array_values(array_filter(
            $statuses,
            static fn(array $status): bool => !empty($status['yanked'])
        ));
        $evidence = [
            'packages_checked' => count($packages),
            'yanked_packages' => $hits,
        ];
        if ($hits === []) {
            return [
                true,
                'No installed package versions are yanked or withdrawn',
                $evidence,
            ];
        }

        $visible = $hits;
        $text = array_map(
            static fn(array $status): string => (string)($status['name'] ?? 'unknown-package')
                . '@' . (string)($status['installed'] ?? 'unknown-version'),
            $visible
        );
        $resultMessage = "Yanked or withdrawn package versions installed:\n    - "
            . implode("\n    - ", $text);
        return [false, $resultMessage, $evidence];
    }

    private function assessCompleteYankedStatuses(array $packages, array $statuses): array
    {
        $hits = []; $unknown = [];
        foreach ($packages as $package) {
            $name = strtolower((string)$package['name']);
            $status = $statuses[$name] ?? null;
            if (!is_array($status)
                || !is_bool($status['yanked'] ?? null)
                || (array_key_exists('yanked_status_known', $status) && $status['yanked_status_known'] !== true)
                || !is_string($status['installed'] ?? null)
                || ltrim($status['installed'], 'vV') !== ltrim((string)$package['version'], 'vV')) {
                $unknown[] = $package;
                continue;
            }
            if ($status['yanked']) $hits[] = ['name' => $name, 'installed' => $package['version']];
        }
        $evidence = ['packages_checked' => count($packages), 'yanked_packages' => $hits, 'packages_unknown' => $unknown];
        if ($hits !== []) return [false, 'Installed package versions explicitly marked yanked or withdrawn by package-status source', $evidence];
        if ($unknown !== []) return [null, '[UNKNOWN] Package-status source did not assess every requested version for withdrawal status', $evidence];
        return [true, 'All requested installed package versions explicitly have non-withdrawn status', $evidence];
    }
    public function marketplaceOutdatedApi(array $args): array
    {
        // These compatibility predicates assess locked build declarations, not installed runtime bytes.
        $selection=$this->dependencySelection(array_replace($args,['dependency_scope'=>'locked']));
        return $this->withDependencyProvenance($this->marketplaceOutdatedApiLocked($args),$selection);
    }

    private function marketplaceOutdatedApiLocked(array $args): array
    {
        $lockFile = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        if (!is_file($lockFile)) {
            return [null, '[UNKNOWN] composer.lock not found'];
        }

        $lock = json_decode((string)$this->collectors->files->read($lockFile), true);
        if (!is_array($lock)) {
            return [null, '[UNKNOWN] Unable to parse composer.lock'];
        }

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
                ['packages_checked' => 0, 'scope' => 'non-core magento2-module packages'],
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

        $maxAgeDays = max(1, (int)($args['max_age_days'] ?? 365));
        $now = time();
        $findings = [];
        $unassessed = [];
        $unclassified = [];
        $excluded = [];
        $assessed = [];

        foreach ($packages as $package) {
            $name = $package['name'];
            $status = $statuses[$name] ?? null;
            if (!is_array($status) || empty($status['classification_known'])) {
                $unclassified[] = $package;
                continue;
            }
            if (empty($status['marketplace'])) {
                $excluded[] = [
                    'name' => $name,
                    'version' => $package['version'],
                    'category' => $status['category'] ?? 'other',
                ];
                continue;
            }
            if (empty($status['known'])) {
                $unassessed[] = $package;
                continue;
            }

            $latestDate = is_string($status['latest_date'] ?? null)
                ? trim($status['latest_date'])
                : '';
            $latestTimestamp = $latestDate !== '' ? strtotime($latestDate) : false;
            $ageDays = $latestTimestamp !== false
                ? max(0, (int)floor(($now - $latestTimestamp) / 86400))
                : null;
            $outdated = !empty($status['outdated']);
            $stale = $ageDays !== null && $ageDays > $maxAgeDays;

            $item = $status;
            $item['age_days'] = $ageDays;
            $item['stale'] = $stale;
            $assessed[] = $item;
            if ($outdated || $stale) {
                $findings[] = $item;
            }
        }

        $evidence = [
            'scope' => 'API-classified Marketplace magento2-module packages',
            'max_age_days' => $maxAgeDays,
            'packages_checked' => count($packages),
            'packages_excluded_by_category' => $excluded,
            'packages_unclassified' => $unclassified,
            'packages_assessed' => count($assessed),
            'packages_unassessed' => $unassessed,
            'findings' => $findings,
        ];

        if ($findings !== []) {
            $visible = $findings;
            $details = array_map(static function (array $status) use ($maxAgeDays): string {
                $name = (string)($status['name'] ?? 'unknown-package');
                $reasons = [];
                if (!empty($status['outdated'])) {
                    $reasons[] = (string)($status['installed'] ?? '?')
                        . ' < ' . (string)($status['latest'] ?? '?');
                }
                if (!empty($status['stale'])) {
                    $reasons[] = 'latest release is '
                        . (string)($status['age_days'] ?? '?')
                        . ' days old (limit ' . $maxAgeDays . ')';
                }
                return $name . ' [' . implode('; ', $reasons) . ']';
            }, $visible);

            $resultMessage = "Third-party Magento modules require maintenance:\n    - "
                . implode("\n    - ", $details);
            if ($unassessed !== []) {
                $unassessedDetails = array_map(
                    static fn(array $package): string => $package['name'] . '@' . $package['version'],
                    $unassessed
                );
                $resultMessage .= "\n    Release metadata unavailable for:\n    - "
                    . implode("\n    - ", $unassessedDetails);
            }
            if ($unclassified !== []) {
                $unclassifiedDetails = array_map(
                    static fn(array $package): string => $package['name'] . '@' . $package['version'],
                    $unclassified
                );
                $resultMessage .= "\n    Marketplace classification unavailable for:\n    - "
                    . implode("\n    - ", $unclassifiedDetails);
            }
            return [false, $resultMessage, $evidence];
        }

        if ($unassessed !== [] || $unclassified !== []) {
            $names = array_map(
                static fn(array $package): string => $package['name'] . '@' . $package['version'],
                array_merge($unassessed, $unclassified)
            );
            $resultMessage = "[UNKNOWN] Marketplace classification or release metadata unavailable for:\n    - "
                . implode("\n    - ", $names);
            return [null, $resultMessage, $evidence];
        }

        if ($assessed === []) {
            return [
                true,
                'No API-classified Marketplace extensions found in composer.lock',
                $evidence,
            ];
        }

        return [
            true,
            'Third-party Magento modules are current and have a release within the freshness window',
            $evidence,
        ];
    }

    public function directOutdatedApi(array $args): array
    {
        // These compatibility predicates assess locked build declarations, not installed runtime bytes.
        $selection=$this->dependencySelection(array_replace($args,['dependency_scope'=>'locked']));
        return $this->withDependencyProvenance($this->directOutdatedApiLocked($args),$selection);
    }

    private function directOutdatedApiLocked(array $args): array
    {
        if (($problem = $this->strictInventoryProblem($args, true)) !== null) return $problem;
        $lockFile = $this->ctx->abs($args['lock_file'] ?? 'composer.lock');
        $jsonFile = $this->ctx->abs($args['json_file'] ?? 'composer.json');
        if (!is_file($lockFile)) {
            return [null, '[UNKNOWN] composer.lock not found'];
        }
        if (!is_file($jsonFile)) {
            return [null, '[UNKNOWN] composer.json not found'];
        }

        $installed = $this->readLockPackages($lockFile);
        if (!is_array($installed) || $installed === []) {
            return [null, '[UNKNOWN] Unable to parse composer.lock'];
        }
        $composer = json_decode((string)$this->collectors->files->read($jsonFile), true);
        if (!is_array($composer)) {
            return [null, '[UNKNOWN] Unable to parse composer.json'];
        }

        $sections = ['require'];
        if (!array_key_exists('include_dev', $args) || !empty($args['include_dev'])) {
            $sections[] = 'require-dev';
        }
        $direct = [];
        foreach ($sections as $section) {
            foreach ((array)($composer[$section] ?? []) as $name => $constraint) {
                $name = strtolower(trim((string)$name));
                if ($name === ''
                    || $name === 'php'
                    || str_starts_with($name, 'ext-')
                    || str_starts_with($name, 'lib-')
                    || in_array($name, ['composer-plugin-api', 'composer-runtime-api'], true)
                ) {
                    continue;
                }
                $direct[$name] = [
                    'name' => $name,
                    'constraint' => (string)$constraint,
                    'section' => $section,
                ];
            }
        }

        if ($direct === []) {
            return [
                true,
                'No direct Composer package dependencies found',
                ['sections' => $sections, 'direct_dependencies' => []],
            ];
        }

        $packages = [];
        $unknown = [];
        foreach ($direct as $name => $dependency) {
            $info = $installed[$name] ?? null;
            $version = is_array($info) ? trim((string)($info['version'] ?? '')) : '';
            if ($version === '') {
                $unknown[] = $dependency + ['reason' => 'not_present_in_composer_lock'];
                continue;
            }
            $packages[] = [
                'name' => $name,
                'version' => ltrim($version, 'vV'),
            ];
        }

        if ($packages === []) {
            return [
                null,
                '[UNKNOWN] No direct dependencies could be resolved from composer.lock',
                ['sections' => $sections, 'direct_dependencies' => array_values($direct), 'unknown' => $unknown],
            ];
        }

        [$ok, $apiMessage, $statuses] = $this->fetchPackageStatuses($args, $packages);
        if (!$ok) {
            return [
                null,
                '[UNKNOWN] Package status API request failed: ' . $apiMessage,
                $this->packageStatusApiFailureEvidence($packages, [
                    'unresolved_direct_dependencies' => count($unknown),
                ]),
            ];
        }

        $findings = [];
        $current = [];
        foreach ($packages as $package) {
            $status = $statuses[$package['name']] ?? null;
            $dependency = $direct[$package['name']];
            if (!is_array($status)) {
                $unknown[] = $dependency + [
                    'installed' => $package['version'],
                    'reason' => 'missing_status',
                ];
                continue;
            }
            if (empty($status['release_history_known'])) {
                $unknown[] = $dependency + [
                    'installed' => $package['version'],
                    'reason' => 'release_history_unavailable',
                ];
                continue;
            }
            $latest = is_string($status['latest'] ?? null) ? trim($status['latest']) : '';
            if ($latest === '') {
                $unknown[] = $dependency + [
                    'installed' => $package['version'],
                    'reason' => 'latest_stable_version_unavailable',
                ];
                continue;
            }

            $item = $dependency + [
                'installed' => $package['version'],
                'latest' => $latest,
                'latest_date' => is_string($status['latest_date'] ?? null)
                    ? $status['latest_date']
                    : null,
            ];
            if (!empty($status['outdated'])
                || version_compare($package['version'], ltrim($latest, 'vV'), '<')
            ) {
                $findings[] = $item;
            } else {
                $current[] = $item;
            }
        }

        $evidence = [
            'scope' => $sections,
            'direct_dependencies' => array_values($direct),
            'packages_assessed' => count($current) + count($findings),
            'packages_current' => $current,
            'packages_outdated' => $findings,
            'packages_unknown' => $unknown,
        ];

        if ($findings !== []) {
            $details = array_map(
                static fn(array $item): string => $item['section'] . ': '
                    . $item['name'] . '@' . $item['installed']
                    . ' -> latest ' . $item['latest']
                    . ' (constraint ' . $item['constraint'] . ')',
                $findings
            );
            $resultMessage = "Outdated direct dependencies:\n    - " . implode("\n    - ", $details);
            if ($unknown !== []) {
                $unknownDetails = array_map(static function (array $item): string {
                    $installed = isset($item['installed']) ? '@' . $item['installed'] : '';
                    return $item['section'] . ': ' . $item['name'] . $installed
                        . ' (' . $item['reason'] . ')';
                }, $unknown);
                $resultMessage .= "\n    Direct dependency status unavailable for:\n    - "
                    . implode("\n    - ", $unknownDetails);
            }
            return [false, $resultMessage, $evidence];
        }

        if ($unknown !== []) {
            $details = array_map(static function (array $item): string {
                $installed = isset($item['installed']) ? '@' . $item['installed'] : '';
                return $item['section'] . ': ' . $item['name'] . $installed
                    . ' (' . $item['reason'] . ')';
            }, $unknown);
            return [
                null,
                "[UNKNOWN] Direct dependency status unavailable for:\n    - "
                    . implode("\n    - ", $details),
                $evidence,
            ];
        }

        return [
            true,
            'All ' . count($current) . ' direct dependencies use the latest stable release',
            $evidence,
        ];
    }

    public function outdatedOffline(array $args): array
    {
        // 0) Load composer.lock
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

        // 1) Resolve bundle root (zip/dir/file-inside-bundle)
        $candidates = [];
        if (!empty($args['release_meta'])) $candidates[] = (string)$args['release_meta']; // optional direct hint
        if (!empty($args['cve_data']))     $candidates[] = (string)$args['cve_data'];
        if (!empty($this->ctx->cveData))   $candidates[] = (string)$this->ctx->cveData;
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
            return [null, "[UNKNOWN] Release metadata not found; bundle root unresolved; tried: " . $msg];
        }

        // 2) Load DATA/release-history.json (fallback rules/)
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

        $rawRelease = $loadText('release-history.json') ?? $loadText('rules/release-history.json');
        if ($rawRelease === null) {
            return [null, "[UNKNOWN] Release metadata not found (DATA/release-history.json)"];
        }

        $jRelease = json_decode($rawRelease, true);
        if (!is_array($jRelease)) {
            return [null, "[UNKNOWN] Invalid release-history.json (not JSON object/array)"];
        }

        // 3) Normalize → latestStable['vendor/pkg'] = 'x.y.z[-pN]'
        $latestStable = [];
        $isAssoc = static function (array $a): bool {
            return array_keys($a) !== range(0, count($a) - 1);
        };
        $isStable = static function (string $v): bool {
            if (stripos($v, 'dev') !== false) return false;
            return !preg_match('/(?:alpha|beta|rc)\d*$/i', $v);
        };

        // Hỗ trợ container { "packages": [...] }
        $payload = isset($jRelease['packages']) && is_array($jRelease['packages']) ? $jRelease['packages'] : $jRelease;

        if ($isAssoc($payload)) {
            // Map: "pkg" => [ ... ]  hoặc  "pkg" => { "versions":[...] }
            foreach ($payload as $pkg => $row) {
                $versions = [];
                if (is_array($row)) {
                    if (isset($row['versions']) && is_array($row['versions'])) {
                        $versions = $row['versions'];
                    } else {
                        $versions = $row; // có thể đã là list versions
                    }
                }
                $versions = array_values(array_filter(array_map(fn($v) => is_string($v) ? ltrim($v, 'vV') : '', $versions), fn($v) => $v !== ''));
                if (!$versions) continue;
                $versions = array_values(array_filter($versions, $isStable));
                if (!$versions) continue;
                usort($versions, fn($a, $b) => version_compare($b, $a)); // desc
                $latestStable[$pkg] = $versions[0];
            }
        } else {
            // List: [{"package":"pkg","versions":[...]}]
            foreach ($payload as $row) {
                if (!is_array($row)) continue;
                $pkg = $row['package'] ?? null;
                $versions = $row['versions'] ?? null;
                if (!is_string($pkg) || !is_array($versions)) continue;
                $versions = array_values(array_filter(array_map(fn($v) => is_string($v) ? ltrim($v, 'vV') : '', $versions), fn($v) => $v !== ''));
                if (!$versions) continue;
                $versions = array_values(array_filter($versions, $isStable));
                if (!$versions) continue;
                usort($versions, fn($a, $b) => version_compare($b, $a)); // desc
                $latestStable[$pkg] = $versions[0];
            }
        }

        if (!$latestStable) {
            return [true, "No latest versions resolvable from release-history.json (empty after normalize)"];
        }

        // 4) Compare installed vs latest
        $outdated = [];
        foreach ($installed as $pkg => $cur) {
            if (!isset($latestStable[$pkg])) continue;
            $latest = $latestStable[$pkg];
            if (version_compare($cur, $latest, '<')) {
                $outdated[] = "{$pkg} {$cur} -> < {$latest}";
            }
        }

        if ($outdated) {
            // In nhiều dòng cho dễ đọc
            $lines = array_map(static fn($s) => ' - ' . $s, $outdated);
            return [false, "Outdated packages (offline):\n" . implode(PHP_EOL, $lines)];
        }
        return [true, "All installed packages are up-to-date against release-history.json"];
    }
}
