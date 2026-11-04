<?php
declare(strict_types=1);
namespace Magebean\Engine;
use Magebean\Engine\Checks\CheckRegistry;

/** Selection policies for resolved scan targets. No console or transport dependency. */
final class LegacyScanPlanner
{
    /** Diagnostics contain plain segments; presentation belongs to adapters.
     * @param callable(ScanDiagnostic):void|null $diagnostic
     * A null plan represents a diagnosed selection failure; loader errors still throw.
     */
    public function planCli(ScanRequest $request, CheckRegistry $registry, ?callable $diagnostic = null): ?ScanPlan
    {
        $diagnostic ??= static function (ScanDiagnostic $diagnostic): void {};
        $projectPath = $request->context->path;
        $targetMode = (string)($request->context->get('meta', [])['target_mode'] ?? 'LOCAL');
        $options = $request->options;
        $standard = strtolower((string)($options['standard'] ?? 'magebean'));
        $profileOpt = trim((string)($options['profile'] ?? ''));
        if (in_array(strtolower($profileOpt), ['baseline', 'all', 'magebean', 'external'], true) && !is_file(ProjectPath::resolve($profileOpt, $targetMode === 'REMOTE' ? (string)getcwd() : $projectPath))) {
            throw new \RuntimeException('Unknown internal requirement profile: ' . $profileOpt);
        }
        $rulesOpt = (string)($options['rules'] ?? '');
        $excludeRulesOpt = (string)($options['exclude-rules'] ?? '');
        $controlsOpt = (string)($options['controls'] ?? '');
        $configOpt = trim((string)($options['config'] ?? ''));
        $capabilitiesOpt = trim((string)($options['capabilities'] ?? ''));
        $includeManualReview = (bool)($options['include-manual-review'] ?? false);
        $pciContextOpt = trim((string)($options['pci-context'] ?? ''));
        $pciEvidenceOpt = trim((string)($options['pci-evidence'] ?? ''));
        $pciReportOpt = trim((string)($options['pci-report'] ?? ''));
        $configBasePath = $targetMode === 'REMOTE' ? (string)getcwd() : $projectPath;
        $configFile = $configOpt !== ''
            ? ProjectPath::normalize(ProjectPath::resolve($configOpt, $configBasePath))
            : ($targetMode === 'REMOTE' ? null : ProjectConfigLoader::discover($projectPath));
        $projectConfig = ProjectConfigLoader::load($configFile);
        if ($configFile !== null) {
            $diagnostic(new ScanDiagnostic('info', 'Loaded Magebean project config:', ' ' . $configFile));
        }
        $capabilities = is_array($projectConfig['capabilities'] ?? null) ? $projectConfig['capabilities'] : [];
        if ($capabilitiesOpt !== '') {
            foreach (array_filter(array_map('trim', explode(',', $capabilitiesOpt))) as $capability) {
                $capabilities[strtolower($capability)] = true;
            }
        }

        // normalize controls filter
        $controlsFilter = $this->normalizeControlList($projectConfig['include_controls'] ?? []);
        if ($controlsOpt !== '') {
            $controlsFilter = $this->normalizeControlList($controlsOpt);
        }

        $pack = $targetMode === 'REMOTE'
            ? RulePackLoader::loadExternalMagento($controlsFilter)
            : RulePackLoader::loadAll($controlsFilter);

        if ($controlsFilter) {
            $loaded = $pack['controls'] ?? [];
            $missing = array_values(array_diff($controlsFilter, $loaded));
            if ($missing) {
                $message = $targetMode === 'REMOTE'
                    ? 'Control(s) not supported in REMOTE mode: '
                    : 'Control file(s) not found: ';
                $diagnostic(new ScanDiagnostic('error', $message . implode(', ', $missing)));
                return null;
            }
        }

        $pack = RulePackMerger::applyProjectConfig($pack, LegacyAsvsRequirementPolicy::evidenceConfig($projectConfig));

        $activeProfile = [
                'id' => 'basic',
                'title' => 'Magebean Basic',
                'description' => 'Selected deployment security checks.',
                'report_template' => 'standard',
                '_source' => 'builtin:basic',
            ];
        $hasExplicitRuleSelection = trim($rulesOpt) !== '';
        if ($hasExplicitRuleSelection) {
            $standard = 'explicit-rules';
            $activeProfile['id'] = 'explicit-rules';
            $activeProfile['title'] = 'Explicit Rule Selection';
            $activeProfile['description'] = 'Rules explicitly selected from the available catalog with --rules.';
            $activeProfile['_source'] = 'cli:--rules';
            $diagnostic(new ScanDiagnostic('info', 'Profile selection bypassed:', ' explicit --rules selection'));
        } else {
            if ($profileOpt === '') {
                $profileOpt = in_array($standard, ['owasp', 'pci'], true) ? $standard : 'basic';
            }
            if ($profileOpt !== '') {
                $profileBasePath = $targetMode === 'REMOTE' ? (string)getcwd() : $projectPath;
                $profile = ProfileLoader::load($profileOpt, $profileBasePath);
                $profileCanBePartial = $targetMode === 'REMOTE'
                    || $controlsFilter !== [] || $projectConfig !== [];
                $pack = ProfileLoader::apply($pack, $profile, $profileCanBePartial, $capabilities);
                $pack = LegacyAsvsRequirementAdapter::compile($pack, $profile, $capabilities, $targetMode === 'REMOTE' || $controlsFilter !== [] || !empty(LegacyAsvsRequirementPolicy::evidenceConfig($projectConfig)['include_rules']) || !empty(LegacyAsvsRequirementPolicy::evidenceConfig($projectConfig)['select_rules']) || !empty(LegacyAsvsRequirementPolicy::evidenceConfig($projectConfig)['exclude_rules']) || !empty($projectConfig['exclude_controls']));
                $activeProfile = ProfileLoader::publicMetadata($profile);
                $standard = (string)($activeProfile['id'] ?? $standard);
                $diagnostic(new ScanDiagnostic('info', 'Loaded profile:', ' ' . (string)($activeProfile['id'] ?? $profileOpt)));
            }
        }

        if ($hasExplicitRuleSelection && stripos($rulesOpt, 'OWASP-ASVS:') !== false) {
            if ($profileOpt === '') throw new \RuntimeException('Canonical ASVS IDs require --profile=asvs-l1/l2/l3 for assessment-level context.');
            $requirementProfile = ProfileLoader::load($profileOpt, $configBasePath);
            if (!LegacyAsvsRequirementAdapter::supports($requirementProfile)) throw new \RuntimeException('Canonical ASVS IDs require an ASVS --profile for assessment-level context.');
            $activeProfile = ProfileLoader::publicMetadata($requirementProfile);
            $standard = (string)$activeProfile['id'];
            $canonical = LegacyAsvsRequirementAdapter::compile(ProfileLoader::apply($pack, $requirementProfile, $targetMode === 'REMOTE' || $controlsFilter !== [] || $projectConfig !== [], $capabilities), $requirementProfile, $capabilities, $targetMode === 'REMOTE' || $controlsFilter !== []);
            if (LegacyAsvsRequirementPolicy::hasCanonical($projectConfig)) $canonical = LegacyAsvsRequirementPolicy::apply($canonical, $projectConfig);
            $pack['rules'] = array_merge($pack['rules'], $canonical['rules']);
        }

        if (!$hasExplicitRuleSelection) $pack = LegacyAsvsRequirementPolicy::apply($pack, $projectConfig);

        $activeProfileId = strtolower((string)($activeProfile['id'] ?? ''));
        $isPciProfile = $standard === 'pci' || str_starts_with($activeProfileId, 'pci-dss');
        if (!$isPciProfile && ($pciContextOpt !== '' || $pciEvidenceOpt !== '' || $pciReportOpt !== '')) {
            throw new \RuntimeException('--pci-context, --pci-evidence, and --pci-report require the PCI profile.');
        }
        $profileRulesTotal = count($pack['rules'] ?? []);
        $profileManualRulesTotal = count(array_filter($pack['rules'] ?? [], static fn(array $rule): bool => strtolower((string)($rule['verification'] ?? 'automated')) === 'manual'));
        $manualRulesExcluded = 0;
        if (!$hasExplicitRuleSelection && !$includeManualReview) {
            $beforeManualFilter = count($pack['rules'] ?? []);
            $pack['rules'] = array_values(array_filter(
                $pack['rules'] ?? [],
                static fn(array $rule): bool => strtolower((string)($rule['verification'] ?? 'automated')) !== 'manual'
            ));
            $manualRulesExcluded = $beforeManualFilter - count($pack['rules']);

        }

        foreach ($pack['rules'] ?? [] as $rule) {
            $id = (string) ($rule['id'] ?? '');
            if (preg_match('/^MB-[0-9]{4,}$/D', $id)) MagebeanRetirement::reject($id);
            if (($rule['family'] ?? null) === 'magebean' && RequirementPolicy::requiresHuman($rule)) {
                throw new \RuntimeException('Active Magebean selections cannot require human evidence: '.$id);
            }
        }

        // filter by --rules (comma-separated IDs)
        $requestedIds = [];
        if ($rulesOpt !== '') {
            $requestedIds = array_values(array_unique(array_filter(array_map('trim', explode(',', $rulesOpt)))));
            if ($requestedIds) {
                $byId = [];
                foreach ($pack['rules'] as $r) {
                    $byId[strtoupper((string)($r['id'] ?? ''))] = $r;
                }
                $selected = [];
                $selectedRequirements = [];
                $unknown  = [];
                foreach ($requestedIds as $id) {
                    $key = strtoupper($id);
                    if (isset($byId[$key])) {
                        if (str_starts_with($key, 'OWASP-ASVS:')) {
                            if (isset($selectedRequirements[$key])) continue;
                            $selectedRequirements[$key] = true;
                        }
                        $selected[] = $byId[$key];
                    }
                    else $unknown[] = $id;
                }
                foreach ($unknown as $id) {
                    $label = $targetMode === 'REMOTE'
                        ? 'Rule not supported in REMOTE mode:'
                        : 'Unknown rule id:';
                    $diagnostic(new ScanDiagnostic('comment', $label, ' ' . $id));
                }
                if ($selected) {
                    // giữ nguyên controls pack để render/summary, nhưng thay tập rules đã chọn
                    $pack['rules'] = $selected;
                } else {
                    $diagnostic(new ScanDiagnostic('error', 'No valid rules matched the --rules filter.'));
                    return null;
                }
            }
        }

        if ($excludeRulesOpt !== '') {
            $excludedIds = array_values(array_unique(array_filter(array_map(
                static fn(string $id): string => strtoupper(trim($id)),
                explode(',', $excludeRulesOpt)
            ))));
            if ($excludedIds) {
                $pack['rules'] = array_values(array_filter(
                    $pack['rules'],
                    static fn(array $rule): bool => !in_array(strtoupper((string)($rule['id'] ?? '')), $excludedIds, true) && array_intersect($rule['legacy_rule_ids'] ?? [], $excludedIds) === []
                ));
            }
        }

        if ($hasExplicitRuleSelection) {
            $profileRulesTotal = count($pack['rules'] ?? []);
            $profileManualRulesTotal = count(array_filter(
                $pack['rules'] ?? [],
                static fn(array $rule): bool => strtolower((string)($rule['verification'] ?? 'automated')) === 'manual'
            ));
            $manualRulesExcluded = 0;
        }
        $validationErrors = RuleValidator::validatePack($pack, $registry);
        if ($validationErrors) {
            $diagnostic(new ScanDiagnostic('error', 'Invalid rule pack:'));
            foreach (array_slice($validationErrors, 0, 20) as $error) {
                $diagnostic(new ScanDiagnostic('plain', '  - ' . $error));
            }
            if (count($validationErrors) > 20) {
                $diagnostic(new ScanDiagnostic('plain', sprintf('  - ... and %d more', count($validationErrors) - 20)));
            }
            return null;
        }

        if (empty($pack['rules'])) {
            $diagnostic(new ScanDiagnostic('error', 'No rules found. Check rules directory or control filter.'));
            return null;
        }

        return new ScanPlan($request, $pack, [
            'configBasePath' => $configBasePath,
            'configFile' => $configFile,
            'activeProfile' => $activeProfile,
            'standard' => $standard,
            'isPciProfile' => $isPciProfile,
            'profileRulesTotal' => $profileRulesTotal,
            'profileManualRulesTotal' => $profileManualRulesTotal,
            'manualRulesExcluded' => $manualRulesExcluded,
            'includeManualReview' => $includeManualReview,
            'hasExplicitRuleSelection' => $hasExplicitRuleSelection,
            'requestedIds' => $requestedIds,
            'controlsFilter' => $controlsFilter,
        ]);
    }

    /** Agent policy deliberately uses only the bundled catalog and manifest order. */
    public function planAgent(ScanRequest $request): ScanPlan
    {
        $manifest = $request->options['manifest'] ?? [];
        $schema = (string)($manifest['schema_version'] ?? '');
        if ($schema !== '1.0') throw new \RuntimeException("Unsupported manifest schema version {$schema}.");
        $entries = is_array($manifest['rules'] ?? null) ? $manifest['rules'] : [];
        $manifestIndex = [];
        foreach ($entries as $entry) {
            $key = strtoupper((string)($entry['rule_key'] ?? ''));
            if (str_starts_with($key, 'OWASP-ASVS:') && isset($manifestIndex[$key])) throw new \RuntimeException('Duplicate canonical requirement in manifest.');
            if ($key !== '') $manifestIndex[$key] = $entry;
        }
        $requested = array_keys($manifestIndex);
        if ($requested === []) throw new \RuntimeException('Manifest contains no rule IDs.');
        $all = RulePackLoader::loadAll();
        $index = [];
        foreach ($all['rules'] as $rule) $index[strtoupper((string)($rule['id'] ?? ''))] = $rule;
        $canonicalError = null;
        if (array_filter($requested, static fn(string $id): bool => str_starts_with($id, 'OWASP-ASVS:'))) {
            try {
                $profileName = (string)($manifest['profile'] ?? '');
                if (!in_array(strtolower($profileName), ['asvs-l1', 'asvs-l2', 'asvs-l3'], true)) throw new \RuntimeException('Canonical ASVS manifest requires a bundled ASVS profile context.');
                $profile = ProfileLoader::loadBundled(strtolower($profileName));
                if (!LegacyAsvsRequirementAdapter::supports($profile)) throw new \RuntimeException('Canonical ASVS manifest requires an ASVS profile.');
                $capabilities = is_array($manifest['capabilities'] ?? null) ? $manifest['capabilities'] : [];
                foreach (LegacyAsvsRequirementAdapter::compile(ProfileLoader::apply($all, $profile, false, $capabilities), $profile, $capabilities)['rules'] as $definition) $index[$definition['id']] = $definition;
            } catch (\RuntimeException $error) { $canonicalError = $error->getMessage(); }
        }
        $selected = []; $unsupported = [];
        foreach ($requested as $id) {
            $entry = $manifestIndex[$id];
            $base = ['assessment_item_id' => (string)$entry['assessment_item_id'], 'rule_key' => $id];
            if (!isset($index[$id])) {
                $unsupported[] = $base + ['status' => 'unsupported', 'message' => str_starts_with($id, 'OWASP-ASVS:') ? ($canonicalError ?? 'Requirement is unavailable for the manifest profile/capability context.') : 'Rule is not bundled in this CLI version.'];
                continue;
            }
            $rule = $index[$id];
            // Preserve the existing check-name predicate; changing it is a separate behavior fix.
            $manual = false;
            foreach ($rule['checks'] ?? [] as $check) if (($check['name'] ?? '') === 'manual_review') $manual = true;
            if ($manual) {
                $unsupported[] = $base + ['status' => 'unsupported', 'message' => 'Manual-review rules are not executed by agents.'];
                continue;
            }
            $selected[] = $rule;
        }
        return new ScanPlan($request, ['rules' => $selected], ['manifestIndex' => $manifestIndex, 'unsupported' => $unsupported], true);
    }

    private function normalizeControlId(string $raw): string
    {
        $id = strtoupper(trim($raw));
        if ($id === '') return '';
        if (preg_match('/^MB-C(\d{2})$/', $id, $m)) return 'MB-C' . $m[1];
        if (preg_match('/^MB-(\d{2})$/', $id, $m)) return 'MB-C' . $m[1];
        if (preg_match('/^C(\d{2})$/', $id, $m)) return 'MB-C' . $m[1];
        if (preg_match('/^(\d{2})$/', $id, $m)) return 'MB-C' . $m[1];
        return '';
    }

    private function normalizeControlList(mixed $raw): array
    {
        if (is_string($raw)) {
            $parts = array_map('trim', explode(',', $raw));
        } elseif (is_array($raw)) {
            $parts = $raw;
        } else {
            return [];
        }

        $normalized = [];
        $invalid = [];
        foreach ($parts as $control) {
            if (!is_scalar($control)) {
                $invalid[] = '[non-scalar]';
                continue;
            }
            $control = trim((string)$control);
            if ($control === '') {
                continue;
            }
            $nc = $this->normalizeControlId($control);
            if ($nc === '') {
                $invalid[] = $control;
            } else {
                $normalized[] = $nc;
            }
        }

        if ($invalid) {
            throw new \RuntimeException(
                'Invalid control id(s): ' . implode(', ', $invalid) . "\nExpected format: MB-C01 or MB-01"
            );
        }

        return array_values(array_unique($normalized));
    }





}
