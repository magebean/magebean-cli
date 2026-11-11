<?php
declare(strict_types=1);
namespace Magebean\Engine;
use Magebean\Engine\Checks\CheckRegistry;
use Magebean\Engine\Checks\MagentoModuleIntegrityCheck;

/** Primary selection uses internal identities; legacy execution is an explicit adapter. */
final class ScanPlanner
{
    public function planCli(ScanRequest $request, CheckRegistry $registry, ?callable $diagnostic = null): ?ScanPlan
    {
        $diagnostic ??= static function (ScanDiagnostic $d): void {};
        $options = $request->options;
        $launchProfile = in_array(strtolower(trim((string) ($options['profile'] ?? ''))), ['development', 'prelaunch'], true);
        $requested = self::ids($options['rules'] ?? '');
        $moduleSelection = $options['modules'] ?? null;
        $modules = $moduleSelection === null ? [] : MagentoModuleIntegrityCheck::moduleNames(array_map('trim', explode(',', $moduleSelection)));
        $internal = array_filter($requested, static fn(string $id): bool => (preg_match('/^MB-[0-9]{4,}$/D', $id) === 1));
        if ($modules !== [] && $requested !== [] && $internal === []) throw new \RuntimeException('--modules requires module audit criteria.');
        if ($launchProfile && $requested !== [] && $internal === []) throw new \RuntimeException('Development and prelaunch require canonical Magebean rule IDs.');
        if ($requested !== [] && $internal === []) return (new LegacyScanPlanner())->planCli($request, $registry, $diagnostic);
        foreach ($internal as $id) MagebeanRetirement::reject($id);
        if ($internal !== [] && count($internal) !== count($requested)) throw new \RuntimeException('Select internal requirement IDs separately from deprecated legacy execution IDs.');
        $mode = strtoupper((string)($request->context->get('meta', [])['target_mode'] ?? 'LOCAL'));
        if($mode==='HYBRID')$mode='LOCAL';
        $base = $mode === 'REMOTE' ? (string)getcwd() : $request->context->path;
        $configOpt = trim((string)($options['config'] ?? ''));
        $configFile = $configOpt !== '' ? ProjectPath::normalize(ProjectPath::resolve($configOpt, $base)) : ($mode === 'REMOTE' ? null : ProjectConfigLoader::discover($base));
        $config = ProjectConfigLoader::load($configFile);
        $legacyPolicyIds = self::ids($options['exclude-rules'] ?? '');
        foreach (['include_rules','select_rules','exclude_rules'] as $field) $legacyPolicyIds=array_merge($legacyPolicyIds,self::ids($config[$field]??[]));
        $legacyPolicyIds=array_merge($legacyPolicyIds,array_map('strtoupper',array_keys($config['override_rules']??[])));
        foreach ($legacyPolicyIds as $id) {
            if (preg_match('/^MB-[0-9]{4,}$/D', $id)) MagebeanRetirement::reject($id);
        }
        $usesLegacyPolicy=array_filter($legacyPolicyIds,static fn(string $id):bool=>preg_match('/^MB-R[0-9]+$/D',$id)===1||str_starts_with($id,'OWASP-ASVS:'))!==[];
        if($usesLegacyPolicy){
            if ($launchProfile) throw new \RuntimeException('Development and prelaunch require canonical project policy selectors.');
            if($internal!==[])throw new \RuntimeException('Use internal requirement IDs for policy when selecting internal requirements.');
            $diagnostic(new ScanDiagnostic('comment','Using the deprecated selection-policy compatibility adapter.'));
            if ($modules !== []) throw new \RuntimeException('--modules requires module audit criteria.');
            return (new LegacyScanPlanner())->planCli($request,$registry,$diagnostic);
        }
        // Existing executable custom packs retain their explicit compatibility path.
        if (!empty($config['rules']) || !empty($config['rule_files']) || !empty($config['rule_packs']) || !empty($config['rule_paths'])) {
            if ($launchProfile) throw new \RuntimeException('Development and prelaunch do not execute legacy custom rule packs.');
            if ($internal !== []) throw new \RuntimeException('Legacy project rule packs cannot redefine internal requirements.');
            $diagnostic(new ScanDiagnostic('comment', 'Using the deprecated project-rule compatibility adapter.'));
            if ($modules !== []) throw new \RuntimeException('--modules requires module audit criteria.');
            return (new LegacyScanPlanner())->planCli($request, $registry, $diagnostic);
        }
        $caps = self::normalizeCapabilities($config['capabilities'] ?? []);
        foreach (self::ids($options['capabilities'] ?? '') as $cap) $caps[strtolower($cap)] = true;
        $profile = trim((string)($options['profile'] ?? ''));
        $requestedFamilies=[];
        if($requested!==[]){
            $catalogIndex=array_column(RequirementCatalog::loadAll()['rules'],null,'id');
            foreach($requested as$id)foreach(isset($catalogIndex[$id])?[$id]:RequirementCatalog::resolveAlias($id)as$resolved)if(isset($catalogIndex[$resolved]))$requestedFamilies[$catalogIndex[$resolved]['family']]=true;
            if(count($requestedFamilies)>1)throw new \RuntimeException('Select Magebean, ASVS and PCI requirements in separate scans.');
        }
        if ($profile === '') $profile = $requested !== [] ? match(array_key_first($requestedFamilies)){'asvs'=>'asvs-l3','pci'=>'pci',default=>'basic'} : (in_array(strtolower((string)($options['standard'] ?? '')), ['owasp','pci'], true) ? strtolower($options['standard']) : 'basic');
        if (is_file(ProjectPath::resolve($profile, $base))) $profile = ProjectPath::resolve($profile, $base);
        if(is_file($profile)){$custom=json_decode((string)file_get_contents($profile),true,512,JSON_THROW_ON_ERROR);if(!isset($custom['requirement_ids'])){if($modules!==[])throw new \RuntimeException('--modules requires module audit criteria.');if($internal!==[])throw new \RuntimeException('Internal selections require a primary requirement_ids profile.');$diagnostic(new ScanDiagnostic('comment','Using the deprecated custom-profile compatibility adapter.'));return (new LegacyScanPlanner())->planCli($request,$registry,$diagnostic);}}
        if ($launchProfile && $requested !== []) {
            $members = RequirementProfileCatalog::load($profile)['requirement_ids'];
            if ($outside = array_diff($requested, $members)) {
                throw new \RuntimeException('Rules outside the selected development/prelaunch profile: '.implode(', ', $outside).'. Select those rules without this profile.');
            }
        }
        $pack = RequirementCatalog::forProfile($profile, $caps, $mode);
        $activeProfile = $pack['profile'];
        if($requestedFamilies!==[]&&!isset($requestedFamilies[$activeProfile['family']]))throw new \RuntimeException('Selected requirements do not belong to the profile family; choose a profile from the same source.');
        if($configFile!==null)$diagnostic(new ScanDiagnostic('info','Loaded Magebean project config:',' '.$configFile));
        $diagnostic(new ScanDiagnostic('info','Loaded profile:',' '.(string)($activeProfile['id']??$profile)));
        $profileInventoryCount=$pack['inventory_count'];$omittedRequirements=$pack['omitted_requirements']??[];
        $controls = $this->normalizeControlList($options['controls'] ?? ($config['include_controls'] ?? []));
        if ($controls !== []) {
            $known = RequirementCatalog::loadAll()['controls'];
            if ($missing = array_diff($controls, $known)) throw new \RuntimeException('Unknown control(s): ' . implode(', ', $missing));
            $pack['rules'] = array_values(array_filter($pack['rules'], static fn(array $r): bool => RequirementCatalog::matchesControls($r,$controls)));
        }
        $pack = RequirementPolicy::apply($pack, $config);
        $total = count($pack['rules']);
        $manualTotal = count(array_filter($pack['rules'], static fn(array $r): bool => RequirementPolicy::requiresHuman($r)));
        $includeManual = (bool)($options['include-manual-review'] ?? false);
        $hidden = 0;
        if ($requested === [] && !$includeManual) {
            $pack['rules'] = array_values(array_filter($pack['rules'], static fn(array $r): bool => !RequirementPolicy::requiresHuman($r)));
            $hidden = $total - count($pack['rules']);
        }
        if ($requested !== []) {
            // Explicit internal selectors use the full catalog, independent of profile membership.
            $all = RequirementCatalog::loadAll($controls);
            $index = array_column($all['rules'], null, 'id');
            $selected = [];
            $selectedIds=[];
            foreach ($requested as $requestedId) {
                $canonicalIds=isset($index[$requestedId])?[$requestedId]:RequirementCatalog::resolveAlias($requestedId);
                if(count($canonicalIds)!==1){$diagnostic(new ScanDiagnostic('comment','Unknown or ambiguous requirement:',' '.$requestedId));continue;}
                $id=$canonicalIds[0];
                if (!isset($index[$id]) || !in_array($mode, $index[$id]['target_modes'], true)) {
                    $diagnostic(new ScanDiagnostic('comment', 'Unknown or unavailable requirement:', ' ' . $requestedId));
                    continue;
                }
                if(isset($selectedIds[$id]))continue;
                $selectedIds[$id]=true;$r = $index[$id];
                if (isset($pack['assessment_level'])) $r['assessment_level'] = $pack['assessment_level'];
                $selected[] = $r;
            }
            $all['rules'] = $selected;
            $all['profile'] = $pack['profile'];
            $all['assessment_level'] = $pack['assessment_level'] ?? null;
            $pack = RequirementPolicy::apply($all, $config);
            $selected = $pack['rules'];
            $total = count($selected);
            $manualTotal = count(array_filter($selected, static fn(array $r): bool => RequirementPolicy::requiresHuman($r)));
        }
        $excluded = RequirementPolicy::resolveIds(self::ids($options['exclude-rules'] ?? ''), $activeProfile['id'] ?? null);
        $pack['rules'] = array_values(array_filter($pack['rules'], static fn(array $r): bool => !in_array($r['id'], $excluded, true)));
        foreach ($pack['rules'] as &$definition) {
            if (isset($definition['execution_variants'][$mode]['obligations'])) {
                $definition['obligations'] = $definition['execution_variants'][$mode]['obligations'];
                $definition['checks'] = array_merge(...array_map(static fn(array $o): array => $o['checks'], $definition['obligations']));
                $definition['execution_scope'] = $mode;
            }
            if (isset($definition['applicability']['capability'])) {
                $cap = $definition['applicability']['capability'];
                $enabled = array_is_list($caps) ? in_array($cap, $caps, true) : filter_var($caps[$cap] ?? false, FILTER_VALIDATE_BOOLEAN);
                $definition['applicability']['state'] = $enabled ? 'APPLICABLE' : 'UNKNOWN';
            }
        }
        unset($definition);
        if ($modules !== []) {
            $matched = false;
            foreach ($pack['rules'] as &$definition) {
                $matched = self::applyModules($definition, $modules) || $matched;
            }
            unset($definition);
            if (!$matched) throw new \RuntimeException('--modules requires module audit criteria.');
        }
        $pack['controls'] = RequirementCatalog::controlIds($pack['rules']);
        $errors = RuleValidator::validatePack($pack, $registry);
        if ($errors !== []) {
            foreach (array_slice($errors, 0, 20) as $error) $diagnostic(new ScanDiagnostic('error', $error));
            return null;
        }
        if ($pack['rules'] === []) { $diagnostic(new ScanDiagnostic('error', 'No requirements matched the selection.')); return null; }
        $standard = (string)$activeProfile['id'];
        $pci = $standard === 'pci' || str_starts_with($standard, 'pci-dss');
        if (!$pci && (!empty($options['pci-context']) || !empty($options['pci-evidence']) || !empty($options['pci-report']))) throw new \RuntimeException('--pci-context, --pci-evidence, and --pci-report require the PCI profile.');
        return new ScanPlan($request, $pack, [
            'configBasePath'=>$base,'configFile'=>$configFile,'activeProfile'=>$activeProfile,'standard'=>$standard,'isPciProfile'=>$pci,
            'profileRulesTotal'=>$total,'profileManualRulesTotal'=>$manualTotal,'manualRulesExcluded'=>$hidden,
            'includeManualReview'=>$includeManual,'hasExplicitRuleSelection'=>$requested!==[],'requestedIds'=>$requested,'controlsFilter'=>$controls,
            'automationOnly'=>(($activeProfile['automation_only']??false)===true || (!$includeManual && $pack['rules']!==[] && array_filter($pack['rules'],[RequirementPolicy::class,'requiresHuman'])===[])),'capabilities'=>$caps,'profile_selector'=>$profile,'assessment_model'=>'internal-requirement-v1','profileInventoryCount'=>$profileInventoryCount,'omittedRequirements'=>$omittedRequirements,
        ]);
    }

    /** Dashboard manifest cardinality and keys are preserved, including legacy requests. */
    public function planAgent(ScanRequest $request): ScanPlan
    {
        $manifest = $request->options['manifest'] ?? [];
        if (isset($manifest['rules']) && (!is_array($manifest['rules']) || array_filter($manifest['rules'],static fn($e):bool=>!is_array($e))!==[])) throw new \RuntimeException('Manifest rules must be an array of entries.');
        $entries = is_array($manifest['rules'] ?? null) ? $manifest['rules'] : [];
        $internalEntries = array_values(array_filter($entries, static fn(array $e): bool => (preg_match('/^MB-[0-9]{4,}$/D', strtoupper((string)($e['rule_key'] ?? ''))) === 1)));
        if ($internalEntries === []) return (new LegacyScanPlanner())->planAgent($request);
        if (($manifest['schema_version'] ?? '') !== '1.0') throw new \RuntimeException('Unsupported manifest schema version.');
        if (!is_array($manifest['rules'] ?? null)) throw new \RuntimeException('Manifest rules must be an array.');
        if (isset($manifest['assessment_level']) && !in_array($manifest['assessment_level'], [1,2,3], true)) throw new \RuntimeException('Invalid manifest assessment level.');
        $index = []; $selected = []; $unsupported = []; $bindings=[]; $executedIds=[];
        $all = array_column(RequirementCatalog::loadAll()['rules'], null, 'id');
        $manifestFamilies=[];
        foreach($entries as$entry){
            $key=strtoupper((string)($entry['rule_key']??''));
            if (preg_match('/^MB-[0-9]{4,}$/D', $key) && MagebeanRetirement::diagnostic($key) !== null) {
                $manifestFamilies['magebean'] = true;
                continue;
            }
            foreach(isset($all[$key])?[$key]:RequirementCatalog::resolveAlias($key)as$resolved)if(isset($all[$resolved]))$manifestFamilies[$all[$resolved]['family']]=true;
        }
        if(count($manifestFamilies)>1)throw new \RuntimeException('Agent assessments cannot mix Magebean, ASVS and PCI requirement families.');
        if(isset($manifest['requirement_family'])&&(!in_array($manifest['requirement_family'],['magebean','asvs','pci'],true)||($manifestFamilies!==[]&&!isset($manifestFamilies[$manifest['requirement_family']]))))throw new \RuntimeException('Manifest requirement family does not match its requirements.');
        $legacyEntries = array_values(array_filter($entries, static fn(array $e): bool => !(preg_match('/^MB-[0-9]{4,}$/D', strtoupper((string)($e['rule_key'] ?? ''))) === 1)));
        $legacyRules = [];
        if ($legacyEntries !== []) {
            $legacyManifest = $manifest; $legacyManifest['rules'] = $legacyEntries;
            $legacyRequest = new ScanRequest($request->context, array_replace($request->options, ['manifest'=>$legacyManifest]));
            $legacy = (new LegacyScanPlanner())->planAgent($legacyRequest);
            $legacyRules = array_column($legacy->pack['rules'], null, 'id');
            $unsupported = $legacy->metadata['unsupported'];
        }
        foreach ($entries as $entry) {
            $id = strtoupper((string)($entry['rule_key'] ?? ''));
            if ($id === '') continue;
            if (isset($index[$id]) && (preg_match('/^MB-[0-9]{4,}$/D', $id) === 1)) throw new \RuntimeException('Duplicate internal requirement in manifest.');
            $index[$id] = $entry;
        }
        foreach ($index as $id=>$entry) {
            if (preg_match('/^MB-[0-9]{4,}$/D', $id) && ($message = MagebeanRetirement::diagnostic($id)) !== null) {
                $unsupported[] = ['assessment_item_id' => (string)($entry['assessment_item_id'] ?? ''),
                    'rule_key' => $id, 'status' => 'unsupported', 'message' => $message];
                continue;
            }
            if (!(preg_match('/^MB-[0-9]{4,}$/D', $id) === 1)) { if (isset($legacyRules[$id])) {$selected[]=$legacyRules[$id];$bindings[]=['requested_key'=>$id,'assessment_item_id'=>(string)($entry['assessment_item_id']??''),'canonical_id'=>$id];} continue; }
            $canonicalIds=isset($all[$id])?[$id]:RequirementCatalog::resolveAlias($id);
            $canonicalId=count($canonicalIds)===1?$canonicalIds[0]:null;
            if ($canonicalId===null || !isset($all[$canonicalId])) { $unsupported[]=['assessment_item_id'=>(string)($entry['assessment_item_id']??''),'rule_key'=>$id,'status'=>'unsupported','message'=>'Requirement is not bundled in this CLI version.']; continue; }
            $r=$all[$canonicalId];
            $mode=strtoupper((string)($request->context->get('meta',[])['target_mode']??'LOCAL'));if($mode==='HYBRID')$mode='LOCAL';
            if(!in_array($mode,$r['target_modes'],true)){$unsupported[]=['assessment_item_id'=>(string)($entry['assessment_item_id']??''),'rule_key'=>$id,'status'=>'unsupported','message'=>'Requirement is unavailable in this target mode.'];continue;}
            if(isset($r['execution_variants'][$mode]['obligations'])){$r['obligations']=$r['execution_variants'][$mode]['obligations'];$r['checks']=array_merge(...array_map(static fn(array $o):array=>$o['checks'],$r['obligations']));$r['execution_scope']=$mode;}
            if(isset($r['applicability']['capability'])){$cap=$r['applicability']['capability'];$caps=is_array($manifest['capabilities']??null)?$manifest['capabilities']:[];$enabled=array_is_list($caps)?in_array($cap,$caps,true):filter_var($caps[$cap]??false,FILTER_VALIDATE_BOOLEAN);$r['applicability']['state']=$enabled?'APPLICABLE':'UNKNOWN';
                if(!$enabled&&($r['family']??'')==='magebean'&&!RequirementPolicy::requiresHuman($r)){
                    $unsupported[]=['assessment_item_id'=>(string)($entry['assessment_item_id']??''),'rule_key'=>$id,'status'=>'unsupported','message'=>'Optional scan context is not enabled: '.$cap.'.'];
                    continue;
                }
            }
            if (($r['family'] ?? null) === 'magebean' && isset($manifest['module_names'])
                && in_array('magento_module_integrity', array_column($r['checks'], 'name'), true)) {
                if (!is_array($manifest['module_names'])) throw new \RuntimeException('Manifest module_names must be a list.');
                self::applyModules($r, MagentoModuleIntegrityCheck::moduleNames($manifest['module_names']));
            }
            if (isset($manifest['assessment_level'])) $r['assessment_level']=$manifest['assessment_level'];
            $bindings[]=['requested_key'=>$id,'assessment_item_id'=>(string)($entry['assessment_item_id']??''),'canonical_id'=>$canonicalId];
            if(!isset($executedIds[$canonicalId])){$selected[]=$r;$executedIds[$canonicalId]=true;}
        }
        return new ScanPlan($request, ['assessment_model'=>'internal-requirement-v1','rules'=>$selected], ['manifestIndex'=>$index,'unsupported'=>$unsupported,'manifestBindings'=>$bindings], true);
    }

    private static function applyModules(array &$definition, array $modules): bool
    {
        if (($definition['family'] ?? null) !== 'magebean') return false;
        $matched = false;
        foreach ($definition['obligations'] as &$obligation) {
            foreach ($obligation['checks'] as &$check) {
                if ($check['name'] !== 'magento_module_integrity') continue;
                $check['args']['modules'] = $modules;
                $matched = true;
            }
            unset($check);
        }
        unset($obligation);
        if ($matched) {
            $definition['checks'] = array_merge(...array_column($definition['obligations'], 'checks'));
        }
        return $matched;
    }

    /** Lists and maps share one canonical shape before additive CLI enables. */
    private static function normalizeCapabilities(mixed $raw): array
    {
        if (!is_array($raw)) return [];
        $caps = [];
        if (array_is_list($raw)) {
            foreach ($raw as $name) {
                if (!is_string($name) || trim($name) === '') continue;
                $caps[strtolower(trim($name))] = true;
            }
        } else {
            foreach ($raw as $name => $enabled) {
                if (!is_string($name) || trim($name) === '') continue;
                $caps[strtolower(trim($name))] = filter_var($enabled, FILTER_VALIDATE_BOOLEAN);
            }
        }
        return $caps;
    }

    private static function ids(mixed $raw): array
    {
        if (is_string($raw)) $raw=explode(',', $raw);
        if (!is_array($raw)) return [];
        return array_values(array_unique(array_filter(array_map(static fn($v):string=>strtoupper(trim((string)$v)), $raw))));
    }
    private function normalizeControlList(mixed $raw): array
    {
        $result=[];
        $known=RequirementCatalog::loadAll()['controls'];
        foreach (self::ids($raw) as $id) {
            if(in_array($id,$known,true)){$result[]=$id;continue;}
            if (!preg_match('/^(?:MB-C|MB-|C)?(\d{2})$/',$id,$m)) throw new \RuntimeException('Invalid control id: '.$id);
            $result[]='MB-C'.$m[1];
        }
        return array_values(array_unique($result));
    }
}
