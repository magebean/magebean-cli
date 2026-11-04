<?php
declare(strict_types=1);

namespace Magebean\Engine\Checks;

use Magebean\Engine\{CheckResult, Context, MagebeanDetectorAnalysis};
use Magebean\Engine\Collectors\CollectorSet;

final class MagentoModuleLifecycleCheck
{
    private const PATCH_INTERFACES = [
        'Data' => 'Magento\Framework\Setup\Patch\DataPatchInterface',
        'Schema' => 'Magento\Framework\Setup\Patch\SchemaPatchInterface',
    ];
    private const HANDLERS = ['crontab', 'queue_consumer', 'communication'];

    public function __construct(private readonly Context $context, private readonly CollectorSet $collectors) {}

    public function run(string $kind, array $modules, array $gaps): CheckResult
    {
        $selected = array_column(array_filter($modules, static fn(array $module): bool => $module['identity'] !== null), null, 'identity');
        $findings = [];
        foreach ($modules as $module) {
            if ($module['identity'] === null) $gaps[] = ['reason' => 'module_identity_unavailable', 'file' => $module['root']];
        }
        if ($selected !== []) {
            $analysis = $this->collectors->magentoAnalysis->collect($this->context, array_keys($selected), [
                'validate_schemas' => $kind === 'declarative-schema', 'schema_kinds' => ['db_schema'],
            ]);
            foreach ($analysis['gaps'] as $gap) {
                if ($gap['reason'] === 'xml_parse_unavailable') {
                    $xml = pathinfo($gap['file'], PATHINFO_FILENAME);
                    if ($kind === 'setup-patches' || !in_array($xml, $kind === 'declarative-schema' ? ['db_schema'] : self::HANDLERS, true)) continue;
                    if ($kind === 'declarative-schema' && ($analysis['documents'][$gap['file']]['schema_status'] ?? '') === 'malformed') continue;
                }
                if ($kind === 'declarative-schema' && in_array($gap['reason'], ['php_parse_unavailable', 'symbol_budget_exceeded'], true)) continue;
                $gaps[] = $gap;
            }
            if ($analysis['gaps_truncated']) $gaps[] = ['reason' => 'lifecycle_analysis_gaps_truncated'];
            if ($kind === 'declarative-schema') {
                array_push($gaps, ...$analysis['schema_gaps']);
                foreach ($analysis['documents'] as $file => $doc) {
                    if ($doc['kind'] !== 'db_schema' || $doc['area'] !== 'global' || !isset($selected[$doc['module']])) continue;
                    if (!in_array($doc['schema_status'], ['malformed', 'invalid'], true)) continue;
                    $findings[] = self::finding($selected[$doc['module']], $file, $doc['line'], 'invalid-declarative-schema',
                        'Declarative schema XML fails static validation.',
                        'The document has malformed syntax or is rejected by its declared installed XSD.',
                        'Correct the XML against the installed schema before deploying.');
                }
            } elseif ($kind === 'setup-patches') {
                $patchFiles = $analysis['patch_files'];
                foreach ($analysis['gaps'] as $gap) {
                    if ($gap['reason'] === 'symbol_budget_exceeded') unset($patchFiles[$gap['file']]);
                }
                $findings = $this->patches($analysis['symbols'], $patchFiles, $selected, $gaps);
            } else {
                $findings = $this->handlers($analysis, $selected, $gaps);
            }
        }
        $diagnostics = [];
        foreach ($gaps as $gap) {
            $detail = implode(' · ', array_filter([$gap['file'] ?? '', $gap['subject'] ?? '']));
            $message = str_replace('_', ' ', $gap['reason']).($detail !== '' ? ' · '.$detail : '');
            $diagnostics[$message] = ['message' => $message, 'action' => 'Verify the declaration, local schema and source for referenced classes. Select their modules if needed.'];
        }
        return MagebeanDetectorAnalysis::result('magento-module-'.$kind, '1.0', $findings, array_values($diagnostics));
    }

    private function patches(array $symbols, array $patchFiles, array $modules, array &$gaps): array
    {
        $findings = [];
        $graph = [];
        $patches = [];
        foreach ($patchFiles as $file => $definition) {
            $expected = $definition['expected_class'];
            $key = strtolower($expected);
            $rows = $symbols[$key] ?? [];
            if (count($rows) > 1) {
                $gaps[] = ['reason' => 'patch_symbol_ambiguous', 'file' => $file];
                continue;
            }
            $patch = $rows[0] ?? null;
            $module = $modules[$definition['module']];
            if ($patch === null || $patch['file'] !== $file || $patch['kind'] !== 'class' || $patch['abstract']) {
                $findings[] = self::finding($module, $file, $patch['line'] ?? 1, 'patch-class-declaration-unavailable',
                    'Setup patch file does not declare the expected concrete class.',
                    'The module name, setup directory and filename determine the class Magento discovers.',
                    'Declare the concrete class matching the patch location and module identity.', $expected);
                continue;
            }
            $interface = self::PATCH_INTERFACES[$definition['kind']];
            $contract = self::implements($patch, $interface, $symbols);
            if ($contract === null) {
                $gaps[] = ['reason' => 'patch_inheritance_unresolved', 'file' => $patch['file']];
            } elseif (!$contract) {
                $findings[] = self::finding($module, $patch['file'], $patch['line'], 'patch-interface-mismatch',
                    'Patch class does not implement the interface for its setup directory.',
                    'The indexed ancestry does not declare '.$interface.'.',
                    'Implement the matching Magento setup patch interface.', $patch['name']);
                continue;
            }
            $dependencies = $patch['patch_dependencies'];
            if ($dependencies === null) {
                $gaps[] = ['reason' => 'patch_dependencies_not_static', 'file' => $patch['file']];
                continue;
            }
            $patches[$key] = $patch;
            $graph[$key] = [];
            foreach ($dependencies as $dependency) {
                $target = strtolower(ltrim($dependency, '\\'));
                $candidate = $symbols[$target] ?? [];
                if (count($candidate) !== 1) {
                    $gaps[] = ['reason' => 'patch_dependency_symbol_unresolved', 'file' => $patch['file'], 'subject' => $dependency];
                    continue;
                }
                $targetInterface = self::implements($candidate[0], $interface, $symbols);
                if ($targetInterface === false) {
                    $otherInterface = self::PATCH_INTERFACES[$definition['kind'] === 'Data' ? 'Schema' : 'Data'];
                    $other = self::implements($candidate[0], $otherInterface, $symbols);
                    if ($other === true) {
                        $gaps[] = ['reason' => 'cross_kind_patch_dependency_unsupported', 'file' => $patch['file'], 'subject' => $dependency];
                        continue;
                    }
                    if ($other === null) $targetInterface = null;
                }
                if ($targetInterface === null) {
                    $gaps[] = ['reason' => 'patch_dependency_interface_unresolved', 'file' => $patch['file'], 'subject' => $dependency];
                    continue;
                }
                if (!$targetInterface || $candidate[0]['kind'] !== 'class' || $candidate[0]['abstract']) {
                    $findings[] = self::finding($module, $patch['file'], $patch['line'], 'patch-dependency-not-concrete',
                        'Patch dependency is incompatible with the patch kind.',
                        'The referenced symbol is not a concrete class implementing the expected patch interface.',
                        'Reference a concrete compatible setup patch.', $dependency);
                    continue;
                }
                $graph[$key][] = $target;
            }
        }

        $visited = [];
        $active = [];
        $reported = [];
        $visit = function (string $key) use (&$visit, &$visited, &$active, &$reported, &$findings, &$gaps, $graph, $patches, $modules): void {
            if (isset($visited[$key]) || !isset($graph[$key])) return;
            if (count($active) >= 128) {
                $gaps[] = ['reason' => 'patch_graph_depth_exceeded', 'file' => $patches[$key]['file']];
                return;
            }
            $visited[$key] = $active[$key] = true;
            foreach ($graph[$key] as $target) {
                if (!isset($active[$target])) {
                    $visit($target);
                    continue;
                }
                $cycle = array_slice(array_keys($active), array_search($target, array_keys($active), true));
                $fingerprint = $cycle;
                sort($fingerprint);
                $signature = implode('|', $fingerprint);
                if (isset($reported[$signature])) continue;
                $reported[$signature] = true;
                $patch = $patches[$key];
                $names = array_map(static fn(string $member): string => $patches[$member]['name'], [...$cycle, $target]);
                $findings[] = self::finding($modules[$patch['module']], $patch['file'], $patch['line'], 'patch-dependency-cycle',
                    'Static patch dependencies form a cycle.', implode(' → ', $names),
                    'Remove the circular dependency and verify the installation order.', $patch['name']);
            }
            unset($active[$key]);
        };
        foreach (array_keys($graph) as $key) $visit($key);
        return $findings;
    }

    private static function implements(array $symbol, string $interface, array $symbols): ?bool
    {
        $wanted = strtolower($interface);
        $pending = [$symbol];
        $visited = [];
        $complete = true;
        while ($pending !== []) {
            $row = array_pop($pending);
            $name = strtolower($row['name']);
            if ($name === $wanted) return true;
            if (isset($visited[$name])) continue;
            if (count($visited) >= 128) return null;
            $visited[$name] = true;
            foreach (array_merge($row['implements'], $row['extends']) as $parent) {
                $key = strtolower(ltrim($parent, '\\'));
                if ($key === $wanted) return true;
                $candidates = $symbols[$key] ?? [];
                if (count($candidates) === 1) $pending[] = $candidates[0];
                else $complete = false;
            }
        }
        return $complete ? false : null;
    }

    private function handlers(array $analysis, array $modules, array &$gaps): array
    {
        $findings = [];
        $symbols = $analysis['symbols'];
        foreach ($analysis['documents'] as $file => $document) {
            if ($document['area'] !== 'global' || !in_array($document['kind'], self::HANDLERS, true)
                || !isset($modules[$document['module']])) continue;
            $module = $modules[$document['module']];
            foreach ($document['declarations'] as $handler) {
                $class = $handler['class'];
                $method = $handler['method'];
                $rows = $symbols[strtolower(ltrim($class, '\\'))] ?? [];
                if ($class === '' || $method === '' || count($rows) !== 1) {
                    $gaps[] = ['reason' => 'handler_symbol_unresolved', 'file' => $file, 'subject' => $class.'::'.$method];
                    continue;
                }
                $symbol = $rows[0];
                $entry = $symbol['methods'][strtolower($method)] ?? null;
                if ($entry === null && ($symbol['extends'] !== [] || $symbol['traits'] !== [] || $symbol['implements'] !== [])) {
                    $gaps[] = ['reason' => 'handler_inheritance_unresolved', 'file' => $file, 'subject' => $class.'::'.$method];
                    continue;
                }
                if ($entry !== null && $entry['visibility'] === 'public') continue;
                $findings[] = self::finding($module, $file, $handler['line'], 'handler-method-unavailable',
                    'Configured handler does not reference a public method in the indexed declaration.',
                    'The referenced method is missing or non-public in the supported static scope.',
                    'Point the declaration to the intended public handler.', $class.'::'.$method);
            }
        }
        return $findings;
    }

    private static function finding(array $module, string $file, int $line, string $key, string $message, string $reasoning, string $remediation, ?string $symbol = null): array
    {
        return compact('key', 'message', 'reasoning', 'remediation') + [
            'category' => 'correctness', 'confidence' => 'confirmed', 'severity' => 'medium',
            'locations' => [['file' => $file, 'line' => $line]],
            'subject' => array_filter(['module' => $module['identity'], 'package' => $module['package'],
                'version' => $module['version'], 'area' => 'global', 'symbol' => $symbol]),
        ];
    }
}
