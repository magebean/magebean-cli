<?php
declare(strict_types=1);

namespace Magebean\Engine\Checks;

use Magebean\Engine\{CheckResult, Context, MagebeanDetectorAnalysis};
use Magebean\Engine\Collectors\{CollectorSet, MagentoDiConfiguration};

final class MagentoDiCheck
{
    public function __construct(private readonly Context $context, private readonly CollectorSet $collectors) {}

    public function run(string $kind, array $modules, array $inventory): CheckResult
    {
        $configuration = (new MagentoDiConfiguration($this->collectors->session))->collect($this->context, $inventory);
        $findings = [];
        $gaps = array_merge($inventory['selection_gaps'], $configuration['gaps']);
        $selected = array_column($modules, null, 'identity');
        unset($selected['']);

        $hasDeclarations = false;
        foreach ($configuration['scopes'] as $table) {
            foreach (self::entries($kind, $table) as [, , $row]) {
                if (isset($selected[$row['module']])) $hasDeclarations = true;
            }
        }
        if ($configuration['complete'] && $hasDeclarations) {
            $symbols = $this->collectors->magentoAnalysis->collect($this->context, array_keys($selected));
            foreach ($symbols['gaps'] as $gap) {
                if ($gap['reason'] !== 'xml_parse_unavailable') $gaps[] = $gap;
            }
            if ($symbols['gaps_truncated']) $gaps[] = ['reason' => 'di_symbol_gaps_truncated'];
            $seen = [];
            foreach ($configuration['scopes'] as $area => $table) {
                foreach (self::entries($kind, $table) as [$name, $key, $row]) {
                    if (!isset($selected[$row['module']])) continue;
                    [$status, $reason] = $this->inspect($kind, $name, $key, $row, $table, $symbols['symbols']);
                    if ($status === 'ok') continue;
                    $label = $key === null ? $name : $name.'::'.$key;
                    $signature = serialize([$row['file'], $row['line'], $label, $status, $reason]);
                    if ($status === 'gap') {
                        $gaps[$signature] = $row + ['reason' => $reason];
                        continue;
                    }
                    // Shared global findings appear once unless the area declares its own override.
                    if (isset($seen[$signature])) continue;
                    $seen[$signature] = true;
                    $module = $selected[$row['module']];
                    $findings[] = [
                        'key' => $kind.'-'.$reason, 'message' => str_replace('_', ' ', ucfirst($reason)).'.',
                        'reasoning' => 'The supported DI declaration and indexed PHP symbols conflict in the '.$area.' scope.',
                        'remediation' => 'Correct the DI declaration and verify the affected area on the installed Magento version.',
                        'confidence' => 'confirmed', 'category' => 'correctness', 'severity' => 'medium',
                        'locations' => [['file' => $row['file'], 'line' => $row['line']]],
                        'subject' => array_filter(['module' => $row['module'], 'package' => $module['package'],
                            'version' => $module['version'], 'area' => $area, 'symbol' => $label]),
                    ];
                }
            }
        }
        $diagnostics = [];
        foreach ($gaps as $gap) {
            $message = str_replace('_', ' ', $gap['reason']).(!empty($gap['file']) ? ' · '.$gap['file'] : '');
            $diagnostics[$message] = ['message' => $message, 'action' => 'Verify local configuration and select any module that supplies a referenced PHP symbol.'];
        }
        return MagebeanDetectorAnalysis::result('magento-module-'.$kind, '1.0', $findings, array_values($diagnostics));
    }

    private static function entries(string $kind, array $table): iterable
    {
        $type = match ($kind) {
            'di-preference' => 'preference', 'di-virtual-type' => 'virtualType',
            'di-arguments' => 'argument', 'di-plugins' => 'plugin',
        };
        foreach ($table[$type] ?? [] as $name => $row) {
            if (in_array($type, ['preference', 'virtualType'], true)) {
                yield [$name, null, $row];
            } else {
                foreach ($row as $key => $entry) yield [$name, $key, $entry];
            }
        }
    }

    private function inspect(string $kind, string $name, ?string $key, array $row, array $table, array $symbols): array
    {
        $ok = ['ok', ''];
        if ($kind === 'di-plugins' && in_array($row['disabled'] ?? '', ['true', '1'], true)) return $ok;
        [$resolved, $cycle] = $kind === 'di-plugins' ? [$name, false] : self::resolve($name, $table, $kind !== 'di-virtual-type');
        if ($cycle) {
            return in_array($kind, ['di-preference', 'di-virtual-type'], true)
                ? ['finding', 'di_resolution_cycle'] : ['gap', 'di_target_cycle'];
        }
        $target = self::symbol($resolved, $symbols);
        if ($target === null && $kind !== 'di-plugins') return ['gap', 'di_target_symbol_unresolved'];

        if ($kind === 'di-preference' || $kind === 'di-virtual-type') {
            if (!self::concrete($target)) return ['finding', 'di_target_not_instantiable'];
            if ($kind === 'di-virtual-type') return $ok;
            if (self::symbol($name, $symbols) === null) return ['gap', 'di_preference_contract_unresolved'];
            $compatible = self::assignable($target, $name, $symbols);
            return match ($compatible) {
                true => $ok, false => ['finding', 'di_preference_target_incompatible'],
                null => ['gap', 'di_preference_inheritance_unresolved'],
            };
        }
        if ($kind === 'di-arguments') {
            [$constructor, $known] = self::method($target, '__construct', $symbols);
            if (!$known) return ['gap', 'di_constructor_inheritance_unresolved'];
            $parameters = array_column($constructor['parameters'] ?? [], null, 'name');
            if (!isset($parameters[$key])) return ['finding', 'di_constructor_parameter_unknown'];
            $parameter = $parameters[$key];
            $type = ltrim($parameter['type'] ?? '', '?');
            if ($parameter['variadic'] || strpbrk($type, '|&') !== false) return ['gap', 'di_argument_signature_unsupported'];
            if (in_array($row['type'], ['', 'const', 'init_parameter'], true)) return ['gap', 'di_argument_value_unresolved'];
            // PHP scalar coercion and object resolution are outside this narrow mismatch predicate.
            if ($row['type'] === 'array' && !in_array($type, ['', 'array', 'iterable', 'mixed', 'callable'], true)) {
                return ['finding', 'di_array_argument_type_incompatible'];
            }
            return $ok;
        }

        // The directly configured subject and its declared plugin hooks only.
        $subject = self::symbol($name, $symbols);
        if (isset($table['virtualType'][$name])) return ['finding', 'di_plugin_subject_virtual'];
        if ($subject === null) return ['gap', 'di_plugin_subject_unresolved'];
        if ($subject['final']) return ['finding', 'di_plugin_subject_final'];
        [$pluginName, $pluginCycle] = self::resolve($row['type'] ?? '', $table, true);
        $plugin = self::symbol($pluginName, $symbols);
        if ($pluginCycle || $plugin === null) return ['gap', 'di_plugin_class_unresolved'];
        if (!self::concrete($plugin)) return ['finding', 'di_plugin_class_not_instantiable'];
        foreach ($plugin['methods'] as $hook) {
            if ($hook['visibility'] !== 'public' || !preg_match('/^(?:before|after|around)([A-Z_].*)$/D', $hook['name'], $parts)) continue;
            $methodName = strtolower($parts[1]);
            [$method, $known] = self::method($subject, $methodName, $symbols);
            if (!$known) return ['gap', 'di_plugin_method_inheritance_unresolved'];
            if ($method === null) return ['gap', 'di_plugin_hook_target_unresolved'];
            if ($method['final'] || $method['static'] || $method['visibility'] !== 'public'
                || in_array($methodName, ['__construct', '__destruct'], true)) {
                return ['finding', 'di_plugin_hook_target_not_interceptable'];
            }
        }
        return $ok;
    }

    private static function resolve(string $name, array $table, bool $preferences): array
    {
        $seen = [];
        while (true) {
            $entry = $preferences ? ($table['preference'][$name] ?? null) : null;
            if ($entry === null) {
                $preferences = false;
                $entry = $table['virtualType'][$name] ?? null;
            }
            if ($entry === null) return [$name, false];
            if (isset($seen[$name])) return [$name, true];
            if (count($seen) >= 128) return ['', false];
            $seen[$name] = true;
            $name = $entry['target'];
        }
    }

    private static function symbol(string $name, array $symbols): ?array
    {
        $rows = $symbols[strtolower(ltrim($name, '\\'))] ?? [];
        return count($rows) === 1 ? $rows[0] : null;
    }

    private static function concrete(array $symbol): bool
    {
        return $symbol['kind'] === 'class' && !$symbol['abstract']
            && ($symbol['methods']['__construct']['visibility'] ?? 'public') === 'public';
    }

    private static function assignable(array $target, string $contract, array $symbols): ?bool
    {
        $wanted = strtolower(ltrim($contract, '\\'));
        $pending = [$target['name']];
        $visited = [];
        $complete = true;
        while ($pending !== []) {
            $name = array_pop($pending);
            $normalized = strtolower(ltrim($name, '\\'));
            if ($normalized === $wanted) return true;
            if (isset($visited[$normalized])) continue;
            if (count($visited) >= 128) return null;
            $visited[$normalized] = true;
            $symbol = self::symbol($name, $symbols);
            if ($symbol === null) {
                $complete = false;
                continue;
            }
            array_push($pending, ...$symbol['extends'], ...$symbol['implements']);
        }
        return $complete ? false : null;
    }

    private static function method(array $symbol, string $name, array $symbols): array
    {
        for ($depth = 0; $depth < 128; ++$depth) {
            if (isset($symbol['methods'][$name])) return [$symbol['methods'][$name], true];
            if ($symbol['traits'] !== [] || count($symbol['extends']) > 1) return [null, false];
            if ($symbol['extends'] === []) return [null, true];
            $symbol = self::symbol($symbol['extends'][0], $symbols);
            if ($symbol === null) break;
        }
        return [null, false];
    }
}
