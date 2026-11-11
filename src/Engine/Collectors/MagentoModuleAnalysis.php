<?php
declare(strict_types=1);

namespace Magebean\Engine\Collectors;

use Magebean\Engine\Context;

/** Builds reusable indexes for explicitly selected roots from the passive inventory. */
final class MagentoModuleAnalysis
{
    public function __construct(
        private readonly MagentoModuleInventory $inventory,
        private readonly ?CollectionSession $session = null,
    ) {}

    public function collect(Context $context, array $moduleNames, array $limits = []): array
    {
        if (!array_is_list($moduleNames) || count($moduleNames) > 1000) {
            throw new \InvalidArgumentException('Select up to 1000 module names explicitly.');
        }
        foreach ($moduleNames as $name) {
            if (!is_string($name) || !preg_match('/^[A-Za-z0-9]+_[A-Za-z0-9_]+$/D', $name)) {
                throw new \InvalidArgumentException('Invalid module identity in source selection.');
            }
        }
        $moduleNames = array_values(array_unique($moduleNames));
        sort($moduleNames, SORT_STRING);
        $limits = array_intersect_key($limits, array_flip(['max_files', 'max_file_bytes', 'max_total_bytes', 'timeout_seconds', 'validate_schemas', 'schema_kinds', 'dependency_symbols']));
        ksort($limits);
        $load = fn(): array => $this->index($context, $moduleNames, $limits);
        $key = 'magento-module-analysis:'.hash('sha256', serialize([$context->path, $moduleNames, $limits]));
        return $this->session?->remember($key, $load) ?? $load();
    }

    private function index(Context $context, array $moduleNames, array $limits): array
    {
        $inventory = $this->inventory->collect($context);
        $paths = [];
        $gaps = [];
        $identitiesByRoot = array_column(array_filter($inventory['modules'], static fn(array $module): bool => $module['root'] !== null), 'identity', 'root');
        foreach ($moduleNames as $name) {
            $roots = $inventory['module_roots'][$name] ?? [];
            if (count($roots) !== 1 || ($identitiesByRoot[$roots[0]] ?? null) !== $name) {
                $gaps[] = ['reason' => 'selected_module_unresolvable', 'file' => '', 'subject' => $name];
                continue;
            }
            $paths[$roots[0]] = $name;
        }
        ksort($paths);
        if (count($paths) > 100) {
            $gaps[] = ['reason' => 'selected_root_budget_exceeded', 'file' => ''];
            $paths = array_slice($paths, 0, 100, true);
        }
        $excluded = array_values(array_diff(array_keys($identitiesByRoot), array_keys($paths)));
        $sources = $paths === [] ? ['files' => [], 'gaps' => [], 'files_read' => 0, 'bytes_read' => 0]
            : (new BoundedSourceInventory($this->session))->collect($context, [
                'paths' => array_keys($paths),
                'include_ext' => ['php', 'xml'],
                'exclude_paths' => $excluded,
                'verify_stable' => true,
            ] + $limits);
        $scannedRoots = [];
        foreach ($sources['files'] as &$file) {
            $directory = dirname($file['file']);
            while ($directory !== '.') {
                if (isset($paths[$directory])) {
                    $scannedRoots[$directory] = true;
                    $file['module'] = $paths[$directory];
                    $file['module_relative_path'] = substr($file['file'], strlen($directory) + 1);
                    break;
                }
                $directory = dirname($directory);
            }
        }
        unset($file);
        $php = (new MagentoPhpSymbolIndex())->index($sources['files'], $this->session);
        if (($limits['dependency_symbols'] ?? false) === true) {
            $dependencies = (new MagentoDependencySymbols($this->session))->expand($context, $php['symbols'], $sources['files']);
            $php['symbols'] = $dependencies['symbols'];
            array_push($php['gaps'], ...$dependencies['gaps']);
        }
        $root = realpath($context->path);
        $schemaFiles = ($limits['validate_schemas'] ?? false) && $root !== false
            ? new MagentoInventoryFiles($context, $root, $this->session) : null;
        $xml = (new MagentoXmlIndex())->index($sources['files'], $inventory['schema_module_roots'], $inventory['framework_root'], $schemaFiles, $limits['schema_kinds'] ?? []);
        $gaps = array_merge($gaps, $sources['gaps'], $php['gaps'], $xml['gaps']);
        foreach (array_diff_key($paths, $scannedRoots) as $path => $name) {
            $gaps[] = ['reason' => 'selected_module_source_unobserved', 'file' => $path, 'subject' => $name];
        }
        return [
            'complete' => $inventory['complete'] && $gaps === [],
            'inventory' => $inventory,
            'requested_modules' => $moduleNames,
            'selected_roots' => $paths,
            'coverage' => [
                'discovered' => count($identitiesByRoot),
                'selected' => count($paths),
                'excluded' => count($excluded),
                'scanned' => count($scannedRoots),
            ],
            'files_read' => $sources['files_read'],
            'bytes_read' => $sources['bytes_read'],
            'gaps' => array_slice($gaps, 0, 100),
            'gaps_truncated' => count($gaps) > 100,
            'schema_gaps' => $schemaFiles?->gaps ?? [],
            'symbols' => $php['symbols'],
            'patch_files' => $php['patch_files'],
            'documents' => $xml['documents'],
        ];
    }
}
