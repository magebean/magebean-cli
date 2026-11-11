<?php
declare(strict_types=1);

namespace Magebean\Engine\Collectors;

use Magebean\Engine\Context;

/** Passive, ordered projection of supported DI declarations. Argument values stay private. */
final class MagentoDiConfiguration
{
    private const AREAS = ['frontend', 'adminhtml', 'graphql', 'webapi_rest', 'webapi_soap', 'crontab'];

    public function __construct(private readonly CollectionSession $session) {}

    public function collect(Context $context, array $inventory): array
    {
        return $this->session->remember('magento-di:'.$context->path, fn(): array => $this->read($context, $inventory));
    }

    private function read(Context $context, array $inventory): array
    {
        $root = realpath($context->path);
        if ($root !== false && ($context->get('meta', [])['launch_profile'] ?? '') === 'development'
            && (!($inventory['module_order_known'] ?? false) || !$inventory['complete'])) {
            // Source files are independent declarations, never an invented enabled-module merge order.
            $reader = new MagentoInventoryFiles($context, $root, $this->session);
            $scopes = [];
            foreach ($inventory['modules'] as $module) {
                if (!is_string($module['root'] ?? null)) continue;
                foreach (array_merge(['global'], self::AREAS) as $area) {
                    $file = $module['root'].'/etc/'.($area === 'global' ? '' : $area.'/').'di.xml';
                    $source = $reader->read($file);
                    if ($source === null) continue;
                    $doc = MagentoXmlIndex::parse($source);
                    if ($doc === null || $doc->documentElement->nodeName !== 'config') {
                        $reader->gap($file, 'di_xml_unresolved');
                        continue;
                    }
                    $table = [];
                    self::overlay($table, $doc, $file, $module['identity']);
                    $scopes['declaration:'.$file] = $table;
                }
            }
            return ['scopes' => $scopes, 'complete' => $reader->complete, 'gaps' => $reader->gaps, 'declaration_only' => true];
        }
        if ($root === false || !$inventory['complete'] || !($inventory['module_order_known'] ?? false)) {
            return ['scopes' => [], 'complete' => false, 'gaps' => [['reason' => 'di_module_order_or_inventory_unresolved']]];
        }
        $reader = new MagentoInventoryFiles($context, $root, $this->session);
        $paths = ['global' => [['app/etc/di.xml', null]]];
        foreach ($inventory['module_order'] as $name) {
            $roots = $inventory['module_roots'][$name] ?? [];
            if (count($roots) !== 1) {
                $reader->gap('app/etc/config.php', 'di_module_root_unresolved', $name);
                continue;
            }
            $paths['global'][] = [$roots[0].'/etc/di.xml', $name];
            foreach (self::AREAS as $area) $paths[$area][] = [$roots[0].'/etc/'.$area.'/di.xml', $name];
        }
        $scopes = [];
        foreach ($paths as $area => $sources) {
            $table = $area === 'global' ? [] : $scopes['global'];
            $changed = false;
            foreach ($sources as [$file, $module]) {
                $source = $reader->read($file);
                if ($source === null) continue;
                $doc = MagentoXmlIndex::parse($source);
                if ($doc === null || $doc->documentElement->nodeName !== 'config') {
                    $reader->gap($file, 'di_xml_unresolved');
                    continue;
                }
                $changed = true;
                self::overlay($table, $doc, $file, $module);
            }
            if ($area === 'global' || $changed) $scopes[$area] = $table;
        }
        return ['scopes' => $scopes, 'complete' => $reader->complete, 'gaps' => $reader->gaps];
    }

    private static function overlay(array &$table, \DOMDocument $document, string $file, ?string $module): void
    {
        $xpath = new \DOMXPath($document);
        foreach ($xpath->query('/config/preference | /config/type | /config/virtualType') as $node) {
            $kind = $node->nodeName;
            $name = $node->getAttribute($kind === 'preference' ? 'for' : 'name');
            if ($name === '') continue;
            $origin = ['file' => $file, 'line' => $node->getLineNo(), 'module' => $module];
            if ($kind !== 'type') {
                $table[$kind][$name] = $origin + ['target' => $node->getAttribute('type')];
            }
            if ($kind === 'preference') continue;
            foreach ($xpath->query('arguments/argument | plugin', $node) as $entry) {
                $key = $entry->getAttribute('name');
                if ($key === '') continue;
                $row = ['file' => $file, 'line' => $entry->getLineNo(), 'module' => $module];
                if ($entry->nodeName === 'plugin') {
                    $previous = $table['plugin'][$name][$key] ?? [];
                    $attributes = [];
                    foreach (['type', 'disabled'] as $attr) {
                        if ($entry->hasAttribute($attr)) $attributes[$attr] = $entry->getAttribute($attr);
                    }
                    $table['plugin'][$name][$key] = $row + $attributes + $previous;
                } else {
                    $table['argument'][$name][$key] = $row + [
                        'type' => $entry->getAttributeNS('http://www.w3.org/2001/XMLSchema-instance', 'type'),
                    ];
                }
            }
        }
    }
}
