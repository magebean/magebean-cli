<?php
declare(strict_types=1);
namespace Magebean\Engine\Collectors;

use Magebean\Engine\Context;

/** Bounded reference-only Composer symbol context. Never loads generated PHP/autoloaders. */
final class MagentoDependencySymbols
{
    public function __construct(private readonly ?CollectionSession $session = null) {}

    public function expand(Context $context, array $symbols, array $sources): array
    {
        $root = realpath($context->path);
        if ($root === false) return ['symbols' => $symbols, 'gaps' => []];
        $reader = new MagentoInventoryFiles($context, $root, $this->session);
        $manifest = $reader->json('composer.json') ?? [];
        $vendor = MagentoInventoryFiles::relative('', is_string($manifest['config']['vendor-dir'] ?? null) ? $manifest['config']['vendor-dir'] : 'vendor');
        $metadata = $vendor === null ? null : $vendor.'/composer/installed.json';
        $installed = $metadata === null ? null : $reader->json($metadata);
        $mappings = []; $classmaps = [];
        $add = static function(array $autoload, string $base) use (&$mappings, &$classmaps): void {
            foreach (['psr-4', 'psr-0'] as $kind) foreach ((array)($autoload[$kind] ?? []) as $prefix => $directories) {
                if (!is_string($prefix)) continue;
                foreach ((array)$directories as $directory) {
                    if (!is_string($directory)) continue;
                    $path = $directory === '' ? $base : MagentoInventoryFiles::relative($base, $directory);
                    if ($path !== null) $mappings[] = ['prefix'=>$prefix, 'path'=>$path, 'kind'=>$kind];
                }
            }
            foreach ((array)($autoload['classmap'] ?? []) as $path) {
                if (is_string($path) && ($normalized=MagentoInventoryFiles::relative($base, $path)) !== null) $classmaps[$normalized]=true;
            }
        };
        $add((array)($manifest['autoload'] ?? []), '');
        $add((array)($manifest['autoload-dev'] ?? []), '');
        foreach ((array)($installed['packages'] ?? $installed ?? []) as $package) {
            if (!is_array($package) || !is_string($package['name'] ?? null) || $vendor === null) continue;
            $pathValue=$package['install-path']??$package['installed-path']??null;
            $base=is_string($pathValue)?MagentoInventoryFiles::relative(dirname($metadata),$pathValue):MagentoInventoryFiles::relative($vendor,$package['name']);
            if ($base === null) continue;
            $autoload=$package['autoload']??null;
            if (!is_array($autoload)) $autoload=$reader->json($base.'/composer.json')['autoload']??[];
            if (is_array($autoload)) $add($autoload,$base);
        }
        if (count($mappings)>1000) { $reader->gap('', 'dependency_mapping_budget_exceeded'); $mappings=array_slice($mappings,0,1000); }
        if (count($classmaps)>100) $reader->gap('', 'dependency_classmap_scope_budget_exceeded');
        usort($mappings,static fn(array $a,array $b):int=>strlen($b['prefix'])<=>strlen($a['prefix']));
        $pending=[]; $seen=[]; $loaded=[]; $files=0;
        $enqueue=static function(string $name) use (&$pending):void {
            foreach (preg_split('/[?\\|&]/', $name) ?: [] as $part) {
                $part=ltrim(trim($part),'\\');
                if (!in_array(strtolower($part), ['int','float','string','bool','array','object','mixed','iterable','callable','void','never','null','false','true','self','static','parent'], true) && preg_match('/^[A-Za-z_][A-Za-z0-9_\\\\]*$/D',$part)) $pending[$part]=true;
            }
        };
        $references=static function(array $rows) use ($enqueue):void {
            foreach ($rows as $entries) foreach ($entries as $symbol) {
                foreach (array_merge($symbol['extends'],$symbol['implements'],$symbol['traits']) as $name) $enqueue($name);
                foreach ($symbol['patch_dependencies']??[] as $name) if (is_string($name)) $enqueue($name);
                foreach ($symbol['methods'] as $method) {
                    $enqueue($method['return_type']??'');
                    foreach ($method['parameters'] as $parameter) $enqueue($parameter['type']??'');
                }
            }
        };
        $references($symbols);
        foreach ($sources as $source) if ($source['extension']==='xml') {
            $doc=MagentoXmlIndex::parse($source['content']);
            if ($doc===null) continue;
            foreach ((new \DOMXPath($doc))->query('//@type | //@for | //@class | //@instance | //@name') as $attribute) {
                if ($attribute->nodeName !== 'name' || str_contains($attribute->nodeValue,'\\') || str_contains($attribute->nodeValue,'_')) $enqueue($attribute->nodeValue);
            }
        }
        // Explicit classmap scopes are bounded; no generated autoload_classmap.php is evaluated.
        if ($classmaps!==[]) {
            $capture=(new BoundedSourceInventory($this->session))->collect($context,['paths'=>array_slice(array_keys($classmaps),0,100),'include_ext'=>['php'],'max_files'=>500,'max_total_bytes'=>4194304,'verify_stable'=>true]);
            $indexed=(new MagentoPhpSymbolIndex())->index($capture['files'],$this->session);
            $classmapSymbols=$indexed['symbols'];
            foreach (array_merge($capture['gaps'],$indexed['gaps']) as $gap) $reader->gap($gap['file']??'', 'dependency_'.$gap['reason']);
        } else $classmapSymbols=[];
        while ($pending!==[]) {
            if (count($seen)>=500 || $files>=500) { $reader->gap('', 'dependency_symbol_budget_exceeded'); break; }
            $name=array_key_first($pending); unset($pending[$name]); $key=strtolower($name);
            if (isset($seen[$key]) || isset($symbols[$key])) continue;
            $seen[$key]=true;
            if (isset($classmapSymbols[$key])) { $symbols[$key]=$classmapSymbols[$key]; $references([$key=>$symbols[$key]]); continue; }
            foreach ($mappings as $mapping) {
                if (!str_starts_with($name,$mapping['prefix'])) continue;
                $suffix=$mapping['kind']==='psr-4'?substr($name,strlen($mapping['prefix'])):$name;
                if ($mapping['kind']==='psr-0') {
                    $position=strrpos($suffix,'\\');
                    $suffix=$position===false?str_replace('_','/',$suffix):substr($suffix,0,$position+1).str_replace('_','/',substr($suffix,$position+1));
                }
                $suffix=str_replace('\\','/',$suffix);
                $file=MagentoInventoryFiles::relative($mapping['path'],$suffix.'.php');
                if ($file===null || isset($loaded[$file])) continue;
                $content=$reader->read($file);
                if ($content===null) continue;
                $loaded[$file]=true; ++$files;
                $indexed=(new MagentoPhpSymbolIndex())->index([['file'=>$file,'extension'=>'php','content'=>$content]],$this->session);
                foreach ($indexed['symbols'] as $symbolKey=>$rows) if (!isset($symbols[$symbolKey])) $symbols[$symbolKey]=$rows;
                foreach ($indexed['gaps'] as $gap) $reader->gap($gap['file']??'', 'dependency_'.$gap['reason']);
                $references($indexed['symbols']);
                if (isset($symbols[$key])) break;
            }
        }
        return ['symbols'=>$symbols,'gaps'=>$reader->gaps];
    }
}
