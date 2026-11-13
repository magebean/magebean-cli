<?php
declare(strict_types=1);
namespace Magebean\Engine\Collectors;

use Magebean\Engine\Context;

/** Observed dependency identities. Metadata is read as data; installed.php is never executed. */
final class DependencyInventory
{
    public function __construct(private readonly FileCollector $files, private readonly CollectionSession $session) {}

    public function collect(Context $context, array $args = []): array
    {
        $paths = [(string)($args['lock_file'] ?? 'composer.lock'), (string)($args['composer_file'] ?? $args['json_file'] ?? 'composer.json')];
        return $this->session->remember('dependency-inventory:'.hash('sha256', serialize([$context->path, $paths])),
            fn(): array => $this->observe($context, $paths));
    }

    private function observe(Context $context, array $paths): array
    {
        $out = ['observed_at'=>gmdate(DATE_ATOM), 'sources'=>[], 'locked'=>[], 'installed'=>[],
            'lock_complete'=>true, 'installed_complete'=>false, 'installed_present'=>false,
            'installed_dev_mode'=>null, 'installed_metadata'=>null, 'declared_require'=>[], 'declared_require_dev'=>[],
            'declared_modules'=>null, 'gaps'=>[], 'lock_gaps'=>[], 'installed_gaps'=>[]];
        $read = function (string $path, string $scope) use ($context, &$out): ?array {
            $absolute=$context->abs($path);
            if (!is_file($absolute)) { $out['sources'][$scope]=['path'=>$path,'state'=>'missing']; return null; }
            $size=@filesize($absolute);
            $raw=is_int($size) && $size <= 8*1024*1024 ? $this->files->read($absolute) : false;
            $data=is_string($raw) ? json_decode($raw,true) : null;
            $out['sources'][$scope]=['path'=>$path,'state'=>is_array($data)?'read':'invalid_or_unreadable',
                'sha256'=>is_string($raw)?hash('sha256',$raw):null];
            return is_array($data)?$data:null;
        };
        [$lockPath,$rootPath]=$paths;
        $root=$read($rootPath,'root_manifest');
        foreach (['require'=>'declared_require','require-dev'=>'declared_require_dev'] as $key=>$field) {
            if (is_array($root[$key] ?? null)) $out[$field]=$root[$key];
        }
        $lock=$read($lockPath,'lockfile');
        if (!is_array($lock) || !is_array($lock['packages'] ?? null) || !array_is_list($lock['packages'])) $out['lock_gaps'][]='lock_inventory_invalid';
        $seenLock=[];
        foreach (['packages','packages-dev'] as $section) {
            if ($section==='packages-dev' && !isset($lock[$section])) continue;
            $rows=$lock[$section]??null;
            if (!is_array($rows) || !array_is_list($rows)) { $out['lock_gaps'][]='lock_section_invalid:'.$section; continue; }
            foreach ($rows as $record) {
                if (!$this->identity($record)) { $out['lock_gaps'][]='lock_package_identity_invalid'; continue; }
                $name=$record['name'];
                if (isset($seenLock[$name])) { unset($out['locked'][$name]); $out['lock_gaps'][]='lock_duplicate:'.$name; continue; }
                $seenLock[$name]=true;
                $out['locked'][$name]=array_replace($record,['development_dependency'=>$section==='packages-dev','evidence_source'=>$lockPath]);
            }
        }
        $out['lock_complete']=$out['lock_gaps']===[];
        $vendor=$root['config']['vendor-dir']??'vendor';
        $safe=is_string($vendor) && $vendor!=='' && !str_contains($vendor,chr(0)) && !str_contains($vendor,':')
            && !str_starts_with(str_replace('\\','/',$vendor),'/') && !in_array('..',explode('/',str_replace('\\','/',$vendor)),true);
        $vendor=$safe ? MagentoInventoryFiles::relative('', $vendor) : null;
        $metadata=$vendor!==null ? $vendor.'/composer/installed.json' : null;
        if ($metadata!==null) {
            $cursor=$context->path;
            foreach (explode('/', $metadata) as $part) {
                $cursor.=DIRECTORY_SEPARATOR.$part;
                if (is_link($cursor)) { $metadata=null; break; }
            }
        }
        $out['installed_metadata_path']=$metadata;
        $installed=$metadata!==null?$read($metadata,'installed_metadata'):null;
        $out['installed_metadata']=$installed;
        $out['installed_present']=$metadata!==null && is_file($context->abs($metadata));
        if ($metadata===null) $out['installed_gaps'][]='vendor_directory_unsupported';
        elseif ($out['installed_present']) {
            if (!is_array($installed)) $out['installed_gaps'][]='installed_inventory_invalid';
            else {
                $rows=$installed['packages']??$installed;
                if (isset($installed['dev']) && is_bool($installed['dev'])) $out['installed_dev_mode']=$installed['dev'];
                if (!is_array($rows) || !array_is_list($rows)) $out['installed_gaps'][]='installed_package_list_invalid';
                else {
                    $seenInstalled=[];
                    foreach ($rows as $record) {
                        if (!$this->identity($record)) { $out['installed_gaps'][]='installed_package_identity_invalid'; continue; }
                        $name=$record['name'];
                        if (isset($seenInstalled[$name])) { unset($out['installed'][$name]); $out['installed_gaps'][]='installed_duplicate:'.$name; continue; }
                        $seenInstalled[$name]=true;
                        $out['installed'][$name]=array_replace($record,['evidence_source'=>$metadata]);
                    }
                    $out['installed_complete']=$out['installed_gaps']===[];
                }
            }
        }
        $config=$context->abs('app/etc/config.php');
        if (is_file($config) && (@filesize($config) ?: 0)<=4*1024*1024) {
            $source=$this->files->read($config);
            if (is_string($source)) {
                try { $out['declared_modules']=(new MagentoStaticPhp())->moduleStates($source); } catch (\PhpParser\Error) {}
                $out['sources']['module_declarations']=['path'=>'app/etc/config.php','sha256'=>hash('sha256',$source),'scope'=>'source_declaration'];
            }
        }
        $out['gaps']=array_merge($out['lock_gaps'],$out['installed_gaps']);
        return $out;
    }

    private function identity(mixed $record): bool
    {
        return is_array($record) && is_string($record['name']??null)
            && preg_match('~^[a-z0-9_.-]+/[a-z0-9_.-]+$~D',$record['name'])===1
            && is_string($record['version']??null) && trim($record['version'])!=='' && trim($record['version'])===$record['version'];
    }

    public function select(array $inventory, string $scope = 'current'): array
    {
        $rows=[];
        $installed=$scope!=='locked' && ($inventory['installed_present'] || $inventory['installed_metadata_path']===null);
        $records=$installed?$inventory['installed']:$inventory['locked'];
        foreach ($records as $name=>$record) {
            $locked=$inventory['locked'][$name]??null;
            $rows[$name]=array_replace($record,['dependency_observation'=>[
                'scope'=>$installed?'installed_dependency':'locked_dependency',
                'source_path'=>$record['evidence_source'], 'observed_at'=>$inventory['observed_at'],
                'installed'=>$installed?true:null, 'locked_version'=>$locked['version']??null,
                'development_dependency'=>$locked['development_dependency']??(isset($inventory['declared_require_dev'][$name])?true:null),
                'matches_locked_version'=>$installed && $locked!==null ? $record['version']===$locked['version'] : null,
                'runtime_reachability'=>'unverified', 'module_activation'=>'separate_declaration_only',
            ]]);
        }
        return ['packages'=>$rows,'scope'=>$installed?'installed_dependency':'locked_dependency',
            'complete'=>$installed?$inventory['installed_complete']:$inventory['lock_complete'],
            'gaps'=>$installed?$inventory['installed_gaps']:$inventory['lock_gaps'],
            'observed_at'=>$inventory['observed_at'],'sources'=>$inventory['sources'],
            'installed_dev_mode'=>$inventory['installed_dev_mode'],
            'excluded_locked_packages'=>$installed && $inventory['installed_complete']?array_values(array_diff(array_keys($inventory['locked']),array_keys($inventory['installed']))):[],
            'declared_modules'=>$inventory['declared_modules'],
            'coverage_note'=>'Composer metadata identifies recorded installation or locked build intent, not executable bytes, module activation or runtime reachability.'];
    }
}
