<?php
declare(strict_types=1);
namespace Magebean\Engine;
/** Requirements have one owning family; reusable checks do not merge their conclusions. */
final class RequirementCatalog
{
    public static function loadAll(array $controls = []): array
    {
        $rules=[];$seen=[];
        foreach (['magebean','asvs','pci'] as $family) {
            $data=self::read($family.'-catalog');
            if (($data['family']??null)!==$family || !is_array($data['requirements']??null)) throw new \RuntimeException('Invalid requirement family catalog: '.$family);
            foreach ($data['requirements'] as $definition) {
                $id=$definition['id']??null;
                if (!is_string($id) || isset($seen[$id]) || ($definition['family']??null)!==$family) throw new \RuntimeException('Duplicate identity or invalid owning family in '.$family.' catalog.');
                if ($family === 'magebean' && RequirementPolicy::requiresHuman($definition)) {
                    throw new \RuntimeException('Active Magebean catalog cannot require human evidence: '.$id);
                }
                $seen[$id]=true;$rules[]=$definition;
            }
        }
        $inventoryCount=count($rules);
        if($controls!==[])$rules=array_values(array_filter($rules,static fn(array $r):bool=>self::matchesControls($r,$controls)));
        return ['assessment_model'=>'internal-requirement-v1','controls'=>self::controlIds($rules),'rules'=>$rules,'inventory_count'=>$inventoryCount];
    }
    public static function forProfile(string $name,array $capabilities=[],string $mode='LOCAL'):array
    {
        $profile=RequirementProfileCatalog::load($name);$index=array_column(self::loadAll()['rules'],null,'id');$rules=[];$omitted=[];
        foreach($profile['requirement_ids'] as $id){if(!isset($index[$id]))throw new \RuntimeException('Unknown internal requirement in profile: '.$id);$r=$index[$id];
            if(!in_array(strtoupper($mode),$r['target_modes'],true)){$omitted[]=['id'=>$id,'reason_code'=>'TARGET_MODE_UNSUPPORTED'];continue;}
            $cap=$r['applicability']['capability']??null;
            if($cap!==null && !self::enabled($capabilities,$cap)){$omitted[]=['id'=>$id,'reason_code'=>'CAPABILITY_CONTEXT_MISSING','capability'=>$cap];continue;}
            if(isset($profile['assessment_level']))$r['assessment_level']=$profile['assessment_level'];$rules[]=$r;
        }
        $meta=$profile;unset($meta['requirement_ids']);
        return ['assessment_model'=>'internal-requirement-v1','rules'=>$rules,'controls'=>self::controlIds($rules),'profile'=>$meta,'assessment_level'=>$profile['assessment_level']??null,'inventory_count'=>count($profile['requirement_ids']),'omitted_requirements'=>$omitted];
    }
    public static function matchesControls(array $definition,array $controls):bool{return array_intersect($controls,array_values(array_unique(array_merge([$definition['control']],$definition['control_tags']??[]))))!==[];}
    public static function controlIds(array $definitions):array{$ids=[];foreach($definitions as $definition)$ids=array_merge($ids,[$definition['control']],$definition['control_tags']??[]);return array_values(array_unique($ids));}
    public static function resolveAlias(string $id,?string $profile=null):array{return LegacyRequirementAliases::resolve($id,$profile);}
    public static function metadata():array{return ['schema_version'=>'1.0','assessment_model'=>'internal-requirement-v1','count'=>count(self::loadAll()['rules']),'identity_namespace'=>'MB-REQ','families'=>['magebean','asvs','pci'],'allocation'=>self::read('allocation-manifest')];}
    public static function read(string $file):array
    {
        $path=__DIR__.'/../Rules/requirements/'.$file.'.json';$text=file_get_contents($path);if($text===false)throw new \RuntimeException('Missing persisted requirement data: '.$file);return json_decode($text,true,512,JSON_THROW_ON_ERROR);
    }
    private static function enabled(array $caps,string $name):bool{return array_is_list($caps)?in_array($name,$caps,true):filter_var($caps[$name]??false,FILTER_VALIDATE_BOOLEAN);}
    /** Deprecated compiler compatibility. Primary catalog never calls this adapter. */
    public static function supports(array $profile):bool{return LegacyAsvsRequirementAdapter::supports($profile);}
    public static function compile(array $pack,array $profile,array $capabilities=[],bool $restrictToAvailable=false):array{return LegacyAsvsRequirementAdapter::compile($pack,$profile,$capabilities,$restrictToAvailable);}
}
