<?php
declare(strict_types=1);
namespace Magebean\Engine;
/** Project policy selects identities; it cannot rewrite an obligation. */
final class RequirementPolicy
{
    public static function requiresHuman(array $rule): bool
    {
        if (($rule['verification'] ?? 'automated') === 'manual' || !empty($rule['human_evidence']['required'])) return true;
        foreach ($rule['obligations'] ?? [] as $obligation) {
            if (($obligation['role'] ?? 'mandatory') !== 'supporting' && ($obligation['proof'] ?? '') === 'human') return true;
        }
        return false;
    }
    public static function resolveIds(array $ids, ?string $profile=null): array
    {
        $resolved=[];
        foreach ($ids as $id) {
            MagebeanRetirement::reject($id);
            $matches=RequirementCatalog::resolveAlias($id,$profile);
            if ($matches===[]) throw new \RuntimeException('Unknown requirement selector: '.$id);
            $resolved=array_merge($resolved,$matches);
        }
        return array_values(array_unique($resolved));
    }
    public static function apply(array $pack,array $config):array
    {
        if (($pack['assessment_model']??'')!=='internal-requirement-v1') return LegacyAsvsRequirementPolicy::apply($pack,$config);
        $profile=$pack['profile']['id']??null;
        $include=self::resolveIds(self::ids($config['include_rules']??$config['select_rules']??[]),$profile);
        $exclude=self::resolveIds(self::ids($config['exclude_rules']??[]),$profile);
        $excludeControls=$config['exclude_controls']??[];
        if (is_string($excludeControls)) $excludeControls=explode(',',$excludeControls);
        $overrides=[];
        foreach ($config['override_rules']??[] as $id=>$override) {
            if (!is_array($override)||array_diff(array_keys($override),['title','severity','messages','remediation'])!==[]) throw new \RuntimeException('Requirement overrides may change presentation/severity only. Identity, criterion and obligations are immutable.');
            if(isset($override['severity'])&&!in_array($override['severity'],['info','low','medium','high','critical'],true))throw new \RuntimeException('Invalid requirement severity override.');
            if(isset($override['title'])&&(!is_string($override['title'])||trim($override['title'])===''))throw new \RuntimeException('Requirement title override must be non-empty text.');
            $ids=self::resolveIds([strtoupper((string)$id)],$profile);
            if (count($ids)!==1) throw new \RuntimeException('Use a single internal requirement ID for an override; legacy aliases may fan out.');
            $overrides[$ids[0]]=$override;
        }
        $selected=[];
        foreach ($pack['rules'] as $r) {
            if ($include!==[]&&!in_array($r['id'],$include,true)) continue;
            if (in_array($r['id'],$exclude,true)||RequirementCatalog::matchesControls($r,$excludeControls)) continue;
            $presented=array_replace($r,$overrides[$r['id']]??[]);
            if (isset($overrides[$r['id']]['severity'])) $presented['presentation_severity_override']=true;
            $selected[]=$presented;
        }
        $pack['rules']=$selected;return $pack;
    }
    public static function hasCanonical(array $config):bool{return LegacyAsvsRequirementPolicy::hasCanonical($config);}
    public static function evidenceConfig(array $config):array{return LegacyAsvsRequirementPolicy::evidenceConfig($config);}
    private static function ids(mixed $raw):array
    {
        if(is_string($raw))$raw=explode(',',$raw);
        if(!is_array($raw))return [];
        return array_values(array_unique(array_filter(array_map(static fn($v):string=>strtoupper(trim((string)$v)),$raw))));
    }
}
