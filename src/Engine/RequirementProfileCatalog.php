<?php
declare(strict_types=1);
namespace Magebean\Engine;
final class RequirementProfileCatalog
{
    public static function load(string $name):array
    {
        if(is_file($name)){$p=json_decode((string)file_get_contents($name),true,512,JSON_THROW_ON_ERROR);if(!is_array($p['requirement_ids']??null))throw new \RuntimeException('Primary profiles require requirement_ids.');$p+=['id'=>basename($name,'.json'),'title'=>'Custom requirements'];return self::validate($p);}
        $name=strtolower(trim($name));$name=['default'=>'basic','best-practices'=>'basic','owasp'=>'owasp-top-10-2025','pci'=>'pci-dss-v4.0.1','pci-dss'=>'pci-dss-v4.0.1','production'=>'hardening','production-hardening'=>'hardening'][$name]??$name;
        $all=RequirementCatalog::read('internal-profiles')['profiles'];foreach($all as $key=>$p)if($key===$name||in_array($name,$p['aliases']??[],true))return self::validate($p);throw new \RuntimeException('Unknown internal requirement profile: '.$name);
    }
    public static function all():array{return RequirementCatalog::read('internal-profiles')['profiles'];}
    private static function validate(array $p):array
    {
        if(!is_array($p['requirement_ids']??null))throw new \RuntimeException('Profile requires requirement_ids.');$known=array_column(RequirementCatalog::loadAll()['rules'],null,'id');$seen=[];
        foreach($p['requirement_ids'] as $id){if(!is_string($id)||preg_match('/^MB-[0-9]+$/D',$id)!==1)throw new \RuntimeException('Unknown internal requirement identity in profile.');MagebeanRetirement::reject($id);$resolved=isset($known[$id])?[$id]:LegacyRequirementAliases::resolve($id);if(count($resolved)!==1||!isset($known[$resolved[0]]))throw new \RuntimeException('Unknown internal requirement identity in profile.');$seen[$resolved[0]]=true;}
        $p['requirement_ids']=array_keys($seen);
        if (in_array($p['id']??'', ['basic','hardening','owasp-top-10-2025','module-integrity','module-source','module-lifecycle','module-reliability','development','prelaunch'],true)) {
            if (($p['automation_only']??false)!==true || !empty($p['evidence_tasks'])) throw new \RuntimeException('Magebean profiles must be automated-only without manual evidence tasks.');
            foreach ($p['requirement_ids'] as $id) if (RequirementPolicy::requiresHuman($known[$id])) throw new \RuntimeException('Magebean profiles cannot include human-evidence requirements: '.$id);
        }
        if (($p['id']??'')==='hardening') {
            $profiles=RequirementCatalog::read('internal-profiles')['profiles'];
            foreach (['basic','owasp-top-10-2025'] as $included) {
                if (array_diff($profiles[$included]['requirement_ids'],$p['requirement_ids'])!==[]) throw new \RuntimeException('Hardening must include all requirements from '.$included.'.');
            }
            foreach ($profiles['basic']['evidence_tasks']??[] as $task) {
                if (!in_array($task,$p['evidence_tasks']??[],true)) throw new \RuntimeException('Hardening must retain Basic external evidence tasks.');
            }
        }
        $families=[];foreach($p['requirement_ids'] as $id)$families[$known[$id]['family']]=true;
        if(count($families)>1)throw new \RuntimeException('A requirement profile cannot mix Magebean, ASVS and PCI families.');
        $family=$p['family']??array_key_first($families);
        if($family!==null&&!in_array($family,['magebean','asvs','pci'],true))throw new \RuntimeException('Unknown requirement profile family.');
        if($families!==[]&&!isset($families[$family]))throw new \RuntimeException('Requirement profile family does not match its members.');
        $expected=match($p['id']??''){'basic','hardening','owasp-top-10-2025','module-integrity','module-source','module-lifecycle','module-reliability','development','prelaunch'=>'magebean','asvs-l1','asvs-l2','asvs-l3'=>'asvs','pci','pci-dss-v4.0.1'=>'pci',default=>null};
        if($expected!==null&&$family!==$expected)throw new \RuntimeException('Built-in profile must use its own requirement family.');
        if ($family === 'magebean' && !empty($p['evidence_tasks'])) throw new \RuntimeException('Magebean profiles cannot include manual evidence tasks.');
        if($family!==null)$p['family']=$family;
        if(isset($p['assessment_level'])&&!in_array($p['assessment_level'],[1,2,3],true))throw new \RuntimeException('Invalid profile assessment level.');return $p;
    }
}
