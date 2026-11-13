<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\{RequirementCatalog, RequirementProfileCatalog, RequirementPolicy};
$p=RequirementProfileCatalog::load('takeover');
$assert=static function(bool $ok,string $message):void { if(!$ok) throw new RuntimeException($message); };
$assert(count($p['requirement_ids'])===86 && count(array_unique($p['requirement_ids']))===86,'Stable takeover membership');
$assert($p['automation_only']===true && $p['family']==='magebean','Automated Magebean profile');
$rules=array_column(RequirementCatalog::loadAll()['rules'],null,'id');
foreach($p['requirement_ids'] as $id) $assert($rules[$id]['family']==='magebean'&&!RequirementPolicy::requiresHuman($rules[$id]),'Automated family ownership '.$id);
foreach(['basic','module-integrity','module-source','module-lifecycle','module-reliability'] as $included) $assert(array_diff(RequirementProfileCatalog::load($included)['requirement_ids'],$p['requirement_ids'])===[],'Retain '.$included.' coverage');
foreach(['MB-0039','MB-0061','MB-0065','MB-0070','MB-0799','MB-0800'] as $id) $assert(in_array($id,$p['requirement_ids'],true),'Takeover operational scope '.$id);
foreach(['MB-0069','MB-0805','MB-0806','MB-0828'] as $id) $assert(!in_array($id,$p['requirement_ids'],true),'Avoid duplicate or agency-specific policies '.$id);
foreach(['LOCAL','REMOTE'] as $mode) {
 $pack=RequirementCatalog::forProfile('takeover',[],$mode);
 foreach($pack['rules'] as $r) $assert(in_array($mode,$r['target_modes'],true),'Target applicability is preserved');
 if($mode==='LOCAL') $assert(count($pack['rules'])===82,'Local default excludes two worker capabilities');
 else $assert(count($pack['rules'])>0&&count($pack['rules'])<86,'Remote coverage is limited');
}
$full=RequirementCatalog::forProfile('takeover',['runtime_worker_access','runtime_worker_inventory','log_rotation_config','cache_backend_policy'],'LOCAL');
$assert(count($full['rules'])===86,'Worker capabilities activate full membership');
$entry=$argv[1]??__DIR__.'/../bin/magebean';
foreach([['rules:list','--profile=takeover'],['audit','--help']] as $args) {
 $process=proc_open([PHP_BINARY,$entry,...$args,'--no-ansi'],[1=>['pipe','w'],2=>['pipe','w']],$pipes);
 $out=stream_get_contents($pipes[1]).stream_get_contents($pipes[2]); fclose($pipes[1]); fclose($pipes[2]);
 $assert(proc_close($process)===0,$out);
 $assert(str_contains($out,$args[0]==='rules:list'?'Total Rules Listed: 82':'takeover'),$out);
}
echo "Takeover profile passed\n";
