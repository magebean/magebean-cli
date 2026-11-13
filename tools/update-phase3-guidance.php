<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\MagebeanFindingSemantics;
foreach (['magebean-catalog','internal-catalog'] as $name) {
    $path=__DIR__.'/../src/Rules/requirements/'.$name.'.json';
    $data=json_decode(file_get_contents($path),true,512,JSON_THROW_ON_ERROR);
    foreach ($data['requirements'] as &$rule) {
        if (($rule['family']??'')!=='magebean') continue;
        $semantics=MagebeanFindingSemantics::profile($rule['id']);
        $guidance=MagebeanFindingSemantics::guidance($rule,$semantics);
        $rule['finding_guidance']['observation_semantics']=$semantics+['confidence_basis'=>'Observed condition only; exploitability and runtime reachability require separate evidence.'];
        if (in_array($semantics['category'],['policy','informational'],true) || $semantics['confidence']==='suspected') {
            $rule['finding_guidance']['risk']=$guidance['impact'];
            $rule['finding_guidance']['triage']=[$guidance['action'],'Use the reported file/line, configuration key, module/area or package/version evidence. Resolve independent collection gaps separately.'];
            $rule['finding_guidance']['verification']=[$guidance['verification'],$guidance['recheck'],'Confirm the real trust boundary or operational behavior separately; a passing bounded predicate is not overall store assurance.'];
            $rule['remediation']=[$guidance['action'],$guidance['verification'],$guidance['recheck']];
        }
    }
    unset($rule);
    file_put_contents($path,json_encode($data,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR)."\n");
}
