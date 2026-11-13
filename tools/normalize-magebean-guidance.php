<?php
declare(strict_types=1);
/** Editorial normalization only: criteria, checks, identities and profile membership are unchanged. */
$root=dirname(__DIR__);$dir=$root.'/src/Rules/requirements/';
$catalog=json_decode(file_get_contents($dir.'magebean-catalog.json'),true,512,JSON_THROW_ON_ERROR);
$audit=["# Magebean guidance review",'',"Scope: every Magebean catalog requirement. Guidance version 2 preserves the requirement-specific corrective action and verification. No criterion, check, profile membership or standards clause is changed.",'',"Findings must identify actual observations. Collection instructions explain scanner access; they do not establish a deployment vulnerability. An absent optional app/code directory produces no finding. Findings remain independent.",'',"| Requirement | Scope | Checks |",'| --- | --- | --- |'];
foreach($catalog['requirements']as&$r){
 $checks=array_values(array_unique(array_column($r['checks']??[],'name')));$names=implode(', ',$checks);$args=[];
 foreach($r['checks']??[]as$c)foreach($c['args']??[]as$key=>$value){
  if(!in_array($key,['file','files','path','paths','lock_file','json_file','env_file','config_path','config_paths','setting','settings','directory','directories'],true))continue;
  foreach(is_array($value)?$value:[$value]as$v)if(is_string($v)&&strlen($v)<180)$args[]=$v;
 }
 $scope=implode(', ',array_unique($args));
 if(preg_match('/(?:code_|automated_source)/',$names)){
  $category='application_source';$evidence='For each reported file and line, inspect the named construct and enclosing method; trace externally controlled values to the affected operation. Keep the reported construct separate from any unproven exploit path.';
  $validation='In a build or staging environment, exercise the affected feature with ordinary, malformed and unauthorized input as relevant to the reported operation; verify that legitimate behavior still works. Production rescanning remains read-only.';
 }elseif(preg_match('/composer_|dependency_/',$names)){
  $category='dependencies';$evidence='Match each reported package, locked version, advisory or policy field to composer.lock and composer.json in the scanned release; record the upstream response and collection time. Maintenance or version-policy observations alone do not establish an exploitable vulnerability.';
  $validation='Resolve the relevant Composer update in a reviewed build, inspect the lockfile diff and test Magento/module compatibility in staging before deployment. Rerun against the deployed lockfile and the same advisory/source policy.';
 }elseif(preg_match('/cron/',$names)){
  $category='scheduler';$evidence='Identify the exact installed scheduler source or cron_schedule job_code, status and timestamps in the evidence. Distinguish a missing entry, a slower schedule, stale successful execution and an overdue backlog; they need different corrective actions.';
  $validation='After the scheduler fix, observe a subsequent scheduled execution and inspect the affected job status and private cron logs. A crontab entry alone does not prove execution health; do not invoke cron jobs from the scanner.';
 }elseif(preg_match('/http_|runtime_|basic_sensitive_http|checkout_csp/',$names)){
  $category='http_response';$evidence='Use the exact reported URL, response status, redirect chain and header/cookie/certificate value. Identify whether Magento, the origin, reverse proxy or CDN produced the response before changing configuration; do not infer every route from one response.';
  $validation='Repeat the same read-only request from the scanner after deployment and compare the effective response, including redirects and edge caches. Test the affected storefront, Admin or checkout behavior in staging before rollout.';
 }elseif(preg_match('/secret|git_|env_not_tracked/',$names)){
  $category='secret_exposure';$evidence='Privately inspect only the reported file/line or repository reference; retain redacted evidence and verify whether the match is an active credential or expected test value. Do not paste secrets into findings, tickets or command output.';
  $validation='For a confirmed exposed credential, verify revocation at its issuer and application use of the replacement. Rerun the same file/history scope; removing the string does not invalidate previously exposed credentials.';
 }elseif(preg_match('/fs_|file_|readonly|upload_signatures|media_executable/',$names)){
  $category='filesystem';$evidence='Inspect each reported relative path, permission/owner, artifact signature or serving location. Confirm the actual deployment and PHP worker identities, ACLs, symlinks and document root; do not execute suspicious files or print protected file contents.';
  $validation='Verify access as the relevant runtime identity and retest the affected upload, cache or release feature after the scoped change. Rerun against the same deployment; avoid recursive permission changes unrelated to the reported paths.';
 }else{
  $category='deployment_configuration';$evidence='Compare the reported setting, module, role or runtime value with this exact criterion: '.$r['criterion'].' Identify the installed version, effective configuration source and applicable scope before making the specific change below.';
  $validation='Read back the effective setting or role/runtime state from the same source used by the check, then test the affected authentication, application or integration flow in staging. A changed file alone does not establish that the production worker uses it.';
 }
 $g=$r['finding_guidance'];$g['version']=2;$g['category']=$category;
 $g['interpretation']='Assessed requirement: '.$r['criterion'].' Interpret only the reported resources and collected scope; the finding is not proof of exploitation or of the state of unobserved components.';
 $g['expected_observation']=['checks'=>$checks,'declared_resources'=>array_values(array_unique($args)),'criterion'=>$r['criterion']];
 $g['triage']=[$evidence, 'Apply the requirement-specific corrective action only to resources supported by this finding. If the scanner only reports an access or parsing problem, resolve that named collection problem first; do not treat it as proof of the security violation.'];
 $g['verification']=array_values(array_unique(array_merge([$g['verification'][0]],[$validation,'Rerun '.$r['id'].' with the same profile, release and relevant target scope; compare the actual evidence and retain the new result.'])));
 $r['finding_guidance']=$g;
 // Keep the reviewed, requirement-specific change and functional verification; replace the generic closing paragraph.
 $r['remediation'][2]='Recheck '.$r['id'].': '.$validation;
 $audit[]='| '.$r['id'].' | '.$category.' | '.str_replace('|','/',$names).' |';
}
unset($r);$index=array_column($catalog['requirements'],null,'id');
$flags=JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR;
file_put_contents($dir.'magebean-catalog.json',json_encode($catalog,$flags)."\n");
$aggregate=json_decode(file_get_contents($dir.'internal-catalog.json'),true,512,JSON_THROW_ON_ERROR);
foreach($aggregate['requirements']as&$r)if(isset($index[$r['id']]))$r=$index[$r['id']];unset($r);
file_put_contents($dir.'internal-catalog.json',json_encode($aggregate,$flags)."\n");
file_put_contents($root.'/docs/archive/reviews/magebean-guidance-review.md',implode("\n",$audit)."\n");
echo 'Normalized '.count($index)." Magebean requirements; standards and requirement semantics unchanged.\n";
