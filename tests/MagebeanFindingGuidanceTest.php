<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\{RequirementCatalog,Context,ScanRunner};
use Magebean\Engine\Reporting\HtmlReporter;
use Magebean\Agent\AgentScanner;
$n=0;function guideAssert(bool $v,string $m):void{global$n;++$n;if(!$v)throw new RuntimeException($m);}
$catalog=RequirementCatalog::read('magebean-catalog')['requirements'];
guideAssert(count($catalog)===110,'Review covers entire Magebean family including scoped automation additions');
foreach($catalog as$r){
 guideAssert(count($r['remediation']??[])>=3,'Change, verify and rerun guidance exists '.$r['id']);
 guideAssert(!empty($r['finding_guidance']['triage'])&&!empty($r['finding_guidance']['verification']),'Investigation and validation exist '.$r['id']);
 guideAssert(($r['finding_guidance']['version']??0)===2,'Current editorial version '.$r['id']);
 guideAssert(($r['finding_guidance']['expected_observation']['criterion']??'')===$r['criterion'],'Guidance follows exact requirement scope '.$r['id']);
 guideAssert(($r['finding_guidance']['expected_observation']['checks']??[])===array_values(array_unique(array_column($r['checks'],'name'))),'Guidance names actual checks '.$r['id']);
 guideAssert(count($r['finding_guidance']['verification'])>=3,'Functional verification and rescan are distinct '.$r['id']);
}
$aggregate=array_column(RequirementCatalog::read('internal-catalog')['requirements'],null,'id');
foreach($catalog as$r)guideAssert($aggregate[$r['id']]===$r,'Import aggregate and runtime catalog agree '.$r['id']);
foreach(['asvs','pci'] as$family)foreach(RequirementCatalog::read($family.'-catalog')['requirements']as$r)guideAssert(!isset($r['finding_guidance']),'Magebean editorial guidance does not rewrite standard clauses');
$root=sys_get_temp_dir().'/mb-guidance-'.bin2hex(random_bytes(5));mkdir($root.'/app/code/Example',0777,true);
try{
 file_put_contents($root.'/app/code/Example/Input.php',"<?php\n\$value = \$_GET['id'];\n");
 $rule=array_column($catalog,null,'id')['MB-0014'];
 $result=(new ScanRunner(new Context($root,''),['rules'=>[$rule]]))->run();$f=$result['findings'][0];
 guideAssert($f['status']==='FAIL','Real token policy violation retained');
 guideAssert(str_contains($f['message'],'does not establish exploitability'),'Policy evidence does not claim exploit');
 guideAssert($f['requirement']['finding_guidance']===$rule['finding_guidance'],'Structured interpretation reaches report');
 guideAssert(str_contains(implode(' ',$f['remediation']),'RequestInterface')&&str_contains(implode(' ',$f['remediation']),'does not validate'),'Input access is not marketed as validation');
 $wire=(new AgentScanner())->run($root,['schema_version'=>'1.0','manifest_hash'=>'sha256:guide','rules'=>[['rule_key'=>'MB-0014','assessment_item_id'=>'item']]])['results'][0];
 $ev=$wire['evidence']['obligations'][0]['checks'][0]['evidence'];
 guideAssert($ev['matches'][0]['file']==='app/code/Example/Input.php'&&$ev['matches'][0]['line']===2&&$ev['matches'][0]['variable']==='$_GET','Agent retains file, line and variable for Console');
 guideAssert(!str_contains(json_encode($wire),$root),'Agent does not expose installation root');
 file_put_contents($root.'/template.html','<html>{{table}}{{cve_section}}</html>');
 (new HtmlReporter($root.'/template.html',true))->write($result,$root.'/report.html');
 $html=file_get_contents($root.'/report.html');
 guideAssert(str_contains($html,'Remediation guidance')&&str_contains($html,'Verification after remediation')&&str_contains($html,'RequestInterface'),'Detailed export carries usable next actions');
 echo "MagebeanFindingGuidanceTest: $n assertions passed\n";
}finally{foreach(['report.html','template.html','app/code/Example/Input.php']as$f)if(is_file($root.'/'.$f))unlink($root.'/'.$f);rmdir($root.'/app/code/Example');rmdir($root.'/app/code');rmdir($root.'/app');rmdir($root);}
