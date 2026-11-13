<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\Checks\{MagentoDiCheck, DependencyPolicyCheck};
use Magebean\Engine\{Context};
use Magebean\Engine\Collectors\CollectorSet;
$root=sys_get_temp_dir().'/mb-current-state-part3-'.bin2hex(random_bytes(6));mkdir($root,0700);
$results=[];
try {
 $check=new MagentoDiCheck(new Context($root,''),new CollectorSet());$inspect=new ReflectionMethod($check,'inspect');
 $base=['kind'=>'class','abstract'=>false,'final'=>false,'traits'=>[],'extends'=>[],'implements'=>[],'methods'=>[]];
 $parent=$base+['name'=>'Fixture\ParentType'];$parent['methods']['__construct']=['visibility'=>'private','parameters'=>[]];
 $child=$base+['name'=>'Fixture\ChildType'];$child['extends']=['Fixture\ParentType'];$child['implements']=['Fixture\Contract'];
 $contract=['kind'=>'interface','abstract'=>false,'final'=>false,'traits'=>[],'extends'=>[],'implements'=>[],'methods'=>[],'name'=>'Fixture\Contract'];
 $symbols=['fixture\parenttype'=>[$parent],'fixture\childtype'=>[$child],'fixture\contract'=>[$contract]];
 $table=['preference'=>['Fixture\Contract'=>['target'=>'Fixture\ChildType']]];
 $results[]=['rules'=>['MB-0815','MB-0816','MB-0818'],'case'=>'Preference resolves to child inheriting private constructor','actual'=>$inspect->invoke($check,'di-preference','Fixture\Contract',null,[],$table,$symbols),'expected_scope'=>'Do not certify instantiability without checking inherited construction'];
 class QaCurrentStatePrivateParent { private function __construct(){} }
 class QaCurrentStatePrivateChild extends QaCurrentStatePrivateParent {}
 try {new QaCurrentStatePrivateChild();$runtime='instantiable';}catch(Throwable$e){$runtime=get_class($e).': '.$e->getMessage();}
 $results[]=['rules'=>['MB-0815','MB-0816'],'case'=>'PHP runtime cross-check of same synthetic inheritance pattern','actual'=>$runtime];
 $target=$base+['name'=>'Fixture\CallableSubject'];$target['methods']['__construct']=['visibility'=>'public','parameters'=>[['name'=>'callback','type'=>'callable','variadic'=>false]]];
 $results[]=['rules'=>['MB-0817'],'case'=>'Unexamined array assigned to callable constructor parameter','actual'=>$inspect->invoke($check,'di-arguments','Fixture\CallableSubject','callback',['type'=>'array'],[],['fixture\callablesubject'=>[$target]]),'qualification'=>'This checks array type compatibility, not that an arbitrary array is callable.'];
 $source=['url'=>'https://example.invalid/repository.git','reference'=>'approved-fixture-revision'];
 foreach(['1.0.0','']as$version){
  file_put_contents($root.'/composer.lock',json_encode(['packages'=>[['name'=>'fixture/package','version'=>$version,'source'=>$source]]]));
  file_put_contents($root.'/composer.json','{}');file_put_contents($root.'/policy.json',json_encode(['schema_version'=>1,'packages'=>['fixture/package'=>['source'=>$source]],'root_repositories'=>[]]));
  $result=(new DependencyPolicyCheck(new Context($root,'')))->sourcePolicy(['policy_file'=>'policy.json']);
  $results[]=['rules'=>['MB-0805'],'case'=>'Exact source policy with package version '.json_encode($version),'actual'=>$result[0]===true?'PASS':($result[0]===false?'FAIL':'UNKNOWN'),'message'=>$result[1]];
 }
 echo json_encode(['scope'=>'Synthetic direct-helper probes, not a full Magento runtime or live-store audit.','observations'=>$results],JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR)."\n";
}finally{foreach(['composer.lock','composer.json','policy.json']as$f)if(is_file($root.'/'.$f))unlink($root.'/'.$f);rmdir($root);}
