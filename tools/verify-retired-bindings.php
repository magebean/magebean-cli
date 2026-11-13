<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\{Context,RequirementCatalog};
use Magebean\Engine\Checks\CheckRegistry;
$root=sys_get_temp_dir().'/mb-retirement-binding-probe-'.bin2hex(random_bytes(6));
mkdir($root,0700);
$rows=[];
try {
 foreach(RequirementCatalog::read('magebean-retirements')['requirements'] as $rule) {
  $checks=[];
  foreach($rule['checks'] as $check) {
   $registry=CheckRegistry::fromContext(new Context($root,''));
   if($check['name']==='system_egress_restricted') {
    $checks[]=['name'=>$check['name'],'registered'=>$registry->has($check['name']),'executed'=>false,'reason'=>'Host firewall probe deliberately excluded from empty-project fixture.'];
    continue;
   }
   $result=$registry->runResult($check['name'],$check['args']??[]);
   $checks[]=['name'=>$check['name'],'registered'=>$registry->has($check['name']),'executed'=>true,'outcome'=>$result->outcome->value,'message'=>$result->message];
  }
  $rows[]=['id'=>$rule['id'],'title'=>$rule['title'],'checks'=>$checks];
 }
} finally { rmdir($root); }
echo json_encode(['scope'=>'Empty temporary project, no runtime URL, no dependency lock, no host firewall probing. Direct handler outcomes only; not criterion qualification or evidence of impossibility.','rules'=>$rows],JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR)."\n";
