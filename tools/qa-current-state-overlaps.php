<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\{Context,RequirementCatalog,RequirementAssessmentEvaluator,MagebeanRiskObservation};
use Magebean\Engine\Checks\CheckRegistry;
$root=sys_get_temp_dir().'/mb-current-overlap-'.bin2hex(random_bytes(6));$rows=[];
$put=static function(string $p,string $t)use($root):void{if(!is_dir(dirname($root.'/'.$p)))mkdir(dirname($root.'/'.$p),0700,true);file_put_contents($root.'/'.$p,$t);};
$catalog=array_column(RequirementCatalog::read('magebean-catalog')['requirements'],null,'id');
$run=static function(string $id,string $case,Context $context)use($catalog,&$rows):void{
 $r=$catalog[$id];$reg=CheckRegistry::fromContext($context);$a=RequirementAssessmentEvaluator::evaluate($r,fn($name,$args)=>$reg->runResult($name,$args));$risk=MagebeanRiskObservation::fromAssessment($r,$a);
 $findings=array_values(array_filter($risk['findings'],static fn(array $f):bool=>($f['kind']??'')==='observed_issue'));
 $rows[]=['id'=>$id,'case'=>$case,'assessment'=>$a->outcome->value,'observed_findings'=>count($findings),'messages'=>array_column($findings,'message'),'locations'=>array_map(static fn(array$f):array=>$f['evidence']['locations']??$f['evidence']['files']??[], $findings),'collection_complete'=>$risk['collection_complete']];
};
try{
 $put('pub/media/unexpected.php','not executed');
 $ctx=new Context($root,'');foreach(['MB-0780','MB-0800']as$id)$run($id,'same_media_filename',$ctx);
 $put('composer.json','{"require":{"magento/framework":"103.0.7"}}');
 $put('vendor/composer/installed.json','{"packages":[{"name":"magento/framework","version":"103.0.7","install-path":"../magento/framework"}]}');
 $put('vendor/magento/framework/.keep','');
 $put('app/code/Acme/Probe/registration.php','<?php \Magento\Framework\Component\ComponentRegistrar::register(\Magento\Framework\Component\ComponentRegistrar::MODULE,"Acme_Probe",__DIR__);');
 $put('app/code/Acme/Probe/etc/module.xml','<config><module name="Acme_Probe"/></config>');
 $put('app/code/Acme/Probe/Runner.php','<?php namespace Acme\Probe; class Runner { public function run(){ \exec($_GET["command"]); } }');
 $ctx=new Context($root,'','',['meta'=>['launch_profile'=>'development']]);foreach(['MB-0790','MB-0822']as$id)$run($id,'same_request_command_location',$ctx);
 $put('app/code/Acme/Probe/Runner.php','<?php namespace Acme\Probe; class Runner { public function run(){ $logger->error("problem", ["request"=>$_POST]); } }');
 foreach(['MB-0795','MB-0814']as$id)$run($id,'same_request_logging_location',$ctx);
 echo json_encode(['scope'=>'read-only synthetic filenames/source; samplePHPneverexecuted','results'=>$rows],JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES)."\n";
}finally{if(is_dir($root)){$it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST);foreach($it as$f)$f->isDir()&&!$f->isLink()?rmdir($f->getPathname()):unlink($f->getPathname());rmdir($root);}}
