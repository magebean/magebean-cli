<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\{CheckOutcome, Context, MagebeanDetectorAnalysis};
use Magebean\Engine\Checks\{AutomatedSourcePolicyCheck, MagentoModuleSourceCheck};
use Magebean\Engine\Collectors\CollectorSet;
$root=sys_get_temp_dir().'/mb-development-source-qa-'.bin2hex(random_bytes(6));
$put=static function(string $file,string $text)use($root):void{if(!is_dir(dirname($root.'/'.$file)))mkdir(dirname($root.'/'.$file),0700,true);file_put_contents($root.'/'.$file,$text);};
$n=0;$assert=static function(bool $ok,string $message)use(&$n):void{++$n;if(!$ok)throw new RuntimeException($message);};
$context=new Context($root,'','',['meta'=>['launch_profile'=>'development','target_mode'=>'LOCAL']]);
$policy=static function(string $kind,string $source)use($put,$context){$put('app/code/Fixture/Module/Source.php',$source);return(new AutomatedSourcePolicyCheck($context))->run(['kind'=>$kind,'paths'=>['app/code'],'include_ext'=>['php']]);};
$module=['identity'=>'Fixture_Module','root'=>'app/code/Fixture/Module','package'=>null,'version'=>null];
$flow=static function(string $source)use($put,$context,$module):array{$put('app/code/Fixture/Module/Source.php',$source);return(new MagentoModuleSourceCheck($context,new CollectorSet()))->run('request-sinks',[$module['root']=>$module],['modules'=>[$module]],[])->evidence[MagebeanDetectorAnalysis::EVIDENCE_KEY];};
try{
 foreach(['return true;','return (true);','return (((true)));','/* deliberate */ return (/* note */ true);'] as $body) $assert($policy('csrf_unconditional_bypass','<?php class C { function validateForCsrf($r) {'.$body.'} }')->outcome===CheckOutcome::Fail,'Equivalent unconditional CSRF acceptance is found: '.$body);
 $assert($policy('csrf_unconditional_bypass','<?php class C { function validateForCsrf($r) { if ($r) return true; return null; } }')->outcome===CheckOutcome::Pass,'Conditional handling is outside unconditional bypass policy');
 foreach(['shell_execution'=>'exec','native_unserialize'=>'unserialize','native_upload'=>'move_uploaded_file','dynamic_execution'=>'create_function'] as $kind=>$name){
  $assert($policy($kind,'<?php namespace Fixture; function '.$name.'($v) {} '.$name.'("safe");')->outcome===CheckOutcome::Pass,'Namespace-local '.$name.' is not a native invocation');
  $assert($policy($kind,'<?php namespace Fixture; '.$name.'($input);')->outcome===CheckOutcome::Unknown,'Ambiguous namespace fallback cannot certify native identity: '.$name);
  $assert($policy($kind,'<?php namespace Fixture; \\'.$name.'($input);')->outcome===CheckOutcome::Fail,'Fully qualified global '.$name.' remains prohibited');
 }
 $assert($policy('shell_execution','<?php $callable=exec(...);')->outcome===CheckOutcome::Pass,'First-class callable creation is not itself invocation');
 foreach(['exec($_GET["x"])','\\exec(command: $_GET["x"])','\\proc_open(command: $_GET["x"], descriptor_spec: [], pipes: $pipes)','\\pcntl_exec(path: $_GET["x"])'] as $call){
  $analysis=$flow('<?php function action(){'.$call.';}');
  $assert(count($analysis['findings'])===1&&$analysis['complete'],'Global direct/named command request flow found: '.$call);
 }
 $analysis=$flow('<?php namespace Fixture; use function exec as run; function action(){run(command: $_POST["x"]);}');
 $assert(count($analysis['findings'])===1&&$analysis['complete'],'Resolved native alias participates in request flow');
 $analysis=$flow('<?php namespace Fixture; function exec($value) {} function action(){exec($_GET["x"]);}');
 $assert($analysis['findings']===[]&&$analysis['complete'],'Namespace-local command-shaped helper is not a shell flow');
 $analysis=$flow('<?php namespace Fixture; function action(){exec($_GET["x"]);}');
 $assert($analysis['findings']===[]&&!$analysis['complete']&&str_contains(json_encode($analysis['gaps']),'namespace resolution unavailable'),'Ambiguous namespaced command reports missing resolution');
 $analysis=$flow('<?php function action($db){$db->query(sql: $_GET["x"]);}');
 $assert($analysis['findings']===[]&&!$analysis['complete']&&str_contains(json_encode($analysis['gaps']),'argument binding unavailable'),'Unknown SQL named binding cannot yield a clean analysis');
 $analysis=$flow('<?php function action($db){$db->query("SELECT * FROM t WHERE id = ?", [$_GET["id"]]); \\exec((string) 123);}');
 $assert($analysis['findings']===[]&&$analysis['complete'],'Bound query values and unrelated command values are not request text flows');
 $put('composer.json','{"name":"fixture/project","require":{"magento/framework":"*"}}');
 $put('vendor/composer/installed.json','{"packages":[]}');
 $put('app/code/Fixture/Module/registration.php','<?php \\Magento\\Framework\\Component\\ComponentRegistrar::register(\\Magento\\Framework\\Component\\ComponentRegistrar::MODULE,"Fixture_Module",__DIR__);');
 $put('app/code/Fixture/Module/etc/module.xml','<config><module name="Fixture_Module"/></config>');
 $put('app/code/Fixture/Module/Source.php','<?php namespace Fixture; class Child extends \\Unavailable\\ParentClass { public function action() {} }');
 $analysis=(new MagentoModuleSourceCheck($context,new CollectorSet()))->run('php-contract',[$module['root']=>$module],[],[])->evidence[MagebeanDetectorAnalysis::EVIDENCE_KEY];
 $assert($analysis['findings']===[]&&!$analysis['complete']&&str_contains(json_encode($analysis['gaps']),'parent contract unresolved'),'Unavailable direct parent cannot silently complete contract analysis');
 echo "Development source QA regressions: $n assertions passed\n";
}finally{
 if(is_dir($root)){$tree=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST);foreach($tree as $file){if($file->isDir()&&!$file->isLink())rmdir($file->getPathname());else unlink($file->getPathname());}rmdir($root);}
}
