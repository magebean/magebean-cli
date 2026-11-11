<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\Context;
use Magebean\Engine\Checks\MagentoModuleIntegrityCheck;
use Magebean\Engine\Collectors\{CollectorSet,MagentoDiConfiguration};
$root=sys_get_temp_dir().'/mb-development-declarations-'.bin2hex(random_bytes(5));
$put=static function(string $path,string $source)use($root):void { @mkdir(dirname($root.'/'.$path),0700,true);file_put_contents($root.'/'.$path,$source); };
$n=0;$assert=static function(bool $ok,string $message)use(&$n):void { ++$n;if(!$ok)throw new RuntimeException($message); };
$run=static function(string $kind)use($root):array { $ctx=new Context($root,'','',['meta'=>['launch_profile'=>'development']]);$r=(new MagentoModuleIntegrityCheck($ctx,new CollectorSet()))->run(['kind'=>$kind]);return $r->evidence['magebean_detector_analysis']; };
try {
 $put('composer.json','{"require":{"magento/framework":"103.0.7"}}');
 $put('vendor/composer/installed.json',json_encode(['packages'=>[['name'=>'magento/framework','version'=>'103.0.7','install-path'=>'../magento/framework','autoload'=>['psr-4'=>['Magento\\Framework\\'=>'']]]]]));
 $put('vendor/magento/framework/Contract.php','<?php namespace Magento\\Framework; throw new \\RuntimeException("Must not execute dependencies"); interface Contract {}');
 $put('vendor/magento/framework/Base.php','<?php namespace Magento\\Framework; class Base { public function __construct(array $items=[]) {} }');
 $put('app/code/Fixture/Example/registration.php','<?php \\Magento\\Framework\\Component\\ComponentRegistrar::register(\\Magento\\Framework\\Component\\ComponentRegistrar::MODULE,"Fixture_Example",__DIR__);');
 $put('app/code/Fixture/Example/etc/module.xml','<config><module name="Fixture_Example"/></config>');
 $put('app/code/Fixture/Example/Impl.php','<?php namespace Fixture\\Example; class Impl extends \\Magento\\Framework\\Base implements \\Magento\\Framework\\Contract {}');
 $put('app/code/Fixture/Example/etc/di.xml','<config xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><preference for="Magento\\Framework\\Contract" type="Fixture\\Example\\Impl"/><type name="Fixture\\Example\\Impl"><arguments><argument name="items" xsi:type="array"/></arguments></type></config>');
 $ctx=new Context($root,'','',['meta'=>['launch_profile'=>'development']]);$set=new CollectorSet();$inventory=$set->magentoModules->collect($ctx);
 $configuration=(new MagentoDiConfiguration($set->session))->collect($ctx,$inventory);
 $assert($configuration['declaration_only']===true&&count($configuration['scopes'])===1,'No config uses independent source declaration scopes');
 $assert(!is_file($root.'/app/etc/config.php'),'Fixture does not invent deployment module state');
 foreach(['di-preference','di-arguments'] as $kind){$r=$run($kind);$assert($r['complete']&&$r['findings']===[],'Installed vendor reference closure resolves '.$kind.': '.json_encode($r));}
 $analysis=$set->magentoAnalysis->collect($ctx,['Fixture_Example'],['dependency_symbols'=>true]);
 $assert(isset($analysis['symbols']['magento\\framework\\contract'])&&isset($analysis['symbols']['magento\\framework\\base']),'PSR-4 dependency closure includes contracts and parents');
 $assert($analysis['symbols']['magento\\framework\\contract'][0]['module']===null,'Dependency context is not an audited module');
 $put('app/code/Fixture/Example/etc/di.xml','<config><virtualType name="CycleA" type="CycleB"/><virtualType name="CycleB" type="CycleA"/></config>');
 $r=$run('di-virtual-type');$assert(count($r['findings'])===2,'Source-only virtual type cycle is actionable');
 $assert(str_contains($r['findings'][0]['evidence']['reasoning'],'effective merged DI are not established'),'Source DI findings explicitly limit runtime claims');
 $put('app/code/Fixture/Example/etc/webapi.xml','<routes><route url="/V1/secrets" method="GET"><service class="Fixture\\Example\\Impl" method="execute"/><resources><resource ref="anonymous"/></resources></route></routes>');
 $r=$run('rest-anonymous');$assert(count($r['findings'])===1&&$r['findings'][0]['confidence']==='suspected','No-config source route remains a suspected declaration');
 $assert(!str_contains(json_encode($r['gaps']),'module enablement unavailable'),'Unknown activation does not suppress source declaration audit');
 $put('app/etc/config.php','<?php return ["modules"=>["Fixture_Example"=>0]];');
 $r=$run('rest-anonymous');$assert(count($r['findings'])===1,'Disabled module source declaration stays reviewable in development');
 $put('app/code/Fixture/Example/etc/webapi.xml','<routes><route url="/V1/example" method="GET"><service class="Fixture\\Example\\Impl" method="execute"/><resources><resource ref="Fixture_Example::missing"/></resources></route></routes>');
 $r=$run('rest-acl');$assert(count($r['findings'])===1&&str_contains($r['findings'][0]['evidence']['reasoning'],'runtime access are not established'),'Source ACL absence is suspected and scoped');
 echo "Development module declarations: $n assertions passed\n";
} finally {
 if(is_dir($root)){$tree=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST);foreach($tree as$f)$f->isDir()&&!$f->isLink()?rmdir($f->getPathname()):unlink($f->getPathname());rmdir($root);}
}
