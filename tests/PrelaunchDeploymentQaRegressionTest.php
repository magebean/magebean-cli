<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\Context;
use Magebean\Engine\Checks\{BasicExposureCheck,FilesystemCheck,MagentoCheck,CheckRegistry};
$root=sys_get_temp_dir().'/mb-prelaunch-local-'.bin2hex(random_bytes(5));
$put=static function(string $path,string $text)use($root):void { @mkdir(dirname($root.'/'.$path),0755,true);file_put_contents($root.'/'.$path,$text); };
$n=0;$assert=static function(bool $ok,string $message)use(&$n):void { ++$n;if(!$ok)throw new RuntimeException($message); };
try {
 $put('app/etc/env.php','<?php return [];');$put('app/etc/config.php','<?php return [];');
 foreach(["zend_extension=xdebug.so\nzend_extension=opcache.so\n","zend_extension=opcache.so\nzend_extension=\"xdebug.so\" ; enabled\n"] as $ini) {
  $put('php.ini',$ini);$assert((new MagentoCheck(new Context($root,'')))->deploymentDebugFlagsDisabled([])[0]===false,'All repeatable extension declarations are inspected');
 }
 $put('php.ini',"zend_extension=xdebug.so\nzend_extension=opcache.so\nxdebug.mode=off\n");
 $assert((new MagentoCheck(new Context($root,'')))->deploymentDebugFlagsDisabled([])[0]===true,'Explicit disabled Xdebug mode preserves existing criterion');
 $put('php.ini',"zend_extension[]=xdebug.so\n");
 $assert((new MagentoCheck(new Context($root,'')))->deploymentDebugFlagsDisabled([])[0]===null,'Array-shaped extension declaration cannot yield a clean result');
 unlink($root.'/php.ini');
 mkdir($root.'/pub',0755);mkdir($root.'/media-target',0755);symlink($root.'/media-target',$root.'/pub/media');
 $assert((new BasicExposureCheck(new Context($root,'')))->mediaExecutableFiles([])[0]===null,'Root media symlink cannot yield a clean inventory');unlink($root.'/pub/media');rmdir($root.'/pub');
 mkdir($root.'/pub-target/media',0755,true);symlink($root.'/pub-target',$root.'/pub');
 $assert((new BasicExposureCheck(new Context($root,'')))->mediaExecutableFiles([])[0]===null,'Ancestor pub symlink cannot yield a clean inventory');unlink($root.'/pub');mkdir($root.'/pub/media',0755,true);
 mkdir($root.'/pub/media/a/b/c',0755,true);
 $assert((new BasicExposureCheck(new Context($root,'')))->mediaExecutableFiles(['max_entries'=>1])[0]===null,'Empty media directories consume traversal budget');
 $put('pub/media/evil.php','<?php');
 $assert((new BasicExposureCheck(new Context($root,'')))->mediaExecutableFiles([])[0]===false,'Concrete media filename remains actionable');
 unlink($root.'/pub/media/evil.php');
 $fs=new FilesystemCheck(new Context($root,''));
 $assert($fs->noWorldWritable(['strict_observation'=>true,'max_entries'=>1])[0]===null,'Permission budget cannot produce clean result');
 chmod($root,0777);
 $assert($fs->noWorldWritable(['strict_observation'=>true,'max_entries'=>1])[0]===false,'Observed permission counterexample survives traversal budget');chmod($root,0755);
 mkdir($root.'/pub/var/log',0755,true);
 $assert($fs->logsReportsNotInWebroot(['strict_scope'=>true,'max_entries'=>1])[0]===null,'Log inventory budget stays unknown');
 $assert($fs->logsReportsNotInWebroot(['strict_scope'=>true])[0]===false,'Concrete log placement remains actionable');
 mkdir($root.'/pub/static/frontend/Fixture/theme/en_US',0755,true);
 $assert($fs->staticContentDeployed(['strict_scope'=>true,'max_entries'=>1])[0]===null,'Static inventory budget cannot invent missing artifacts');
 $put('pub/static/frontend/Fixture/theme/en_US/app.css','body{}');
 $assert($fs->staticContentDeployed(['strict_scope'=>true])[0]===true,'Readable static artifact presence passes exact existential criterion');
 $put('generated/metadata/global.php','<?php');$put('generated/code/Factory.php','<?php');
 $assert($fs->diCompiled(['max_entries'=>1])[0]===null,'DI artifact traversal bound produces unknown');
 $assert($fs->diCompiled([])[0]===true,'Readable generated PHP artifacts pass presence criterion');
 // Representative tree: count all entries and prove configurable budget recovery.
 for($i=0;$i<1500;$i++)$put('tree/d'.intdiv($i,50).'/f'.$i.'.txt','x');
 $start=microtime(true);
 $assert($fs->noWorldWritable(['strict_observation'=>true,'path'=>'tree','max_entries'=>1000])[0]===null,'Representative 1500-file tree respects explicit entry bounds');
 $assert($fs->noWorldWritable(['strict_observation'=>true,'path'=>'tree','max_entries'=>5000])[0]===true,'Representative tree completes with sufficient budget');
 $elapsed=microtime(true)-$start;
 foreach(['fs_no_world_writable'=>['strict_observation'=>true], 'fs_logs_reports_not_in_webroot'=>['strict_scope'=>true], 'fs_static_content_deployed'=>['strict_scope'=>true], 'fs_di_compiled'=>[], 'basic_media_executable_files'=>[]] as $check=>$args){
  $registry=CheckRegistry::fromContext(new Context($root,''));$error=new UnexpectedValueException('worker cancellation');
  $registry->beginCollection(null,static function()use($error):void{throw $error;});$seen=false;
  try{$registry->run($check,$args);}catch(UnexpectedValueException $caught){$seen=$caught===$error;}finally{$registry->endCollection();}
  $assert($seen,'Original worker cancellation propagates through '.$check);
 }
 echo "Prelaunch deployment QA: $n assertions passed; representative tree ".round($elapsed,3)."s\n";
} finally {
 if(is_dir($root)){chmod($root,0755);$tree=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST);foreach($tree as$f)$f->isDir()&&!$f->isLink()?rmdir($f->getPathname()):unlink($f->getPathname());rmdir($root);}
}
