<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\Context;
use Magebean\Engine\Checks\CheckRegistry;
$archive=array_column(json_decode(file_get_contents(__DIR__.'/../src/Rules/requirements/magebean-retirements.json'),true,512,JSON_THROW_ON_ERROR)['requirements'],null,'id');
$base=sys_get_temp_dir().'/mb-retirement-part3-'.bin2hex(random_bytes(6));mkdir($base,0700);
$cases=[];$seq=0;$server=null;
$probe=static function(string $id,string $case,array $files,array $context=[],array $override=[])use(&$cases,&$seq,$base,$archive):void{
 $root=$base.'/case'.(++$seq);mkdir($root,0700);
 foreach($files as$path=>$text){if(!is_dir(dirname($root.'/'.$path)))mkdir(dirname($root.'/'.$path),0700,true);file_put_contents($root.'/'.$path,$text);}
 $binding=$archive[$id]['checks'][0];$args=array_replace($binding['args']??[],$override);
 $out=CheckRegistry::fromContext(new Context($root,'','',$context))->run($binding['name'],$args);
 $cases[]=['id'=>$id,'case'=>$case,'binding'=>$binding['name'],'overrides'=>$override,'result'=>$out[0]===true?'PASS':($out[0]===false?'FAIL':'UNKNOWN'),'message'=>str_replace($root,'<FIXTURE>',(string)($out[1]??'')),'untested_bindings'=>array_column(array_slice($archive[$id]['checks'],1),'name')];
};
$php=static fn(array $arr):string=>'<?php return '.var_export($arr,true).';';
try{
 $rows=['admin_user'=>[['user_id'=>1,'username'=>'fixture-admin','is_active'=>1]],'authorization_role'=>[['role_id'=>1,'parent_id'=>0,'role_type'=>'G','user_id'=>0,'role_name'=>'Administrators'],['role_id'=>2,'parent_id'=>1,'role_type'=>'U','user_id'=>1,'role_name'=>'Fixture']], 'authorization_rule'=>[['rule_id'=>1,'role_id'=>1,'resource_id'=>'Magento_Backend::all','permission'=>'allow']]];
 $probe('MB-0101','global grant without approvals',[],['admin_acl_rows'=>$rows]);
 $probe('MB-0101','same grant explicitly approved',[],['admin_acl_rows'=>$rows],['approved_global_role_ids'=>[1],'approved_global_user_ids'=>[1]]);
 $probe('MB-0102','missing account evidence',[]);
 $probe('MB-0102','malformed account evidence',['.magebean/pci/2.2.2-vendor-default-accounts.json'=>'{}']);
 foreach([4,12]as$min)$probe('MB-0731','configured minimum '.$min,['app/etc/config.php'=>$php(['system'=>['default'=>['admin'=>['security'=>['min_password_length'=>$min]]]]])]);
 foreach([
  'MB-0732'=>['rawQuery'=>'<?php $db->rawQuery("SELECT * FROM customer WHERE id=".$_GET["id"]);','bound query'=>'<?php $db->query("SELECT * FROM customer WHERE id = ?", [$id]);','indirect sql'=>'<?php $f="rawQuery"; $db->$f($sql);'],
  'MB-0733'=>['raw template'=>'<?= $value ?>','html helper'=>'<?= $escaper->escapeHtml($value) ?>','wrong JS context helper'=>'<script>const x = "<?= $escaper->escapeHtml($value) ?>";</script>'],
  'MB-0734'=>['native unsafe'=>'<?php unserialize($_GET["x"]);','classes disabled'=>'<?php unserialize($payload, ["allowed_classes"=>false]);','indirect unsafe'=>'<?php call_user_func("unserialize", $_GET["x"]);'],
  'MB-0735'=>['request command'=>'<?php exec($_GET["x"]);','constant command'=>'<?php exec("whoami");','indirect command'=>'<?php $fn="exec"; $fn($_GET["x"]);'],
  'MB-0736'=>['raw JS'=>'<script>const x = "<?= $value ?>";</script>','JS helper'=>'<script>const x = "<?= $escaper->escapeJs($value) ?>";</script>','wrong HTML helper'=>'<script>const x = "<?= $escaper->escapeHtml($value) ?>";</script>'],
  'MB-0737'=>['named password log'=>'<?php $logger->info($password);','neutral payload log'=>'<?php $logger->info($value);','unrelated mask comment'=>'<?php /* mask unrelated data elsewhere */ $logger->info($password);'],
  'MB-0743'=>['named email log'=>'<?php $logger->info($email);','neutral payload log'=>'<?php $logger->info($value);'],
  'MB-0746'=>['gateway log'=>'<?php $gateway->send($request); $logger->info($password);','unrelated redact comment'=>'<?php /* redact is documentation only */ $gateway->send($request); $logger->info($password);'],
 ]as$id=>$variants)foreach($variants as$label=>$source){$ext=in_array($id,['MB-0733','MB-0736'],true)?'phtml':'php';$probe($id,$label,['app/code/Fixture/Example/Subject.'.$ext=>$source]);}
 foreach([['zend_extension=xdebug.so', 'enabled extension'],['xdebug.mode=off', 'mode off only']]as[$ini,$label])$probe('MB-0738',$label,['php.ini'=>$ini]);
 foreach(['On','Off']as$value)$probe('MB-0739','display_errors '.$value,['php.ini'=>'display_errors='.$value]);
 foreach([0,1]as$value){
  $probe('MB-0740','template_hints '.$value,['app/etc/env.php'=>$php(['system'=>['default'=>['dev/debug/template_hints'=>$value]]])]);
  $probe('MB-0742','inline translation '.$value,['app/etc/env.php'=>$php(['system'=>['default'=>['dev/translate_inline/active'=>$value]]])]);
  $probe('MB-0745','payment debug '.$value,['app/etc/env.php'=>$php(['system'=>['default'=>['payment'=>['fixture'=>['debug'=>$value]]]]])]);
 }
 foreach(['Cm_Cache_Backend_File','Cm_Cache_Backend_Redis']as$backend)$probe('MB-0741','backend '.$backend,['app/etc/env.php'=>$php(['cache'=>['frontend'=>['default'=>['backend'=>$backend]]]])]);
 $probe('MB-0741','both frontend Redis declarations',['app/etc/env.php'=>$php(['cache'=>['frontend'=>['default'=>['backend'=>'Cm_Cache_Backend_Redis'],'page_cache'=>['backend'=>'Cm_Cache_Backend_Redis']]]])]);
 $probe('MB-0744','no lock data',[]);
 $probe('MB-0744','valid library inventory unavailable status',['composer.lock'=>json_encode(['packages'=>[['name'=>'fixture/library','version'=>'1.0.0','type'=>'library']]])],[],['status_endpoint'=>'invalid']);
 // Test the real package-status transport/parser against a loopback fixture.
 $socket=stream_socket_server('tcp://127.0.0.1:0');$address=stream_socket_get_name($socket,false);fclose($socket);
 file_put_contents($base.'/status-mode.json','null');
 file_put_contents($base.'/router.php', '<?php header("Content-Type: application/json"); $mode=json_decode(file_get_contents(__DIR__."/status-mode.json"),true); echo json_encode(["schema_version"=>"magebean-package-status-response-v1","packages"=>[["name"=>"fixture/library","abandoned_status_known"=>$mode!==null,"abandoned"=>$mode===true]]]);');
 $server=proc_open([PHP_BINARY,'-S',$address,$base.'/router.php'],[1=>['file',$base.'/server.log','a'],2=>['file',$base.'/server.log','a']],$pipes);
 if(!is_resource($server))throw new RuntimeException('Cannot start package-status fixture');
 $ready=false;for($i=0;$i<100;$i++){$socket=@stream_socket_client('tcp://'.$address,timeout:0.05);if($socket){fclose($socket);$ready=true;break;}usleep(10000);}if(!$ready)throw new RuntimeException('Package-status fixture unavailable');
 foreach([true,false,null]as$status){
  file_put_contents($base.'/status-mode.json',json_encode($status));
  foreach([false,true]as$strict){
   $probe('MB-0744','loopback abandoned='.json_encode($status).($strict?' active MB-0061 strict scope':' archived args'),['composer.lock'=>json_encode(['packages'=>[['name'=>'fixture/library','version'=>'1.0.0','type'=>'library']]])],[],['status_endpoint'=>'https://'.$address,'timeout_ms'=>1000,'token'=>'','strict_scope'=>$strict]);
  }
 }
 $probe('MB-0747','synthetic test PAN',['var/log/payment.log'=>'{"card_number":"4111111111111111"}']);
 $probe('MB-0747','no log inventory',[]);
 $probe('MB-0748','PHP disguised as image',['pub/media/picture.jpg'=>'<?php echo "inert fixture";']);
 $probe('MB-0748','non-PHP shebang signature',['pub/media/script.txt'=>"#!/usr/bin/env python\nprint('fixture')\n"]);
 $probe('MB-0748','no upload inventory',[]);
 echo json_encode(['description'=>'Direct archived handlers, not requirement assessments. API and HTTP exclusions are explicit.','cases'=>$cases],JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR)."\n";
}finally{
 if(is_resource($server)){proc_terminate($server);proc_close($server);}
 $it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($base,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST);
 foreach($it as$f){if($f->isDir()&&!$f->isLink())rmdir($f->getPathname());else unlink($f->getPathname());}rmdir($base);
}
