<?php
declare(strict_types=1);
require __DIR__ . '/../../../vendor/autoload.php';
use Magebean\Engine\Context;
use Magebean\Engine\Checks\Families\InputSafetySourceChecks;
use Magebean\Engine\Checks\Families\TemplateRequestSourceChecks;
use Magebean\Engine\Checks\Families\DataProtectionSourceChecks;
$root=sys_get_temp_dir().'/mb-source-feasibility-'.bin2hex(random_bytes(6));
mkdir($root);mkdir($root.'/app');
$cases=[
 ['command_unguarded',InputSafetySourceChecks::class,'commandExecutionSafety','<?php shell_exec($_GET["cmd"]);'],
 ['command_unrelated_guard',InputSafetySourceChecks::class,'commandExecutionSafety','<?php $safe=escapeshellarg("fixed"); shell_exec($_GET["cmd"]);'],
 ['command_comment_only',InputSafetySourceChecks::class,'commandExecutionSafety','<?php /* shell_exec($_GET["cmd"]); */ return 1;'],
 ['eval_unguarded',InputSafetySourceChecks::class,'dynamicExecutionSafety','<?php eval($_GET["cmd"]);'],
 ['eval_comment_only',InputSafetySourceChecks::class,'dynamicExecutionSafety','<?php /* eval($_GET["cmd"]); */ return 1;'],
 ['unserialize_untrusted_allowed_classes_false',InputSafetySourceChecks::class,'unserializeSafety','<?php unserialize($_GET["x"], ["allowed_classes"=>false]);'],
 ['csrf_empty_token',TemplateRequestSourceChecks::class,'csrfFormKey','<form method="post"><input name="form_key" value=""></form>'],
 ['csrf_missing_token',TemplateRequestSourceChecks::class,'csrfFormKey','<form method="post"><input name="x"></form>'],
 ['xml_unsafe',DataProtectionSourceChecks::class,'unsafeXmlParsing','<?php simplexml_load_string($x, null, LIBXML_NOENT);'],
 ['xml_unsafe_unrelated_blocked_word',DataProtectionSourceChecks::class,'unsafeXmlParsing','<?php $blocked = true; simplexml_load_string($x, null, LIBXML_NOENT);'],
];
$out=[];
try{
 foreach($cases as [$name,$class,$fn,$code]){
  file_put_contents($root.'/app/probe.phtml',$code);
  $r=(new $class(new Context($root,'')))->$fn(['paths'=>['app'],'include_ext'=>['php','phtml']]);
  $out[]=['case'=>$name,'outcome'=>$r[0]===true?'PASS':($r[0]===false?'FAIL':'UNKNOWN'),'message'=>$r[1]];
 }
 foreach(['missing','oversized','unreadable'] as $kind){
  if($kind==='oversized')file_put_contents($root.'/app/probe.phtml','<?php shell_exec($_GET["cmd"]);'.str_repeat(' ',1048577));
  if($kind==='unreadable'){file_put_contents($root.'/app/probe.phtml','<?php shell_exec($_GET["cmd"]);');chmod($root.'/app/probe.phtml',0000);}
  $r=(new InputSafetySourceChecks(new Context($root,'')))->commandExecutionSafety(['paths'=>[$kind==='missing'?'absent':'app'],'include_ext'=>['phtml']]);
  $out[]=['case'=>'command_'.$kind,'outcome'=>$r[0]===true?'PASS':($r[0]===false?'FAIL':'UNKNOWN'),'message'=>$r[1],'effective_uid'=>function_exists('posix_geteuid')?posix_geteuid():null];
 }
 file_put_contents(__DIR__.'/source-probes.json',json_encode($out,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES)."\n");
 echo json_encode($out,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES)."\n";
}finally{chmod($root.'/app/probe.phtml',0644);unlink($root.'/app/probe.phtml');rmdir($root.'/app');rmdir($root);}
