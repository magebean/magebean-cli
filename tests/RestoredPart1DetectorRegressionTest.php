<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\Context;
use Magebean\Engine\Checks\{CheckRegistry,SystemCheck};
$root=sys_get_temp_dir().'/mb-restored-part1-'.bin2hex(random_bytes(5));$server=null;$oldPath=getenv('PATH');
$put=static function(string $path,string $contents)use($root):void{@mkdir(dirname($root.'/'.$path),0755,true);file_put_contents($root.'/'.$path,$contents);};
$n=0;$assert=static function(bool $ok,string $why)use(&$n):void{++$n;if(!$ok)throw new RuntimeException($why);};
$run=static function(string $check,array $args=[])use($root):array{return CheckRegistry::fromContext(new Context($root,''))->run($check,$args);};
try {
 $put('app/etc/env.php','<?php return ["backend"=>["frontName"=>"privateadmin"]];');
 $put('nginx.conf','location /privateadmin/ { allow 127.0.0.1; deny all; }');
 $assert($run('magento_admin_exposure_restricted')[0]===null,'Unloaded server ACL example cannot prove Admin ingress restriction');
 $put('SECURITY.md','No mitigation exists. There is no expiry or rollback plan.');
 $assert($run('security_mitigations_documented')[0]===null,'Negated mitigation words cannot certify mitigation acceptance');
 $put('devops/logrotate.conf',"var/log/*.log {\n daily\n rotate 7\n compress\n}\n");$assert($run('fs_log_rotation_configured')[0]===true,'Supported explicit logrotate declaration remains automated');
 $put('devops/logrotate.conf',"var/log/*.log {\n rotate 0\n compress\n}\n");$assert($run('fs_log_rotation_configured')[0]===false,'Explicit zero retention is a real policy violation');
 $put('devops/logrotate.conf',"var/log/*.log {\n daily\n rotate 7\n compress\n}\nvar/log/error.log {\n daily\n rotate 0\n compress\n}\n");$assert($run('fs_log_rotation_configured')[0]===false,'An earlier valid log stanza cannot hide invalid retention');
 $put('devops/logrotate.conf',"rotate 7\ncompress\n");$assert($run('fs_log_rotation_configured')[0]===null,'Unrelated global words do not establish a target log declaration');
 $put('devops/logrotate.conf',"var/log/*.log {\n rotate 7\n compress\n}\n");$assert($run('fs_log_rotation_configured')[0]===null,'Missing cadence is unresolved rather than proof of no external host rotation');
 foreach(['hourly','daily','weekly','monthly','yearly','size 10M','minsize 100k','maxsize 1G'] as $cadence){$put('devops/logrotate.conf',"var/log/*.log {\n $cadence\n rotate 7\n compress\n}\n");$assert($run('fs_log_rotation_configured')[0]===true,'Supported candidate cadence: '.$cadence);}
 $put('devops/logrotate.conf',"var/log/a.log {\n daily\n rotate 7\n}\nvar/log/b.log {\n compress\n}\n");$assert($run('fs_log_rotation_configured')[0]===false,'Known missing compression survives another stanza missing cadence');
 $put('mockbin/ufw',"#!/bin/sh\nprintf 'Status: inactive\\n'\n");chmod($root.'/mockbin/ufw',0755);putenv('PATH='.$root.'/mockbin:'.$oldPath);
 foreach([["-P OUTPUT DROP\n",true],["-P OUTPUT DROP\n-A OUTPUT -m comment --comment qa -j ACCEPT\n",false],["-P OUTPUT DROP\n-A OUTPUT -j ANOTHER_CHAIN\n",null],["-P OUTPUT ACCEPT\n",false]] as [$text,$expected]){
  $put('mockbin/iptables',"#!/bin/sh\ncat <<'RULES'\n".$text."RULES\n");chmod($root.'/mockbin/iptables',0755);
  $assert((new SystemCheck(new Context($root,'')))->egressRestricted()[0]===$expected,'Firewall exceptions cannot be hidden by default policy: '.$text);
 }
 putenv('PATH='.$oldPath);
 $checks=['code_ssrf_safeguards','code_dynamic_execution_safety','code_path_traversal_safety','code_upload_safety','code_csprng_safety','code_unserialize_safety','code_command_execution_safety','code_raw_sql'];
 foreach($checks as$check)$assert($run($check,['paths'=>['absent'],'include_ext'=>['php']])[0]===null,'Unavailable source is UNKNOWN: '.$check);
 $put('app/code/Fixture/Check.php','<?php $fn="exec"; $fn($_GET["command"]);');
 foreach(['code_ssrf_safeguards','code_unserialize_safety','code_command_execution_safety','code_raw_sql'] as$check)$assert($run($check,['paths'=>['app/code']])[0]===null,'Indirect dispatch remains unresolved: '.$check);
 $put('app/code/Fixture/Check.php','<?php $db->query("SELECT * FROM records WHERE id = ?", [$id]);');
 $assert($run('code_raw_sql',['paths'=>['app/code']])[0]===true,'Bound values do not become dynamic SQL construction findings');
 $put('app/code/Fixture/Check.php','<?php $db->query("SELECT "."1");');
 $assert($run('code_raw_sql',['paths'=>['app/code']])[0]===true,'Concatenating only string literals does not create a dynamic query');
 $put('app/code/Fixture/Check.php','<?php $db->query("SELECT * FROM records WHERE id = ".$id);');
 $assert($run('code_raw_sql',['paths'=>['app/code']])[0]===false,'Direct concatenated SQL argument remains a candidate finding');
 $put('app/code/Fixture/Check.php','<?php eval($_GET["code"]);');
 $assert($run('code_dynamic_execution_safety',['paths'=>['app/code']])[0]===false,'Concrete dynamic execution pattern remains actionable');
 $socket=stream_socket_server('tcp://127.0.0.1:0');$host=stream_socket_get_name($socket,false);fclose($socket);
 $put('status.txt','403');$put('router.php','<?php $mode=trim(file_get_contents(__DIR__."/status.txt")); if($mode==="login"){echo "<input name=\"login[username]\">";} elseif($mode==="redirect"){header("Location: /landing");} elseif($mode==="plain"){echo "ordinary page";}else http_response_code((int)$mode);');
 $server=proc_open([PHP_BINARY,'-S',$host,$root.'/router.php'],[1=>['file',$root.'/server.log','a'],2=>['file',$root.'/server.log','a']],$pipes,$root);
 for($i=0;$i<100;$i++){if($socket=@stream_socket_client('tcp://'.$host,timeout:0.05)){fclose($socket);break;}usleep(10000);}
 $put('app/etc/config.php','<?php return '.var_export(['system'=>['default'=>['web'=>['secure'=>['base_url'=>'http://'.$host]]]]],true).';');
 foreach([['403',true],['plain',null],['redirect',null],['login',false]] as[$mode,$expected]){
  $put('status.txt',$mode);$assert($run('magento_admin_exposure_restricted',['timeout_ms'=>500])[0]===$expected,'Runtime Admin observation exact scope: '.$mode);
 }
 echo "Restored part1 detector regression: $n assertions passed\n";
} finally {
 putenv('PATH='.$oldPath);if(is_resource($server)){proc_terminate($server);proc_close($server);}
 if(is_dir($root)){$it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST);foreach($it as$f)$f->isDir()&&!$f->isLink()?rmdir($f->getPathname()):unlink($f->getPathname());rmdir($root);}
}
