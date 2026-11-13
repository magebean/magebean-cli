<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\Context;
use Magebean\Engine\Checks\CheckRegistry;
$archive=json_decode(file_get_contents(__DIR__.'/../src/Rules/requirements/magebean-retirements.json'),true)['requirements'];
$rows=array_slice($archive,0,20);$root=sys_get_temp_dir().'/mb-retirement-part1-'.bin2hex(random_bytes(5));
$put=static function(string $path,string $text)use($root):void{@mkdir(dirname($root.'/'.$path),0755,true);file_put_contents($root.'/'.$path,$text);};
$results=[];$pathBefore=getenv('PATH');
$run=static function(string $case,array $rule,array $overrides=[])use($root,&$results):void {
 foreach($rule['checks'] as $check){if($check['name']==='system_egress_restricted'&&$case!=='firewall-comment-bypass')continue;
  $args=array_replace($check['args']??[],$overrides);
  $result=CheckRegistry::fromContext(new Context($root,''))->run($check['name'],$args);
  $results[]=['case'=>$case,'id'=>$rule['id'],'check'=>$check['name'],'status'=>$result[0]===true?'PASS':($result[0]===false?'FAIL':'UNKNOWN'),'message'=>$result[1]??''];
 }
};
try {
 $put('app/etc/env.php','<?php return ["backend"=>["frontName"=>"privateadmin"]];');
 $put('app/code/Fixture/Neutral.php','<?php function fixtureNeutral() { return 1; }');@mkdir($root.'/app/design',0755,true);@mkdir($root.'/routes',0755,true);@mkdir($root.'/vendor');@mkdir($root.'/lib');
 foreach($rows as$rule)$run('neutral-source-no-lock',$rule);
 $payload= <<<'SOURCE'
<?php
class Webhook {
 public function execute() {
  $url=$_GET['url']; file_get_contents($url);
  eval($_GET['code']); file_get_contents('/tmp/'.$_GET['path']);
  move_uploaded_file($_FILES['f']['tmp_name'],$_GET['destination']);
  $passwordResetToken=rand(); session_start();
  $endpoint='http://api.example.test/receive';
 }
}
SOURCE;
 $put('app/code/Fixture/Webhook.php',$payload);$put('app/design/form.phtml','<form method="post" action="/save"><input name="secret"></form>');
 foreach($rows as$rule)if(str_starts_with($rule['checks'][0]['name'],'code_'))$run('literal-risk-source',$rule);
 $put('nginx.conf',"# Inactive example only; never loaded by a server\nlocation /privateadmin/ { allow 127.0.0.1; deny all; }\n");
 $run('unloaded-nginx-acl-hint',$rows[1]);
 chmod($root.'/app',0555);chmod($root.'/vendor',0555);chmod($root.'/lib',0555);chmod($root.'/app/etc',0555);chmod($root.'/app/code',0555);chmod($root.'/app/design',0555);chmod($root.'/app/code/Fixture',0555);
 foreach(new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root.'/app',FilesystemIterator::SKIP_DOTS))as$f)if($f->isFile())chmod($f->getPathname(),0444);
 $run('unix-modes-readonly',$rows[0]);
 chmod($root.'/app',0755);$run('owner-writable-mode',$rows[0]);
 $put('devops/logrotate.conf',"var/log/*.log {\n rotate 7\n compress\n}\n");$run('literal-valid-logrotate',$rows[9]);
 $put('devops/logrotate.conf',"var/log/*.log {\n rotate 0\n compress\n}\n");$run('zero-retention-logrotate',$rows[9]);
 $put('SECURITY.md','No mitigation exists. There is no expiry or rollback plan.');$run('negated-mitigation-words',$rows[12]);
 $put('mockbin/ufw',"#!/bin/sh\nprintf 'Status: inactive\\n'\n");$put('mockbin/iptables',"#!/bin/sh\nprintf '%s\\n' '-P OUTPUT DROP' '-A OUTPUT -m comment --comment qa -j ACCEPT'\n");chmod($root.'/mockbin/ufw',0755);chmod($root.'/mockbin/iptables',0755);putenv('PATH='.$root.'/mockbin:'.$pathBefore);
 $run('firewall-comment-bypass',$rows[19]);putenv('PATH='.$pathBefore);
 echo json_encode(['notes'=>'Direct handlers only; PASS/FAIL/UNKNOWN are observed handler outcomes, not security conclusions. No customer project or remote APIs used.','results'=>$results],JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES),"\n";
} finally {
 putenv('PATH='.$pathBefore);
 if(is_dir($root)){$tree=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::SELF_FIRST);foreach($tree as$f)if($f->isDir()&&!$f->isLink())chmod($f->getPathname(),0755);$tree=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST);foreach($tree as$f)$f->isDir()&&!$f->isLink()?rmdir($f->getPathname()):unlink($f->getPathname());rmdir($root);}
}
