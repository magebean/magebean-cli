<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\Checks\HttpCheck;
use Magebean\Engine\Collectors\{HttpCollector, CollectorSet, CollectionSession};
use Magebean\Engine\Context;
$n=0;$assert=static function(bool $ok,string $message)use(&$n):void{++$n;if(!$ok)throw new RuntimeException($message);};
$exercise=static function(string $base)use($assert):void{
 $collector=new HttpCollector();
 $late=(new HttpCheck(new Context('.', $base)))->dispatch('http_no_directory_listing',['strict_scope'=>true,'paths'=>['/late/']]);
 $assert($late[0]===false,'Directory index after the former 8KiB cutoff must be detected');
 $redirect=(new HttpCheck(new Context('.', $base.'/redirect')))->dispatch('http_force_https_redirect',['strict_scope'=>true]);
 $assert($redirect[0]===null&&($redirect[2]['checked'][0]['location_count']??0)===2,'Conflicting duplicate Location cannot confirm a secure redirect');
 $single=(new HttpCheck(new Context('.', $base.'/single')))->dispatch('http_force_https_redirect',['strict_scope'=>true]);
 $assert($single[0]===true,'Single direct same-host HTTPS redirect remains valid');
 foreach(['/large-body'=>'body','/large-header'=>'headers']as$path=>$part){
  $r=$collector->fetch($base.$path,follow:false);
  $assert($r[0]===null,'Oversize '.$part.' cannot produce a complete response');
  $assert(!isset($r[2]['body']),'Incomplete responses do not leak retained response bodies');
  if($part==='body')$assert(($r[2]['reason_code']??'')==='HTTP_RESPONSE_LIMIT_EXCEEDED','Body budget is explicitly reported');
 }
 $short=$collector->fetch($base.'/short-body',follow:false);
 $assert($short[0]===null&&!isset($short[2]['body']),'A truncated declared response cannot complete collection');
 $huge=(new HttpCheck(new Context('.', $base)))->dispatch('http_no_directory_listing',['strict_scope'=>true,'paths'=>['/large-body']]);
 $assert($huge[0]===null,'A body budget cannot create a clean directory listing conclusion');
};
if(($argv[1]??'')==='--stream-client'){$exercise($argv[2]);echo "Stream HTTP bounds passed\n";exit;}
if(($argv[1]??'')==='--tls-server'){
 $ctx=stream_context_create(['ssl'=>['local_cert'=>$argv[2].'/cert.pem','local_pk'=>$argv[2].'/key.pem','verify_peer'=>false]]);
 $server=stream_socket_server('tls://'.$argv[3],$errno,$error,STREAM_SERVER_BIND|STREAM_SERVER_LISTEN,$ctx);
 if(!$server)throw new RuntimeException($error);
 while(true){$client=@stream_socket_accept($server,2);if(!$client)continue;$request=(string)fgets($client);while(($line=fgets($client))!==false&&trim($line)!==''){}
  $cookie='Set-Cookie: PHPSESSID=x; Secure; HttpOnly; SameSite=Lax; SameSite=None' . "\r\n";
  if(str_contains($request,'/safe'))$cookie='Set-Cookie: PHPSESSID=x; Secure; HttpOnly; SameSite=Lax' . "\r\n";
  elseif(str_contains($request,'/preference'))$cookie='Set-Cookie: admin_theme=dark; SameSite=Lax' . "\r\n";
  elseif(str_contains($request,'/bad'))$cookie.='Set-Cookie: frontend=x; SameSite=Lax' . "\r\n";
  @fwrite($client,"HTTP/1.1 200 OK\r\n".$cookie."Content-Length: 2\r\nConnection: close\r\n\r\nok");fclose($client);
 }
}
if(($argv[1]??'')==='--tls-client'){
 foreach(['/safe'=>true,'/ambiguous'=>null,'/bad'=>false,'/preference'=>null]as$path=>$expected){
  $r=(new HttpCheck(new Context('.', $argv[2], '', ['meta'=>['launch_profile'=>'prelaunch']])))->dispatch('http_cookie_flags',['strict_scope'=>true,'paths'=>[$path]]);
  $assert($r[0]===$expected,'Cookie result '.$path.': '.json_encode($r));
  if($path==='/bad')$assert(count($r[2]['failures'])===1&&count($r[2]['incomplete_paths'])===1,'Known bad cookie and ambiguous cookie remain separate observations');
 }
 echo "TLS cookie ambiguity passed\n";exit;
}
$root=sys_get_temp_dir().'/mb-prelaunch-http-regression-'.bin2hex(random_bytes(6));mkdir($root);$servers=[];
$port=static function():string{$s=stream_socket_server('tcp://127.0.0.1:0');$address=stream_socket_get_name($s,false);fclose($s);return $address;};
$start=static function(array $command,string $address)use(&$servers,$root,$assert):void{
 $p=proc_open($command,[1=>['file',$root.'/server.log','a'],2=>['file',$root.'/server.log','a']],$pipes);$assert(is_resource($p),'Server starts');$servers[]=$p;
 for($i=0;$i<100;$i++){$s=@stream_socket_client('tcp://'.$address,timeout:.05);if($s){fclose($s);return;}usleep(20000);}throw new RuntimeException('Fixture server did not become ready');
};
$child=static function(array $command)use($assert):string{$p=proc_open($command,[1=>['pipe','w'],2=>['pipe','w']],$pipes);$out=stream_get_contents($pipes[1]);$err=stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);$assert(proc_close($p)===0,$out.$err);return $out;};
try{
 file_put_contents($root.'/router.php', <<<'PHP_ROUTER'
<?php
$p=$_SERVER['REQUEST_URI'];
if(str_contains($p,'short-body')){header('Content-Length: 100');echo 'short';return;}
if(str_contains($p,'large-body')){echo str_repeat(' ',1048577).'<title>Index of /media/</title>';return;}
if(str_contains($p,'large-header')){header('X-Pad: '.str_repeat('x',70000));echo 'ok';return;}
if(str_contains($p,'redirect')){header('Location: http://outside.invalid/',false,302);header('Location: https://'.$_SERVER['HTTP_HOST'].'/',false,302);return;}
if(str_contains($p,'single')){header('Location: https://'.$_SERVER['HTTP_HOST'].'/',true,302);return;}
echo str_repeat(' ',9000).'<title>Index of /media/</title>';
PHP_ROUTER);
 $address=$port();$start([PHP_BINARY,'-S',$address,$root.'/router.php'],$address);$exercise('http://'.$address);
 $assert(str_contains($child([PHP_BINARY,'-n',__FILE__,'--stream-client','http://'.$address]),'Stream HTTP bounds passed'),'Stream fallback exercises the same collection limits');
 if(function_exists('curl_init')){
  $session=new CollectionSession();$calls=0;$cancel=new RuntimeException('QA cancellation');
  $session->begin(null,static function()use(&$calls,$cancel):void{if(++$calls===2)throw $cancel;});
  $seen=null;try{(new HttpCollector($session))->fetch('http://'.$address);}catch(RuntimeException $e){$seen=$e;}finally{$session->end();}
  $assert($seen===$cancel,'Cancellation from HTTP callback propagates unchanged');
 }
 $method=new ReflectionMethod(HttpCheck::class,'assessCookieFlags');$check=new HttpCheck(new Context('.', ''));
 foreach(['Lax; SameSite=None','None; SameSite=Lax','Lax; SameSite=Lax']as$values){$r=$method->invoke($check,'PHPSESSID=x; Secure; HttpOnly; SameSite='.$values,['phpsessid'],['lax','strict'],[]);$assert($r['ok']===null&&$r['ambiguous_samesite'],'Duplicate SameSite is always unresolved');}
 $r=$method->invoke($check,'admin_theme=dark; SameSite=Lax',['phpsessid'],['lax','strict'],[]);$assert($r===null,'Cookie name substring cannot establish authentication sensitivity');
 $r=$method->invoke($check,'custom_auth=x',['custom_auth'],['lax','strict'],[]);$assert($r['ok']===false,'Explicit custom sensitive names remain assessed');
 if(function_exists('openssl_pkey_new')){
  $config="[req]\ndistinguished_name=dn\n[dn]\n[v3_req]\nsubjectAltName=IP:127.0.0.1\nbasicConstraints=critical,CA:TRUE\n";file_put_contents($root.'/openssl.cnf',$config);
  $key=openssl_pkey_new(['private_key_bits'=>2048]);$csr=openssl_csr_new(['commonName'=>'127.0.0.1'],$key,['config'=>$root.'/openssl.cnf']);$cert=openssl_csr_sign($csr,null,$key,1,['config'=>$root.'/openssl.cnf','x509_extensions'=>'v3_req']);
  openssl_pkey_export($key,$keyPem);openssl_x509_export($cert,$certPem);file_put_contents($root.'/key.pem',$keyPem);file_put_contents($root.'/cert.pem',$certPem);
  $tlsAddress=$port();$start([PHP_BINARY,__FILE__,'--tls-server',$root,$tlsAddress],$tlsAddress);
  $assert(str_contains($child([PHP_BINARY,'-d','curl.cainfo='.$root.'/cert.pem','-d','openssl.cafile='.$root.'/cert.pem',__FILE__,'--tls-client','https://'.$tlsAddress]),'TLS cookie ambiguity passed'),'Verified TLS public cookie collector preserves failures and gaps');
 }
 echo "Prelaunch HTTP QA regressions: $n assertions passed\n";
}finally{foreach($servers as$p){proc_terminate($p);proc_close($p);}foreach(glob($root.'/*')as$f)unlink($f);rmdir($root);}
