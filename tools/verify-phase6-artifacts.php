<?php
declare(strict_types=1);
$root=dirname(__DIR__);$rows=[];
foreach(['magebean.phar','artifacts/magebean-one-time.phar'] as $relative){
 $file=$root.'/'.$relative;$phar=new Phar($file);$checked=0;
 foreach(new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root.'/src',FilesystemIterator::SKIP_DOTS)) as $source){
  if(!$source->isFile())continue;$path=substr($source->getPathname(),strlen($root)+1);
  if(!isset($phar[$path])||hash_file('sha256',$source->getPathname())!==hash('sha256',$phar[$path]->getContent()))throw new RuntimeException('Artifact differs from source: '.$relative.' '.$path);
  ++$checked;
 }
 $rows[$relative]=['sha256'=>hash_file('sha256',$file),'bytes'=>filesize($file),'source_files_matched'=>$checked,'signature_type'=>$phar->getSignature()['hash_type']];
}
echo json_encode(['source_parity'=>true,'artifacts'=>$rows],JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR),"\n";
