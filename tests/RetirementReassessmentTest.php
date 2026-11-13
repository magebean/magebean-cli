<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\{Context,RequirementCatalog,RequirementProfileCatalog,RequirementPolicy,RequirementDefinitionValidator,MagebeanRetirement};
use Magebean\Engine\Checks\CheckRegistry;
$review=RequirementCatalog::read('magebean-retirement-review');
$archive=array_column(RequirementCatalog::read('magebean-retirements')['requirements'],null,'id');
$active=array_column(RequirementCatalog::loadAll()['rules'],null,'id');
$n=0;$assert=static function(bool $ok,string $message)use(&$n):void{++$n;if(!$ok)throw new RuntimeException($message);};
$expected=['MB-0043','MB-0093','MB-0731','MB-0733','MB-0736','MB-0739','MB-0740','MB-0741','MB-0742','MB-0744'];
$assert(count($review['requirements'])===60&&count(array_unique(array_column($review['requirements'],'id')))===60,'Exactly60 evidence decisions');
$assert($review['classifications']===['partial_active_coverage'=>29,'detector_rework_required'=>12,'restored_scoped_automated'=>10,'insufficient_evidence'=>6,'external_context_required'=>3],'Explicit evidence classification totals');
$root=sys_get_temp_dir().'/mb-reassessment-'.bin2hex(random_bytes(6));
$put=static function(string $file,string $text)use($root):void{if(!is_dir(dirname($root.'/'.$file)))mkdir(dirname($root.'/'.$file),0700,true);file_put_contents($root.'/'.$file,$text);};
try{
 $registry=CheckRegistry::fromContext(new Context($root,''));
 foreach($review['requirements'] as $row){
  $id=$row['id'];$assert(isset($archive[$id]),'Every decision is rooted in immutable archive');
  $assert($row['active']===in_array($id,$expected,true),'Activation is an explicit evidence decision '.$id);
  $assert(is_file(__DIR__.'/../'.$row['evidence_report']),'Evidence report exists '.$id);
  foreach($row['related_active_rules'] as $replacement)$assert(isset($active[$replacement])&&$active[$replacement]['family']==='magebean','Actual owned partial replacement '.$id);
  if(!$row['active']){$assert(MagebeanRetirement::diagnostic($id)!==null&&!str_contains(MagebeanRetirement::diagnostic($id),'requires human evidence'),'Inactive classification does not claim inherent manual-only evaluation');continue;}
  $r=$active[$id];$assert($r['revision']>$archive[$id]['revision']&&!RequirementPolicy::requiresHuman($r),'Restored version is automatic');
  $assert(RequirementDefinitionValidator::validate($r,$registry)===[],'Valid restored binding '.$id);
  $assert(MagebeanRetirement::diagnostic($id)===null,'Restored canonical selector accepted '.$id);
  $assert(in_array($archive[$id]['criterion'],array_column($r['criterion_history'],'criterion'),true),'Prior criterion preserved '.$id);
 }
 $put('composer.json','{"require":{"magento/framework":"103.0.7"}}');
 $put('bin/magento','<?php throw new RuntimeException("Must not bootstrap Magento");');
 $configuration=[]; $configuration['system']['default']['admin']['security']['minimum_password_length']=12;
 $put('app/etc/config.php','<?php return '.var_export($configuration,true).';');
 $env=['system'=>['default'=>['dev/debug/template_hints'=>0,'dev/debug/template_hints_storefront'=>0,'dev/translate_inline/active'=>0]],'cache'=>['frontend'=>['default'=>['backend'=>'Cm_Cache_Backend_Redis'],'page_cache'=>['backend'=>'Cm_Cache_Backend_Redis']]]];
 $put('app/etc/env.php','<?php return '.var_export($env,true).';');
 $put('php.ini',"display_errors=Off\n");
 $put('devops/logrotate.conf',"var/log/*.log {\n daily\n rotate 7\n compress\n}\n");
 $put('docs/pci-evidence.md','checkout SAQ access review incident response vendor responsibilities');
 $put('app/view.phtml','<p><?= $escaper->escapeHtml($value) ?></p><script>const x="<?= $escaper->escapeJs($value) ?>";</script>');
 $entry=$argv[1]??__DIR__.'/../bin/magebean';
 $cli=static function(array $args)use($root,$entry):array{
  $p=proc_open([PHP_BINARY,$entry,'audit','--path='.$root,...$args,'--no-interaction','--no-ansi'],[1=>['pipe','w'],2=>['pipe','w']],$pipes);
  if(!is_resource($p))throw new RuntimeException('CLI fixture unavailable');$out=stream_get_contents($pipes[1]).stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);return[proc_close($p),$out];
 };
 $local=array_values(array_diff($expected,['MB-0744']));
 [$code,$out]=$cli(['--rules='.implode(',',$local),'--capabilities=evidence_document_lint,cache_backend_policy,log_rotation_config']);$assert($code===0&&!str_contains($out,'HUMAN VERIFICATION'),$out);
 $put('php.ini',"display_errors=On\n");[$code,$out]=$cli(['--rules=MB-0739']);$assert($code===1&&str_contains($out,'display_errors'),$out);
 $put('app/view.phtml','<script>const x="<?= $escaper->escapeHtml($value) ?>";</script>');
 [$code,$out]=$cli(['--rules=MB-0733,MB-0736']);$assert($code===1&&str_contains($out,'context-specific'),$out);
 foreach(['basic'=>37,'hardening'=>86,'development'=>31,'prelaunch'=>60,'takeover'=>86] as $id=>$count)$assert(count(RequirementProfileCatalog::load($id)['requirement_ids'])===$count,'Existing profile selection stays deliberate '.$id);
 echo "Retirement reassessment canonical CLI: $n assertions passed\n";
}finally{
 if(is_dir($root)){$it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST);foreach($it as$f)$f->isDir()&&!$f->isLink()?rmdir($f->getPathname()):unlink($f->getPathname());rmdir($root);}
}
