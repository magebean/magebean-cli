<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\Context;
use Magebean\Engine\Checks\{CodeSearchCheck,PhpConfigCheck};
$root=sys_get_temp_dir().'/mb-restored-template-'.bin2hex(random_bytes(6));mkdir($root.'/app',0700,true);$n=0;
$assert=static function(bool$ok,string$message)use(&$n):void{++$n;if(!$ok)throw new RuntimeException($message);};
$source=static function(string$text,bool$js=false,array$args=[])use($root):array{file_put_contents($root.'/app/view.phtml',$text);$check=new CodeSearchCheck(new Context($root,''));return $js?$check->jsContextEscaping(['paths'=>['app']]+$args):$check->phtmlEscapedOutput(['paths'=>['app']]+$args);};
$write=static function(string$file,string$text)use($root):void{if(!is_dir(dirname($root.'/'.$file)))mkdir(dirname($root.'/'.$file),0700,true);file_put_contents($root.'/'.$file,$text);};
try{
 foreach([
  ['<?= $value ?>',false],
  ['<?= $escaper->escapeHtml($value) ?>',true],
  ['<?= $escaper->escapeHtml($value).$raw ?>',false],
  ['<?= "escapeHtml(".$raw ?>',false],
  ['<?= /* @noEscape */ $value ?>',false],
  ['<script>const x="<?= $escaper->escapeHtml($value) ?>";</script>',false],
  ['<script>const x="<?= $escaper->escapeJs($value) ?>";</script>',true],
  ['<script>const x=<?= json_encode($value) ?>;</script>',true],
  ['<script>const x=<?= $serializer->serialize($value) ?>;</script>',null],
  ['<script>const x=<?= json_encode($value, $flags) ?>;</script>',null],
  ['<script>const x=`<?= $escaper->escapeJs($value) ?>`;</script>',null],
  ['<a title="<?= $escaper->escapeHtmlAttr($value) ?>">x</a>',true],
  ['<a title="<?= $escaper->escapeHtml($value) ?>">x</a>',false],
  ['<a href="<?= $escaper->escapeUrl($value) ?>">x</a>',true],
  ['<div onclick="run(\'<?= $escaper->escapeJs($value) ?>\')"></div>',null],
  ['<?php function f(){echo $value;} ?>',null],
  ['<?= $custom->sanitize($value) ?>',null],
  ['<?= "interpolated $value" ?>',false],
  ['<?= $f($value) ?>',null],
  ["<?php printf('%s', \$raw); ?>",null],
  ["<?php include 'other.phtml'; ?>",null],
  ['<script>const r=/"/;const x=<?= json_encode($value) ?>;</script>',null],
  ['<?php echo "<script>const x=\""; ?><?= $escaper->escapeHtml($value) ?>',null],
  ['<?= $fake->escapeHtml($value) ?>',null],
  ['<?= Fake::escapeHtml($value) ?>',null],
  ['<?php $escaper=new Fake; ?><?= $escaper->escapeHtml($value) ?>',null],
  ['<?php namespace Fake; function json_encode($x){return $x;} ?><script>const x=<?= json_encode($value) ?>;</script>',null],
  ['<script>const x="<?= $escaper->escapeJsQuote($value) ?>";</script>',null],
  ['<?php if (',null],
 ]as[$text,$expected]){$r=$source($text);$assert($r[0]===$expected,'Template outcome '.json_encode($text).' got '.json_encode($r));}
 foreach([
  ['<script>const x="<?= $value ?>";</script>',false],
  ['<script>const x="<?= $escaper->escapeJs($value) ?>";</script>',true],
  ['<script>const x="<?= $escaper->escapeHtml($value) ?>";</script>',false],
 ]as[$text,$expected])$assert($source($text,true)[0]===$expected,'JS-only supported output');
 unlink($root.'/app/view.phtml');$assert((new CodeSearchCheck(new Context($root,'')))->phtmlEscapedOutput(['paths'=>['app']])[0]===null,'No template inventory is not clean');
 $assert($source('<?= $escaper->escapeHtml($value) ?>',false,['max_file_bytes'=>8])[0]===null,'Oversized template is not clean');
 $write('app/etc/env.php','<?php file_put_contents('.var_export($root.'/executed',true).',"bad"); return [];');
 $check=new PhpConfigCheck(new Context($root,''));
 $assert($check->templateHintsDisabled([])[0]===null&&!file_exists($root.'/executed'),'Dynamic config is never executed by restored flags');
 $assert($check->devDebugConfigDisabled([])[0]===null&&!file_exists($root.'/executed'),'Dynamic debug config remains unassessed');
 $assert($check->noFileCacheBackend([])[0]===null&&!file_exists($root.'/executed'),'Dynamic cache config remains unassessed');
 $write('app/etc/env.php','<?php return [];');$assert($check->templateHintsDisabled([])[0]===null,'Missing template flag is unknown');
 foreach([0=>true,1=>false]as$value=>$expected){$write('app/etc/env.php','<?php return '.var_export(['system'=>['default'=>['dev/debug/template_hints'=>$value]]],true).';');$assert($check->templateHintsDisabled([])[0]===$expected,'Explicit template flag '.$value);}
 $write('app/etc/env.php','<?php return '.var_export(['system'=>['default'=>['dev/debug/template_hints'=>null]]],true).';');$assert($check->templateHintsDisabled([])[0]===null,'Null is not an explicitly disabled flag');
 foreach(["display_errors=On\n"=>false,"display_errors=Off\n"=>true,"display_errors=On\ndisplay_errors=Off\n"=>true,"display_errors[]=Off\n"=>null,"memory_limit=128M\n"=>null]as$ini=>$expected){$write('php.ini',$ini);$assert($check->displayErrorsDisabled(['files'=>['php.ini']])[0]===$expected,'Effective supplied ini declaration '.json_encode($ini));}
 $write('php.ini','display_errors=Off');$assert($check->displayErrorsDisabled(['files'=>['php.ini']])[0]===true,'Known disabled ini can pass');
 echo "Restored template/config regressions: $n assertions passed\n";
}finally{$it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST);foreach($it as$f)$f->isDir()&&!$f->isLink()?rmdir($f->getPathname()):unlink($f->getPathname());rmdir($root);}
