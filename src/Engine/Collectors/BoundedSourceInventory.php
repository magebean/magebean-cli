<?php
declare(strict_types=1);
namespace Magebean\Engine\Collectors;

use Magebean\Engine\Context;

/** A completeness-aware local inventory. Contents are internal and must never be report evidence. */
final class BoundedSourceInventory
{
    public function __construct(private readonly ?CollectionSession $session=null) {}
    public function collect(Context $ctx, array $args = []): array
    {
        $scope=array_intersect_key($args,array_flip(['paths','include_ext','max_files','max_file_bytes','max_total_bytes','timeout_seconds','exclude_paths','verify_stable']));
        $load=fn():array=>$this->capture($ctx,$args);
        return $this->session?->remember('bounded-source:'.hash('sha256',$ctx->path.serialize($scope)),$load)??$load();
    }
    private function capture(Context $ctx, array $args): array
    {
        $paths=$args['paths']??['app/code'];
        $extensions=$args['include_ext']??['php','phtml'];
        if(!is_array($paths)||!array_is_list($paths)||$paths===[]||count($paths)>100||!is_array($extensions)||!array_is_list($extensions)||$extensions===[]||count($extensions)>30)throw new \InvalidArgumentException('Bounded nonempty source paths and extensions required.');
        foreach($extensions as $ext)if(!is_string($ext)||!preg_match('/^[a-z0-9]+$/D',$ext))throw new \InvalidArgumentException('Invalid source extension.');
        $excluded = $args['exclude_paths'] ?? [];
        if (!is_array($excluded) || !array_is_list($excluded) || count($excluded) > 20000) throw new \InvalidArgumentException('Invalid excluded source paths.');
        foreach(array_merge($paths, $excluded) as $path)if(!is_string($path)||$path===''||str_contains($path,"\0")||preg_match('~(?:^/|^[A-Za-z]:|(?:^|/)\.\.(?:/|$))~',str_replace('\\','/',$path)))throw new \InvalidArgumentException('Source paths must remain inside the project.');
        $excluded = array_fill_keys($excluded, true);
        $verifyStable = ($args['verify_stable'] ?? false) === true;
        $result=['files'=>[],'complete'=>true,'gaps'=>[],'files_read'=>0,'bytes_read'=>0,'scope'=>$paths];
        $gap=static function(string $reason,string $path)use(&$result):void{$result['complete']=false;if(count($result['gaps'])<50)$result['gaps'][]=['reason'=>$reason,'file'=>$path];};
        $root=realpath($ctx->path);
        if(($ctx->get('meta',[])['target_mode']??'')==='REMOTE'||$root===false||!is_dir($root)){$gap('local_source_unavailable','');return $result;}
        $root=rtrim(str_replace('\\','/',$root),'/');
        $maxFiles=max(1,min(10000,(int)($args['max_files']??2000)));
        $maxFileBytes=max(1,min(10485760,(int)($args['max_file_bytes']??1048576)));
        $maxBytes=max(1,min(104857600,(int)($args['max_total_bytes']??10485760)));
        $deadline=microtime(true)+max(0.001,min(30,(float)($args['timeout_seconds']??5)));
        $seen=[];$stack=[];$entriesSeen=0;
        foreach($paths as $path){
            $cursor=$root;$linked=false;
            foreach(explode('/',str_replace('\\','/',$path)) as $part){if($part===''||$part==='.')continue;$cursor.='/'.$part;if(is_link($cursor)){$gap('symlink_not_followed',$path);$linked=true;break;}}
            if(!$linked)$stack[]=$root.'/'.str_replace('\\','/',$path);
        }
        while($stack!==[]){
            $this->session?->checkpoint();
            $file=array_pop($stack);$relative=ltrim(substr($file,strlen($root)),'/');
            if(microtime(true)>$deadline){$gap('deadline_exceeded',$relative);break;}
            if(isset($excluded[$relative]) || isset($seen[$file]))continue;$seen[$file]=true;
            if ($verifyStable) clearstatcache(true, $file);
            // Do not follow any link: hidden descendants and alternate targets cannot be certified complete.
            if(is_link($file)){$gap('symlink_not_followed',$relative);continue;}
            $real=realpath($file);
            if($real===false){$gap('missing_source_path',$relative);continue;}
            $real=str_replace('\\','/',$real);
            if($real!==$root&&!str_starts_with($real,$root.'/')){$gap('source_outside_project',$relative);continue;}
            if(is_dir($file)){
                if(!is_readable($file)){$gap('unreadable_directory',$relative);continue;}
                try{
                    foreach(new \FilesystemIterator($file,\FilesystemIterator::SKIP_DOTS) as $entry){
                        if(++$entriesSeen>20000||microtime(true)>$deadline){$gap('entry_or_deadline_budget_exceeded',$relative);break 2;}
                        $stack[]=$entry->getPathname();
                    }
                }catch(\UnexpectedValueException){$gap('unreadable_directory',$relative);}
                continue;
            }
            if(!is_file($file)){$gap('unsupported_source_entry',$relative);continue;}
            $ext=strtolower(pathinfo($file,PATHINFO_EXTENSION));if(!in_array($ext,$extensions,true))continue;
            if(count($result['files'])>=$maxFiles){$gap('file_budget_exceeded',$relative);break;}
            $expected = $verifyStable ? @lstat($file) : null;
            $size=@filesize($file);
            if($size===false||!is_readable($file)){$gap('unreadable_source',$relative);continue;}
            if($size>$maxFileBytes){$gap('oversized_source',$relative);continue;}
            if($size+$result['bytes_read']>$maxBytes){$gap('total_byte_budget_exceeded',$relative);break;}
            $handle=@fopen($file,'rb');if($handle===false){$gap('unreadable_source',$relative);continue;}
            $before=fstat($handle);$content=stream_get_contents($handle,$maxFileBytes+1);$after=fstat($handle);fclose($handle);
            if($content===false||strlen($content)>$maxFileBytes||$before===false||$after===false||$before['size']!==$after['size']||strlen($content)!==$after['size']){$gap('source_changed_or_truncated',$relative);continue;}
            if ($verifyStable) {
                clearstatcache(true, $file);
                $current = @lstat($file);
                foreach (['dev', 'ino', 'size', 'mtime', 'ctime'] as $field) {
                    if ($expected === false || $current === false || $expected[$field] !== $before[$field]
                        || $before[$field] !== $after[$field] || $after[$field] !== $current[$field]) {
                        $gap('source_changed_or_truncated', $relative);
                        continue 2;
                    }
                }
                if (strlen($content) + $result['bytes_read'] > $maxBytes) {
                    $gap('total_byte_budget_exceeded', $relative);
                    break;
                }
            }
            $result['files'][]=['file'=>$relative,'content'=>$content,'extension'=>$ext];$result['files_read']++;$result['bytes_read']+=strlen($content);
        }
        if($result['files_read']===0)$gap('no_eligible_source_files','');
        usort($result['files'],static fn(array $a,array $b):int=>strcmp($a['file'],$b['file']));
        return $result;
    }
}
