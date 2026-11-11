<?php
declare(strict_types=1);
namespace Magebean\Engine\Checks;

use Magebean\Engine\Context;
use Magebean\Engine\Collectors\CollectorSet;

/** Bounded observations; never execute uploaded code or retain response contents. */
final class BasicExposureCheck
{
    public function __construct(private Context $ctx, private mixed $probe = null, private ?CollectorSet $collectors = null) { $this->collectors ??= new CollectorSet(); }

    public function mediaExecutableFiles(array $args): array
    {
        $project = realpath($this->ctx->path);
        if ($project === false) return [null, '[UNKNOWN] Readable project inventory unavailable', []];
        $cursor = $project;
        foreach (['pub', 'media'] as $part) {
            $cursor .= DIRECTORY_SEPARATOR.$part;
            if (is_link($cursor)) return [null, '[UNKNOWN] Media root or ancestor is a symlink; its target is not assessed', ['collection_gaps' => ['media_root_symlink']]];
        }
        $root = realpath($cursor);
        if ($root === false || !is_dir($root) || !is_readable($root)) return [null, '[UNKNOWN] Readable pub/media inventory unavailable', []];
        $limit = max(1, min(50000, (int)($args['max_entries'] ?? 10000)));
        $deadline = microtime(true) + max(1, min(15000, (int)($args['max_duration_ms'] ?? 5000))) / 1000;
        $seen = 0; $gaps = []; $found = [];
        try {
            $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::SELF_FIRST);
            foreach ($it as $file) {
                $this->collectors->session->checkpoint();
                if (microtime(true) > $deadline) { $gaps[] = 'time_budget'; break; }
                if (++$seen > $limit) { $gaps[] = 'entry_budget'; break; }
                $relative = substr($file->getPathname(), strlen($root) + 1);
                if ($file->isLink()) { $gaps[] = $relative; continue; }
                if (!$file->isFile()) continue;
                if (!is_readable($file->getPathname())) { $gaps[] = $relative; continue; }
                if (preg_match('~\.(?:php\d*|phtml|pht|phar)(?:\.|$)~i', $relative)) $found[] = $relative;
                if (count($found) >= 50) break;
            }
        } catch (\UnexpectedValueException $e) { $gaps[] = 'unreadable_subtree'; }
        $ev = ['scope'=>'pub/media filenames; server execution policy requires separate evidence', 'entries'=>$seen, 'files'=>$found, 'collection_gaps'=>array_slice($gaps,0,50)];
        if ($found) return [false, 'Executable PHP-like filenames found in media', $ev];
        if ($gaps) return [null, '[UNKNOWN] Media filename inventory incomplete', $ev];
        return [true, 'No executable PHP-like filenames in collected media inventory', $ev];
    }

    public function sensitiveHttpPaths(array $args): array
    {
        $base = (new HttpCheck($this->ctx))->runtimeBaseUrl();
        if ($base === '') return [null, 'Runtime URL unavailable for sensitive-path probes after Magento configuration discovery; check store configuration and scanner read access.', ['reason_code'=>'SCAN_INPUT_URL_MISSING']];
        $paths = ['/app/etc/env.php','/app/etc/config.php','/.git/HEAD','/composer.json','/var/log/system.log','/var/report/'];
        $checked = []; $failed = false; $unknown = false;
        foreach ($paths as $path) {
            // Never follow redirects or download the full file, including when Range is ignored.
            $url = rtrim($base,'/') . $path;
            $r = $this->probe !== null ? ($this->probe)($url) : $this->prefix($url, min(8000,max(100,(int)($args['timeout_ms']??2000))));
            $status = (int)($r['status']??0); $body = (string)($r['prefix']??'');
            $signature = match ($path) {
                '/app/etc/env.php','/app/etc/config.php' => preg_match('~<\?php\b|[\x22\x27](?:crypt|db|modules|system)[\x22\x27]\s*=>~i',$body)===1,
                '/.git/HEAD' => preg_match('~^(?:ref: refs/|[a-f0-9]{40}\s*$)~i',$body)===1,
                '/composer.json' => is_array(json_decode($body,true)) && (isset(json_decode($body,true)['require']) || isset(json_decode($body,true)['name'])),
                '/var/log/system.log' => preg_match('~\[?\d{4}-\d\d-\d\d[T ][^\r\n]+(?:main\.|CRITICAL|ERROR|WARNING|INFO)~i',$body)===1,
                default => preg_match('~Index of /(?:var/)?report~i',$body)===1,
            };
            $exposed = in_array($status,[200,206],true) && $signature;
            $checked[] = ['path'=>$path,'status'=>$status,'signature_detected'=>$exposed];
            if ($exposed) $failed=true;
            elseif (!in_array($status,[401,403,404,410],true)) $unknown=true;
        }
        $ev=['scope'=>'six named HTTP paths; no response body retained','checked'=>$checked];
        if ($failed) return [false,'Sensitive deployment artifact signature exposed over HTTP',$ev];
        if ($unknown) return [null,'[UNKNOWN] Some sensitive paths were not conclusively denied or absent',$ev];
        return [true,'Named sensitive paths returned access denial or absence',$ev];
    }

    private function prefix(string $url, int $timeoutMs): array
    {
        $context=stream_context_create(['http'=>['method'=>'GET','header'=>"Range: bytes=0-4095\r\nUser-Agent: Magebean-CLI/1.0\r\n",'ignore_errors'=>true,'follow_location'=>0,'timeout'=>$timeoutMs/1000], 'ssl'=>['verify_peer'=>true,'verify_peer_name'=>true]]);
        $stream=@fopen($url,'rb',false,$context);
        if ($stream===false) return ['status'=>0,'prefix'=>''];
        stream_set_timeout($stream,max(1,(int)ceil($timeoutMs/1000)));
        $body=@stream_get_contents($stream,4096); $meta=stream_get_meta_data($stream); fclose($stream);
        $status=0;
        foreach ((array)($meta['wrapper_data']??[]) as $line) if (preg_match('~^HTTP/\S+\s+(\d{3})~',$line,$m)) $status=(int)$m[1];
        return ['status'=>!empty($meta['timed_out'])?0:$status,'prefix'=>is_string($body)?$body:''];
    }
}
