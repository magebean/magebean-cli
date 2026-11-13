<?php
declare(strict_types=1);
namespace Magebean\Engine\Checks;
use Magebean\Engine\Context;
use Magebean\Engine\Collectors\CollectorSet;

/** Bounded, reusable deployment observations; contains no requirement identity. */
final class DeploymentStateCheck
{
    public function __construct(private Context $ctx, private ?CollectorSet $collectors = null) { $this->collectors ??= new CollectorSet(); }
    public function webrootArtifacts(array $args): array
    {
        $root=$this->ctx->abs((string)($args['webroot']??'pub'));
        if(!is_dir($root))return[null,'[UNKNOWN] Webroot is unavailable: pub; provide a readable deployed webroot.'];
        $project=realpath($this->ctx->path);$pending=[$root];$visited=[];$gaps=[];$count=0;$limit=max(1,(int)($args['max_entries']??1000000));
        $patterns=$args['forbidden']??['.git','.env','.env.local','.env.*','*.bak','*.old','*~'];
        while($pending!==[]){
            $this->collectors->session->checkpoint();$path=array_pop($pending);
            foreach($patterns as$pattern)if(fnmatch((string)$pattern,basename($path)))return[false,'Forbidden artifact found in deployed webroot: '.$path,['path'=>$path,'pattern'=>$pattern,'entries_assessed'=>$count]];
            if(++$count>$limit)return[null,'[UNKNOWN] Webroot traversal reached its entry limit; increase max_entries to finish the assessment.',['entries_assessed'=>$count]];
            $stat=@lstat($path);if($stat===false){$gaps[]='metadata_unavailable';continue;}
            if(($stat['mode']&0170000)===0120000){$resolved=realpath($path);if($resolved===false||$project===false||($resolved!==$project&&!str_starts_with($resolved,$project.DIRECTORY_SEPARATOR))){$gaps[]='symlink_target_unresolved_or_outside_project';continue;} $path=$resolved; foreach($patterns as$pattern)if(fnmatch((string)$pattern,basename($path)))return[false,'Forbidden artifact reachable through deployed webroot symlink: '.$path,['path'=>$path,'pattern'=>$pattern,'entries_assessed'=>$count]];}
            if(!is_readable($path)){ $gaps[]='path_unreadable';continue;}
            if(!is_dir($path))continue;
            $key=realpath($path);if($key===false){$gaps[]='directory_path_unresolved';continue;}if(isset($visited[$key]))continue;$visited[$key]=true;
            $children=@scandir($path);if($children===false){$gaps[]='directory_unreadable';continue;}
            foreach($children as$child)if($child!=='.'&&$child!=='..')$pending[]=$path.DIRECTORY_SEPARATOR.$child;
        }
        if($gaps!==[])return[null,'[UNKNOWN] Webroot traversal is incomplete; fix unreadable paths or unresolved external symlinks.',['gaps'=>array_values(array_unique($gaps)),'entries_assessed'=>$count]];
        return[true,'No forbidden artifacts found in the completely traversed deployed webroot.',['entries_assessed'=>$count,'root'=>$root]];
    }
    public function cacheTypeEnabled(array $args): array
    {
        $relative=(string)($args['file']??'app/etc/env.php');$file=$this->ctx->abs($relative);
        $config=$this->collectors->php->load($file,$relative,static function()use($file):mixed{return include $file;});
        if(isset($config['__ERROR__']))return[null,'[UNKNOWN] Cannot read deployed cache configuration; supply readable app/etc/env.php.'];
        $type=(string)($args['type']??'full_page');$value=$config['cache_types'][$type]??null;
        if(!in_array($value,[0,1,'0','1',false,true],true))return[null,'[UNKNOWN] cache_types.'.$type.' is absent or malformed in app/etc/env.php; collect Magento cache:status or persist the cache type state.',['file'=>$relative,'cache_type'=>$type]];
        $ok=in_array($value,[1,'1',true],true);
        return[$ok,$ok?'Declared Full Page Cache type is enabled.':'Declared Full Page Cache type is disabled.',['file'=>$relative,'cache_type'=>$type,'enabled'=>$ok]];
    }
    /** Bounded readiness predicate on the actual Magento indexer_state table. */
    public function indexersDatabaseReady(array $args): array
    {
        $evidence = ['source' => 'indexer_state', 'scope' => 'deployment_database', 'observed_at'=>gmdate(DATE_ATOM), 'runtime_process_verified'=>false];
        $pdo = $this->ctx->get('pdo');
        $prefix = (string)$this->ctx->get('db_table_prefix', '');
        try {
            if (!$pdo instanceof \PDO) {
                $relative = (string)($args['env_file'] ?? 'app/etc/env.php');
                $file = $this->ctx->abs($relative);
                $config = $this->collectors->php->load($file, $relative, static function () use ($file): mixed { return include $file; });
                if (isset($config['__ERROR__'])) return [null, '[UNKNOWN] Indexer database configuration is unreadable; allow the scanner to read ' . $relative, $evidence + ['reason' => 'env_file_unavailable']];
                $db = $config['db']['connection']['default'] ?? null;
                if (!is_array($db)) return [null, '[UNKNOWN] Magento default database connection is missing; provide the deployed app/etc/env.php', $evidence + ['reason' => 'db_config_missing']];
                $host = (string)($db['host'] ?? 'localhost'); $name = (string)($db['dbname'] ?? ''); $port = $db['port'] ?? null;
                if ($port === null && substr_count($host, ':') === 1) [$host, $port] = explode(':', $host, 2);
                if ($name === '' || str_contains($name, ';') || str_contains($host, ';') || ($port !== null && (!ctype_digit((string)$port) || (int)$port < 1 || (int)$port > 65535))) throw new \RuntimeException('Invalid connection settings');
                $dsn = 'mysql:host=' . $host . ';dbname=' . $name . ';charset=utf8mb4';
                if ($port !== null) $dsn .= ';port=' . $port;
                $pdo = new \PDO($dsn, (string)($db['username'] ?? ''), (string)($db['password'] ?? ''), [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION, \PDO::ATTR_TIMEOUT => 2]);
                $prefix = (string)($config['db']['table_prefix'] ?? '');
            }
            if (preg_match('/^[A-Za-z0-9_]*$/D', $prefix) !== 1) throw new \RuntimeException('Invalid table prefix');
            try { $statement = $pdo->query('SELECT indexer_id, status, updated FROM `' . $prefix . 'indexer_state`'); }
            catch (\PDOException) { $statement = $pdo->query('SELECT indexer_id, status FROM `' . $prefix . 'indexer_state`'); }
            $rows = $statement->fetchAll(\PDO::FETCH_ASSOC);
            if ($rows === []) return [null, '[UNKNOWN] indexer_state has no rows; initialize Magento indexers and collect their installed state', $evidence + ['reason' => 'indexer_rows_empty']];
            $notReady = []; $working = [];
            foreach ($rows as $row) {
                if (!is_string($row['indexer_id'] ?? null) || $row['indexer_id'] === '' || !in_array($row['status'] ?? null, ['valid', 'invalid', 'working'], true)) return [null, '[UNKNOWN] indexer_state contains an unrecognized status; verify the deployment schema and indexer data', $evidence + ['reason' => 'indexer_rows_malformed']];
                if ($row['status'] === 'invalid') $notReady[] = $row;
                if ($row['status'] === 'working') {
                    $updated=AbsoluteTimestamp::parse(isset($row['updated']) ? str_replace(' ', 'T', $row['updated']).'Z' : null);
                    $row['record_age_seconds']=$updated!==null && $updated->getTimestamp()<=time()?time()-$updated->getTimestamp():null;
                    $row['stuck_process_established']=false;
                    $working[]=$row;
                }
            }
            $evidence += ['indexers_seen'=>count($rows), 'not_ready'=>$notReady, 'working'=>$working];
            if ($notReady!==[]) return [false, 'Recorded Magento indexers have invalid state', $evidence];
            if ($working!==[]) return [null, '[UNKNOWN] Indexing is recorded as working; one database snapshot cannot establish a stuck or unhealthy process', $evidence];
            return [true, 'All recorded Magento indexers have valid state', $evidence];
        } catch (\Throwable $error) {
            return [null, '[UNKNOWN] Unable to read Magento indexer_state; verify the deployed DB connection and SELECT permission on indexer_state', $evidence + ['reason' => 'indexer_database_collection_failed']];
        }
    }

}
