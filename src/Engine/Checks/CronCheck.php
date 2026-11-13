<?php

declare(strict_types=1);

namespace Magebean\Engine\Checks;

use Magebean\Engine\Context;

final class CronCheck
{
    public function __construct(private ?Context $ctx = null) {}

    /**
     * args:
     *  - users: string[]  (ví dụ ["www-data","nginx","apache","www","magento","deploy"])
     *  - patterns: string[] (regex PCRE, KHÔNG có delimiter /…/)
     *  - timeout_ms?: int (mặc định 2000)
     */
    public function crontabGrep(array $args): array
    {
        $users    = array_values(array_filter(array_map('trim', (array)($args['users'] ?? []))));
        $patterns = array_values(array_filter((array)($args['patterns'] ?? [])));
        $timeout  = (int)($args['timeout_ms'] ?? 2000);

        if (!$patterns) {
            return [null, 'No patterns provided'];
        }
        if (!$users) {
            // fallback phổ biến
            $users = ['www-data','nginx','apache','http','www','magento','deploy'];
        }

        $found = [];
        foreach ($users as $u) {
            $txt = $this->readUserCrontab($u, $timeout);
            if ($txt === null) continue; // user không có crontab / không đọc được
            foreach ($this->matchingCronLines($txt, $patterns) as $line) {
                $found[] = $u . ': ' . $line;
            }
        }

        if ($found) {
            return [true, 'Found cron: ' . implode(' | ', array_slice($found, 0, 5))];
        }

        // thử thêm các nguồn hệ thống (optional)
        foreach (['/etc/crontab', '/etc/cron.d'] as $path) {
            $txt = $this->readCronFileOrDir($path);
            if ($txt === null) continue;
            foreach ($this->matchingCronLines($txt, $patterns) as $line) {
                return [true, 'Found cron in ' . $path . ': ' . $line];
            }
        }

        return [false, 'No matching crontab entries'];
    }

    public function magentoCronConfigured(array $args): array
    {
        $users = array_values(array_filter(array_map('trim', (array)($args['users'] ?? []))));
        if (!$users) {
            $users = ['www-data','nginx','apache','http','www','magento','deploy'];
        }

        $patterns = array_values(array_filter((array)($args['patterns'] ?? [
            '(?:^|\s)(?:php\s+[^\n]*?)?bin/magento\s+cron:run\b',
            '(?:^|\s)(?:php\s+[^\n]*?)?bin/magento\s+setup:cron:run\b',
            '(?:^|\s)(?:php\s+[^\n]*?)?update/cron\.php\b',
        ])));
        if (!$patterns) {
            return [null, '[UNKNOWN] No cron patterns provided', []];
        }

        $timeout = (int)($args['timeout_ms'] ?? 2000);
        $checked = [];
        $found = [];

        foreach ($users as $user) {
            $txt = $this->readUserCrontab($user, $timeout);
            $checked[] = ['source' => 'user_crontab', 'user' => $user, 'readable' => $txt !== null];
            if ($txt === null) {
                continue;
            }

            foreach ($this->matchingCronLines($txt, $patterns) as $line) {
                $found[] = ['source' => 'user_crontab', 'user' => $user, 'line' => $line];
            }
        }

        foreach (['/etc/crontab', '/etc/cron.d'] as $path) {
            $txt = $this->readCronFileOrDir($path);
            $checked[] = ['source' => 'system_cron', 'path' => $path, 'readable' => $txt !== null];
            if ($txt === null) {
                continue;
            }

            foreach ($this->matchingCronLines($txt, $patterns) as $line) {
                $found[] = ['source' => 'system_cron', 'path' => $path, 'line' => $line];
            }
        }

        if ($found !== []) {
            if ($this->ctx !== null) {
                $project = rtrim($this->ctx->path, '/');
                $scoped = array_filter($found, static fn(array $entry): bool => str_contains($entry['line'], $project . '/bin/magento') || str_contains($entry['line'], $project . '/update/cron.php') || preg_match('~\bcd\s+[\"\']?' . preg_quote($project, '~') . '[\"\']?\s*(?:&&|;)~', $entry['line']) === 1);
                if ($scoped === []) return [null, '[UNKNOWN] Magento cron found, but installation scope is unverified', ['checked' => $checked, 'found' => $found]];
                $found = array_values($scoped);
            }
            return [true, 'Found Magento cron entry', ['checked' => $checked, 'found' => array_slice($found, 0, 10)]];
        }

        $repoEvidence = $this->findRepoCronEvidence($args, $patterns);
        $readableCronSources = array_values(array_filter($checked, static fn(array $entry): bool => !empty($entry['readable'])));
        $evidence = ['checked' => $checked, 'repo_evidence' => $repoEvidence];

        if ($repoEvidence !== []) {
            return [null, '[UNKNOWN] Magento cron command found in deployment files, but no readable crontab source confirmed it', $evidence];
        }

        if ($readableCronSources === []) {
            return [null, '[UNKNOWN] No readable crontab sources found and no deployment cron evidence detected', $evidence];
        }

        return [false, 'No Magento cron entry found in readable crontab sources or deployment configuration', $evidence];
    }

    public function heartbeatRecent(array $args): array
    {
        if (!empty($args['database_only'])) return $this->databaseMetric('heartbeat', $args);
        if ($this->ctx === null) {
            return [null, '[UNKNOWN] Project context is unavailable for cron heartbeat check', []];
        }

        $maxAge = (int)($args['seconds'] ?? 900);
        if ($maxAge <= 0) {
            return [null, '[UNKNOWN] cron_heartbeat_recent requires a positive seconds value', []];
        }

        $files = $args['files'] ?? null;
        if ($files === null && isset($args['file'])) {
            $files = [$args['file']];
        }
        if (!is_array($files)) {
            $files = [
                'var/cron/cron.timestamp',
                'var/log/cron.log',
                'var/log/magento.cron.log',
            ];
        }

        $observed = [];
        foreach ($files as $file) {
            if (!is_scalar($file)) {
                continue;
            }
            $relative = (string)$file;
            $absolute = $this->ctx->abs($relative);
            if (!is_file($absolute)) {
                $observed[] = ['file' => $relative, 'present' => false];
                continue;
            }

            $mtime = @filemtime($absolute);
            if ($mtime === false) {
                $observed[] = ['file' => $relative, 'present' => true, 'readable' => false];
                continue;
            }

            $age = max(0, time() - $mtime);
            $observed[] = [
                'file' => $relative,
                'present' => true,
                'readable' => true,
                'mtime' => $mtime,
                'age_seconds' => $age,
                'ok' => $age <= $maxAge,
            ];
        }

        $readable = array_values(array_filter($observed, static fn(array $entry): bool => !empty($entry['readable'])));
        $recent = array_values(array_filter($readable, static fn(array $entry): bool => !empty($entry['ok'])));
        $evidence = ['max_age_seconds' => $maxAge, 'observed' => $observed];

        if ($recent !== []) {
            return [true, 'Cron heartbeat is recent', $evidence + ['recent' => $recent]];
        }

        if ($readable !== []) {
            return [false, 'Cron heartbeat is stale', $evidence + ['stale' => $readable]];
        }

        return [null, '[UNKNOWN] No readable cron heartbeat files found', $evidence];
    }

    public function backlogBelowThreshold(array $args): array
    {
        if (!empty($args['database_only'])) return $this->databaseMetric('backlog', $args);
        if ($this->ctx === null) {
            return [null, '[UNKNOWN] Project context is unavailable for cron backlog check', []];
        }

        $max = (int)($args['max'] ?? $args['threshold'] ?? 1000);
        if ($max < 0) {
            return [null, '[UNKNOWN] cron_backlog_below_threshold requires a non-negative max value', []];
        }

        $files = $args['files'] ?? null;
        if ($files === null && isset($args['file'])) {
            $files = [$args['file']];
        }
        if (!is_array($files)) {
            $files = [
                'var/cron/queue.size',
                'var/cron/backlog.json',
                'var/cron/backlog.txt',
            ];
        }

        $observed = [];
        foreach ($files as $file) {
            if (!is_scalar($file)) {
                continue;
            }
            $relative = (string)$file;
            $absolute = $this->ctx->abs($relative);
            if (!is_file($absolute)) {
                $observed[] = ['file' => $relative, 'present' => false];
                continue;
            }

            $content = @file_get_contents($absolute);
            if (!is_string($content)) {
                $observed[] = ['file' => $relative, 'present' => true, 'readable' => false];
                continue;
            }

            $count = $this->parseBacklogCount($content);
            $entry = ['file' => $relative, 'present' => true, 'readable' => true];
            if ($count === null) {
                $entry['parseable'] = false;
                $observed[] = $entry;
                continue;
            }

            $entry['parseable'] = true;
            $entry['count'] = $count;
            $entry['ok'] = $count < $max;
            $observed[] = $entry;
        }

        $parseable = array_values(array_filter($observed, static fn(array $entry): bool => !empty($entry['parseable'])));
        $failures = array_values(array_filter($parseable, static fn(array $entry): bool => empty($entry['ok'])));
        $evidence = ['threshold' => $max, 'observed' => $observed];

        if ($failures !== []) {
            return [false, 'Cron backlog is above threshold', $evidence + ['failures' => $failures]];
        }

        if ($parseable !== []) {
            return [true, 'Cron backlog is below threshold', $evidence + ['backlog' => $parseable]];
        }

        return [null, '[UNKNOWN] No parseable cron backlog metrics found', $evidence];
    }

    /** Read only the deployment's actual Magento scheduler table. */
    private function databaseMetric(string $metric, array $args): array
    {
        $evidence = ['source' => 'cron_schedule', 'scope' => 'deployment_database', 'observed_at'=>gmdate(DATE_ATOM)];
        if ($this->ctx === null) return [null, '[UNKNOWN] Deployment path is unavailable for cron database collection', $evidence];
        $pdo = $this->ctx->get('pdo');
        $prefix = (string)$this->ctx->get('db_table_prefix', '');
        try {
            if (!$pdo instanceof \PDO) {
                $relative = (string)($args['env_file'] ?? 'app/etc/env.php');
                $file = $this->ctx->abs($relative);
                if (!is_file($file) || !is_readable($file)) return [null, '[UNKNOWN] Magento database configuration is unreadable; allow the scanner to read ' . $relative, $evidence + ['reason' => 'env_file_unavailable']];
                $env = include $file;
                $connection = is_array($env) ? ($env['db']['connection']['default'] ?? null) : null;
                if (!is_array($connection)) return [null, '[UNKNOWN] Magento default database configuration is missing; run on the deployed Magento installation with readable app/etc/env.php', $evidence + ['reason' => 'db_config_missing']];
                $host = (string)($connection['host'] ?? 'localhost');
                $name = (string)($connection['dbname'] ?? '');
                if (str_contains($host, ';') || str_contains($name, ';') || $name === '') throw new \RuntimeException('Invalid database configuration');
                $port = $connection['port'] ?? null;
                if ($port === null && substr_count($host, ':') === 1) [$host, $port] = explode(':', $host, 2);
                if ($port !== null && (!ctype_digit((string)$port) || (int)$port < 1 || (int)$port > 65535)) throw new \RuntimeException('Invalid database port');
                $dsn = 'mysql:host=' . $host . ';dbname=' . $name . ';charset=utf8mb4';
                if ($port !== null) $dsn .= ';port=' . $port;
                $pdo = new \PDO($dsn, (string)($connection['username'] ?? ''), (string)($connection['password'] ?? ''), [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION, \PDO::ATTR_TIMEOUT => 2]);
                $prefix = (string)($env['db']['table_prefix'] ?? '');
            }
            if (preg_match('/^[A-Za-z0-9_]*$/D', $prefix) !== 1) throw new \RuntimeException('Invalid table prefix');
            $table = '`' . $prefix . 'cron_schedule`';
            if ($metric === 'heartbeat') {
                $maxAge = (int)($args['seconds'] ?? 900);
                if ($maxAge <= 0) return [null, '[UNKNOWN] Cron heartbeat seconds must be positive', $evidence];
                $statement = $pdo->query('SELECT MAX(executed_at) FROM ' . $table . " WHERE status IN ('success', 'running', 'error') AND executed_at IS NOT NULL");
                $raw = $statement->fetchColumn();
                if ($raw === null || $raw === false || $raw === '') return [false, 'No executed cron job is recorded in cron_schedule', $evidence + ['max_age_seconds' => $maxAge]];
                $date = \DateTimeImmutable::createFromFormat('!Y-m-d H:i:s', (string)$raw, new \DateTimeZone('UTC'));
                if ($date === false || $date->format('Y-m-d H:i:s') !== (string)$raw) return [null, '[UNKNOWN] cron_schedule.executed_at is malformed; check scheduler timestamp integrity', $evidence];
                $age = time() - $date->getTimestamp();
                if ($age < -60) return [null, '[UNKNOWN] Cron execution timestamp is in the future; synchronize the scanner and database clocks', $evidence + ['reason' => 'clock_skew']];
                $ok = $age <= $maxAge;
                return [$ok, $ok ? 'Recorded cron execution is recent' : 'Recorded cron execution is stale', $evidence + ['metric'=>'execution_freshness', 'included_execution_statuses'=>['success','running','error'], 'successful_completion_established'=>false, 'executed_at' => $raw, 'age_seconds' => max(0, $age), 'max_age_seconds' => $maxAge]];
            }
            $threshold = (int)($args['max'] ?? $args['threshold'] ?? 1000);
            if ($threshold < 0) return [null, '[UNKNOWN] Cron backlog threshold must be nonnegative', $evidence];
            $statement = $pdo->prepare('SELECT COUNT(*) FROM ' . $table . " WHERE status = 'pending' AND scheduled_at <= ?");
            $statement->execute([gmdate('Y-m-d H:i:s')]);
            $count = (int)$statement->fetchColumn();
            $ok = $count < $threshold;
            return [$ok, $ok ? 'Due pending cron backlog is below threshold' : 'Due pending cron backlog meets or exceeds threshold', $evidence + ['metric'=>'due_pending_backlog', 'successful_completion_established'=>false, 'due_pending_count' => $count, 'threshold' => $threshold, 'future_jobs_excluded' => true]];
        } catch (\Throwable $error) {
            return [null, '[UNKNOWN] Unable to read Magento cron_schedule; verify the deployed DB connection and SELECT permission for the scheduler table', $evidence + ['reason' => 'cron_database_collection_failed']];
        }
    }

    private function readUserCrontab(string $user, int $timeoutMs): ?string
    {
        // ưu tiên lệnh crontab -u (nếu được phép)
        if (function_exists('proc_open')) {
            $cmd = ['bash','-lc', 'crontab -u ' . escapeshellarg($user) . ' -l 2>/dev/null || true'];
            $desc = [1 => ['pipe','w'], 2 => ['pipe','w'], 0 => ['pipe','r']];
            $p = @proc_open($cmd, $desc, $pipes, null, null, ['bypass_shell'=>true]);
            if (is_resource($p)) {
                fclose($pipes[0]);
                stream_set_timeout($pipes[1], max(1, (int)ceil($timeoutMs/1000)));
                $out = stream_get_contents($pipes[1]);
                fclose($pipes[1]);
                if (is_resource($pipes[2])) fclose($pipes[2]);
                @proc_close($p);
                $out = is_string($out) ? trim($out) : '';
                if ($out !== '') return $out;
            }
        }

        // fallback đọc file hệ thống (Debian/Ubuntu): /var/spool/cron/crontabs/<user>
        $spool = '/var/spool/cron/crontabs/' . $user;
        if (is_readable($spool)) {
            $s = @file_get_contents($spool);
            if (is_string($s) && $s !== '') return $s;
        }
        return null;
    }

    private function readCronFileOrDir(string $path): ?string
    {
        if (is_file($path) && is_readable($path)) {
            $s = @file_get_contents($path);
            return is_string($s) ? $s : null;
        }
        if (is_dir($path) && is_readable($path)) {
            $buf = '';
            foreach (scandir($path) ?: [] as $f) {
                if ($f === '.' || $f === '..') continue;
                $p = $path . '/' . $f;
                if (is_file($p) && is_readable($p)) {
                    $buf .= "\n" . @file_get_contents($p);
                }
            }
            return trim($buf) !== '' ? $buf : null;
        }
        return null;
    }

    /**
     * @param string[] $patterns
     * @return string[]
     */
    private function matchingCronLines(string $txt, array $patterns): array
    {
        $found = [];
        foreach (preg_split("~\r?\n~", $txt) as $ln) {
            $line = trim((string)$ln);
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }
            foreach ($patterns as $rx) {
                if (@preg_match('/' . str_replace('/', '\/', (string)$rx) . '/i', $line) === 1) {
                    $found[] = $line;
                    break;
                }
            }
        }

        return $found;
    }

    private function parseBacklogCount(string $content): ?int
    {
        $trimmed = trim($content);
        if ($trimmed === '') {
            return null;
        }

        if (preg_match('~^\d+$~', $trimmed) === 1) {
            return (int)$trimmed;
        }

        $json = json_decode($trimmed, true);
        if (is_array($json)) {
            foreach (['count', 'queue_size', 'backlog', 'pending', 'missed'] as $key) {
                if (isset($json[$key]) && (is_int($json[$key]) || is_string($json[$key])) && preg_match('/^[0-9]+$/D', (string)$json[$key]) === 1) {
                    return (int)$json[$key];
                }
            }
        }

        if (preg_match('~(?:queue[_ -]?size|backlog|pending|missed)\D{0,20}(?P<count>\d+)~i', $trimmed, $match) === 1) {
            return (int)$match['count'];
        }

        return null;
    }

    /**
     * @param string[] $patterns
     * @return array<int,array<string,mixed>>
     */
    private function findRepoCronEvidence(array $args, array $patterns): array
    {
        if ($this->ctx === null) {
            return [];
        }

        $paths = $args['repo_paths'] ?? ['deploy', '.github', '.gitlab-ci', '.circleci'];
        $includeExt = array_map('strtolower', (array)($args['include_ext'] ?? [
            'sh', 'bash', 'txt', 'conf', 'yml', 'yaml', 'ini', 'env',
        ]));
        $max = max(1, (int)($args['max_results'] ?? 20));
        $evidence = [];

        foreach ((array)$paths as $relative) {
            if (!is_scalar($relative)) {
                continue;
            }
            $root = $this->ctx->abs((string)$relative);
            if (!is_dir($root)) {
                continue;
            }

            $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS));
            foreach ($iterator as $file) {
                if (!$file->isFile() || $file->getSize() > 1024 * 1024) {
                    continue;
                }
                $filename = $file->getFilename();
                $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
                if ($ext === '' || !in_array($ext, $includeExt, true)) {
                    continue;
                }

                $content = @file_get_contents($file->getPathname());
                if (!is_string($content)) {
                    continue;
                }
                $content = implode("\n", array_map(static fn(string $line): string => str_starts_with(ltrim($line), '#') ? '' : $line, preg_split('~\r?\n~', $content) ?: []));
                foreach ($patterns as $rx) {
                    if (preg_match('/' . str_replace('/', '\/', (string)$rx) . '/im', $content, $match, PREG_OFFSET_CAPTURE) !== 1) {
                        continue;
                    }
                    $offset = (int)$match[0][1];
                    $evidence[] = [
                        'file' => $file->getPathname(),
                        'line' => substr_count(substr($content, 0, $offset), "\n") + 1,
                        'pattern' => (string)$rx,
                    ];
                    if (count($evidence) >= $max) {
                        return $evidence;
                    }
                }
            }
        }

        return $evidence;
    }
}
