<?php
declare(strict_types=1);
$archive = isset($argv[1]) ? realpath($argv[1]) : null;
if (isset($argv[1]) && !$archive) throw new RuntimeException('Supply a valid PHAR path.');
require $archive ? 'phar://'.$archive.'/vendor/autoload.php' : __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\Checks\{AbsoluteTimestamp, DependencyPolicyCheck, GitHistoryCheck, MagentoDiCheck};
use Magebean\Engine\Checks\Families\{ComposerAdvisoryChecks, ComposerRepositoryChecks};
use Magebean\Engine\Collectors\CollectorSet;
use Magebean\Engine\Context;

$count = 0;
$assert = static function (bool $ok, string $message) use (&$count): void {
    ++$count;
    if (!$ok) throw new RuntimeException($message);
};
$root = sys_get_temp_dir().'/magebean-phase1-'.bin2hex(random_bytes(8));
mkdir($root, 0700);
$put = static function (string $path, string $content) use ($root): void {
    $directory = dirname($root.'/'.$path);
    if (!is_dir($directory)) mkdir($directory, 0700, true);
    file_put_contents($root.'/'.$path, $content);
};
$git = static function (array $args) use ($root): void {
    $process = proc_open(array_merge(['git', '-C', $root], $args), [1=>['pipe','w'], 2=>['pipe','w']], $pipes);
    $output = stream_get_contents($pipes[1]); $error = stream_get_contents($pipes[2]);
    fclose($pipes[1]); fclose($pipes[2]);
    if (proc_close($process) !== 0) throw new RuntimeException('Fixture Git operation failed: '.$error.$output);
};
try {
    // PHP runtime is the independent oracle for inherited constructor visibility.
    class Phase1PrivateParent { private function __construct() {} }
    class Phase1PrivateChild extends Phase1PrivateParent {}
    try { new Phase1PrivateChild(); $blocked = false; } catch (Error) { $blocked = true; }
    $assert($blocked, 'PHP rejects inherited private constructor');
    class Phase1PublicParent { public function __construct() {} }
    class Phase1PublicChild extends Phase1PublicParent {}
    $assert(new Phase1PublicChild() instanceof Phase1PublicParent, 'PHP accepts inherited public constructor');
    $base = ['kind'=>'class', 'abstract'=>false, 'final'=>false, 'traits'=>[], 'extends'=>[], 'implements'=>[], 'methods'=>[]];
    $parent = $base + ['name'=>'Fixture\ParentType'];
    $child = $base + ['name'=>'Fixture\ChildType']; $child['extends']=['Fixture\ParentType'];
    $child['implements']=['Fixture\Contract'];
    $contract = $base + ['name'=>'Fixture\Contract']; $contract['kind']='interface';
    $di = new MagentoDiCheck(new Context($root, ''), new CollectorSet());
    $inspect = new ReflectionMethod($di, 'inspect');
    $preference = ['preference'=>['Fixture\Contract'=>['target'=>'Fixture\ChildType']]];
    foreach (['private', 'protected', 'public'] as $visibility) {
        $parent['methods']['__construct']=['visibility'=>$visibility, 'parameters'=>[]];
        $symbols=['fixture\parenttype'=>[$parent], 'fixture\childtype'=>[$child], 'fixture\contract'=>[$contract]];
        $expected = $visibility === 'public' ? 'ok' : 'finding';
        $assert($inspect->invoke($di, 'di-preference', 'Fixture\Contract', null, [], $preference, $symbols)[0] === $expected,
            'Preference checks inherited '.$visibility.' constructor');
        $virtual=['virtualType'=>['VirtualFixture'=>['target'=>'Fixture\ChildType']]];
        $assert($inspect->invoke($di, 'di-virtual-type', 'VirtualFixture', null, [], $virtual, $symbols)[0] === $expected,
            'Virtual type checks inherited '.$visibility.' constructor');
        $assert($inspect->invoke($di, 'di-plugins', 'Fixture\Contract', 'plugin', ['type'=>'Fixture\ChildType'], [], $symbols)[0] === $expected,
            'Plugin checks inherited '.$visibility.' constructor');
    }
    unset($symbols['fixture\parenttype']);
    $assert($inspect->invoke($di, 'di-preference', 'Fixture\Contract', null, [], $preference, $symbols)[0] === 'gap', 'Missing parent cannot establish construction');
    $child['extends']=[]; $child['traits']=['Fixture\UnknownTrait']; $symbols['fixture\childtype']=[$child];
    $assert($inspect->invoke($di, 'di-preference', 'Fixture\Contract', null, [], $preference, $symbols)[0] === 'gap', 'Unresolved trait constructor cannot pass');
    $child['traits']=[]; $child['methods']['__construct']=['visibility'=>'public', 'parameters'=>[['name'=>'callback', 'type'=>'callable', 'variadic'=>false]]];
    $symbols['fixture\childtype']=[$child];
    $assert($inspect->invoke($di, 'di-arguments', 'Fixture\ChildType', 'callback', ['type'=>'array'], [], $symbols)[0] === 'gap', 'Array without callable proof is incomplete');
    $child['methods']['__construct']['parameters'][0]['type']='array'; $symbols['fixture\childtype']=[$child];
    $assert($inspect->invoke($di, 'di-arguments', 'Fixture\ChildType', 'callback', ['type'=>'array'], [], $symbols)[0] === 'ok', 'Supported array parameter still passes');
    $child['methods']['__construct']['parameters'][0]['type']='string'; $symbols['fixture\childtype']=[$child];
    $assert($inspect->invoke($di, 'di-arguments', 'Fixture\ChildType', 'callback', ['type'=>'array'], [], $symbols)[0] === 'finding', 'Proven array/string mismatch remains a finding');

    $repository = new ComposerRepositoryChecks(new Context($root, ''));
    $release = new ReflectionMethod($repository, 'assessReleaseRecencyStatuses');
    $advisory = new ComposerAdvisoryChecks(new Context($root, ''));
    $age = new ReflectionMethod($advisory, 'assessAdvisoryPublicationAges');
    $packages=[['name'=>'fixture/package', 'version'=>'1.0.0']];
    $fresh=gmdate(DATE_ATOM, time()-86400);
    foreach (['2026-02-30T00:00:00Z', 'yesterday', '2099-01-01T00:00:00Z', '', '2026-01-01T24:00:00Z', '2026-01-01T00:00:00+99:00'] as $date) {
        $status=['fixture/package'=>['release_history_known'=>true, 'latest_date'=>$date]];
        $assert($release->invoke($repository, $packages, $status, ['strict_scope'=>true])[0] === null, 'Invalid/future release is UNKNOWN: '.$date);
        $result=$age->invoke($advisory, ['findings'=>[['package'=>'fixture/package', 'version'=>'1.0.0', 'advisory'=>'QA-DATE', 'published'=>$date]]], []);
        $assert($result[0] === null && $result[2]['missing_published_date'][0]['open_days'] === null, 'Invalid/future advisory is not zero-day PASS: '.$date);
    }
    foreach ([$fresh, '2000-02-29T12:34:56Z', '2000-02-29', '2000-02-29T12:34:56.123456789+07:00'] as $date) {
        $parsed=AbsoluteTimestamp::parse($date);
        $assert($parsed !== null, 'Valid absolute timestamp accepted: '.$date);
    }
    $assert(AbsoluteTimestamp::parse('2025-02-29') === null, 'Nonleap calendar date rejected');
    $assert(AbsoluteTimestamp::parse('2000-02-29T12:34:56+07:00')->getTimestamp() === AbsoluteTimestamp::parse('2000-02-29T05:34:56Z')->getTimestamp(), 'Offset normalization retains actual instant');
    foreach ([$fresh=>true, '2000-01-01T00:00:00Z'=>false] as $date=>$expected) {
        $assert($release->invoke($repository, $packages, ['fixture/package'=>['release_history_known'=>true, 'latest_date'=>$date]], ['strict_scope'=>true])[0] === $expected, 'Valid recent/stale release preserves outcome');
        $result=$age->invoke($advisory, ['findings'=>[['package'=>'fixture/package', 'published'=>$date]]], []);
        $assert($result[0] === $expected && !str_contains($result[1], 'remediation SLA'), 'Publication age preserves outcome without invented SLA');
        $assert($result[2]['sla_days'] === $result[2]['publication_age_threshold_days'], 'Legacy numeric wire field remains compatible');
    }
    $mixed=$age->invoke($advisory, ['findings'=>[['package'=>'fixture/old', 'published'=>'2000-01-01T00:00:00Z'], ['package'=>'fixture/unknown', 'published'=>'yesterday']]], []);
    $assert($mixed[0] === false && count($mixed[2]['missing_published_date']) === 1, 'Proven age violation survives partial date coverage');

    $source=['url'=>'https://example.invalid/repository.git', 'reference'=>'fixture-revision'];
    $put('composer.json', '{}');
    $put('policy.json', json_encode(['schema_version'=>1, 'packages'=>['fixture/package'=>['source'=>$source]], 'root_repositories'=>[]]));
    foreach (['1.0.0'=>true, ''=>null, '   '=>null] as $version=>$expected) {
        $put('composer.lock', json_encode(['packages'=>[['name'=>'fixture/package', 'version'=>$version, 'source'=>$source]]]));
        $assert((new DependencyPolicyCheck(new Context($root, '')))->sourcePolicy(['policy_file'=>'policy.json'])[0] === $expected, 'Source match needs a nonblank version');
    }
    foreach ([['name'=>'fixture/package', 'source'=>$source], ['name'=>'fixture/package', 'version'=>123, 'source'=>$source]] as $malformed) {
        $put('composer.lock', json_encode(['packages'=>[$malformed]]));
        $assert((new DependencyPolicyCheck(new Context($root, '')))->sourcePolicy(['policy_file'=>'policy.json'])[0] === null, 'Missing or nonstring version cannot pass');
    }
    $put('composer.lock', json_encode(['packages'=>[['name'=>'fixture/package', 'version'=>'1.0.0', 'source'=>array_replace($source, ['reference'=>'wrong'])]]]));
    $assert((new DependencyPolicyCheck(new Context($root, '')))->sourcePolicy(['policy_file'=>'policy.json'])[0] === false, 'Valid identity with wrong source still fails');

    $secret='AKIA'.str_repeat('A', 16);
    $put('app/etc/env.php', '<?php // '.$secret); chmod($root.'/app/etc/env.php', 0600);
    $scan=new GitHistoryCheck(new Context($root, '')); $args=['patterns'=>['AKIA[0-9A-Z]{16}']];
    $assert($scan->workingTreeScan($args)[0] === true, 'Expected runtime secret is not exposure by itself');
    $assert($scan->workingTreeScan($args+['paths'=>['app/etc/env.php']])[0] === true, 'Explicit path cannot bypass expected-runtime exclusion');
    $assert($scan->secretScan($args)[0] === null, 'No Git metadata remains incomplete, not a secret finding');
    $put('app/etc/env.php.bak', $secret);
    $assert($scan->workingTreeScan($args)[0] === false, 'Credential backup is not expected runtime storage');
    unlink($root.'/app/etc/env.php.bak');
    $put('unexpected.php', $secret);
    $unexpected=$scan->workingTreeScan($args);
    $assert($unexpected[0] === false && str_contains($unexpected[1], 'unexpected.php:1'), 'Unexpected source secret remains actionable');
    $assert(!str_contains(json_encode($unexpected), $secret), 'Unexpected secret bytes are redacted');
    unlink($root.'/unexpected.php');
    $git(['init', '-q']);
    $git(['add', '--', 'app/etc/env.php']);
    $staged=$scan->secretScan($args);
    $assert($staged[0] === false && $staged[2]['git_index_findings'][0]['scope'] === 'git_index', 'Staged env secret detected before first commit');
    $assert(!str_contains(json_encode($staged), $secret), 'Staged secret bytes are redacted');
    $git(['-c','user.name=QA Fixture','-c','user.email=qa@example.invalid','-c','core.hooksPath=/dev/null','commit','-qm','Synthetic secret fixture']);
    $put('app/etc/env.php', '<?php return [];');
    $git(['add', '--', 'app/etc/env.php']);
    $history=$scan->secretScan($args);
    $assert($history[0] === false && count(array_filter($history[2]['git_history_findings'], static fn($r)=>$r['scope']==='git_history')) > 0, 'Removing current secret retains historical evidence');
    $assert(!str_contains(json_encode($history), $secret), 'Historical secret bytes are redacted');
    $assert($scan->secretScan($args+['exclude_dirs'=>['.git','app/etc/env.php']])[0] === true, 'Explicit file exclusions apply consistently to index and history');
    echo "Current-state Phase 1 correctness: $count assertions passed\n";
} finally {
    // Remove only the test-owned absolute temporary directory, never a workspace tree.
    $iterator=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($iterator as $entry) $entry->isDir() && !$entry->isLink() ? rmdir($entry->getPathname()) : unlink($entry->getPathname());
    rmdir($root);
}
