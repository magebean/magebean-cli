<?php
declare(strict_types=1);

require __DIR__.'/../vendor/autoload.php';

use Magebean\Engine\{RequirementCatalog, RequirementPolicy, RequirementProfileCatalog};

function launchAssert(bool $ok, string $message): void
{
    if (!$ok) throw new RuntimeException($message);
}

$root = sys_get_temp_dir().'/mb-launch-'.bin2hex(random_bytes(6));
$entry = $argv[1] ?? __DIR__.'/../bin/magebean';
$put = static function (string $path, string $contents) use ($root): void {
    $file = $root.'/'.$path;
    if (!is_dir(dirname($file))) mkdir(dirname($file), 0700, true);
    file_put_contents($file, $contents);
};
$cli = static function (array $args) use ($entry, $root): array {
    $proc = proc_open([PHP_BINARY, $entry, ...$args, '--no-interaction', '--no-ansi'], [
        1 => ['pipe', 'w'], 2 => ['pipe', 'w'],
    ], $pipes, $root);
    if (!is_resource($proc)) throw new RuntimeException('Cannot start CLI fixture.');
    $output = stream_get_contents($pipes[1]);
    $error = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    return [proc_close($proc), $output.$error];
};
$server = null;
try {
    $put('composer.json', '{"name":"fixture/project","require":{"magento/product-community-edition":"2.4.7"},"config":{"platform":{"php":"8.1.0"}}}');
    $put('composer.lock', '{"packages":[{"name":"magento/framework","version":"103.0.6"}],"packages-dev":[]}');
    $put('vendor/composer/installed.json', '{"packages":[{"name":"magento/framework","version":"103.0.6","install-path":"../magento/framework"}]}');
    $put('vendor/magento/framework/.keep', '');
    $put('app/code/Fixture/Example/registration.php', '<?php \Magento\Framework\Component\ComponentRegistrar::register(\Magento\Framework\Component\ComponentRegistrar::MODULE, "Fixture_Example", __DIR__);');
    $put('app/code/Fixture/Example/etc/module.xml', '<config><module name="Fixture_Example"/></config>');
    $put('app/code/Fixture/Example/Example.php', '<?php function action() { \exec($_GET["command"]); }');

    $catalog = array_column(RequirementCatalog::loadAll()['rules'], null, 'id');
    foreach (['development' => 28, 'prelaunch' => 52] as $profile => $count) {
        $members = RequirementProfileCatalog::load($profile)['requirement_ids'];
        launchAssert(count($members) === $count && count(array_unique($members)) === $count, 'Profile membership is canonical and unique.');
        foreach ($members as $id) {
            launchAssert($catalog[$id]['family'] === 'magebean' && !RequirementPolicy::requiresHuman($catalog[$id]), 'Profile stays automated and Magebean-owned.');
        }
        [$exit, $listing] = $cli(['rules:list', '--profile='.$profile]);
        launchAssert($exit === 0 && str_contains($listing, 'Total Rules Listed: '.$count), $listing);
    }

    [$auditExit, $auditOut] = $cli(['audit', '--profile=development', '--rules=MB-0822']);
    [$exit, $out] = $cli(['scan', '--profile=development', '--rules=MB-0822']);
    launchAssert($exit === 1 && str_contains($out, 'Fixture_Example') && str_contains($out, 'Request input reaches a command call'), $out);
    launchAssert($auditExit === $exit && str_contains($auditOut, 'Fixture_Example') && str_contains($auditOut, 'Request input reaches a command call'), $auditOut);
    [$exit, $out] = $cli(['scan', '--profile=development', '--path=.', '--rules=MB-0828']);
    launchAssert($exit === 3 && str_contains($out, 'advisory snapshot unavailable'), $out);
    $put('.magebean/osv-db.json', '[{"id":"FIXTURE-001","affected":[{"package":{"ecosystem":"Packagist","name":"magento/framework"},"versions":["103.0.1"]}]}]');
    [$exit, $out] = $cli(['scan', '--profile=development', '--path=.', '--rules=MB-0828']);
    launchAssert($exit === 0, $out);
    $put('.magebean/osv-db.json', '[{"id":"FIXTURE-001","affected":[{}]}]');
    [$exit, $out] = $cli(['scan', '--profile=development', '--path=.', '--rules=MB-0828']);
    launchAssert($exit === 3 && str_contains($out, 'invalid affected package'), $out);
    $put('.magebean/osv-db.json', '[{"id":"FIXTURE-001","withdrawn":"2024-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"Packagist","name":"magento/framework"},"versions":["103.0.6"]}]}]');
    [$exit, $out] = $cli(['scan', '--profile=development', '--path=.', '--rules=MB-0828']);
    launchAssert($exit === 0, $out);
    [$exit, $out] = $cli(['scan', '--profile=development', '--path=.', '--rules=MB-0031']);
    launchAssert($exit === 1 && str_contains($out, 'outside the selected'), $out);
    [$exit, $out] = $cli(['scan', '--profile=development', '--path=.']);
    launchAssert($exit === 3 && str_contains($out, 'Request input reaches a command call') && !str_contains($out, 'Deployment mode is not production'), $out);

    $put('bin/magento', '<?php throw new RuntimeException("Do not bootstrap the fixture");');
    $put('app/etc/config.php', '<?php return ["modules" => ["Fixture_Example" => 1]];');
    $put('app/etc/env.php', '<?php return ["MAGE_MODE" => "developer", "system" => ["default" => ["web" => ["secure" => ["base_url" => "http://127.0.0.1:1/"]]]]];');
    $args = ['scan', '--profile=prelaunch', '--path=.', '--rules=MB-0031,MB-0779'];
    [$exit, $out] = $cli($args);
    launchAssert($exit === 3 && str_contains($out, 'Runtime coverage unavailable') && str_contains($out, 'MB-0031'), $out);

    $socket = stream_socket_server('tcp://127.0.0.1:0');
    if ($socket === false) throw new RuntimeException('Cannot allocate a loopback fixture port.');
    $host = stream_socket_get_name($socket, false);
    fclose($socket);
    $put('router.php', '<?php header("X-Frame-Options: DENY"); echo "staging fixture";');
    $server = proc_open([PHP_BINARY, '-S', $host, $root.'/router.php'], [
        1 => ['file', $root.'/server.log', 'a'], 2 => ['file', $root.'/server.log', 'a'],
    ], $pipes, $root);
    if (!is_resource($server)) throw new RuntimeException('Cannot launch loopback fixture.');
    for ($i = 0; $i < 50; ++$i) {
        $ready = @stream_socket_client('tcp://'.$host, timeout: 0.05);
        if ($ready !== false) {
            fclose($ready);
            break;
        }
        usleep(20000);
    }
    [$exit, $out] = $cli([...$args, '--url=http://'.$host]);
    launchAssert($exit === 1 && str_contains($out, 'Tested endpoint: http://'.$host)
        && str_contains($out, 'MB-0031') && !str_contains($out, 'is ignored'), $out);
    [$exit, $out] = $cli(['scan', '--profile=prelaunch', '--path=.', '--url=http://'.$host]);
    launchAssert($exit === 3 && str_contains($out, 'Running 52 audit rules') && str_contains($out, 'MB-0031'), $out);
    proc_terminate($server);
    proc_close($server);
    $server = null;
    [$exit, $out] = $cli([...$args, '--url=http://'.$host]);
    launchAssert($exit === 3 && str_contains($out, 'MB-0031'), $out);
} finally {
    if (is_resource($server)) {
        proc_terminate($server);
        proc_close($server);
    }
    if (is_dir($root)) {
        $tree = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($tree as $file) {
            if ($file->isDir() && !$file->isLink()) rmdir($file->getPathname());
            else unlink($file->getPathname());
        }
        rmdir($root);
    }
}
echo "Development and prelaunch profiles passed\n";
