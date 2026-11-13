<?php
declare(strict_types=1);
namespace Magebean\Engine\Checks;

use Magebean\Engine\Context;

/** Bounded declarative policy checks. No provider or approval is inferred. */
final class DependencyPolicyCheck
{
    public function __construct(private Context $ctx) {}

    public function sourcePolicy(array $args): array
    {
        $lock = $this->json((string)($args['lock_file'] ?? 'composer.lock'));
        $root = $this->json((string)($args['composer_file'] ?? 'composer.json'));
        $policy = $this->json((string)($args['policy_file'] ?? '.magebean/dependency-source-policy.json'));
        if ($lock === null || $root === null || $policy === null) return $this->unknown('Readable lock, root Composer metadata and source policy are required');
        if (($policy['schema_version'] ?? null) !== 1 || !is_array($policy['packages'] ?? null)
            || !is_array($policy['root_repositories'] ?? null) || !is_array($lock['packages'] ?? null)
            || (isset($lock['packages-dev']) && !is_array($lock['packages-dev']))) return $this->unknown('Unsupported or incomplete source policy/inventory schema');
        if (array_merge($lock['packages'], $lock['packages-dev'] ?? []) === []) return $this->unknown('Empty Composer inventory cannot establish Magento dependency coverage');
        $fail = []; $unknown = []; $seen = [];
        $repositories = $root['repositories'] ?? [];
        if (!is_array($repositories)) return $this->unknown('Malformed root repository declarations');
        // Exact declarations account for private hosts, path repositories and disabled defaults.
        if ($this->canonical($repositories) !== $this->canonical($policy['root_repositories'])) $fail[] = ['scope' => 'root_repositories', 'reason' => 'declaration_policy_mismatch'];
        foreach (array_merge($lock['packages'], $lock['packages-dev'] ?? []) as $package) {
            if (!is_array($package) || !is_string($package['name'] ?? null) || trim($package['name']) === '' || !is_string($package['version'] ?? null) || trim($package['version']) === '') { $unknown[] = ['reason' => 'malformed_package']; continue; }
            $name = strtolower($package['name']);
            if (isset($seen[$name])) { $unknown[] = ['package' => $name, 'reason' => 'duplicate_package']; continue; }
            $seen[$name] = true;
            $approved = $policy['packages'][$name] ?? null;
            if (!is_array($approved)) { $unknown[] = ['package' => $name, 'reason' => 'package_policy_missing']; continue; }
            if (($approved['metadata_only'] ?? false) === true && ($package['type'] ?? '') === 'metapackage') {
                if (isset($package['source']) || isset($package['dist'])) $unknown[] = ['package' => $name, 'reason' => 'metapackage_has_source'];
            } else {
                foreach (['source', 'dist'] as $kind) {
                    if (!isset($package[$kind])) { if (isset($approved[$kind])) $fail[] = ['package' => $name, 'reason' => $kind . '_missing_from_lock']; continue; }
                    $actual = $package[$kind]; $expected = $approved[$kind] ?? null;
                    if (!is_array($actual) || !is_array($expected) || !is_string($actual['url'] ?? null) || !is_string($actual['reference'] ?? null)
                        || !is_string($expected['url'] ?? null) || !is_string($expected['reference'] ?? null)
                        || trim($actual['reference']) === '' || trim($expected['reference']) === '' || trim($expected['url']) === '') {
                        $unknown[] = ['package' => $name, 'reason' => $kind . '_identity_incomplete']; continue;
                    }
                    if ($actual['url'] !== $expected['url'] || $actual['reference'] !== $expected['reference']) $fail[] = ['package' => $name, 'reason' => $kind . '_policy_mismatch'];
                }
                if (!isset($package['source']) && !isset($package['dist'])) $unknown[] = ['package' => $name, 'reason' => 'source_and_dist_missing'];
            }
            if ($this->canonical($package['replace'] ?? []) !== $this->canonical($approved['replace'] ?? [])) $fail[] = ['package' => $name, 'reason' => 'replacement_policy_mismatch'];
        }
        return $this->result($fail, $unknown, ['packages_checked' => count($seen), 'scope' => 'Collected Composer lock source/dist identities, replacement declarations and root repository policy; no installed-byte integrity proof']);
    }

    public function mitigationRecords(array $args): array
    {
        $data = $this->json((string)($args['inventory_file'] ?? '.magebean/mitigations.json'));
        $expected = $args['expected_ids'] ?? null;
        if ($data === null || !is_array($expected) || $expected === [] || !array_is_list($expected) || ($data['schema_version'] ?? null) !== 1 || !is_array($data['records'] ?? null) || !array_is_list($data['records'])) return $this->unknown('Readable mitigation inventory and nonempty explicit expected_ids policy are required');
        foreach ($expected as $id) if (!is_string($id) || trim($id) === '') return $this->unknown('Malformed expected mitigation identity');
        $generated = $this->date($data['generated_at'] ?? null);
        $maxAge = max(1, (int)($args['max_age_days'] ?? 30));
        if ($generated === null || $generated > time() || time() - $generated > $maxAge * 86400) return $this->unknown('Mitigation inventory timestamp is missing, invalid, future or stale');
        $fail = []; $unknown = []; $seen = []; $references=[];
        foreach ($data['records'] as $record) {
            if (!is_array($record) || !is_string($record['id'] ?? null) || trim($record['id']) === '') { $unknown[] = ['reason' => 'record_identity_missing']; continue; }
            $id = $record['id'];
            if (count($references)<100 && preg_match('~^[a-z0-9_.-]+/[a-z0-9_.-]+$~D',(string)($record['package']??''))
                && preg_match('/^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$/D',(string)($record['advisory']??''))
                && preg_match('/^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/D',(string)($record['version']??''))) {
                $references[]=['record_id'=>$id,'package'=>$record['package'],'version'=>$record['version'],'advisory'=>$record['advisory'],'basis'=>'supplied_record_claim_only'];
            }
            if (isset($seen[$id])) { $fail[] = ['id' => $id, 'reason' => 'duplicate_identity']; continue; }
            $seen[$id] = true;
            foreach (['advisory', 'package', 'version', 'owner', 'action', 'rollback'] as $field) if (!is_string($record[$field] ?? null) || trim($record[$field]) === '') $fail[] = ['id' => $id, 'reason' => 'missing_' . $field];
            $expires = $this->date($record['expires_at'] ?? null);
            if ($expires === null) $fail[] = ['id' => $id, 'reason' => 'invalid_expiry'];
            elseif ($expires <= time()) $fail[] = ['id' => $id, 'reason' => 'expired_record'];
        }
        foreach ($expected as $id) if (!isset($seen[$id])) $fail[] = ['id' => $id, 'reason' => 'expected_record_missing'];
        return $this->result($fail, $unknown, ['records_checked' => count($seen), 'declared_technical_references'=>$references, 'scope' => 'Declared record structure, expiry and supplied expected identity coverage only; no mitigation implementation or truth verification']);
    }

    private function json(string $path): ?array
    {
        if ($path === '' || str_contains($path, "\0") || preg_match('~^(?:[/\\\\]|[A-Za-z]:|[A-Za-z][A-Za-z0-9+.-]*:)~', $path)
            || in_array('..', preg_split('~[/\\\\]+~', $path) ?: [], true)) return null;
        $root = realpath($this->ctx->path); $resolved = realpath($this->ctx->abs($path));
        if (!is_string($root) || !is_string($resolved) || !str_starts_with($resolved, rtrim($root, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR)) return null;
        clearstatcache(true, $resolved); $before = @stat($resolved);
        if (!is_array($before) || !is_file($resolved) || !is_readable($resolved) || $before['size'] > 4 * 1024 * 1024) return null;
        $handle = @fopen($resolved, 'rb');
        if ($handle === false) return null;
        try { $opened = fstat($handle); $raw = stream_get_contents($handle, 4 * 1024 * 1024 + 1); $after = fstat($handle); }
        finally { fclose($handle); }
        clearstatcache(true, $resolved); $pathAfter = @stat($resolved);
        foreach ([$opened, $after, $pathAfter] as $stat) {
            if (!is_array($stat)) return null;
            foreach (['dev', 'ino', 'size', 'mtime', 'ctime'] as $key) if ($stat[$key] !== $before[$key]) return null;
        }
        if (realpath($this->ctx->abs($path)) !== $resolved || !is_string($raw) || strlen($raw) !== $before['size'] || strlen($raw) > 4 * 1024 * 1024) return null;
        $data = json_decode($raw, true);
        return is_array($data) ? $data : null;
    }
    private function canonical(mixed $value): string
    {
        if (is_array($value)) { if (!array_is_list($value)) ksort($value); foreach ($value as &$item) $item = $this->canonical($item); unset($item); }
        return (string)json_encode($value, JSON_UNESCAPED_SLASHES);
    }
    private function date(mixed $value): ?int
    {
        if (!is_string($value) || !preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2})$/D', $value)) return null;
        try { $date = new \DateTimeImmutable($value); $errors = \DateTimeImmutable::getLastErrors(); if (is_array($errors) && ($errors['warning_count'] || $errors['error_count'])) return null; return $date->getTimestamp(); } catch (\Exception) { return null; }
    }
    private function unknown(string $reason): array { return [null, '[UNKNOWN] ' . $reason, ['scope' => 'dependency policy']]; }
    private function result(array $fail, array $unknown, array $evidence): array
    {
        $evidence += ['violations' => $fail, 'unresolved' => $unknown];
        if ($fail !== []) return [false, 'Declared dependency policy violations found', $evidence];
        if ($unknown !== []) return [null, '[UNKNOWN] Dependency policy collection is incomplete', $evidence];
        return [true, 'Collected declarations satisfy the explicit dependency policy', $evidence];
    }
}
