<?php
declare(strict_types=1);

namespace Magebean\Engine\Collectors;

use Magebean\Engine\Context;

/** Shared path and acquisition budget for one module metadata discovery. */
final class MagentoInventoryFiles
{
    public array $gaps = [];
    public bool $complete = true;
    private int $entries = 0;
    private int $bytes = 0;
    private readonly float $deadline;
    private readonly BoundedSourceInventory $source;

    public function __construct(private readonly Context $context, private readonly string $root, private readonly ?CollectionSession $session)
    {
        $this->deadline = microtime(true) + 10;
        $this->source = new BoundedSourceInventory();
    }

    public static function relative(string $base, string $path): ?string
    {
        $path = str_replace('\\', '/', $path);
        if ($path === '' || str_starts_with($path, '/') || preg_match('/[:\x00-\x1f]/', $path)) return null;
        $parts = $base === '' || $base === '.' ? [] : explode('/', $base);
        foreach (explode('/', $path) as $part) {
            if ($part === '' || $part === '.') continue;
            if ($part === '..') {
                if ($parts === []) return null;
                array_pop($parts);
            } else {
                $parts[] = $part;
            }
        }
        return $parts === [] ? null : implode('/', $parts);
    }

    public function gap(string $path, string $reason, ?string $subject = null): void
    {
        $this->complete = false;
        if (count($this->gaps) < 100) $this->gaps[] = ['file' => $path, 'reason' => $reason] + ($subject !== null ? ['subject' => $subject] : []);
    }

    private function resolve(string $path, bool $required): ?string
    {
        $this->session?->checkpoint();
        if (++$this->entries > 20000 || microtime(true) > $this->deadline) {
            $this->gap($path, 'inventory_budget_exceeded');
            return null;
        }
        $cursor = rtrim($this->root, DIRECTORY_SEPARATOR);
        foreach (explode('/', $path) as $part) {
            if ($part === '' || $part === '.' || $part === '..' || preg_match('/[\\\\:\x00-\x1f]/', $part)) {
                $this->gap($path, 'invalid_project_path');
                return null;
            }
            $cursor .= DIRECTORY_SEPARATOR.$part;
            if (is_link($cursor)) {
                $this->gap($path, 'symlink_not_followed');
                return null;
            }
            if (!file_exists($cursor)) {
                if ($required) $this->gap($path, 'metadata_missing');
                return null;
            }
        }
        return $cursor;
    }

    public function exists(string $path): bool
    {
        return $this->resolve($path, false) !== null;
    }

    public function isDirectory(string $path, bool $required = false): bool
    {
        $resolved = $this->resolve($path, $required);
        return $resolved !== null && is_dir($resolved);
    }

    public function directories(string $path): array
    {
        $resolved = $this->resolve($path, false);
        if ($resolved === null) return [];
        $directories = [];
        try {
            foreach (new \FilesystemIterator($resolved, \FilesystemIterator::SKIP_DOTS) as $entry) {
                if (++$this->entries > 20000 || microtime(true) > $this->deadline) {
                    $this->gap($path, 'inventory_budget_exceeded');
                    break;
                }
                $child = $path.'/'.$entry->getFilename();
                if ($entry->isLink()) $this->gap($child, 'symlink_not_followed');
                elseif ($entry->isDir()) $directories[] = $child;
            }
        } catch (\UnexpectedValueException) {
            $this->gap($path, 'directory_unreadable');
        }
        sort($directories, SORT_STRING);
        return $directories;
    }

    public function read(string $path, bool $required = false): ?string
    {
        $resolved = $this->resolve($path, $required);
        if ($resolved === null) return null;
        if (!is_file($resolved) || $this->bytes >= 16777216) {
            $this->gap($path, 'metadata_file_or_budget_unavailable');
            return null;
        }
        $limit = min(2097152, 16777216 - $this->bytes);
        $result = $this->source->collect($this->context, [
            'paths' => [$path],
            'include_ext' => [pathinfo($path, PATHINFO_EXTENSION)],
            'max_files' => 1,
            'verify_stable' => true,
            'max_file_bytes' => $limit,
            'max_total_bytes' => $limit,
        ]);
        $this->bytes += $result['bytes_read'];
        if (!$result['complete']) {
            foreach ($result['gaps'] as $gap) $this->gap($path, $gap['reason']);
            return null;
        }
        return $result['files'][0]['content'] ?? null;
    }

    public function json(string $path, bool $required = false): ?array
    {
        $text = $this->read($path, $required);
        if ($text === null) return null;
        try {
            $value = json_decode($text, true, 64, JSON_THROW_ON_ERROR);
            if (is_array($value)) return $value;
        } catch (\JsonException) {
            // Report a bounded diagnostic without leaking raw metadata.
        }
        $this->gap($path, 'metadata_json_unresolved');
        return null;
    }
}
