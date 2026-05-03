<?php

declare(strict_types=1);

namespace Magebean\Engine;

final class ProfileLoader
{
    private static function dir(): string
    {
        return __DIR__ . '/../Rules/profiles';
    }

    public static function load(string $profile, string $projectPath = ''): array
    {
        $profile = trim($profile);
        if ($profile === '') {
            throw new \RuntimeException('Profile cannot be empty.');
        }

        $file = self::resolveProfileFile($profile, $projectPath);
        $data = self::loadFile($file);
        $data['_source'] = $file;

        return self::normalize($data);
    }

    public static function apply(array $pack, array $profile): array
    {
        $rules = $pack['rules'] ?? [];
        if (!is_array($rules)) {
            $rules = [];
        }

        $byId = [];
        foreach ($rules as $rule) {
            if (!is_array($rule)) {
                continue;
            }
            $id = strtoupper((string)($rule['id'] ?? ''));
            if ($id !== '') {
                $byId[$id] = $rule;
            }
        }

        $includeControls = self::strings($profile['include']['controls'] ?? $profile['controls'] ?? []);
        $includeRules = self::profileRuleIds($profile);
        $excludeRules = self::strings($profile['exclude']['rules'] ?? $profile['exclude_rules'] ?? []);

        $selected = [];
        if ($includeRules) {
            $unknown = [];
            foreach ($includeRules as $id) {
                if (!isset($byId[$id])) {
                    $unknown[] = $id;
                    continue;
                }
                $selected[] = self::withProfileMetadata($byId[$id], $profile, $id);
            }
            if ($unknown) {
                throw new \RuntimeException(sprintf(
                    'Profile "%s" references unknown rule id(s): %s',
                    (string)($profile['id'] ?? 'custom'),
                    implode(', ', $unknown)
                ));
            }
        } elseif ($includeControls) {
            foreach ($rules as $rule) {
                if (!is_array($rule)) {
                    continue;
                }
                $control = strtoupper((string)($rule['control'] ?? ''));
                $id = strtoupper((string)($rule['id'] ?? ''));
                if (in_array($control, $includeControls, true)) {
                    $selected[] = self::withProfileMetadata($rule, $profile, $id);
                }
            }
        } else {
            foreach ($rules as $rule) {
                if (is_array($rule)) {
                    $id = strtoupper((string)($rule['id'] ?? ''));
                    $selected[] = self::withProfileMetadata($rule, $profile, $id);
                }
            }
        }

        if ($excludeRules) {
            $selected = array_values(array_filter(
                $selected,
                static fn(array $rule): bool => !in_array(strtoupper((string)($rule['id'] ?? '')), $excludeRules, true)
            ));
        }

        $pack['rules'] = self::dedupeRules($selected);
        $pack['controls'] = self::controlsForRules($pack['rules']);
        $pack['profile'] = self::publicMetadata($profile);

        return $pack;
    }

    public static function publicMetadata(array $profile): array
    {
        $out = $profile;
        unset($out['rules'], $out['include'], $out['exclude']);
        return $out;
    }

    private static function resolveProfileFile(string $profile, string $projectPath): string
    {
        $candidates = [];

        if (self::looksLikePath($profile)) {
            $candidates[] = $profile;
            if (!self::isAbsolutePath($profile)) {
                $candidates[] = getcwd() . DIRECTORY_SEPARATOR . $profile;
                if ($projectPath !== '') {
                    $candidates[] = rtrim($projectPath, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $profile;
                }
            }
        } else {
            $projectProfileFiles = [
                getcwd() . DIRECTORY_SEPARATOR . '.magebean' . DIRECTORY_SEPARATOR . 'profiles' . DIRECTORY_SEPARATOR . $profile . '.json',
            ];
            if ($projectPath !== '') {
                $projectProfileFiles[] = rtrim($projectPath, DIRECTORY_SEPARATOR)
                    . DIRECTORY_SEPARATOR . '.magebean'
                    . DIRECTORY_SEPARATOR . 'profiles'
                    . DIRECTORY_SEPARATOR . $profile . '.json';
            }
            foreach ($projectProfileFiles as $candidate) {
                if (is_file($candidate)) {
                    return $candidate;
                }
            }

            foreach (scandir(self::dir()) ?: [] as $file) {
                if (!preg_match('/\.json$/i', $file)) {
                    continue;
                }
                $candidate = self::dir() . DIRECTORY_SEPARATOR . $file;
                $data = self::loadFile($candidate);
                $id = strtolower((string)($data['id'] ?? pathinfo($file, PATHINFO_FILENAME)));
                $aliases = array_map(
                    static fn($alias): string => strtolower((string)$alias),
                    is_array($data['aliases'] ?? null) ? $data['aliases'] : []
                );
                if (strtolower($profile) === $id || in_array(strtolower($profile), $aliases, true)) {
                    return $candidate;
                }
            }
        }

        foreach ($candidates as $candidate) {
            if (is_file($candidate)) {
                return $candidate;
            }
        }

        throw new \RuntimeException("Profile not found: {$profile}");
    }

    private static function loadFile(string $file): array
    {
        if (!is_file($file)) {
            throw new \RuntimeException("Profile not found: {$file}");
        }

        $data = json_decode((string)file_get_contents($file), true);
        if (!is_array($data)) {
            throw new \RuntimeException("Invalid profile JSON: {$file}");
        }

        return $data;
    }

    private static function normalize(array $profile): array
    {
        $id = trim((string)($profile['id'] ?? ''));
        if ($id === '') {
            throw new \RuntimeException('Profile is missing required field: id');
        }

        if (!isset($profile['title']) || !is_scalar($profile['title'])) {
            $profile['title'] = $id;
        }
        if (!isset($profile['report_template']) || !is_scalar($profile['report_template'])) {
            $profile['report_template'] = 'standard';
        }

        return $profile;
    }

    private static function withProfileMetadata(array $rule, array $profile, string $id): array
    {
        $metadata = self::ruleMetadata($profile, $id);
        if ($metadata) {
            $rule['profile'] = [
                'id' => (string)($profile['id'] ?? ''),
                'title' => (string)($profile['title'] ?? ''),
                'report_template' => (string)($profile['report_template'] ?? 'standard'),
                'mapping' => $metadata,
            ];
        }

        return $rule;
    }

    private static function ruleMetadata(array $profile, string $id): array
    {
        foreach (($profile['rules'] ?? []) as $entry) {
            if (is_scalar($entry) && strtoupper((string)$entry) === $id) {
                return [];
            }
            if (is_array($entry) && strtoupper((string)($entry['id'] ?? '')) === $id) {
                $metadata = $entry;
                unset($metadata['id']);
                return $metadata;
            }
        }

        return [];
    }

    private static function profileRuleIds(array $profile): array
    {
        $rules = $profile['rules'] ?? $profile['include']['rules'] ?? [];
        if (!is_array($rules)) {
            return [];
        }

        $ids = [];
        foreach ($rules as $entry) {
            if (is_scalar($entry)) {
                $id = strtoupper(trim((string)$entry));
            } elseif (is_array($entry)) {
                $id = strtoupper(trim((string)($entry['id'] ?? '')));
            } else {
                $id = '';
            }
            if ($id !== '') {
                $ids[] = $id;
            }
        }

        return array_values(array_unique($ids));
    }

    private static function strings(mixed $value): array
    {
        if (is_string($value)) {
            $value = explode(',', $value);
        }
        if (!is_array($value)) {
            return [];
        }

        $out = [];
        foreach ($value as $item) {
            if (!is_scalar($item)) {
                continue;
            }
            $item = strtoupper(trim((string)$item));
            if ($item !== '') {
                $out[] = $item;
            }
        }

        return array_values(array_unique($out));
    }

    private static function dedupeRules(array $rules): array
    {
        $out = [];
        $seen = [];
        foreach ($rules as $rule) {
            $id = strtoupper((string)($rule['id'] ?? ''));
            if ($id !== '' && isset($seen[$id])) {
                continue;
            }
            if ($id !== '') {
                $seen[$id] = true;
            }
            $out[] = $rule;
        }

        return $out;
    }

    private static function controlsForRules(array $rules): array
    {
        $controls = [];
        foreach ($rules as $rule) {
            $control = strtoupper((string)($rule['control'] ?? ''));
            if ($control !== '') {
                $controls[] = $control;
            }
        }

        return array_values(array_unique($controls));
    }

    private static function looksLikePath(string $value): bool
    {
        return str_contains($value, DIRECTORY_SEPARATOR)
            || str_contains($value, '/')
            || str_contains($value, '\\')
            || preg_match('/\.json$/i', $value) === 1;
    }

    private static function isAbsolutePath(string $path): bool
    {
        return str_starts_with($path, '/')
            || preg_match('/^[A-Za-z]:[\\\\\\/]/', $path) === 1;
    }
}
