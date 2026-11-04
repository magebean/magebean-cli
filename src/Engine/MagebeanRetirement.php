<?php
declare(strict_types=1);

namespace Magebean\Engine;

final class MagebeanRetirement
{
    public static function diagnostic(string $selector): ?string
    {
        static $retired = null;
        static $aliases = null;
        $retired ??= array_fill_keys(array_column(RequirementCatalog::read('magebean-retirements')['requirements'], 'id'), true);
        $aliases ??= RequirementCatalog::read('legacy-aliases')['aliases'];

        $key = strtoupper(trim($selector));
        $targets = $aliases[$key] ?? [$key];
        if (!isset($retired[$key]) && ($targets === [] || array_diff($targets, array_keys($retired)) !== [])) {
            return null;
        }

        return 'Magebean selector '.$key.' was retired because its criterion requires human evidence. '
            .'Use a current automated Magebean profile or refresh the assessment from the current catalog.';
    }

    public static function reject(string $selector): void
    {
        $message = self::diagnostic($selector);
        if ($message !== null) {
            throw new \RuntimeException($message);
        }
    }
}
