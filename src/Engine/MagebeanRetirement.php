<?php
declare(strict_types=1);

namespace Magebean\Engine;

final class MagebeanRetirement
{
    public static function diagnostic(string $selector): ?string
    {
        static $retired = null;
        static $aliases = null;
        if ($retired === null) {
            $historical = array_fill_keys(array_column(RequirementCatalog::read('magebean-retirements')['requirements'], 'id'), true);
            $active = array_fill_keys(array_column(RequirementCatalog::read('magebean-catalog')['requirements'], 'id'), true);
            $retired = array_diff_key($historical, $active);
        }
        $aliases ??= RequirementCatalog::read('legacy-aliases')['aliases'];

        $key = strtoupper(trim($selector));
        $targets = $aliases[$key] ?? [$key];
        if (!isset($retired[$key]) && ($targets === [] || array_diff($targets, array_keys($retired)) !== [])) {
            return null;
        }

        $review = array_column(RequirementCatalog::read('magebean-retirement-review')['requirements'], null, 'id');
        $id = isset($retired[$key]) ? $key : ($targets[0] ?? $key);
        $record = $review[$id] ?? [];
        $related = $record['related_active_rules'] ?? [];
        return 'Magebean selector '.$key.' was retired from active selection; evidence review: '
            .str_replace('_', ' ', $record['classification'] ?? 'not yet qualified').'. '
            .($related !== [] ? 'Related scoped rules: '.implode(', ', $related).'; these do not establish full equivalence. ' : '')
            .'See docs/archive/retirement/retirement-evidence-review.md. This is not a claim that the criterion cannot be automated.';
    }

    public static function reject(string $selector): void
    {
        $message = self::diagnostic($selector);
        if ($message !== null) {
            throw new \RuntimeException($message);
        }
    }
}
