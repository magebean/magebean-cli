<?php
declare(strict_types=1);
namespace Magebean\Engine\Checks;

/** Absolute upstream dates only; PHP's relative syntax and calendar normalization are not evidence. */
final class AbsoluteTimestamp
{
    public static function parse(mixed $value): ?\DateTimeImmutable
    {
        if (!is_string($value)) return null;
        $value = trim($value);
        if (!preg_match('/^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2}))?$/D', $value, $parts)) return null;
        if (!checkdate((int)$parts[2], (int)$parts[3], (int)$parts[1])) return null;
        if (isset($parts[4]) && ((int)$parts[4] > 23 || (int)$parts[5] > 59 || (int)$parts[6] > 59)) return null;
        $zone = $parts[8] ?? 'Z';
        if ($zone !== 'Z' && ((int)substr($zone, 1, 2) > 23 || (int)substr($zone, 4, 2) > 59)) return null;
        // Sub-microsecond precision cannot affect whole-day age; normalize it explicitly.
        $date = substr($value, 0, 10) . 'T' . (isset($parts[4]) ? $parts[4].':'.$parts[5].':'.$parts[6] : '00:00:00');
        if (!empty($parts[7])) $date .= '.'.substr($parts[7], 0, 6);
        try {
            $parsed = new \DateTimeImmutable($date.$zone);
            $errors = \DateTimeImmutable::getLastErrors();
            return is_array($errors) && ($errors['warning_count'] || $errors['error_count']) ? null : $parsed;
        } catch (\Exception) {
            return null;
        }
    }
}
