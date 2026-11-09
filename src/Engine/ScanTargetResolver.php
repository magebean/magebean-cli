<?php
declare(strict_types=1);
namespace Magebean\Engine;
final class ScanTargetResolver
{
    private const MODE_REMOTE = 'REMOTE';
    private const MODE_LOCAL = 'LOCAL';
    /** Caller owns rendering; the callback receives only the detected path. */
    public function resolve(bool $hasPath, bool $hasUrl, string $pathOpt, string $urlOpt, ?callable $detectedRoot = null): ResolvedScanTarget
    {
        $detectedRoot ??= static function (string $path): void {};
        $targetMode = $this->mode($hasPath, $hasUrl);
        if ($hasPath && $pathOpt === '') {
            throw new \RuntimeException('--path requires a non-empty value.');
        }
        if ($targetMode === self::MODE_REMOTE && $urlOpt === '') {
            throw new \RuntimeException('--url requires a non-empty HTTP or HTTPS URL.');
        }

        $requestedUrl = $targetMode === self::MODE_REMOTE ? $this->normalizeRemoteUrl($urlOpt) : '';

        if ($targetMode === self::MODE_REMOTE) {
            $projectUrl = $requestedUrl;
            $projectPath = 'URL:' . $projectUrl;
        } else {
            $requestedPath = ProjectPath::normalize($hasPath ? $pathOpt : (string)getcwd());

            if (!self::isMagentoRoot($requestedPath)) {
                $detected = self::detectMagentoRoot($requestedPath, 4);
                if ($detected === null) {
                    throw new \RuntimeException(
                        "Cannot locate Magento root from: {$requestedPath}\n" .
                        'Hint: run from your Magento root or pass --path=/absolute/path/to/magento'
                    );
                }
                $detectedRoot($detected);
                $requestedPath = $detected;
            }

            $magentoRoot = $this->findMagentoRoot($requestedPath, 2);
            if ($magentoRoot === null) {
                throw new \RuntimeException(
                    "Not a valid Magento 2 installation.\n" .
                    "- Expected files: bin/magento, composer.json, app/etc/config.php\n" .
                    "- Checked: {$requestedPath} (and up to 2 parents)"
                );
            }

            $this->assertMagento2Root($magentoRoot);
            $projectPath = (string)$magentoRoot;
            $projectUrl = (string)$this->autoDetectBaseUrl($projectPath);
        }

        return new ResolvedScanTarget($projectPath, $projectUrl, $targetMode);
    }
    public function resolveProfile(string $profile, bool $hasPath, bool $hasUrl, string $path, string $url): ResolvedScanTarget
    {
        if ($profile === 'development' && $hasUrl) {
            throw new \RuntimeException('Development uses a local source checkout. Use prelaunch with a staging URL for HTTP checks.');
        }
        if ($hasPath && $path === '') throw new \RuntimeException('--path requires a non-empty value.');
        $origin = $hasUrl ? $this->normalizeRemoteUrl($url) : '';
        $root = realpath($hasPath ? $path : (string) getcwd());
        if ($root === false || !is_dir($root)) throw new \RuntimeException('Magento project path is unavailable.');
        for ($depth = 0; $depth <= 4; ++$depth) {
            if ($profile === 'prelaunch') {
                $candidate = $this->findMagentoRoot($root);
                if ($candidate !== null) {
                    $this->assertMagento2Root($candidate, true);
                    return new ResolvedScanTarget($candidate, $origin, self::MODE_LOCAL, $profile);
                }
            } else {
                $text = @file_get_contents($root.'/composer.json', false, null, 0, 1048577);
                $manifest = is_string($text) && strlen($text) <= 1048576 ? json_decode($text, true) : null;
                foreach (['magento/framework', 'magento/product-community-edition', 'magento/product-enterprise-edition', 'magento/magento-cloud-metapackage'] as $package) {
                    if (isset($manifest['require'][$package]) && is_string($manifest['require'][$package])) {
                        return new ResolvedScanTarget($root, '', self::MODE_LOCAL, $profile);
                    }
                }
            }
            $parent = dirname($root);
            if ($parent === $root) break;
            $root = $parent;
        }
        throw new \RuntimeException('Cannot locate a Magento project for '.$profile.'. Pass --path to the Magento root.');
    }

    private function findMagentoRoot(string $path, int $maxParents = 0): ?string
    {
        $probe = function (string $p): bool {
            return is_dir($p)
                && is_file($p . '/composer.json')
                && is_file($p . '/bin/magento')
                && (is_file($p . '/app/etc/config.php') || is_file($p . '/app/etc/env.php'));
        };

        $current = $path;
        for ($i = 0; $i <= $maxParents; $i++) {
            if ($probe($current)) {
                return realpath($current) ?: $current;
            }
            $parent = dirname($current);
            if ($parent === $current) {
                break;
            }
            $current = $parent;
        }
        return null;
    }

    private function assertMagento2Root(string $root, bool $allowProductPackage = false): void
    {
        // 1) Thư mục tồn tại & đọc được
        if (!is_dir($root) || !is_readable($root)) {
            throw new \RuntimeException("Path '{$root}' is not readable.");
        }

        // 2) Các file/binary quan trọng
        $required = [
            'composer.json',
            'bin/magento',
        ];
        foreach ($required as $rel) {
            $abs = $root . DIRECTORY_SEPARATOR . $rel;
            if (!file_exists($abs)) {
                throw new \RuntimeException("Missing required file: {$rel} at {$root}");
            }
        }

        // 3) Ít nhất phải có một trong hai: app/etc/config.php hoặc app/etc/env.php
        $hasConfig = is_file($root . '/app/etc/config.php') || is_file($root . '/app/etc/env.php');
        if (!$hasConfig) {
            throw new \RuntimeException("Missing app/etc/config.php or app/etc/env.php at {$root}");
        }

        // 4) bin/magento nên executable (không bắt buộc trên mọi OS, nhưng kiểm tra giúp debug)
        $binMagento = $root . '/bin/magento';
        if (!is_readable($binMagento)) {
            throw new \RuntimeException("bin/magento is not readable at {$root}");
        }
        // if (strncasecmp(PHP_OS, 'WIN', 3) !== 0 && !is_executable($binMagento)) {
        //     throw new \RuntimeException("bin/magento is not executable at {$root}");
        // }

        // 5) composer.json phải có "require": { "magento/framework": ... } hoặc name magento/*
        $composer = @file_get_contents($root . '/composer.json');
        if ($composer === false) {
            throw new \RuntimeException("Unable to read composer.json at {$root}");
        }

        $json = json_decode($composer, true);
        if (!is_array($json)) {
            throw new \RuntimeException("Invalid composer.json at {$root}");
        }

        $hasFramework =
            isset($json['require']['magento/framework']) ||
            ($allowProductPackage && (isset($json['require']['magento/product-community-edition'])
                || isset($json['require']['magento/product-enterprise-edition'])
                || isset($json['require']['magento/magento-cloud-metapackage']))) ||
            (isset($json['name']) && is_string($json['name']) && str_starts_with($json['name'], 'magento/'));

        if (!$hasFramework) {
            throw new \RuntimeException(
                "composer.json does not look like a Magento 2 project (missing require: magento/framework)."
            );
        }
    }

    public function mode(bool $hasPath, bool $hasUrl): string
    {
        if ($hasUrl && !$hasPath) {
            return self::MODE_REMOTE;
        }

        return self::MODE_LOCAL;
    }

    private function normalizeRemoteUrl(string $url): string
    {
        $url = trim($url);
        if ($url === '' || filter_var($url, FILTER_VALIDATE_URL) === false) {
            throw new \RuntimeException('Invalid --url. Expected an absolute HTTP or HTTPS URL.');
        }

        $parts = parse_url($url);
        $scheme = strtolower((string)($parts['scheme'] ?? ''));
        $host = (string)($parts['host'] ?? '');
        if (!in_array($scheme, ['http', 'https'], true) || $host === '') {
            throw new \RuntimeException('Invalid --url. Only absolute HTTP and HTTPS URLs are supported.');
        }
        if (isset($parts['user']) || isset($parts['pass'])) {
            throw new \RuntimeException('Invalid --url. Credentials in the target URL are not supported.');
        }
        if (isset($parts['query']) || isset($parts['fragment'])) {
            throw new \RuntimeException('Invalid --url. Use a store base URL without a query string or fragment.');
        }

        return rtrim($url, '/');
    }

    public static function isMagentoRoot(string $dir): bool
    {
        // Tiêu chí an toàn: có cả env.php và bin/magento
        return is_file($dir . '/bin/magento') && is_file($dir . '/composer.json')
            && (is_file($dir . '/app/etc/config.php') || is_file($dir . '/app/etc/env.php'));
    }

    private static function detectMagentoRoot(string $startDir, int $maxUp = 4): ?string
    {
        $dir = ProjectPath::normalize($startDir);
        for ($i = 0; $i <= $maxUp; $i++) {
            if (self::isMagentoRoot($dir)) {
                return $dir;
            }
            $parent = dirname($dir);
            if ($parent === $dir) break; // đến root FS
            $dir = $parent;
        }
        return null;
    }

    private function autoDetectBaseUrl(string $projectPath): string
    {
        return (string)((new \Magebean\Engine\Checks\MagentoCheck(new Context($projectPath,'')))->configuredBaseUrl()['url'] ?? '');
    }
}
