<?php
declare(strict_types=1);

namespace Magebean\Engine\Collectors;

use Magebean\Engine\Context;
use PhpParser\Error;

final class MagentoModuleInventory
{
    public function __construct(private readonly ?CollectionSession $session = null) {}

    public function collect(Context $context): array
    {
        $load = fn(): array => $this->discover($context);
        return $this->session?->remember('magento-module-inventory:'.hash('sha256', $context->path), $load) ?? $load();
    }

    private function discover(Context $context): array
    {
        $out = ['modules' => [], 'themes' => [], 'module_roots' => [], 'schema_module_roots' => [], 'framework_root' => null, 'packages' => [], 'package_providers' => [], 'package_inventory_complete' => false, 'gaps' => [], 'complete' => true];
        $root = realpath($context->path);
        if ($root === false || !is_dir($root) || strtoupper($context->get('meta', [])['target_mode'] ?? '') === 'REMOTE') {
            $out['complete'] = false;
            $out['gaps'][] = ['file' => '', 'reason' => 'local_project_unavailable'];
            return $out;
        }
        $files = new MagentoInventoryFiles($context, $root, $this->session);
        $php = new MagentoStaticPhp();
        $sourceCheckout = ($context->get('meta', [])['launch_profile'] ?? null) === 'development';
        $config = $files->read('app/etc/config.php', !$sourceCheckout);
        try {
            $states = $config === null ? null : $php->moduleStates($config);
        } catch (Error) {
            $states = null;
        }
        if ($config !== null && $states === null) $files->gap('app/etc/config.php', 'module_state_unresolved');

        $candidates = [];
        foreach ($files->directories('app/code') as $vendor) {
            foreach ($files->directories($vendor) as $path) {
                $candidates[$path] = ['origin' => 'app_code'];
            }
        }
        foreach ($files->directories('app/design') as $area) {
            foreach ($files->directories($area) as $vendor) {
                foreach ($files->directories($vendor) as $path) {
                    $candidates[$path] = ['origin' => 'app_design', 'type' => 'magento2-theme'];
                }
            }
        }
        $hasRootManifest = $files->exists('composer.json');
        $rootManifest = $files->json('composer.json');
        foreach (['provide', 'replace'] as $field) {
            foreach (array_keys((array) ($rootManifest[$field] ?? [])) as $provided) $out['package_providers'][$provided] = true;
        }
        if (is_string($rootManifest['name'] ?? null)) $out['package_providers'][$rootManifest['name']] = true;
        $out['target_php'] = $rootManifest['config']['platform']['php'] ?? null;
        $configuredVendor = $rootManifest['config']['vendor-dir'] ?? 'vendor';
        $vendor = is_string($configuredVendor) ? MagentoInventoryFiles::relative('', $configuredVendor) : null;
        if ($vendor === null) $files->gap('composer.json', 'composer_vendor_directory_unresolved');
        $metadata = $vendor === null ? null : $vendor.'/composer/installed.json';
        $installed = $metadata === null ? null : $files->json($metadata, true);
        $out['package_inventory_complete'] = $installed !== null && (!$hasRootManifest || $rootManifest !== null);
        $packages = $installed['packages'] ?? $installed ?? [];
        if (!is_array($packages) || !array_is_list($packages)) {
            $files->gap($metadata ?? 'composer.json', 'installed_packages_unresolved');
            $out['package_inventory_complete'] = false;
            $packages = [];
        }

        foreach ($packages as $package) {
            $name = $package['name'] ?? null;
            if (!is_string($name) || !preg_match('~^[a-z0-9_.-]+/[a-z0-9_.-]+$~D', $name)) {
                $out['package_inventory_complete'] = false;
                $files->gap($metadata ?? 'composer.json', 'package_identity_unresolved');
                continue;
            }
            foreach (['provide', 'replace'] as $field) {
                foreach (array_keys((array) ($package[$field] ?? [])) as $provided) $out['package_providers'][$provided] = true;
            }
            $type = is_string($package['type'] ?? null) ? $package['type'] : 'library';
            $record = ['name' => $name, 'version' => is_string($package['version'] ?? null) ? $package['version'] : null, 'type' => $type];
            if ($type === 'metapackage') {
                $out['packages'][$name] = $record;
                continue;
            }
            $pathValue = $package['install-path'] ?? $package['installed-path'] ?? null;
            $path = is_string($pathValue)
                ? MagentoInventoryFiles::relative(dirname($metadata), $pathValue)
                : MagentoInventoryFiles::relative($vendor, $name);
            if ($path === null || !$files->isDirectory($path, true)) {
                $files->gap($metadata ?? 'composer.json', 'package_install_path_unresolved', $name);
                $out['packages'][$name] = $record;
                continue;
            }
            $record += ['root' => $path, 'path_source' => $pathValue === null ? 'composer_default_layout' : 'composer_installed_path'];
            $out['packages'][$name] = $record;
            if ($name === 'magento/framework') $out['framework_root'] = $path;

            $autoload = $package['autoload']['files'] ?? [];
            if (!is_array($autoload)) {
                $files->gap($path, 'package_autoload_files_unresolved');
                $autoload = [];
            }
            $candidate = $record + ['origin' => 'composer', 'require' => $package['require'] ?? []];
            $foundRegistration = false;
            foreach ($autoload as $relative) {
                // Composer packages may contain several registration files in nested component roots.
                if (!is_string($relative) || basename(str_replace('\\', '/', $relative)) !== 'registration.php') continue;
                $registration = MagentoInventoryFiles::relative($path, $relative);
                if ($registration === null || !str_starts_with($registration, $path.'/')) {
                    $files->gap($path, 'registration_outside_package');
                    continue;
                }
                $candidates[dirname($registration)] = $candidate;
                $foundRegistration = true;
            }
            if ($files->exists($path.'/registration.php') || $files->exists($path.'/etc/module.xml')
                || (!$foundRegistration && in_array($type, ['magento2-module', 'magento2-theme'], true))) {
                $candidates[$path] = $candidate;
            }
        }

        ksort($candidates);
        foreach ($candidates as $path => $candidate) {
            $registrations = [];
            $registration = $files->read($path.'/registration.php');
            if ($registration !== null) {
                try {
                    $parsed = $php->registrations($registration);
                    $registrations = $parsed['entries'];
                    if ($parsed['unresolved']) $files->gap($path.'/registration.php', 'dynamic_registration_unresolved');
                } catch (Error) {
                    $files->gap($path.'/registration.php', 'registration_php_unresolved');
                }
                if ($registrations === []) $files->gap($path.'/registration.php', 'registration_identity_unresolved');
            }
            $moduleXml = $files->read($path.'/etc/module.xml');
            $declared = [];
            $sequence = [];
            $xml = null;
            if ($moduleXml !== null) {
                $xml = MagentoXmlIndex::parse($moduleXml);
                if ($xml === null) {
                    $files->gap($path.'/etc/module.xml', 'module_xml_unresolved');
                } else {
                    $xpath = new \DOMXPath($xml);
                    foreach ($xpath->query('/config/module') as $module) {
                        $declared[] = $module->getAttribute('name');
                        foreach ($xpath->query('sequence/module', $module) as $dependency) $sequence[] = $dependency->getAttribute('name');
                    }
                }
            }
            $registered = array_values(array_filter($registrations, static fn(array $r): bool => $r['type'] === 'module'));
            $theme = array_values(array_filter($registrations, static fn(array $r): bool => $r['type'] === 'theme'));
            if ($theme !== [] || ($candidate['type'] ?? '') === 'magento2-theme') {
                $out['themes'][] = ['root' => $path, 'registrations' => $theme, 'origin' => $candidate['origin'], 'package' => $candidate['name'] ?? null];
            }
            if ($registered === [] && $moduleXml === null && ($candidate['type'] ?? '') !== 'magento2-module') continue;

            $manifest = $files->json($path.'/composer.json');
            $packageName = $candidate['name'] ?? (is_string($manifest['name'] ?? null) ? $manifest['name'] : null);
            $requirements = [];
            foreach ((array) ($manifest['require'] ?? $candidate['require'] ?? []) as $dependency => $constraint) {
                if (is_string($constraint)) $requirements[$dependency] = $constraint;
            }
            $identities = array_values(array_unique(array_filter(array_merge($declared, array_column($registered, 'name')),
                static fn(string $name): bool => preg_match('/^[A-Za-z0-9]+_[A-Za-z0-9_]+$/D', $name) === 1)));
            if (count($identities) !== 1 || count($declared) !== 1 || count($registered) !== 1) {
                $files->gap($path, 'module_identity_incomplete');
            }
            $state = 'unresolvable';
            if (count($identities) === 1 && count($declared) === 1 && count($registered) === 1
                && $declared[0] === $registered[0]['name'] && $states !== null && array_key_exists($identities[0], $states)) {
                $state = $states[$identities[0]] ? 'enabled' : 'disabled';
            }
            $out['modules'][] = [
                'root' => $path,
                'identity' => count($identities) === 1 ? $identities[0] : null,
                'declared' => $declared,
                'registered' => $registered,
                'state' => $state,
                'installed' => true,
                'configured_enabled' => count($identities) === 1 ? ($states[$identities[0]] ?? null) : null,
                'origin' => $candidate['origin'],
                'package' => $packageName,
                'version' => $candidate['version'] ?? null,
                'package_path_source' => $candidate['path_source'] ?? null,
                'composer_require' => $requirements,
                'dependency_manifest' => $manifest !== null ? $path.'/composer.json' : $metadata,
                'registration_parsed' => $registration !== null && $registered !== [],
                'module_xml_parsed' => $moduleXml !== null && isset($xml) && $xml !== null,
                'sequence' => array_values(array_unique($sequence)),
            ];
            foreach ($identities as $identity) $out['module_roots'][$identity][] = $path;
            foreach ($registered as $entry) {
                if (in_array($entry['name'], $identities, true)) $out['schema_module_roots'][$entry['name']][] = $path;
            }
        }
        foreach ($out['module_roots'] as $name => $roots) {
            if (count($roots) > 1) $files->gap($roots[0], 'duplicate_module_identity', $name);
        }
        foreach ($out['modules'] as &$module) {
            if (count($out['module_roots'][$module['identity']] ?? []) > 1) $module['state'] = 'unresolvable';
        }
        unset($module);
        $discoveryComplete = $files->complete;
        foreach ($states ?? [] as $name => $enabled) {
            if (isset($out['module_roots'][$name])) continue;
            $out['modules'][] = [
                'root' => null, 'identity' => $name, 'state' => $discoveryComplete ? 'absent' : 'unresolvable',
                'installed' => $discoveryComplete ? false : null,
                'configured_enabled' => $enabled, 'origin' => 'deployment_config',
            ];
            if ($enabled) $files->gap('app/etc/config.php', 'enabled_module_source_unresolved', $name);
        }
        $out['module_order_known'] = $states !== null;
        $out['module_order'] = array_keys(array_filter($states ?? []));
        $out['complete'] = $files->complete;
        $out['gaps'] = $files->gaps;
        return $out;
    }
}
