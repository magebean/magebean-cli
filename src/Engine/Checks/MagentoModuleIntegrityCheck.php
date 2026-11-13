<?php
declare(strict_types=1);

namespace Magebean\Engine\Checks;

use Magebean\Engine\{CheckResult, Context, MagebeanDetectorAnalysis};
use Magebean\Engine\Collectors\{BoundedSourceInventory, CollectorSet, MagentoInventoryFiles, MagentoXmlIndex};

final class MagentoModuleIntegrityCheck
{
    private const SCHEMA_KINDS = ['module', 'webapi', 'acl', 'routes'];

    public function __construct(private readonly Context $context, private readonly CollectorSet $collectors) {}

    public static function moduleNames(array $names): array
    {
        if (!array_is_list($names) || count($names) > 100) {
            throw new \InvalidArgumentException('Select up to 100 Magento module names.');
        }
        foreach ($names as $name) {
            if (!is_string($name) || !preg_match('/^[A-Za-z0-9]+_[A-Za-z0-9_]+$/D', $name)) {
                throw new \InvalidArgumentException('Module selection requires exact Magento names such as Vendor_Module.');
            }
        }
        return array_values(array_unique($names));
    }

    public function run(array $args): CheckResult
    {
        $kind = $args['kind'] ?? '';
        $requested = self::moduleNames($args['modules'] ?? []);
        $inventory = $this->collectors->magentoModules->collect($this->context);
        $requestedRoots = [];
        foreach ($requested as $name) {
            foreach ($inventory['module_roots'][$name] ?? [] as $root) $requestedRoots[$root] = true;
        }
        $modules = [];
        foreach ($inventory['modules'] as $module) {
            $root = $module['root'];
            if ($root !== null && ($requested === [] ? $module['origin'] === 'app_code' : isset($requestedRoots[$root]))) {
                $modules[$root] = $module;
            }
        }
        $gaps = $inventory['gaps'];
        foreach ($requested as $name) {
            if (!isset($inventory['module_roots'][$name])) $gaps[] = ['reason' => 'selected_module_source_unavailable', 'subject' => $name];
        }
        if (in_array($kind, ['di-preference', 'di-virtual-type', 'di-arguments', 'di-plugins'], true)) {
            return (new MagentoDiCheck($this->context, $this->collectors))->run($kind, $modules, $inventory + ['selection_gaps' => $gaps]);
        }
        if (in_array($kind, ['php-target', 'php-contract', 'magento-platform', 'request-sinks', 'empty-catch', 'loop-query'], true)) {
            return (new MagentoModuleSourceCheck($this->context, $this->collectors))->run($kind, $modules, $inventory, $gaps);
        }
        if (in_array($kind, ['declarative-schema', 'setup-patches', 'handler-references'], true)) {
            return (new MagentoModuleLifecycleCheck($this->context, $this->collectors))->run($kind, $modules, $gaps);
        }
        $findings = [];

        if ($kind === 'identity') {
            $findings = $this->identity($modules, $inventory['schema_module_roots']);
        } elseif ($kind === 'dependencies') {
            if ($inventory['package_inventory_complete']) $findings = $this->dependencies($modules, $inventory);
        } elseif ($kind === 'request-logging') {
            $findings = $this->logging($modules, $inventory, $gaps);
        } else {
            $names = array_values(array_filter(array_column($modules, 'identity'), 'is_string'));
            foreach ($modules as $module) {
                if ($module['identity'] === null) $gaps[] = ['reason' => 'module_identity_unavailable', 'file' => $module['root']];
            }
            $analysis = $this->collectors->magentoAnalysis->collect($this->context, $names, [
                'validate_schemas' => true,
                'schema_kinds' => self::SCHEMA_KINDS,
                'dependency_symbols' => $kind === 'rest-service',
            ]);
            foreach ($analysis['gaps'] as $gap) {
                if ($kind !== 'xml' && $gap['reason'] === 'schema_unavailable') continue;
                if ($kind !== 'rest-service' && in_array($gap['reason'], ['php_parse_unavailable', 'symbol_budget_exceeded'], true)) continue;
                if ($gap['reason'] === 'xml_parse_unavailable') {
                    $fileKind = pathinfo($gap['file'], PATHINFO_FILENAME);
                    if (!in_array($fileKind, $kind === 'xml' ? self::SCHEMA_KINDS : ['webapi'], true)) continue;
                    if ($kind === 'xml' && ($analysis['documents'][$gap['file']]['schema_status'] ?? '') === 'malformed') continue;
                }
                $gaps[] = $gap;
            }
            if ($kind === 'xml') array_push($gaps, ...$analysis['schema_gaps']);
            if ($analysis['gaps_truncated']) $gaps[] = ['reason' => 'analysis_gaps_truncated'];
            $findings = match ($kind) {
                'xml' => $this->xml($analysis['documents'], $modules),
                'rest-service', 'rest-acl', 'rest-anonymous' => $this->rest($kind, $analysis, $modules, $gaps),
                default => throw new \InvalidArgumentException('Unsupported module integrity detector.'),
            };
        }

        $diagnostics = [];
        foreach ($gaps as $gap) {
            $context = array_filter([$gap['file'] ?? '', $gap['subject'] ?? ''], 'is_string');
            $where = implode(' · ', array_filter($context));
            $message = str_replace('_', ' ', $gap['reason']).($where !== '' ? ' · '.$where : '');
            $diagnostics[$message] = [
                'message' => $message,
                'action' => 'Verify the installed module metadata, local source access, and selected module scope.',
            ];
        }
        return MagebeanDetectorAnalysis::result('magento-module-'.$kind, '1.2', $findings, array_values($diagnostics));
    }

    private function identity(array $modules, array $registeredRoots): array
    {
        $findings = [];
        $reported = [];
        foreach ($modules as $root => $module) {
            $registrations = array_column($module['registered'], 'name');
            if (count($registrations) === 1 && count($module['declared']) === 1 && $registrations !== $module['declared']) {
                $findings[] = self::finding($module, 'identity-mismatch', 'Module registration and module.xml declare different names.',
                    'The two statically parsed declarations disagree.', 'Use the same module name in registration.php and etc/module.xml.',
                    [['file' => $root.'/registration.php', 'line' => $module['registered'][0]['line']], ['file' => $root.'/etc/module.xml']]);
            }
            foreach ($registrations as $name) {
                $roots = array_values(array_unique($registeredRoots[$name] ?? []));
                if (count($roots) < 2 || isset($reported[$name])) continue;
                $reported[$name] = true;
                $findings[] = self::finding($module, 'duplicate-registration', 'Multiple roots statically register the same module.',
                    'More than one literal registration declares this identity.', 'Remove the duplicate package or registration.',
                    array_map(static fn(string $path): array => ['file' => $path.'/registration.php'], $roots), symbol: $name);
            }
        }
        return $findings;
    }

    private function dependencies(array $modules, array $inventory): array
    {
        $findings = [];
        $seen = [];
        foreach ($modules as $module) {
            foreach ($module['composer_require'] as $dependency => $constraint) {
                if (!preg_match('~^[a-z0-9_.-]+/[a-z0-9_.-]+$~D', (string) $dependency)
                    || isset($inventory['packages'][$dependency]) || isset($inventory['package_providers'][$dependency])) continue;
                $fingerprint = ($module['package'] ?? $module['root']).'|'.$dependency;
                if (isset($seen[$fingerprint])) continue;
                $seen[$fingerprint] = true;
                $findings[] = self::finding($module, 'missing-package', 'Required Composer package is absent from installed metadata.',
                    'No installed package name, provide entry or replace entry satisfies the declared package identity.',
                    'Install the required package or correct the declaring package metadata.',
                    [['file' => $module['dependency_manifest']]], symbol: $dependency);
            }
        }
        return $findings;
    }

    private function xml(array $documents, array $modules): array
    {
        $findings = [];
        $byName = array_column($modules, null, 'identity');
        foreach ($documents as $file => $document) {
            if (!in_array($document['schema_status'], ['invalid', 'malformed'], true)
                || !in_array($document['kind'], self::SCHEMA_KINDS, true) || !isset($byName[$document['module']])) continue;
            $malformed = $document['schema_status'] === 'malformed';
            $findings[] = self::finding($byName[$document['module']], 'invalid-xml',
                $malformed ? 'Configuration XML is malformed.' : 'Configuration XML fails its declared local schema.',
                $malformed ? 'The document is in supported encoding and the XML parser rejected its syntax.'
                    : 'Libxml validated the document against the project-local installed XSD graph and rejected it.',
                'Correct the document using the schema from the installed Magento version.',
                [['file' => $file, 'line' => $document['line']]], area: $document['area']);
        }
        return $findings;
    }

    private function rest(string $kind, array $analysis, array $modules, array &$gaps): array
    {
        $findings = [];
        $informational = [];
        $byName = array_column($modules, null, 'identity');
        $inventory = $analysis['inventory'];
        $sourceDeclarations = ($this->context->get('meta', [])['launch_profile'] ?? '') === 'development';
        $acl = $kind === 'rest-acl' ? $this->acl($inventory, $gaps) : [];
        foreach ($analysis['documents'] as $file => $document) {
            $module = $byName[$document['module']] ?? null;
            if ($module === null) continue;
            if ($kind === 'rest-anonymous' && $document['kind'] === 'routes') {
                foreach ($document['declarations'] as $route) {
                    $informational[] = self::finding($module, 'controller-route-declaration', 'Magento controller route is declared.',
                        'The module declares a controller router entry. Individual actions and runtime route access are unresolved.',
                        '', [['file' => $file, 'line' => $route['line']]], 'informational', 'informational', 'info',
                        $document['area'], $route['id'].' · '.$route['front_name']);
                }
            }
            if ($document['area'] !== 'global' || $document['kind'] !== 'webapi') continue;
            if ($document['root'] !== 'routes') {
                $gaps[] = ['reason' => 'webapi_document_unresolved', 'file' => $file];
                continue;
            }
            if (!$sourceDeclarations && $kind !== 'rest-service' && $module['state'] !== 'enabled') {
                if ($module['state'] !== 'disabled') $gaps[] = ['reason' => 'module_enablement_unavailable', 'file' => $file];
                continue;
            }
            foreach ($document['declarations'] as $route) {
                $location = [['file' => $file, 'line' => $route['line']]];
                $subject = $route['method'].' '.$route['url'];
                if ($kind === 'rest-service') {
                    $name = strtolower(ltrim($route['service'] ?? '', '\\'));
                    $method = strtolower($route['operation'] ?? '');
                    $symbols = $analysis['symbols'][$name] ?? [];
                    if ($name === '' || $method === '' || count($symbols) !== 1) {
                        $gaps[] = ['reason' => 'rest_service_reference_unresolved', 'file' => $file, 'subject' => $subject];
                        continue;
                    }
                    $symbol = $symbols[0];
                    $entry = $symbol['methods'][$method] ?? null;
                    if (($entry === null && ($symbol['extends'] !== [] || $symbol['traits'] !== [] || $symbol['implements'] !== []))
                        || ($entry !== null && $entry['visibility'] === 'protected' && $symbol['extends'] !== [])) {
                        $gaps[] = ['reason' => 'rest_service_inheritance_unresolved', 'file' => $file, 'subject' => $subject];
                    } elseif ($entry === null || $entry['visibility'] !== 'public' || !in_array($symbol['kind'], ['class', 'interface'], true)) {
                        $findings[] = self::finding($module, 'invalid-service-method', 'REST service declaration does not name a public service method.',
                            'The indexed service declaration has no supported public method matching this route.',
                            'Point the route at the intended public class or service interface method.', $location, area: 'webapi_rest', symbol: $subject);
                    }
                } elseif ($kind === 'rest-acl') {
                    if ($acl === null) continue;
                    foreach ($route['resources'] as $resource) {
                        $ref = $resource['ref'];
                        if (in_array($ref, ['anonymous', 'self'], true) || isset($acl[$ref])) continue;
                        $findings[] = self::finding($module, 'undeclared-acl-reference', $sourceDeclarations ? 'REST source declaration references an ACL resource absent from the collected declarations.' : 'REST route references an ACL resource absent from the collected enabled declarations.',
                            $sourceDeclarations ? 'The named resource was not found in collected source ACL files; module activation and runtime access are not established.' : 'The named resource was not found in the static global ACL files of the installed enabled modules.',
                            'Check the resource ID and the module that declares it.',
                            [['file' => $file, 'line' => $resource['line']]], 'security', 'suspected', 'medium', 'webapi_rest', $ref,
                            ['Runtime or generated ACL additions can change the effective resource tree.']);
                    }
                } elseif (in_array('anonymous', array_column($route['resources'], 'ref'), true)) {
                    if (preg_match('~(?:^|/)(?:exports?|downloads?|credentials|permissions|roles|secrets)(?:/|$)~i', $route['url'])) {
                        $findings[] = self::finding($module, 'sensitive-anonymous-route', 'Anonymous REST declaration names a potentially sensitive operation.',
                            'The route declares anonymous access and its path contains an export, download, or privileged-resource segment.',
                            'Verify intended guest access and enforce the relevant resource or object checks.',
                            $location, 'security', 'suspected', 'medium', 'webapi_rest', $subject,
                            ['Module activation, runtime API restrictions, service checks and intended public access may affect exposure.']);
                    } else {
                        $informational[] = self::finding($module, 'anonymous-route', 'REST route declares anonymous access.',
                            'This route explicitly references the framework anonymous resource.', '', $location,
                            'informational', 'informational', 'info', 'webapi_rest', $subject);
                    }
                } elseif ($kind === 'rest-anonymous') {
                    $informational[] = self::finding($module, 'rest-route', 'REST route declares service and resource metadata.',
                        'The static route lists these resource references: '.implode(', ', array_column($route['resources'], 'ref')).'.',
                        '', $location, 'informational', 'informational', 'info', 'webapi_rest', $subject);
                }
            }
        }
        return array_merge($findings, $informational);
    }

    private function acl(array $inventory, array &$gaps): ?array
    {
        if (!$inventory['complete']) return null;
        $root = realpath($this->context->path);
        if ($root === false) return null;
        $reader = new MagentoInventoryFiles($this->context, $root, $this->collectors->session);
        $paths = [];
        foreach ($inventory['modules'] as $module) {
            if (($this->context->get('meta', [])['launch_profile'] ?? '') === 'development' || $module['state'] === 'enabled') $paths[] = $module['root'].'/etc/acl.xml';
        }
        $resources = [];
        foreach (array_unique($paths) as $path) {
            $source = $reader->read($path);
            if ($source === null) continue;
            $xml = MagentoXmlIndex::parse($source);
            if ($xml === null) {
                $reader->gap($path, 'acl_declaration_unresolved');
                continue;
            }
            foreach (MagentoXmlIndex::declarations($xml, 'acl') as $row) $resources[$row['id']] = true;
        }
        array_push($gaps, ...$reader->gaps);
        return $reader->complete ? $resources : null;
    }

    private function logging(array $modules, array $inventory, array &$gaps): array
    {
        if ($modules === []) return [];
        $paths = array_keys($modules);
        if (count($paths) > 100) {
            $gaps[] = ['reason' => 'selected_root_budget_exceeded'];
            $paths = array_slice($paths, 0, 100);
        }
        $all = array_filter(array_column($inventory['modules'], 'root'), 'is_string');
        $check = new AutomatedSourcePolicyCheck($this->context, new BoundedSourceInventory($this->collectors->session));
        $result = $check->run([
            'kind' => 'direct_request_logging',
            'paths' => $paths,
            'exclude_paths' => array_values(array_diff($all, $paths)),
            'verify_stable' => true,
            'include_ext' => ['php', 'phtml'],
        ]);
        array_push($gaps, ...$result->evidence['gaps'], ...$result->evidence['analysis_gaps']);
        if (!empty($result->evidence['violations_truncated'])) $gaps[] = ['reason' => 'logging_observation_budget_exceeded'];
        $findings = [];
        foreach ($result->evidence['violations'] as $violation) {
            $root = dirname($violation['file']);
            while ($root !== '.' && !isset($modules[$root])) $root = dirname($root);
            if (!isset($modules[$root])) continue;
            $findings[] = self::finding($modules[$root], 'request-logging-policy', 'Named log method receives a direct request superglobal reference.',
                'The existing syntactic request logging policy matched a log-like call argument in the selected source.',
                'Log only explicitly selected and redacted fields.',
                [['file' => $violation['file'], 'line' => $violation['line']]+(isset($violation['byte_offset'])?['byte_offset'=>$violation['byte_offset'],'source_sha256'=>$violation['source_sha256']]:[])], 'policy', 'confirmed', 'medium',
                assumptions: ['The method name is a policy match. Actual log delivery and data sensitivity depend on runtime behavior.']);
        }
        return $findings;
    }

    private static function finding(
        array $module, string $key, string $message, string $reasoning, string $remediation, array $locations,
        string $category = 'correctness', string $confidence = 'confirmed', string $severity = 'medium',
        ?string $area = null, ?string $symbol = null, array $assumptions = [],
    ): array {
        $subject = array_filter([
            'module' => $module['identity'], 'package' => $module['package'], 'version' => $module['version'],
            'area' => $area, 'symbol' => $symbol,
        ], static fn(?string $value): bool => $value !== null);
        return compact('key', 'message', 'reasoning', 'remediation', 'locations', 'category', 'confidence', 'severity', 'subject', 'assumptions');
    }
}
