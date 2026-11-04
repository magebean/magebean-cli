<?php
declare(strict_types=1);

namespace Magebean\Engine\Collectors;

/** Parses local XML without resolving external resources or invoking application code. */
final class MagentoXmlIndex
{
    public static function parse(string $source): ?\DOMDocument
    {
        if (!self::supports($source)) return null;

        $document = new \DOMDocument();
        $document->resolveExternals = false;
        $document->substituteEntities = false;
        return @$document->loadXML($source, LIBXML_NONET | LIBXML_NOERROR | LIBXML_NOWARNING) && $document->doctype === null ? $document : null;
    }

    private static function supports(string $source): bool
    {
        return class_exists(\DOMDocument::class) && !str_contains($source, "\0") && preg_match('//u', $source) === 1
            && !preg_match('/<!DOCTYPE\b/i', $source)
            && !preg_match('/^(?:\xEF\xBB\xBF)?\s*<\?xml[^>]*\bencoding\s*=\s*["\'](?!utf-8["\']|us-ascii["\'])/i', $source);
    }

    public static function schemaPath(string $urn, array $moduleRoots, ?string $frameworkRoot): ?string
    {
        $base = null;
        if (preg_match('~^urn:magento:module:([A-Za-z0-9_]+):(.+)$~D', $urn, $parts)) {
            $roots = array_values(array_unique($moduleRoots[$parts[1]] ?? []));
            $base = count($roots) === 1 ? $roots[0] : null;
            $path = $parts[2];
        } elseif (preg_match('~^urn:magento:framework:(.+)$~D', $urn, $parts)) {
            $base = $frameworkRoot;
            $path = $parts[1];
        }
        if ($base === null || !preg_match('~^[a-zA-Z0-9_./-]+\.xsd$~D', $path)
            || array_intersect(explode('/', $path), ['', '.', '..']) !== []) return null;
        return $base.'/'.$path;
    }

    /**
     * Resolve and load an installed XSD graph via the bounded project reader.
     * Only synthetic URIs backed by that graph are available to libxml.
     */
    public function validate(
        \DOMDocument $document,
        string $schemaPath,
        MagentoInventoryFiles $files,
        array $moduleRoots,
        ?string $frameworkRoot,
    ): string {
        $schemas = [];
        $uris = [];
        $loading = [];
        $load = function (string $path, int $depth = 0) use (&$load, &$schemas, &$uris, &$loading, $files, $moduleRoots, $frameworkRoot): ?string {
            if ($depth > 20 || isset($loading[$path])) return null;
            if (isset($uris[$path])) return $uris[$path];
            if (count($uris) >= 100) return null;

            $source = $files->read($path, true);
            $schema = $source === null ? null : self::parse($source);
            if ($schema === null || $schema->documentElement->namespaceURI !== 'http://www.w3.org/2001/XMLSchema'
                || $schema->documentElement->localName !== 'schema') return null;

            $uri = 'urn:magebean:xsd:'.count($uris);
            $uris[$path] = $uri;
            $loading[$path] = true;
            $xpath = new \DOMXPath($schema);
            $xpath->registerNamespace('xs', 'http://www.w3.org/2001/XMLSchema');
            foreach ($xpath->query('/xs:schema/*[@schemaLocation]') as $reference) {
                $location = $reference->getAttribute('schemaLocation');
                $dependency = str_starts_with($location, 'urn:')
                    ? self::schemaPath($location, $moduleRoots, $frameworkRoot)
                    : MagentoInventoryFiles::relative(dirname($path), $location);
                if ($dependency === null || !str_ends_with($dependency, '.xsd')) return null;
                $target = $load($dependency, $depth + 1);
                if ($target === null) return null;
                $reference->setAttribute('schemaLocation', $target);
            }
            unset($loading[$path]);
            $schemas[$uri] = $schema->saveXML();
            return $uri;
        };
        $root = $load($schemaPath);
        if ($root === null || !function_exists('libxml_get_external_entity_loader')) return 'schema_unavailable';

        $previous = libxml_get_external_entity_loader();
        libxml_set_external_entity_loader(static function (?string $public, ?string $system) use ($schemas) {
            if ($system === null || !isset($schemas[$system])) return null;
            $stream = fopen('php://memory', 'r+');
            fwrite($stream, $schemas[$system]);
            rewind($stream);
            return $stream;
        });
        try {
            // Distinguish a broken schema graph from a valid schema rejecting the document.
            $errorsBefore = libxml_use_internal_errors(true);
            libxml_clear_errors();
            try {
                if (@$document->schemaValidateSource($schemas[$root])) return 'valid';
                $errors = libxml_get_errors();
                if ($errors === []) return 'schema_unavailable';
                foreach ($errors as $error) {
                    // libxml's XML_SCHEMAV_* document-validation diagnostics.
                    if ($error->code < 1801 || $error->code > 1899) return 'schema_unavailable';
                }
                return 'invalid';
            } finally {
                libxml_clear_errors();
                libxml_use_internal_errors($errorsBefore);
            }
        } finally {
            libxml_set_external_entity_loader($previous);
        }
    }

    public static function declarations(\DOMDocument $document, string $kind): array
    {
        $xpath = new \DOMXPath($document);
        $rows = [];
        if ($kind === 'webapi') {
            foreach ($xpath->query('/routes/route') as $route) {
                $service = $xpath->query('service', $route)->item(0);
                $resources = [];
                foreach ($xpath->query('resources/resource', $route) as $resource) {
                    $resources[] = ['ref' => $resource->getAttribute('ref'), 'line' => $resource->getLineNo()];
                }
                $rows[] = [
                    'url' => $route->getAttribute('url'), 'method' => $route->getAttribute('method'),
                    'line' => $route->getLineNo(), 'service' => $service?->getAttribute('class'),
                    'operation' => $service?->getAttribute('method'), 'resources' => $resources,
                ];
            }
        } elseif ($kind === 'acl') {
            foreach ($xpath->query('/config/acl/resources//resource') as $resource) {
                $rows[] = ['id' => $resource->getAttribute('id'), 'line' => $resource->getLineNo()];
            }
        } elseif (in_array($kind, ['crontab', 'queue_consumer', 'communication'], true)) {
            $query = match ($kind) {
                'crontab' => '/config/group/job',
                'queue_consumer' => '/config/consumer[@handler]',
                default => '/config/topic/handler',
            };
            foreach ($xpath->query($query) as $handler) {
                if (in_array($handler->getAttribute('disabled'), ['true', '1'], true)) continue;
                if ($kind === 'queue_consumer') {
                    $consumer = ltrim($handler->getAttribute('consumerInstance'), '\\');
                    if ($consumer !== '' && $consumer !== 'Magento\Framework\MessageQueue\Consumer') continue;
                    [$class, $method] = array_pad(explode('::', $handler->getAttribute('handler'), 2), 2, '');
                } else {
                    $class = $handler->getAttribute($kind === 'crontab' ? 'instance' : 'type');
                    $method = $handler->getAttribute('method');
                }
                $rows[] = ['class' => $class, 'method' => $method, 'line' => $handler->getLineNo()];
            }
        } elseif ($kind === 'routes') {
            foreach ($xpath->query('/config/router/route') as $route) {
                $rows[] = ['id' => $route->getAttribute('id'), 'front_name' => $route->getAttribute('frontName'), 'line' => $route->getLineNo()];
            }
        }
        return $rows;
    }

    public function index(array $files, array $moduleRoots, ?string $frameworkRoot, ?MagentoInventoryFiles $schemaFiles = null, array $schemaKinds = []): array
    {
        $documents = [];
        $gaps = [];
        foreach ($files as $file) {
            $relative = $file['module_relative_path'] ?? $file['file'];
            if ($file['extension'] !== 'xml' || !preg_match('~^etc/(?:(?<area>[a-z_]+)/)?(?<kind>[^/]+)\.xml$~D', $relative, $parts)) continue;
            $document = self::parse($file['content']);
            if ($document === null) {
                $gaps[] = ['reason' => 'xml_parse_unavailable', 'file' => $file['file']];
                if (self::supports($file['content'])) {
                    $documents[$file['file']] = [
                        'kind' => $parts['kind'], 'module' => $file['module'] ?? null,
                        'area' => $parts['area'] ?: 'global', 'root' => null,
                        'line' => 1, 'schema_urn' => null, 'schema_path' => null,
                        'schema_status' => 'malformed', 'declarations' => [],
                    ];
                }
                continue;
            }
            $root = $document->documentElement;
            $urn = $root->getAttributeNS('http://www.w3.org/2001/XMLSchema-instance', 'noNamespaceSchemaLocation');
            $schemaPath = $urn !== '' ? self::schemaPath($urn, $moduleRoots, $frameworkRoot) : null;
            $status = $schemaFiles === null || ($schemaKinds !== [] && !in_array($parts['kind'], $schemaKinds, true)) ? 'not_validated'
                : ($schemaPath === null ? 'schema_unavailable' : $this->validate($document, $schemaPath, $schemaFiles, $moduleRoots, $frameworkRoot));
            if ($status === 'schema_unavailable') $gaps[] = ['reason' => $status, 'file' => $file['file']];
            $documents[$file['file']] = [
                'kind' => $parts['kind'],
                'module' => $file['module'] ?? null,
                'area' => $parts['area'] ?: 'global',
                'root' => $root->localName,
                'line' => $root->getLineNo(),
                'schema_urn' => $urn !== '' ? $urn : null,
                'schema_path' => $schemaPath,
                'schema_status' => $status,
                'declarations' => self::declarations($document, $parts['kind']),
            ];
        }
        return ['documents' => $documents, 'gaps' => $gaps, 'complete' => $gaps === []];
    }
}
