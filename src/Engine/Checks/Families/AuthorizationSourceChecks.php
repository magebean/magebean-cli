<?php
declare(strict_types=1);
namespace Magebean\Engine\Checks\Families;
use Magebean\Engine\Context;
use Magebean\Engine\Collectors\CollectorSet;

final class AuthorizationSourceChecks extends CodeSearchSupport
{
    public function apiExposureMinimized(array $args): array
    {
        $roots = $args['paths'] ?? ['app/code', 'app/etc'];
        $inc = $args['include_ext'] ?? ['xml', 'graphqls', 'php'];
        $max = max(1, (int)($args['max_results'] ?? 100));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $files = $this->collectFiles($rootsAbs, $inc);
        $phpFiles = array_values(array_filter($files, static fn(string $file): bool => strtolower(pathinfo($file, PATHINFO_EXTENSION)) === 'php'));
        $findings = [];
        $filesRead = 0;
        foreach ($files as $file) {
            $content = $this->collectors->files->read($file);
            if ($content === false) {
                continue;
            }

            $filesRead++;
            $extension = strtolower(pathinfo($file, PATHINFO_EXTENSION));
            $scanContent = $this->maskSourceComments($content, $extension);
            if ($extension === 'xml') {
                $fileFindings = $this->apiExposureWebapiFindings($file, $content, $scanContent);
            } elseif ($extension === 'graphqls') {
                $fileFindings = $this->apiExposureGraphqlFindings($file, $content, $scanContent, $phpFiles);
            } else {
                $fileFindings = $this->apiExposurePhpFindings($file, $content, $scanContent);
            }

            foreach ($fileFindings as $finding) {
                $findings[] = $finding;
                if (count($findings) >= $max) {
                    break 2;
                }
            }
        }

        $evidence = [
            'paths' => array_values($roots),
            'files_scanned' => $filesRead,
            'findings' => $findings,
            'truncated' => count($findings) >= $max,
        ];

        if ($findings !== []) {
            $lines = ['High-risk anonymous API or GraphQL exposure detected:'];
            foreach ($findings as $finding) {
                $lines[] = sprintf(
                    '    - %s:%d [%s] %s',
                    $finding['file'],
                    $finding['line'],
                    $finding['kind'],
                    $finding['snippet']
                );
            }
            if ($evidence['truncated']) {
                $lines[] = sprintf('    - output truncated at %d findings', $max);
            }

            return [false, implode("\n", $lines), $evidence];
        }

        return [null, '[UNKNOWN] No supported exposure candidate found; effective API/GraphQL exposure and approved scope remain unresolved', $evidence];
    }

    public function customAuthorizationChecks(array $args): array
    {
        $roots = $args['paths'] ?? ['app/code', 'app/etc'];
        $inc = $args['include_ext'] ?? ['php', 'xml'];
        $max = max(1, (int)($args['max_results'] ?? 100));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $findings = [];
        $filesRead = 0;
        foreach ($this->collectFiles($rootsAbs, $inc) as $file) {
            $content = $this->collectors->files->read($file);
            if ($content === false) {
                continue;
            }

            $filesRead++;
            $extension = strtolower(pathinfo($file, PATHINFO_EXTENSION));
            $scanContent = $this->maskSourceComments($content, $extension);
            $fileFindings = $extension === 'xml'
                ? $this->customAuthorizationXmlFindings($file, $content, $scanContent)
                : $this->customAuthorizationPhpFindings($file, $content, $scanContent);
            foreach ($fileFindings as $finding) {
                $findings[] = $finding;
                if (count($findings) >= $max) {
                    break 2;
                }
            }
        }

        $evidence = [
            'paths' => array_values($roots),
            'files_scanned' => $filesRead,
            'findings' => $findings,
            'truncated' => count($findings) >= $max,
        ];

        if ($findings !== []) {
            $lines = ['Custom controllers or APIs missing authorization evidence:'];
            foreach ($findings as $finding) {
                $lines[] = sprintf(
                    '    - %s:%d [%s] %s',
                    $finding['file'],
                    $finding['line'],
                    $finding['kind'],
                    $finding['snippet']
                );
            }
            if ($evidence['truncated']) {
                $lines[] = sprintf('    - output truncated at %d findings', $max);
            }

            return [false, implode("\n", $lines), $evidence];
        }

        return [null, '[UNKNOWN] No supported missing-gate candidate found; effective function/object authorization remains unresolved', $evidence];
    }

    public function downloadExportAuthorization(array $args): array
    {
        $roots = $args['paths'] ?? ['app/code'];
        $inc = $args['include_ext'] ?? ['php', 'xml'];
        $max = max(1, (int)($args['max_results'] ?? 100));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $findings = [];
        $endpointsSeen = 0;
        $filesRead = 0;
        foreach ($this->collectFiles($rootsAbs, $inc) as $file) {
            $content = $this->collectors->files->read($file);
            if ($content === false) {
                continue;
            }

            $filesRead++;
            $extension = strtolower(pathinfo($file, PATHINFO_EXTENSION));
            $scanContent = $this->maskSourceComments($content, $extension);
            $fileFindings = $extension === 'xml'
                ? $this->downloadExportWebapiFindings($file, $content, $scanContent, $endpointsSeen)
                : $this->downloadExportControllerFindings($file, $content, $scanContent, $endpointsSeen);
            foreach ($fileFindings as $finding) {
                $findings[] = $finding;
                if (count($findings) >= $max) {
                    break 2;
                }
            }
        }

        $evidence = [
            'paths' => array_values($roots),
            'files_scanned' => $filesRead,
            'download_export_endpoints_seen' => $endpointsSeen,
            'findings' => $findings,
            'truncated' => count($findings) >= $max,
        ];

        if ($findings !== []) {
            $lines = ['Download/export endpoints missing authorization evidence:'];
            foreach ($findings as $finding) {
                $detail = isset($finding['url']) ? ' ' . $finding['url'] : '';
                $lines[] = sprintf(
                    '    - %s:%d [%s]%s %s',
                    $finding['file'],
                    $finding['line'],
                    $finding['kind'],
                    $detail,
                    $finding['snippet']
                );
            }
            if ($evidence['truncated']) {
                $lines[] = sprintf('    - output truncated at %d findings', $max);
            }

            return [false, implode("\n", $lines), $evidence];
        }

        if ($filesRead === 0) {
            return [null, '[UNKNOWN] No readable download/export source was collected', $evidence];
        }

        return [null, '[UNKNOWN] Download/export declarations were inspected; effective identity and object ownership enforcement remain unresolved', $evidence];
    }

    public function mediaExecutableCode(array $args): array
    {
        $roots = $args['paths'] ?? ['pub/media', 'pub/import', 'var/import', 'var/export'];
        $max = max(1, (int)($args['max_results'] ?? 100));
        $maxFileBytes = max(1024, (int)($args['max_file_bytes'] ?? 1048576));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $findings = [];
        $filesScanned = 0;
        $filesSkippedLarge = 0;
        foreach ($this->collectFilesAnyExtension($rootsAbs) as $file) {
            $size = @filesize($file);
            if ($size !== false && $size > $maxFileBytes) {
                $filesSkippedLarge++;
                continue;
            }

            $content = $this->collectors->files->read($file);
            if ($content === false) {
                continue;
            }

            $filesScanned++;
            foreach ($this->mediaExecutableFindings($file, $content) as $finding) {
                $findings[] = $finding;
                if (count($findings) >= $max) {
                    break 2;
                }
            }
        }

        $evidence = [
            'paths' => array_values($roots),
            'files_scanned' => $filesScanned,
            'files_skipped_large' => $filesSkippedLarge,
            'findings' => $findings,
            'truncated' => count($findings) >= $max,
        ];

        if ($findings !== []) {
            $lines = ['Executable code or script-enabling handlers detected in media/upload paths:'];
            foreach ($findings as $finding) {
                $lines[] = sprintf(
                    '    - %s:%d [%s] %s',
                    $finding['file'],
                    $finding['line'],
                    $finding['kind'],
                    $finding['snippet']
                );
            }
            if ($evidence['truncated']) {
                $lines[] = sprintf('    - output truncated at %d findings', $max);
            }

            return [false, implode("\n", $lines), $evidence];
        }

        return [true, 'No executable code or script-enabling handlers detected in media/upload paths', $evidence];
    }

    private function apiExposureWebapiFindings(string $file, string $content, string $scanContent): array
    {
        $relative = $this->relativeFile($file);
        if (!str_ends_with($relative, '/webapi.xml') && !str_ends_with($relative, 'webapi.xml')) {
            return [];
        }

        $findings = [];
        $count = preg_match_all('~<route\b[^>]*\burl\s*=\s*([\'\"])(?P<url>[^\'\"]+)\1[^>]*>(?P<body>.*?)</route>~is', $scanContent, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER);
        if ($count === false || $count < 1) {
            return [];
        }

        foreach ($matches as $match) {
            $offset = (int)$match[0][1];
            $url = (string)$match['url'][0];
            $block = (string)$match[0][0];
            if (!$this->hasSensitiveAuthorizationWorkflow($url . "\n" . $block)) {
                continue;
            }
            $resources = $this->xmlResourceRefs($block);
            if ($this->webapiResourcesAuthorizeSensitiveWorkflow($resources, $url)) {
                continue;
            }

            $evidence = $this->matchEvidence($file, $content, 'high_risk_webapi_exposure', $offset);
            $evidence['kind'] = 'high_risk_webapi_exposure';
            $evidence['url'] = $url;
            $evidence['resources'] = $resources;
            $findings[] = $evidence;
        }

        return $findings;
    }

    private function apiExposureGraphqlFindings(string $file, string $content, string $scanContent, array $phpFiles): array
    {
        $findings = [];
        $count = preg_match_all('~(?P<field>\b[A-Za-z_][A-Za-z0-9_]*\b)\s*(?:\([^\)]*\))?\s*:\s*[^\n@#]+@resolver\s*\([^\)]*class\s*:\s*([\'\"])(?P<class>[^\'\"]+)\2[^\)]*\)~i', $scanContent, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER);
        if ($count === false || $count < 1) {
            return [];
        }

        foreach ($matches as $match) {
            $field = (string)$match['field'][0];
            $class = ltrim(str_replace('\\', '\\', (string)$match['class'][0]), '\\');
            $offset = (int)$match[0][1];
            $window = substr($scanContent, max(0, $offset - 500), 1100);
            if (!$this->hasSensitiveAuthorizationWorkflow($field . "\n" . $class . "\n" . $window)) {
                continue;
            }
            if ($this->graphqlResolverHasAuthEvidence($class, $phpFiles)) {
                continue;
            }

            $evidence = $this->matchEvidence($file, $content, 'graphql_resolver_without_auth_evidence', $offset);
            $evidence['kind'] = 'graphql_resolver_without_auth_evidence';
            $evidence['field'] = $field;
            $evidence['resolver'] = $class;
            $findings[] = $evidence;
        }

        return $findings;
    }

    private function apiExposurePhpFindings(string $file, string $content, string $scanContent): array
    {
        $relative = $this->relativeFile($file);
        if (preg_match('~\b(?:IntrospectionQuery|__schema|__type)\b~i', $scanContent, $match, PREG_OFFSET_CAPTURE) === 1
            && preg_match('~\b(?:graphql|schema|resolver|introspection)\b~i', $relative . "\n" . $scanContent) === 1
            && preg_match('~\b(?:disable|disabled|deny|block|production|developerMode|isDevMode|admin)\b~i', substr($scanContent, max(0, (int)$match[0][1] - 500), 1200)) !== 1) {
            $evidence = $this->matchEvidence($file, $content, 'graphql_introspection_exposure_signal', (int)$match[0][1]);
            $evidence['kind'] = 'graphql_introspection_exposure_signal';
            return [$evidence];
        }

        return [];
    }

    private function graphqlResolverHasAuthEvidence(string $class, array $phpFiles): bool
    {
        $candidate = $this->resolverClassToPath($class);
        $files = [];
        if ($candidate !== null) {
            foreach ($phpFiles as $file) {
                if (str_ends_with(str_replace('\\', '/', $file), $candidate)) {
                    $files[] = $file;
                }
            }
        }
        if ($files === []) {
            foreach ($phpFiles as $file) {
                $content = $this->collectors->files->read($file);
                if (!is_string($content)) {
                    continue;
                }
                $needle = preg_quote(ltrim($class, '\\'), '~');
                if (preg_match('~(?:namespace\s+' . str_replace('\\', '\\\\', $needle) . '\b|class\s+' . preg_quote($this->shortClassName($class), '~') . '\b)~', $content) === 1) {
                    $files[] = $file;
                }
            }
        }

        foreach ($files as $file) {
            $content = $this->collectors->files->read($file);
            if (!is_string($content)) {
                continue;
            }
            $scanContent = $this->maskSourceComments($content, 'php');
            if ($this->hasGraphqlResolverAuthEvidence($scanContent)) {
                return true;
            }
        }

        return false;
    }

    private function hasGraphqlResolverAuthEvidence(string $content): bool
    {
        return $this->hasLeadingDenyGuard($content, ['resolve']);
    }

    private function resolverClassToPath(string $class): ?string
    {
        $class = trim($class, '\\');
        if ($class === '' || !str_contains($class, '\\')) {
            return null;
        }
        return str_replace('\\', '/', $class) . '.php';
    }

    private function shortClassName(string $class): string
    {
        $class = trim($class, '\\');
        $pos = strrpos($class, '\\');
        return $pos === false ? $class : substr($class, $pos + 1);
    }

    private function customAuthorizationPhpFindings(string $file, string $content, string $scanContent): array
    {
        $relative = $this->relativeFile($file);
        if (!$this->looksLikeCustomControllerFile($relative, $scanContent)) {
            return [];
        }

        $findings = [];
        $count = preg_match_all('~\bfunction\s+execute\s*\([^)]*\)\s*\{~i', $scanContent, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER);
        if ($count === false || $count < 1) {
            return [];
        }

        foreach ($matches as $match) {
            $offset = (int)$match[0][1];
            $window = substr($scanContent, max(0, $offset - 1400), 3600);
            if (!$this->hasSensitiveAuthorizationWorkflow($relative . "\n" . $window)) {
                continue;
            }
            if ($this->hasControllerAuthorizationEvidence($relative, $window, $scanContent, $offset)) {
                continue;
            }

            $evidence = $this->matchEvidence($file, $content, 'controller_execute_without_authorization', $offset);
            $evidence['kind'] = 'controller_execute_without_authorization';
            $findings[] = $evidence;
        }

        return $findings;
    }

    private function customAuthorizationXmlFindings(string $file, string $content, string $scanContent): array
    {
        $relative = $this->relativeFile($file);
        if (!str_ends_with($relative, '/webapi.xml') && !str_ends_with($relative, 'webapi.xml')) {
            return [];
        }

        $findings = [];
        $count = preg_match_all('~<route\b[^>]*\burl\s*=\s*([\'\"])(?P<url>[^\'\"]+)\1[^>]*>(?P<body>.*?)</route>~is', $scanContent, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER);
        if ($count === false || $count < 1) {
            return [];
        }

        foreach ($matches as $match) {
            $offset = (int)$match[0][1];
            $url = (string)$match['url'][0];
            $body = (string)$match['body'][0];
            $block = (string)$match[0][0];
            if (!$this->hasSensitiveAuthorizationWorkflow($url . "\n" . $block)) {
                continue;
            }

            $resources = $this->xmlResourceRefs($block);
            if ($this->webapiResourcesAuthorizeSensitiveWorkflow($resources, $url)) {
                continue;
            }

            $evidence = $this->matchEvidence($file, $content, 'webapi_route_without_authorization', $offset);
            $evidence['kind'] = 'webapi_route_without_authorization';
            $evidence['url'] = $url;
            $evidence['resources'] = $resources;
            $findings[] = $evidence;
        }

        return $findings;
    }

    private function looksLikeCustomControllerFile(string $relative, string $content): bool
    {
        return preg_match('~/Controller/~i', $relative) === 1
            || preg_match('~\bclass\s+\w*(?:Controller|Action)\w*\b|extends\s+[^\n;]*(?:Action|AbstractAction|Adminhtml|Frontend)~i', $content) === 1;
    }

    private function hasSensitiveAuthorizationWorkflow(string $text): bool
    {
        return preg_match('~\b(?:order|orders|customer|customers|invoice|shipment|creditmemo|refund|download|export|report|address|quote|cart|wishlist|payment|transaction|token|admin)\b~i', $text) === 1;
    }

    private function hasControllerAuthorizationEvidence(string $relative, string $window, string $fileContent, int $offset): bool
    {
        return $this->hasLeadingDenyGuard($fileContent, ['execute'], $offset);
    }

    /** A supported leading negative authorization check must terminate before any following body statements. */
    private function hasLeadingDenyGuard(string $content, array $methods, ?int $offset = null): bool
    {
        try { $nodes = (new \PhpParser\ParserFactory())->createForNewestSupportedVersion()->parse($content) ?? []; }
        catch (\PhpParser\Error) { return false; }
        foreach ((new \PhpParser\NodeFinder())->findInstanceOf($nodes, \PhpParser\Node\Stmt\ClassMethod::class) as $method) {
            if (!in_array(strtolower($method->name->toString()), $methods, true)) continue;
            if ($offset !== null && ($offset < $method->getStartFilePos() || $offset > $method->getEndFilePos())) continue;
            $body = array_values(array_filter($method->stmts ?? [], static fn(\PhpParser\Node $n): bool => !$n instanceof \PhpParser\Node\Stmt\Nop));
            $guard = $body[0] ?? null;
            if (!$guard instanceof \PhpParser\Node\Stmt\If_ || !$guard->cond instanceof \PhpParser\Node\Expr\BooleanNot || $guard->elseifs !== [] || $guard->else !== null) continue;
            $call = $guard->cond->expr;
            if (!$call instanceof \PhpParser\Node\Expr\MethodCall || !$call->name instanceof \PhpParser\Node\Identifier
                || !in_array(strtolower($call->name->name), ['isallowed','isloggedin','canaccess','isgranted'], true)) continue;
            $branch = array_values(array_filter($guard->stmts, static fn(\PhpParser\Node $n): bool => !$n instanceof \PhpParser\Node\Stmt\Nop));
            if (count($branch) !== 1) continue;
            if ($branch[0] instanceof \PhpParser\Node\Stmt\Return_ || ($branch[0] instanceof \PhpParser\Node\Stmt\Expression && $branch[0]->expr instanceof \PhpParser\Node\Expr\Throw_)) return true;
        }
        return false;
    }

    private function declaredAclResource(string $resource): bool
    {
        foreach ($this->collectFiles([$this->ctx->abs('app/code')], ['xml']) as $file) {
            if (!str_ends_with(str_replace(chr(92), '/', $file), '/etc/acl.xml')) continue;
            $text = $this->collectors->files->read($file);
            if (!is_string($text)) continue;
            if (preg_match_all('~<resource\b[^>]*\bid\s*=\s*([\'\"])(.*?)\1~is', $text, $matches)) {
                if (in_array($resource, $matches[2], true)) return true;
            }
        }
        return false;
    }

    private function webapiResourcesAuthorizeSensitiveWorkflow(array $resources, string $url): bool
    {
        if ($resources === []) {
            return false;
        }

        $customerScoped = preg_match('~\b(?:me|mine|my|self|customer)\b~i', $url) === 1;
        foreach ($resources as $resource) {
            $resource = trim((string)$resource);
            if ($resource === '' || preg_match('~^anonymous$~i', $resource) === 1) {
                continue;
            }
            if (preg_match('~^self$~i', $resource) === 1) {
                if ($customerScoped) return true;
                continue;
            }
            if (preg_match('~^(?:Magento_Webapi::all|Magento_Backend::admin|Magento_Adminhtml::admin)$~i', $resource) === 1 || preg_match('~::all$~i', $resource) === 1) {
                continue;
            }
            if ($this->declaredAclResource($resource)) return true;
        }

        return false;
    }

    private function downloadExportControllerFindings(string $file, string $content, string $scanContent, int &$endpointsSeen): array
    {
        $relative = $this->relativeFile($file);
        if (!$this->looksLikeCustomControllerFile($relative, $scanContent)) {
            return [];
        }

        $findings = [];
        $count = preg_match_all('~\bfunction\s+execute\s*\([^)]*\)\s*\{~i', $scanContent, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER);
        if ($count === false || $count < 1) {
            return [];
        }

        foreach ($matches as $match) {
            $offset = (int)$match[0][1];
            $window = substr($scanContent, max(0, $offset - 1400), 4200);
            if (!$this->hasDownloadExportWorkflow($relative . "\n" . $window)) {
                continue;
            }

            $endpointsSeen++;
            if ($this->hasControllerAuthorizationEvidence($relative, $window, $scanContent, $offset)) {
                continue;
            }

            $evidence = $this->matchEvidence($file, $content, 'download_export_controller_without_authorization', $offset);
            $evidence['kind'] = 'download_export_controller_without_authorization';
            $findings[] = $evidence;
        }

        return $findings;
    }

    private function downloadExportWebapiFindings(string $file, string $content, string $scanContent, int &$endpointsSeen): array
    {
        $relative = $this->relativeFile($file);
        if (!str_ends_with($relative, '/webapi.xml') && !str_ends_with($relative, 'webapi.xml')) {
            return [];
        }

        $findings = [];
        $count = preg_match_all('~<route\b[^>]*\burl\s*=\s*([\'\"])(?P<url>[^\'\"]+)\1[^>]*>(?P<body>.*?)</route>~is', $scanContent, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER);
        if ($count === false || $count < 1) {
            return [];
        }

        foreach ($matches as $match) {
            $offset = (int)$match[0][1];
            $url = (string)$match['url'][0];
            $block = (string)$match[0][0];
            if (!$this->hasDownloadExportWorkflow($url . "\n" . $block)) {
                continue;
            }

            $endpointsSeen++;
            $resources = $this->xmlResourceRefs($block);
            if ($this->webapiResourcesAuthorizeDownloadExport($resources, $url)) {
                continue;
            }

            $evidence = $this->matchEvidence($file, $content, 'download_export_webapi_without_authorization', $offset);
            $evidence['kind'] = 'download_export_webapi_without_authorization';
            $evidence['url'] = $url;
            $evidence['resources'] = $resources;
            $findings[] = $evidence;
        }

        return $findings;
    }

    private function hasDownloadExportWorkflow(string $text): bool
    {
        return preg_match('~\b(?:FileFactory|download|downloadable|export|report|invoice|statement|csv|pdf|xlsx?|zip|Content-Disposition|application/(?:pdf|octet-stream|zip)|text/csv|sendFile|streamDownload|create\s*\([^;]{0,160}\.(?:csv|pdf|xlsx?|zip))\b~i', $text) === 1;
    }

    private function webapiResourcesAuthorizeDownloadExport(array $resources, string $url): bool
    {
        if ($resources === []) {
            return false;
        }

        $customerScoped = preg_match('~\b(?:me|mine|my|self|customer)\b~i', $url) === 1;
        foreach ($resources as $resource) {
            $resource = trim((string)$resource);
            if ($resource === '' || preg_match('~^anonymous$~i', $resource) === 1) {
                continue;
            }
            if (preg_match('~^self$~i', $resource) === 1) {
                if ($customerScoped) return true;
                continue;
            }
            if (preg_match('~^(?:Magento_Webapi::all|Magento_Backend::admin|Magento_Adminhtml::admin)$~i', $resource) === 1 || preg_match('~::all$~i', $resource) === 1) {
                continue;
            }
            if ($this->declaredAclResource($resource)) return true;
        }

        return false;
    }

    private function collectFilesAnyExtension(array $roots): array
    {
        return $this->collectors->code->anyExtension($roots);
    }

    private function mediaExecutableFindings(string $file, string $content): array
    {
        $findings = [];
        $relative = $this->relativeFile($file);
        $basename = strtolower(basename($relative));
        $extension = strtolower(pathinfo($relative, PATHINFO_EXTENSION));
        $dangerousExtensions = [
            'php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'php8', 'phar',
            'cgi', 'pl', 'py', 'rb', 'sh', 'bash', 'zsh', 'ksh',
            'asp', 'aspx', 'jsp', 'jspx', 'war',
        ];

        if (in_array($extension, $dangerousExtensions, true)) {
            $evidence = $this->matchEvidence($file, $content, 'executable_extension', 0);
            $evidence['kind'] = 'executable_extension';
            $findings[] = $evidence;
        }

        $patterns = [
            'php_open_tag' => '~<\?(?:php|=|\s)~i',
            'script_shebang' => '~\A#!\s*/(?:usr/bin/env\s+)?(?:php|perl|python\d*|ruby|sh|bash|zsh|ksh|node)\b~i',
        ];
        if ($basename === '.htaccess') {
            $patterns['apache_script_handler'] = '~\b(?:AddHandler|SetHandler|AddType)\b[^\r\n]*(?:php|cgi|perl|python|ruby|application/x-httpd-php)|\bOptions\b[^\r\n]*\+?ExecCGI\b~i';
        }

        foreach ($patterns as $kind => $regex) {
            if (preg_match($regex, $content, $match, PREG_OFFSET_CAPTURE) !== 1) {
                continue;
            }
            $evidence = $this->matchEvidence($file, $content, $kind, (int)$match[0][1]);
            $evidence['kind'] = $kind;
            $findings[] = $evidence;
        }

        return $findings;
    }
}
