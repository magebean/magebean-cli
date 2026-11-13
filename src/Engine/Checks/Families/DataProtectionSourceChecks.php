<?php
declare(strict_types=1);
namespace Magebean\Engine\Checks\Families;
use Magebean\Engine\Context;
use Magebean\Engine\Collectors\CollectorSet;

final class DataProtectionSourceChecks extends CodeSearchSupport
{
    public function piiMinimization(array $args): array
    {
        $roots = $args['paths'] ?? ['app/code'];
        $inc = $args['include_ext'] ?? ['php'];
        $max = max(1, (int)($args['max_results'] ?? 100));
        $excludeDirs = array_values(array_filter(array_map(
            static fn(mixed $path): string => trim(str_replace('\\', '/', (string)$path), '/'),
            (array)($args['exclude_dirs'] ?? ['setup', 'dev/tests', 'dev/tools', 'vendor', 'var', 'generated', 'pub/static', 'pub/media'])
        ), static fn(string $path): bool => $path !== ''));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $findings = [];
        $filesRead = 0;
        foreach ($this->collectFiles($rootsAbs, $inc) as $file) {
            $relativeFile = $this->relativeFile($file);
            if ($this->isExcludedRelativePath($relativeFile, $excludeDirs)) {
                continue;
            }
            $content = $this->collectors->files->read($file);
            if ($content === false) {
                continue;
            }

            $filesRead++;
            foreach ($this->piiMinimizationFindings($file, $content) as $finding) {
                $findings[] = $finding;
                if (count($findings) >= $max) {
                    break 2;
                }
            }
        }

        $evidence = [
            'paths' => array_values($roots),
            'exclude_dirs' => $excludeDirs,
            'files_scanned' => $filesRead,
            'findings' => $findings,
            'truncated' => count($findings) >= $max,
        ];

        if ($filesRead === 0) {
            return [null, '[UNKNOWN] PII minimization scan could not read any target files', $evidence];
        }

        if ($findings !== []) {
            $lines = ['Raw sensitive PII appears in third-party outbound flows:'];
            foreach ($findings as $finding) {
                $lines[] = sprintf(
                    '    - %s:%d [%s] %s',
                    $finding['file'],
                    $finding['line'],
                    $finding['kind'],
                    $finding['field']
                );
            }
            if ($evidence['truncated']) {
                $lines[] = sprintf('    - output truncated at %d findings', $max);
            }

            return [false, implode("\n", $lines), $evidence];
        }

        return [null, '[UNKNOWN] No supported outbound PII candidate was found; runtime payload minimization and approved field scope were not established', $evidence];
    }

    public function unsafeXmlParsing(array $args): array
    {
        $roots = $args['paths'] ?? ['app'];
        $inc = $args['include_ext'] ?? ['php'];
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
            foreach ($this->unsafeXmlParsingFindings($file, $content) as $finding) {
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
            $lines = ['Unsafe XML parsing patterns detected:'];
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

        if ($filesRead === 0) return [null, '[UNKNOWN] No readable PHP files were inspected for XML constructs', $evidence];
        return [null, '[UNKNOWN] No enumerated unsafe XML source pattern found; dynamic flags and parser runtime behavior remain unresolved', $evidence];
    }

    public function hardcodedSecrets(array $args): array
    {
        $roots = $args['paths'] ?? ['app', 'app/design'];
        $inc = $args['include_ext'] ?? ['php', 'phtml', 'js', 'xml', 'json', 'env', 'dist', 'txt', 'pem', 'key', 'yml', 'yaml'];
        $max = max(1, (int)($args['max_results'] ?? 100));
        $allowedFiles = $args['allowed_files'] ?? ['app/etc/env.php'];
        if (!is_array($allowedFiles)) {
            $allowedFiles = ['app/etc/env.php'];
        }
        $allowed = array_fill_keys(array_map('strval', $allowedFiles), true);
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $findings = [];
        $filesRead = 0;
        foreach ($this->collectFiles($rootsAbs, $inc) as $file) {
            if (isset($allowed[$this->relativeFile($file)])) {
                continue;
            }
            $content = $this->collectors->files->read($file);
            if ($content === false) {
                continue;
            }

            $filesRead++;
            foreach ($this->hardcodedSecretFindings($file, $content) as $finding) {
                $findings[] = $finding;
                if (count($findings) >= $max) {
                    break 2;
                }
            }
        }

        $findings = $this->dedupeFindings($findings);
        $evidence = [
            'paths' => array_values($roots),
            'allowed_files' => array_values(array_map('strval', $allowedFiles)),
            'files_scanned' => $filesRead,
            'findings' => $findings,
            'truncated' => count($findings) >= $max,
        ];

        if ($findings !== []) {
            $lines = ['Hardcoded secrets detected outside approved secret storage:'];
            foreach ($findings as $finding) {
                $lines[] = sprintf(
                    '    - %s:%d [%s] %s',
                    $finding['file'],
                    $finding['line'],
                    $finding['kind'],
                    $finding['field'] ?? $finding['pattern']
                );
            }
            if ($evidence['truncated']) {
                $lines[] = sprintf('    - output truncated at %d findings', $max);
            }

            return [false, implode("\n", $lines), $evidence];
        }

        return [null, '[UNKNOWN] No supported literal secret candidate found; dynamic values and uncollected secret stores remain unresolved', $evidence];
    }

    public function apiKeyStorage(array $args): array
    {
        $roots = $args['paths'] ?? ['app/code', 'app/etc', 'app/design', 'setup'];
        $inc = $args['include_ext'] ?? ['php', 'phtml', 'xml', 'sql'];
        $max = max(1, (int)($args['max_results'] ?? 100));
        $envFile = (string)($args['env_file'] ?? 'app/etc/env.php');
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $findings = [];
        $filesRead = 0;
        foreach ($this->collectFiles($rootsAbs, $inc) as $file) {
            if ($this->relativeFile($file) === $envFile) {
                continue;
            }
            $content = $this->collectors->files->read($file);
            if ($content === false) {
                continue;
            }

            $filesRead++;
            foreach ($this->apiKeyStorageFindings($file, $content) as $finding) {
                $findings[] = $finding;
                if (count($findings) >= $max) {
                    break 2;
                }
            }
        }

        $envEvidence = $this->envCredentialKeyEvidence($envFile);
        $evidence = [
            'paths' => array_values($roots),
            'files_scanned' => $filesRead,
            'env_credentials' => $envEvidence,
            'findings' => $findings,
            'truncated' => count($findings) >= $max,
        ];

        if ($findings !== []) {
            $lines = ['API credentials found outside env.php or written to DB config paths:'];
            foreach ($findings as $finding) {
                $lines[] = sprintf(
                    '    - %s:%d [%s] %s',
                    $finding['file'],
                    $finding['line'],
                    $finding['kind'],
                    $finding['field'] ?? $finding['pattern']
                );
            }
            if ($evidence['truncated']) {
                $lines[] = sprintf('    - output truncated at %d findings', $max);
            }

            return [false, implode("\n", $lines), $evidence];
        }

        if ($filesRead === 0) {
            return [null, '[UNKNOWN] No application code/config files found to inspect API credential storage', $evidence];
        }

        $envCount = (int)($envEvidence['credential_keys'] ?? 0);
        $message = $envCount > 0
            ? 'API credential-like keys are present in env.php and no code/DB storage patterns were detected'
            : 'No API credential code/DB storage patterns detected; env.php credential keys were not found';

        return [null, '[UNKNOWN] '.$message.'. Database and external secret storage were not inspected', $evidence];
    }

    public function thirdPartyLoggingSanitized(array $args): array
    {
        $roots = $args['paths'] ?? ['app/code'];
        $inc = $args['include_ext'] ?? ['php'];
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
            foreach ($this->thirdPartyLoggingFindings($file, $content) as $finding) {
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
            $lines = ['Third-party sensitive logging without masking/redaction:'];
            foreach ($findings as $finding) {
                $lines[] = sprintf(
                    '    - %s:%d [%s/%s]',
                    $finding['file'],
                    $finding['line'],
                    $finding['kind'],
                    $finding['risk']
                );
            }
            if ($evidence['truncated']) {
                $lines[] = sprintf('    - output truncated at %d findings', $max);
            }

            return [false, implode("\n", $lines), $evidence];
        }

        if ($filesRead === 0) {
            return [null, '[UNKNOWN] No readable application code was available for third-party logging', $evidence];
        }

        return [null, '[UNKNOWN] No supported third-party log candidate found; opaque payloads and sanitizer behavior remain unresolved', $evidence];
    }

    public function saasIntegrationScoped(array $args): array
    {
        $roots = $args['paths'] ?? ['app/code', 'app/etc'];
        $inc = $args['include_ext'] ?? ['php', 'xml'];
        $max = max(1, (int)($args['max_results'] ?? 100));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $surfaces = [];
        $failures = [];
        $filesRead = 0;
        foreach ($this->collectFiles($rootsAbs, $inc) as $file) {
            $content = $this->collectors->files->read($file);
            if ($content === false) {
                continue;
            }

            $filesRead++;
            foreach ($this->saasIntegrationScopeFindings($file, $content) as $finding) {
                $surfaces[] = $finding;
                if (empty($finding['controls']['ok'])) {
                    $failures[] = $finding;
                    if (count($failures) >= $max) {
                        break 2;
                    }
                }
            }
        }

        $evidence = [
            'paths' => array_values($roots),
            'files_scanned' => $filesRead,
            'surfaces' => $surfaces,
            'failures' => $failures,
            'truncated' => count($failures) >= $max,
        ];

        if ($filesRead === 0) {
            return [null, '[UNKNOWN] No application code/config files found to inspect SaaS declarations', $evidence];
        }

        if ($failures !== []) {
            $lines = ['SaaS integration entry points missing least-privilege ACL or IP allowlist:'];
            foreach ($failures as $failure) {
                $lines[] = sprintf(
                    '    - %s:%d [%s] missing %s',
                    $failure['file'],
                    $failure['line'],
                    $failure['kind'],
                    implode('+', $failure['controls']['missing'] ?? ['scoping'])
                );
            }
            if ($evidence['truncated']) {
                $lines[] = sprintf('    - output truncated at %d findings', $max);
            }

            return [false, implode("\n", $lines), $evidence];
        }

        if ($surfaces === []) {
            return [null, '[UNKNOWN] No supported SaaS entry point was detected; provider grants and deployed restrictions were not inspected', $evidence];
        }

        return [null, '[UNKNOWN] Static SaaS declarations were collected; provider grants and runtime enforcement were not verified', $evidence];
    }

    public function sensitiveLogging(array $args): array
    {
        $roots = $args['paths'] ?? ['app'];
        $inc = $args['include_ext'] ?? ['php'];
        $max = max(1, (int)($args['max_results'] ?? 50));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $offenders = [];
        foreach ($this->collectFiles($rootsAbs, $inc) as $file) {
            $content = $this->collectors->files->read($file);
            if ($content === false) {
                continue;
            }

            foreach ($this->sensitiveLoggingFindings($file, $content) as $finding) {
                $offenders[] = $finding;
                if (count($offenders) >= $max) {
                    break 2;
                }
            }
        }

        if ($offenders !== []) {
            return [
                false,
                'Sensitive data may be logged in: ' . implode(', ', array_map(
                    static fn(array $match): string => $match['file'] . ':' . $match['line'] . ' [' . $match['kind'] . '/' . $match['risk'] . ']',
                    $offenders
                )),
                $offenders,
            ];
        }

        return [null, '[UNKNOWN] No supported sensitive logging candidate found; opaque payloads and sanitizer behavior are unresolved'];
    }

    public function magentoApiCryptoSession(array $args): array
    {
        $roots = $args['paths'] ?? ['app'];
        $inc = $args['include_ext'] ?? ['php'];
        $max = max(1, (int)($args['max_results'] ?? 50));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $offenders = [];
        foreach ($this->collectFiles($rootsAbs, $inc) as $file) {
            $content = $this->collectors->files->read($file);
            if ($content === false) {
                continue;
            }

            foreach ($this->magentoApiCryptoSessionFindings($file, $content) as $finding) {
                $offenders[] = $finding;
                if (count($offenders) >= $max) {
                    break 2;
                }
            }
        }

        if ($offenders !== []) {
            return [
                false,
                'Raw crypto/session API usage found in: ' . implode(', ', array_map(
                    static fn(array $match): string => $match['file'] . ':' . $match['line'] . ' [' . $match['kind'] . '/' . $match['risk'] . ']',
                    $offenders
                )),
                $offenders,
            ];
        }

        return [true, 'Magento crypto and session APIs are used'];
    }

    private function unsafeXmlParsingFindings(string $file, string $content): array
    {
        $findings = [];
        $searchable = $this->maskSourceComments($content, strtolower(pathinfo($file, PATHINFO_EXTENSION)));
        $patterns = [
            'entity_loader_enabled' => '~\blibxml_disable_entity_loader\s*\(\s*false\s*\)~i',
            'dangerous_libxml_flags' => '~\bLIBXML_(?:NOENT|DTDLOAD|DTDATTR)\b~i',
            'dom_resolve_externals' => '~->\s*resolveExternals\s*=\s*true\b~i',
            'dom_substitute_entities' => '~->\s*substituteEntities\s*=\s*true\b~i',
            'dom_validate_on_parse' => '~->\s*validateOnParse\s*=\s*true\b~i',
            'xml_parser_external_entity_handler' => '~\bxml_set_external_entity_ref_handler\s*\(~i',
            'xmlreader_load_dtd_property' => '~->\s*setParserProperty\s*\(\s*XMLReader::LOADDTD\s*,\s*true\s*\)~i',
            'xmlreader_subst_entities_property' => '~->\s*setParserProperty\s*\(\s*XMLReader::SUBST_ENTITIES\s*,\s*true\s*\)~i',
            'dom_xinclude_call' => '~->\s*xinclude\s*\(~i',
            'doctype_in_dynamic_xml' => '~<\!DOCTYPE\s+[^>]+(?:SYSTEM|PUBLIC|ENTITY)~i',
        ];

        foreach ($patterns as $kind => $regex) {
            $count = preg_match_all($regex, $searchable, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER);
            if ($count === false || $count < 1) {
                continue;
            }
            foreach ($matches as $match) {
                $offset = (int)$match[0][1];
                $evidence = $this->matchEvidence($file, $content, $kind, $offset);
                $evidence['kind'] = $kind;
                $findings[] = $evidence;
            }
        }

        $callPatterns = [
            'simplexml_load_with_unsafe_flags' => '~\bsimplexml_load_(?:string|file)\s*\([^;\n]*(?:LIBXML_NOENT|LIBXML_DTDLOAD|LIBXML_DTDATTR)~i',
            'dom_load_with_unsafe_flags' => '~->\s*load(?:XML)?\s*\([^;\n]*(?:LIBXML_NOENT|LIBXML_DTDLOAD|LIBXML_DTDATTR)~i',
            'xmlreader_open_with_unsafe_flags' => '~\bXMLReader::(?:XML|open)\s*\([^;\n]*(?:LIBXML_NOENT|LIBXML_DTDLOAD|LIBXML_DTDATTR)~i',
        ];
        foreach ($callPatterns as $kind => $regex) {
            $count = preg_match_all($regex, $searchable, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER);
            if ($count === false || $count < 1) {
                continue;
            }
            foreach ($matches as $match) {
                $evidence = $this->matchEvidence($file, $content, $kind, (int)$match[0][1]);
                $evidence['kind'] = $kind;
                $findings[] = $evidence;
            }
        }

        $lineSeen = [];
        $deduped = [];
        foreach ($findings as $finding) {
            $key = ($finding['file'] ?? '') . ':' . ($finding['line'] ?? '') . ':' . ($finding['snippet'] ?? '');
            if (isset($lineSeen[$key])) {
                continue;
            }
            $lineSeen[$key] = true;
            $deduped[] = $finding;
        }

        return $deduped;
    }

    private function isSafeLibxmlFlagContext(string $content, int $offset): bool
    {
        $before = substr($content, max(0, $offset - 120), 120);
        $after = substr($content, $offset, 220);
        if (preg_match('~\b(?:LIBXML_NONET|LIBXML_NOERROR|LIBXML_NOWARNING|LIBXML_NOCDATA|LIBXML_COMPACT)\b~i', $after) === 1
            && preg_match('~\b(?:NOENT|DTDLOAD|DTDATTR)\b~i', $after) !== 1) {
            return true;
        }
        return preg_match('~\b(?:avoid|do not use|forbidden|disallow|deny|unsafe|blocked)\b~i', $before . $after) === 1;
    }

    private function hardcodedSecretFindings(string $file, string $content): array
    {
        $findings = $this->apiKeyStorageFindings($file, $content);
        $extension = strtolower(pathinfo($file, PATHINFO_EXTENSION));
        $searchable = $this->maskSourceComments($content, $extension);
        $patterns = [
            'private_key_block' => '~-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----~i',
            'named_secret_literal' => '~[\'\"]?(?P<field>[A-Za-z0-9_.-]*(?:api[_-]?key|secret|token|client[_-]?secret|access[_-]?token|refresh[_-]?token|private[_-]?key|password|passwd|pwd)[A-Za-z0-9_.-]*)[\'\"]?\s*(?:=>|=|:)\s*[\'\"](?P<value>[A-Za-z0-9_\-\/.+=:$]{12,})[\'\"]~i',
            'env_secret_literal' => '~(?m)^\s*(?P<field>[A-Z0-9_]*(?:API_KEY|SECRET|TOKEN|CLIENT_SECRET|ACCESS_TOKEN|REFRESH_TOKEN|PRIVATE_KEY|PASSWORD|PASSWD|PWD)[A-Z0-9_]*)\s*=\s*(?P<value>[A-Za-z0-9_\-\/.+=:$]{12,})\s*$~',
            'bearer_token_literal' => '~\bAuthorization\b\s*(?:=>|=|:)\s*[\'\"]Bearer\s+(?P<value>[A-Za-z0-9_\-\/.+=]{20,})[\'\"]~i',
        ];

        foreach ($patterns as $kind => $regex) {
            $count = preg_match_all($regex, $searchable, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER);
            if ($count === false || $count < 1) {
                continue;
            }

            foreach ($matches as $match) {
                $value = isset($match['value']) && is_array($match['value']) ? (string)$match['value'][0] : 'private-key';
                if ($kind !== 'private_key_block' && !$this->looksLikeStoredSecretLiteral($value)) {
                    continue;
                }
                $field = isset($match['field']) && is_array($match['field']) ? (string)$match['field'][0] : $kind;
                $offset = (int)$match[0][1];
                $evidence = $this->matchEvidence($file, $content, $kind, $offset);
                $evidence['kind'] = $kind;
                $evidence['field'] = $field;
                $evidence['snippet'] = $this->redactSecretSnippet((string)$evidence['snippet']);
                $findings[] = $evidence;
            }
        }

        foreach ($findings as &$finding) {
            if (isset($finding['snippet'])) {
                $finding['snippet'] = $this->redactSecretSnippet((string)$finding['snippet']);
            }
        }
        unset($finding);

        return $findings;
    }

    private function redactSecretSnippet(string $snippet): string
    {
        $snippet = preg_replace('~-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----.*~i', '-----BEGIN PRIVATE KEY----- [REDACTED]', $snippet) ?? $snippet;
        $snippet = preg_replace('~([\'\"])([A-Za-z0-9_\-\/.+=:$]{8,})(\1)~', '$1[REDACTED]$3', $snippet) ?? $snippet;
        $snippet = preg_replace('~(=\s*)([A-Za-z0-9_\-\/.+=:$]{8,})~', '$1[REDACTED]', $snippet) ?? $snippet;
        return $snippet;
    }

    private function apiKeyStorageFindings(string $file, string $content): array
    {
        $findings = [];
        $extension = strtolower(pathinfo($file, PATHINFO_EXTENSION));
        $searchable = $this->maskSourceComments($content, $extension);
        $patterns = [
            'core_config_data_secret_write' => '~\b(?:INSERT\s+INTO|UPDATE)\s+[^;]{0,240}\bcore_config_data\b[^;]{0,500}\b(?:api[_-]?key|secret|token|client[_-]?secret|access[_-]?token|private[_-]?key)\b~is',
            'config_writer_secret_write' => '~(?:->\s*(?:setData|setValue|saveConfig)\s*\(|\bConfig\s*\()[^;]{0,400}\b(?:api[_-]?key|secret|token|client[_-]?secret|access[_-]?token|private[_-]?key)\b~is',
            'hardcoded_secret_array' => '~[\'\"](?P<field>[A-Za-z0-9_./-]*(?:api[_-]?key|secret|token|client[_-]?secret|access[_-]?token|private[_-]?key)[A-Za-z0-9_./-]*)[\'\"]\s*=>\s*[\'\"](?P<value>[^\'\"]{8,})[\'\"]~i',
            'hardcoded_secret_assignment' => '~\$(?P<field>[A-Za-z_][A-Za-z0-9_]*(?:ApiKey|apiKey|Secret|secret|Token|token|PrivateKey|privateKey)[A-Za-z0-9_]*)\s*=\s*[\'\"](?P<value>[^\'\"]{8,})[\'\"]~',
            'xml_secret_value' => '~<(?P<field>[A-Za-z0-9_.:-]*(?:api[_-]?key|secret|token|client[_-]?secret|access[_-]?token|private[_-]?key)[A-Za-z0-9_.:-]*)>\s*(?P<value>[^<\s][^<]{7,})\s*</[^>]+>~i',
        ];

        foreach ($patterns as $kind => $regex) {
            $count = preg_match_all($regex, $searchable, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER);
            if ($count === false || $count < 1) {
                continue;
            }

            foreach ($matches as $match) {
                $value = isset($match['value']) && is_array($match['value']) ? (string)$match['value'][0] : '';
                if ($value !== '' && !$this->looksLikeStoredSecretLiteral($value)) {
                    continue;
                }

                $field = isset($match['field']) && is_array($match['field']) ? (string)$match['field'][0] : $kind;
                $offset = (int)$match[0][1];
                $evidence = $this->matchEvidence($file, $content, $kind, $offset);
                $evidence['kind'] = $kind;
                $evidence['field'] = $field;
                $evidence['offset'] = $offset;
                $findings[] = $evidence;
            }
        }

        return array_merge($findings, $this->constantSecretFindings($file, $content));
    }

    private function constantSecretFindings(string $file, string $content): array
    {
        if (!in_array(strtolower(pathinfo($file, PATHINFO_EXTENSION)), ['php', 'phtml'], true)) return [];
        try { $nodes = (new \PhpParser\ParserFactory())->createForNewestSupportedVersion()->parse($content) ?? []; }
        catch (\PhpParser\Error) { return []; }
        $findings = [];
        foreach ((new \PhpParser\NodeFinder())->find($nodes, static fn(\PhpParser\Node $n): bool => $n instanceof \PhpParser\Node\ArrayItem || $n instanceof \PhpParser\Node\Expr\Assign) as $node) {
            $key = $node instanceof \PhpParser\Node\ArrayItem ? ($node->key instanceof \PhpParser\Node\Scalar\String_ ? $node->key->value : '') : ($node->var instanceof \PhpParser\Node\Expr\Variable && is_string($node->var->name) ? $node->var->name : '');
            $value = $node instanceof \PhpParser\Node\ArrayItem ? $node->value : $node->expr;
            if (!preg_match('~(?:password|passwd|api[_-]?key|secret|token|private[_-]?key)~i', $key) || !$value instanceof \PhpParser\Node\Expr\BinaryOp\Concat) continue;
            $literal = $this->constantSecretString($value);
            if ($literal === null || !$this->looksLikeStoredSecretLiteral($literal)) continue;
            $findings[] = ['file' => $this->relativeFile($file), 'line' => $node->getStartLine(), 'kind' => 'constant_concatenated_secret', 'field' => $key, 'snippet' => '[REDACTED: literal secret candidate]'];
        }
        return $findings;
    }

    private function constantSecretString(\PhpParser\Node $node, int $depth = 0): ?string
    {
        if ($depth > 16) return null;
        if ($node instanceof \PhpParser\Node\Scalar\String_) return strlen($node->value) <= 4096 ? $node->value : null;
        if (!$node instanceof \PhpParser\Node\Expr\BinaryOp\Concat) return null;
        $left = $this->constantSecretString($node->left, $depth + 1); $right = $this->constantSecretString($node->right, $depth + 1);
        return $left !== null && $right !== null && strlen($left) + strlen($right) <= 4096 ? $left.$right : null;
    }

    private function envCredentialKeyEvidence(string $envFile): array
    {
        $path = $this->ctx->abs($envFile);
        if (!is_file($path)) {
            return ['file' => $envFile, 'present' => false, 'credential_keys' => 0];
        }

        $data = @include $path;
        if (!is_array($data)) {
            return ['file' => $envFile, 'present' => true, 'readable' => false, 'credential_keys' => 0];
        }

        return [
            'file' => $envFile,
            'present' => true,
            'readable' => true,
            'credential_keys' => $this->countCredentialKeys($data),
        ];
    }

    private function countCredentialKeys(array $data): int
    {
        $count = 0;
        foreach ($data as $key => $value) {
            if (preg_match('~(?:api[_-]?key|secret|token|client[_-]?secret|access[_-]?token|private[_-]?key)~i', (string)$key) === 1) {
                $count++;
            }
            if (is_array($value)) {
                $count += $this->countCredentialKeys($value);
            }
        }
        return $count;
    }

    private function looksLikeStoredSecretLiteral(string $value): bool
    {
        $trimmed = trim($value);
        if (preg_match('~^(?:0|1|true|false|null|none|changeme|change_me|your[_-]?key|your[_-]?secret|example|test|dummy|placeholder|xxxx|\*+)$~i', $trimmed) === 1) {
            return false;
        }
        if (preg_match('~^(?:\$|\{\{|%env|env\(|getenv\(|config\(|scopeConfig|getValue)~i', $trimmed) === 1) {
            return false;
        }
        return preg_match('~[A-Za-z0-9+/=_-]{8,}~', $trimmed) === 1;
    }

    private function piiMinimizationFindings(string $file, string $content): array
    {
        $findings = [];
        $searchable = $this->maskSourceComments($content, strtolower(pathinfo($file, PATHINFO_EXTENSION)));
        $fieldRegex = '(?:full[_-]?card|card[_-]?number|cc[_-]?(?:num|number)|credit[_-]?card|cvv|cvc|ssn|social[_-]?security|passport[_-]?number|driver[_-]?license|dob|date[_-]?of[_-]?birth|bank[_-]?account|routing[_-]?number|tax[_-]?id)';
        $regex = '~(?P<field>' . $fieldRegex . ')~i';
        $count = preg_match_all($regex, $searchable, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER);
        if ($count === false || $count < 1) {
            return [];
        }

        $seen = [];
        foreach ($matches as $match) {
            $field = (string)$match['field'][0];
            $offset = (int)$match['field'][1];
            $window = $this->codeWindow($searchable, $offset, 1800);
            if (!$this->hasThirdPartyOutboundFlowSignal($window)) {
                continue;
            }

            $evidence = $this->matchEvidence($file, $content, 'raw_sensitive_pii_third_party_flow', $offset);
            $key = $evidence['file'] . ':' . $evidence['line'] . ':' . strtolower($field);
            if (isset($seen[$key])) {
                continue;
            }

            $seen[$key] = true;
            $evidence['kind'] = 'raw_sensitive_pii_third_party_flow';
            $evidence['field'] = $field;
            $findings[] = $evidence;
        }

        return $findings;
    }

    private function hasThirdPartyOutboundFlowSignal(string $window): bool
    {
        return preg_match('~(?:\\b(?:curl_init|curl_setopt|curl_setopt_array|file_get_contents|fopen|fsockopen|stream_socket_client)\\s*\\(|->\\s*(?:request|get|post|put|patch|delete|send)\\s*\\(|https?://|\\b(?:base_uri|api[_-]?url|endpoint|webhook|callback|payment|gateway|stripe|paypal|braintree|adyen|klarna|authorizenet|authorize)\\b)~i', $window) === 1;
    }

    private function hasPiiMinimizationSignal(string $window): bool
    {
        return preg_match('~\b(?:tokeni[sz]e|token|payment[_-]?token|payment[_-]?method[_-]?nonce|nonce|vault|vaulted|customer[_-]?id|profile[_-]?id|redact|redacted|mask|masked|sanitize|filterSensitive|withoutSensitive|removeSensitive|minimi[sz]e|hash|last4)\b~i', $window) === 1;
    }

    private function saasIntegrationScopeFindings(string $file, string $content): array
    {
        $extension = strtolower(pathinfo($file, PATHINFO_EXTENSION));
        if (!$this->hasSaasIntegrationSignal($content, $file)) {
            return [];
        }

        return $extension === 'xml'
            ? $this->saasIntegrationXmlScopeFindings($file, $content)
            : $this->saasIntegrationPhpScopeFindings($file, $content);
    }

    private function saasIntegrationXmlScopeFindings(string $file, string $content): array
    {
        $findings = [];
        $relative = $this->relativeFile($file);

        if (str_ends_with($relative, '/etc/adminhtml/system.xml') || str_ends_with($relative, '/system.xml')) {
            if (preg_match_all('~<section\b(?P<attrs>[^>]*)>(?P<body>.*?)</section>~is', $content, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) > 0) {
                foreach ($matches as $match) {
                    $offset = (int)$match[0][1];
                    $block = (string)$match[0][0];
                    if (!$this->hasSaasIntegrationSignal($block, $file)) {
                        continue;
                    }

                    $resource = $this->firstXmlTagValue($block, 'resource');
                    $evidence = $this->matchEvidence($file, $content, 'saas_system_section_acl', $offset);
                    $evidence['kind'] = 'system_section';
                    $evidence['resource'] = $resource;
                    $evidence['controls'] = $this->saasAclControlEvidence($resource, $block);
                    $findings[] = $evidence;
                }
            }
        }

        if (str_ends_with($relative, '/etc/webapi.xml') || str_ends_with($relative, '/webapi.xml')) {
            if (preg_match_all('~<route\b(?P<attrs>[^>]*)>(?P<body>.*?)</route>~is', $content, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) > 0) {
                foreach ($matches as $match) {
                    $offset = (int)$match[0][1];
                    $block = (string)$match[0][0];
                    $attrs = (string)$match['attrs'][0];
                    if (!$this->hasSaasIntegrationSignal($block . "\n" . $attrs, $file)) {
                        continue;
                    }

                    $resources = $this->xmlResourceRefs($block);
                    $evidence = $this->matchEvidence($file, $content, 'saas_webapi_acl', $offset);
                    $evidence['kind'] = 'webapi_route';
                    $evidence['resources'] = $resources;
                    $evidence['controls'] = $this->saasWebapiControlEvidence($resources, $block . "\n" . $content);
                    $findings[] = $evidence;
                }
            }
        }

        return $findings;
    }

    private function saasIntegrationPhpScopeFindings(string $file, string $content): array
    {
        $findings = [];
        $relative = $this->relativeFile($file);
        $isAdminController = preg_match('~/Controller/Adminhtml/~i', $relative) === 1
            || str_contains($content, '\\Adminhtml\\');
        $isPublicCallback = preg_match('~/Controller/~i', $relative) === 1
            && preg_match('~(?:webhook|callback|ipn|notify|notification)~i', $relative . "\n" . $content) === 1;

        if (!$isAdminController && !$isPublicCallback) {
            return [];
        }

        $offset = $this->firstSaasOffset($content);
        $evidence = $this->matchEvidence($file, $content, 'saas_controller_scope', $offset);
        if ($isAdminController) {
            $resource = $this->phpAdminResource($content);
            $evidence['kind'] = 'admin_controller';
            $evidence['resource'] = $resource;
            $evidence['controls'] = $this->saasAclControlEvidence($resource, $content);
        } else {
            $evidence['kind'] = 'public_callback';
            $evidence['controls'] = $this->saasIpAllowlistControlEvidence($content);
        }

        $findings[] = $evidence;
        return $findings;
    }

    private function saasAclControlEvidence(?string $resource, string $haystack): array
    {
        $hasSpecificAcl = $resource !== null && !$this->isBroadSaasAclResource($resource);
        $hasIpAllowlist = false; // A variable/header keyword is not an enforcing IP gate.
        $missing = [];
        if (!$hasSpecificAcl && !$hasIpAllowlist) {
            $missing[] = 'least_privilege_acl_or_ip_allowlist';
        }

        return [
            'ok' => $missing === [],
            'resource' => $resource,
            'has_specific_acl' => $hasSpecificAcl,
            'has_ip_allowlist' => $hasIpAllowlist,
            'missing' => $missing,
        ];
    }

    private function saasWebapiControlEvidence(array $resources, string $haystack): array
    {
        $hasSpecificAcl = false;
        foreach ($resources as $resource) {
            if (!$this->isBroadSaasAclResource($resource)) {
                $hasSpecificAcl = true;
                break;
            }
        }

        $hasIpAllowlist = false; // A variable/header keyword is not an enforcing IP gate.
        $missing = [];
        if (!$hasSpecificAcl && !$hasIpAllowlist) {
            $missing[] = 'least_privilege_acl_or_ip_allowlist';
        }

        return [
            'ok' => $missing === [],
            'resources' => $resources,
            'has_specific_acl' => $hasSpecificAcl,
            'has_ip_allowlist' => $hasIpAllowlist,
            'missing' => $missing,
        ];
    }

    private function saasIpAllowlistControlEvidence(string $haystack): array
    {
        $hasIpAllowlist = false; // A variable/header keyword is not an enforcing IP gate.
        return [
            'ok' => $hasIpAllowlist,
            'has_ip_allowlist' => $hasIpAllowlist,
            'missing' => $hasIpAllowlist ? [] : ['ip_allowlist'],
        ];
    }

    private function hasSaasIntegrationSignal(string $text, string $file): bool
    {
        return preg_match('~\b(?:saas|connector|integration|webhook|callback|ipn|payment[_-]?gateway|gateway|stripe|paypal|braintree|adyen|klarna|authorizenet|authorize(?:\.net)?|shipstation|taxjar|avalara|mailchimp|klaviyo|salesforce|hubspot|erp|crm|analytics)\b~i', $text . "\n" . $this->relativeFile($file)) === 1;
    }

    private function hasSaasIpAllowlistSignal(string $text): bool
    {
        return preg_match('~\b(?:ip[_-]?allow(?:list)?|allow(?:ed)?[_-]?ips?|cidr|trusted[_-]?proxy|remote[_-]?addr|HTTP_X_FORWARDED_FOR|X-Forwarded-For|IpUtils|ipRange|isAllowedIp|validateIp|Require\s+ip|allow\s+from)\b~i', $text) === 1;
    }

    private function isBroadSaasAclResource(string $resource): bool
    {
        $resource = trim($resource);
        if ($resource === '') {
            return true;
        }

        return preg_match('~^(?:anonymous|self|Magento_Backend::admin|Magento_Adminhtml::admin|Magento_Webapi::all|Magento_Customer::customer)$~i', $resource) === 1
            || preg_match('~::all$~i', $resource) === 1;
    }

    private function firstXmlTagValue(string $xml, string $tag): ?string
    {
        if (preg_match('~<' . preg_quote($tag, '~') . '\b[^>]*>(?P<value>.*?)</' . preg_quote($tag, '~') . '>~is', $xml, $match) === 1) {
            return trim(strip_tags((string)$match['value']));
        }

        return null;
    }

    private function phpAdminResource(string $content): ?string
    {
        if (preg_match('~\bconst\s+ADMIN_RESOURCE\s*=\s*([\'\"])(?P<resource>[^\'\"]+)\1~i', $content, $match) === 1) {
            return trim((string)$match['resource']);
        }

        return null;
    }

    private function firstSaasOffset(string $content): int
    {
        if (preg_match('~\b(?:saas|connector|integration|webhook|callback|ipn|gateway|stripe|paypal|braintree|adyen|klarna|authorizenet|authorize(?:\.net)?|shipstation|taxjar|avalara|mailchimp|klaviyo|salesforce|hubspot|erp|crm|analytics)\b~i', $content, $match, PREG_OFFSET_CAPTURE) === 1) {
            return (int)$match[0][1];
        }

        return 0;
    }

    private function thirdPartyLoggingFindings(string $file, string $content): array
    {
        return $this->loggingArgumentFindings($file, $content, true);
    }

    private function sensitiveLoggingFindings(string $file, string $content): array
    {
        return $this->loggingArgumentFindings($file, $content, false);
    }

    private function loggingArgumentFindings(string $file, string $content, bool $thirdParty): array
    {
        try { $nodes = (new \PhpParser\ParserFactory())->createForNewestSupportedVersion()->parse($content) ?? []; }
        catch (\PhpParser\Error) { return []; }
        $finder = new \PhpParser\NodeFinder(); $findings = [];
        foreach ($finder->findInstanceOf($nodes, \PhpParser\Node\Expr\MethodCall::class) as $call) {
            if (!$call->name instanceof \PhpParser\Node\Identifier || !in_array(strtolower($call->name->name), ['log','debug','info','notice','warning','error','critical','alert','emergency'], true)) continue;
            $receiver = $call->var;
            $logger = $receiver instanceof \PhpParser\Node\Expr\Variable && is_string($receiver->name) ? $receiver->name : ($receiver instanceof \PhpParser\Node\Expr\PropertyFetch && $receiver->name instanceof \PhpParser\Node\Identifier ? $receiver->name->name : '');
            if (!str_contains(strtolower($logger), 'logger')) continue;
            foreach ($call->args as $arg) {
                if (!$arg instanceof \PhpParser\Node\Arg) continue;
                $dynamic = $finder->findFirst($arg->value, static fn(\PhpParser\Node $n): bool => $n instanceof \PhpParser\Node\Expr\Variable || $n instanceof \PhpParser\Node\Expr\PropertyFetch || $n instanceof \PhpParser\Node\Expr\ArrayDimFetch);
                if ($dynamic === null) continue;
                $text = substr($content, $arg->value->getStartFilePos(), $arg->value->getEndFilePos() - $arg->value->getStartFilePos() + 1);
                $sensitive = $thirdParty ? $this->hasThirdPartyLogSensitiveSignal($text) : $this->hasSensitiveLoggingSignal($text);
                if (!$sensitive && !preg_match('/\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b/', $text)) continue;
                if ($thirdParty && !$this->hasThirdPartyLoggingSignal($content, $file)) continue;
                $findings[] = ['file'=>$this->relativeFile($file),'line'=>$call->getStartLine(),'kind'=>$call->name->name,'risk'=>$this->sensitiveLoggingRisk($text),'snippet'=>'[REDACTED: sensitive argument candidate]'];
                break;
            }
        }
        return $findings;
    }

    private function magentoApiCryptoSessionFindings(string $file, string $content): array
    {
        $findings = [];
        $searchable = $this->maskPhpStringsAndComments($content);
        $patterns = [
            'raw_session_start' => '~\bsession_start\s*\(~i',
            'raw_session_superglobal' => '~\$_SESSION\s*\[~',
            'raw_session_control' => '~\b(?:session_id|session_name|session_regenerate_id|session_destroy|setcookie|setrawcookie)\s*\(~i',
            'raw_openssl_crypto' => '~\bopenssl_(?:encrypt|decrypt|cipher_iv_length|random_pseudo_bytes)\s*\(~i',
            'legacy_mcrypt' => '~\bmcrypt_[A-Za-z0-9_]*\s*\(~i',
            'weak_hash_secret' => '~\b(?:md5|sha1)\s*\((?P<args>.{0,240})~is',
            'direct_sodium_crypto' => '~\bsodium_crypto_[A-Za-z0-9_]*\s*\(~i',
        ];

        foreach ($patterns as $kind => $regex) {
            if (preg_match_all($regex, $searchable, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) < 1) {
                continue;
            }

            foreach ($matches as $match) {
                $offset = (int)$match[0][1];
                $args = isset($match['args']) && is_array($match['args']) ? (string)$match['args'][0] : '';
                $risk = $this->magentoApiCryptoSessionRisk($kind, $content, $offset, $args);
                if ($risk === null) {
                    continue;
                }

                $evidence = $this->matchEvidence($file, $content, $kind, $offset);
                $evidence['kind'] = $kind;
                $evidence['risk'] = $risk;
                $findings[] = $evidence;
            }
        }

        return $findings;
    }

    private function hasThirdPartyLoggingSignal(string $text, string $file): bool
    {
        return preg_match('~(?:third[_-]?party|integration|gateway|payment|provider|api|webhook|callback|client|connector|stripe|paypal|braintree|adyen|klarna|authorizenet|authorize|shipping|carrier|tax|fraud|analytics|crm|erp|saas)~i', $text . "\n" . $this->relativeFile($file)) === 1;
    }

    private function hasThirdPartyLogSensitiveSignal(string $text): bool
    {
        return $this->hasSensitiveLoggingSignal($text)
            || preg_match('~\b(?:email|customer[_-]?id|customer[_-]?email|telephone|phone|billing|shipping|address|order[_-]?id|quote[_-]?id|transaction[_-]?id|external[_-]?id|identifier)\b~i', $text) === 1;
    }

    private function hasSensitiveLoggingSignal(string $text): bool
    {
        return preg_match('~[A-Za-z0-9_.-]*(?:email|telephone|phone|address|dob|password|passwd|pwd|token|access[_-]?token|refresh[_-]?token|authorization|auth(?:orization)?[_-]?header|bearer|cookie|set[_-]?cookie|session(?:[_-]?id)?|secret|api[_-]?key|private[_-]?key|cvv|cvc|card[_-]?number|card|pan|payment|expiry|exp[_-]?month|exp[_-]?year)[A-Za-z0-9_.-]*~i', $text) === 1
            || preg_match('~\b(?:Authorization|Cookie|Set-Cookie|X-Api-Key)\b~i', $text) === 1;
    }

    private function hasRedactionSignal(string $text): bool
    {
        return preg_match('~\b(?:redact|redacted|mask|masked|sanitize|sanitized|filterSensitive|removeSensitive|withoutSensitive|scrub|obfuscate)\b~i', $text) === 1
            || preg_match('~(?:\[REDACTED\]|\*{3,}|x{3,}|X{3,})~', $text) === 1;
    }

    private function sensitiveLoggingRisk(string $text): string
    {
        if (preg_match('~\b(?:cvv|cvc|card[_-]?number|pan|Authorization|access[_-]?token|refresh[_-]?token|password|private[_-]?key)\b~i', $text) === 1) {
            return 'high';
        }

        return 'medium';
    }

    private function magentoApiCryptoSessionRisk(string $kind, string $content, int $offset, string $args): ?string
    {
        $window = $this->codeWindow($content, $offset, 1000) . "\n" . $args;

        if ($this->hasMagentoFrameworkCryptoSessionSignal($window)) {
            return null;
        }

        if ($kind === 'weak_hash_secret' && !$this->hasSecurityRandomnessSignal($window)) {
            return null;
        }

        return match ($kind) {
            'legacy_mcrypt', 'raw_openssl_crypto', 'weak_hash_secret' => 'high',
            'direct_sodium_crypto' => 'medium',
            default => 'medium',
        };
    }

    private function hasMagentoFrameworkCryptoSessionSignal(string $window): bool
    {
        return preg_match('~\b(?:Magento\\\\Framework\\\\Encryption\\\\EncryptorInterface|EncryptorInterface|\\\\Magento\\\\Framework\\\\Session|SessionManagerInterface|SessionManager|CustomerSession|CheckoutSession|BackendSession|FormKey|CookieManagerInterface|CookieMetadataFactory|SessionConfig)\b~i', $window) === 1;
    }
}
