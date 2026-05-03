<?php declare(strict_types=1);

namespace Magebean\Engine\Checks;

use Magebean\Engine\Context;

final class CodeSearchCheck
{
    private Context $ctx;

    public function __construct(Context $ctx) { $this->ctx = $ctx; }

    /**
     * args:
     * - paths[]: thư mục tương đối để quét (vd: ["app","vendor","lib","app/design"])
     * - include_ext[]: đuôi file cần quét (mặc định: php, phtml, js, html, xml)
     * - must_match[]: danh sách regex (ít nhất MỖI regex phải xuất hiện 1 lần)
     * - must_not_match[]: danh sách regex (KHÔNG được xuất hiện ở bất kỳ file nào)
     * - max_results: số phát hiện tối đa báo cáo (default 50)
     */
    public function grep(array $args): array
    {
        $roots = $args['paths'] ?? ['app', 'vendor', 'lib', 'app/design'];
        $inc   = $args['include_ext'] ?? ['php','phtml','js','html','xml'];
        $must  = $args['must_match'] ?? [];
        $mustNot = $args['must_not_match'] ?? [];
        $max   = max(1, (int)($args['max_results'] ?? 50));

        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);
        $files = $this->collectFiles($rootsAbs, $inc);

        $matches = [];      // offenders for must_not_match
        $foundMap = [];     // pattern => bool (for must_match)
        foreach ($must as $pat) $foundMap[$pat] = false;

        foreach ($files as $file) {
            $content = @file_get_contents($file);
            if ($content === false) continue;

            // must_not_match: fail ngay nếu có
            foreach ($mustNot as $pat) {
                if (@preg_match('/'.$pat.'/m', '') === false) {
                    return [false, "Invalid regex in must_not_match: /$pat/"];
                }
                if (preg_match('/'.$pat.'/m', $content, $match, PREG_OFFSET_CAPTURE)) {
                    $matches[] = $this->matchEvidence($file, $content, (string)$pat, (int)$match[0][1]);
                    if (count($matches) >= $max) break 2;
                }
            }

            // must_match: đánh dấu nếu thấy
            foreach ($must as $pat) {
                if ($foundMap[$pat] === true) continue;
                if (@preg_match('/'.$pat.'/m', '') === false) {
                    return [false, "Invalid regex in must_match: /$pat/"];
                }
                if (preg_match('/'.$pat.'/m', $content)) {
                    $foundMap[$pat] = true;
                }
            }
        }

        if (!empty($matches)) {
            return [
                false,
                'Forbidden pattern found in: ' . implode(', ', array_map(
                    static fn(array $match): string => $match['file'] . ':' . $match['line'] . ' /' . $match['pattern'] . '/',
                    $matches
                )),
                $matches,
            ];
        }

        // verify all must_match satisfied
        foreach ($foundMap as $pat => $ok) {
            if (!$ok) {
                return [false, "Required pattern not found: /$pat/"];
            }
        }

        return [true, 'code_grep OK (patterns satisfied)'];
    }

    public function rawSql(array $args): array
    {
        $roots = $args['paths'] ?? ['app'];
        $inc = $args['include_ext'] ?? ['php', 'phtml'];
        $max = max(1, (int)($args['max_results'] ?? 50));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);
        $files = $this->collectFiles($rootsAbs, $inc);

        $offenders = [];
        foreach ($files as $file) {
            $content = @file_get_contents($file);
            if ($content === false) {
                continue;
            }

            foreach ($this->rawSqlFindings($file, $content) as $finding) {
                $offenders[] = $finding;
                if (count($offenders) >= $max) {
                    break 2;
                }
            }
        }

        if ($offenders !== []) {
            return [
                false,
                'Potential unsafe raw SQL found in: ' . implode(', ', array_map(
                    static fn(array $match): string => $match['file'] . ':' . $match['line'] . ' [' . $match['kind'] . ']',
                    $offenders
                )),
                $offenders,
            ];
        }

        return [true, 'No unsafe raw SQL patterns detected'];
    }

    public function phtmlEscapedOutput(array $args): array
    {
        $roots = $args['paths'] ?? ['app'];
        $max = max(1, (int)($args['max_results'] ?? 50));
        $escapeFunctions = $args['escape_functions'] ?? [
            'escapeHtml',
            'escapeHtmlAttr',
            'escapeUrl',
            'escapeJs',
            'escapeCss',
        ];
        if (!is_array($escapeFunctions)) {
            $escapeFunctions = [];
        }
        $escapeFunctions = array_values(array_filter(array_map(
            static fn(mixed $fn): string => trim((string)$fn),
            $escapeFunctions
        )));

        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);
        $files = $this->collectFiles($rootsAbs, ['phtml']);

        $offenders = [];
        foreach ($files as $file) {
            $content = @file_get_contents($file);
            if ($content === false) {
                continue;
            }

            foreach ($this->phtmlOutputFindings($file, $content, $escapeFunctions) as $finding) {
                $offenders[] = $finding;
                if (count($offenders) >= $max) {
                    break 2;
                }
            }
        }

        if ($offenders !== []) {
            return [
                false,
                'Unescaped template output found in: ' . implode(', ', array_map(
                    static fn(array $match): string => $match['file'] . ':' . $match['line'],
                    $offenders
                )),
                $offenders,
            ];
        }

        return [true, 'PHTML output uses approved escaping helpers'];
    }

    public function csrfFormKey(array $args): array
    {
        $roots = $args['paths'] ?? ['app'];
        $max = max(1, (int)($args['max_results'] ?? 50));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $offenders = [];
        foreach ($this->collectFiles($rootsAbs, ['phtml', 'html']) as $file) {
            $content = @file_get_contents($file);
            if ($content === false) {
                continue;
            }

            foreach ($this->csrfFormFindings($file, $content) as $finding) {
                $offenders[] = $finding;
                if (count($offenders) >= $max) {
                    break 2;
                }
            }
        }

        foreach ($this->collectFiles($rootsAbs, ['php']) as $file) {
            $content = @file_get_contents($file);
            if ($content === false) {
                continue;
            }

            $finding = $this->csrfPostHandlerFinding($file, $content);
            if ($finding !== null) {
                $offenders[] = $finding;
                if (count($offenders) >= $max) {
                    break;
                }
            }
        }

        if ($offenders !== []) {
            return [
                false,
                'Potential CSRF/form_key gaps found in: ' . implode(', ', array_map(
                    static fn(array $match): string => $match['file'] . ':' . $match['line'] . ' [' . $match['kind'] . ']',
                    $offenders
                )),
                $offenders,
            ];
        }

        return [true, 'POST forms and handlers include form_key protection signals'];
    }

    private function collectFiles(array $roots, array $inc): array
    {
        $ret = [];
        $incLower = array_map('strtolower', $inc);
        foreach ($roots as $root) {
            if (!is_dir($root)) continue;
            $rii = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator(
                $root, \FilesystemIterator::SKIP_DOTS
            ));
            foreach ($rii as $f) {
                if (!$f->isFile()) continue;
                $ext = strtolower(pathinfo($f->getFilename(), PATHINFO_EXTENSION));
                if ($ext === '' || !in_array($ext, $incLower, true)) continue;
                // mặc định bỏ qua file > 1MB để tránh tốn bộ nhớ
                if ($f->getSize() > 1024*1024) continue;
                $ret[] = $f->getPathname();
            }
        }
        return $ret;
    }

    private function rawSqlFindings(string $file, string $content): array
    {
        $findings = [];

        $patterns = [
            'direct_db_api' => '~\b(?:mysqli_query|mysql_query)\s*\(|new\s+\\\\?PDO\s*\(~i',
            'raw_query_method' => '~->\s*rawQuery\s*\(~i',
            'adapter_sql_method' => '~->\s*(?:query|fetchAll|fetchRow|fetchOne|fetchCol|fetchPairs)\s*\((?P<arg>.{0,500})~is',
            'write_method_string_condition' => '~->\s*(?:delete|update)\s*\((?P<arg>.{0,500})~is',
        ];

        foreach ($patterns as $kind => $regex) {
            if (preg_match_all($regex, $content, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) !== 1) {
                continue;
            }
            foreach ($matches as $match) {
                $offset = (int)$match[0][1];
                $arg = isset($match['arg']) && is_array($match['arg']) ? (string)$match['arg'][0] : '';
                if ($kind === 'adapter_sql_method' && !$this->looksLikeUnsafeSqlArgument($arg)) {
                    continue;
                }
                if ($kind === 'write_method_string_condition' && !$this->looksLikeUnsafeConditionArgument($arg)) {
                    continue;
                }

                $evidence = $this->matchEvidence($file, $content, $kind, $offset);
                $evidence['kind'] = $kind;
                $findings[] = $evidence;
            }
        }

        return $findings;
    }

    private function phtmlOutputFindings(string $file, string $content, array $escapeFunctions): array
    {
        $findings = [];
        $patterns = [
            'short_echo' => '~<\?=\s*(?P<expr>.*?)\?>~is',
            'echo_statement' => '~<\?php\s+(?:echo|print)\s+(?P<expr>.*?);?\s*\?>~is',
        ];

        foreach ($patterns as $kind => $regex) {
            if (preg_match_all($regex, $content, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) !== 1) {
                continue;
            }

            foreach ($matches as $match) {
                $expr = isset($match['expr']) && is_array($match['expr']) ? (string)$match['expr'][0] : '';
                if ($this->isEscapedTemplateExpression($expr, $escapeFunctions)) {
                    continue;
                }

                $evidence = $this->matchEvidence($file, $content, $kind, (int)$match[0][1]);
                $evidence['kind'] = $kind;
                $findings[] = $evidence;
            }
        }

        return $findings;
    }

    private function csrfFormFindings(string $file, string $content): array
    {
        $findings = [];
        if (preg_match_all('~<form\b(?P<attrs>[^>]*)>(?P<body>.*?)</form>~is', $content, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) !== 1) {
            return [];
        }

        foreach ($matches as $match) {
            $attrs = (string)$match['attrs'][0];
            $body = (string)$match['body'][0];
            if (!preg_match('~\bmethod\s*=\s*([\'"]?)post\1~i', $attrs)) {
                continue;
            }
            $formBlock = (string)$match[0][0];
            if ($this->formBlockHasFormKey($formBlock)) {
                continue;
            }

            $evidence = $this->matchEvidence($file, $content, 'post_form_without_form_key', (int)$match[0][1]);
            $evidence['kind'] = 'post_form_without_form_key';
            $evidence['snippet'] = trim(substr(preg_replace('~\s+~', ' ', $formBlock) ?? $formBlock, 0, 240));
            $findings[] = $evidence;
        }

        return $findings;
    }

    private function formBlockHasFormKey(string $formBlock): bool
    {
        $withoutComments = preg_replace('~<!--.*?-->|/\*.*?\*/~s', '', $formBlock) ?? $formBlock;

        return preg_match('~<input\b[^>]*\bname\s*=\s*([\'"])form_key\1[^>]*>~i', $withoutComments) === 1
            || preg_match('~getBlockHtml\s*\(\s*([\'"])formkey\1\s*\)~i', $withoutComments) === 1
            || preg_match('~getFormKey\s*\(~i', $withoutComments) === 1
            || preg_match('~FormKey::FORM_KEY~', $withoutComments) === 1;
    }

    private function csrfPostHandlerFinding(string $file, string $content): ?array
    {
        if (!$this->looksLikePostHandler($content)) {
            return null;
        }
        if ($this->hasCsrfValidationSignal($content)) {
            return null;
        }

        $offset = 0;
        if (preg_match('~\b(?:getPost|getPostValue|isPost|POST)\b~i', $content, $match, PREG_OFFSET_CAPTURE)) {
            $offset = (int)$match[0][1];
        }
        $evidence = $this->matchEvidence($file, $content, 'post_handler_without_form_key_validation', $offset);
        $evidence['kind'] = 'post_handler_without_form_key_validation';

        return $evidence;
    }

    private function looksLikePostHandler(string $content): bool
    {
        return preg_match('~\b(?:getPost|getPostValue|isPost)\s*\(|\$_POST\b|RequestInterface~i', $content) === 1
            && preg_match('~\bexecute\s*\(~', $content) === 1;
    }

    private function hasCsrfValidationSignal(string $content): bool
    {
        return preg_match('~\b(?:FormKey\\Validator|formKeyValidator|validateForCsrf|CsrfAwareActionInterface|FORM_KEY|getFormKey|form_key)\b~i', $content) === 1;
    }

    private function isEscapedTemplateExpression(string $expr, array $escapeFunctions): bool
    {
        if (stripos($expr, '@noEscape') !== false || stripos($expr, 'noEscape') !== false) {
            return true;
        }

        $trimmed = trim($expr);
        if ($trimmed === '') {
            return true;
        }

        if (preg_match('~^(?:true|false|null|\d+(?:\.\d+)?|[\'"][^\'"]*[\'"])$~i', $trimmed) === 1) {
            return true;
        }

        foreach ($escapeFunctions as $fn) {
            if ($fn !== '' && preg_match('~(?:->|::)?' . preg_quote($fn, '~') . '\s*\(~i', $expr) === 1) {
                return true;
            }
        }

        return false;
    }

    private function looksLikeUnsafeSqlArgument(string $arg): bool
    {
        if (!preg_match('~\b(?:select|insert|update|delete|replace|drop|alter|truncate)\b~i', $arg)) {
            return false;
        }

        return str_contains($arg, '.')
            || str_contains($arg, '$')
            || str_contains($arg, '{$')
            || preg_match('~["\'][^"\']*\b(?:select|insert|update|delete|replace|drop|alter|truncate)\b[^"\']*["\']~i', $arg) === 1;
    }

    private function looksLikeUnsafeConditionArgument(string $arg): bool
    {
        if (!preg_match('~["\'][^"\']*(?:=|<|>|like|in\s*\()[^"\']*["\']~i', $arg)) {
            return false;
        }

        return str_contains($arg, '.') || str_contains($arg, '$') || str_contains($arg, '{$');
    }

    private function matchEvidence(string $file, string $content, string $pattern, int $offset): array
    {
        $line = substr_count(substr($content, 0, $offset), "\n") + 1;
        $lineStart = strrpos(substr($content, 0, $offset), "\n");
        $lineStart = $lineStart === false ? 0 : $lineStart + 1;
        $lineEnd = strpos($content, "\n", $offset);
        $lineEnd = $lineEnd === false ? strlen($content) : $lineEnd;

        return [
            'file' => $file,
            'line' => $line,
            'pattern' => $pattern,
            'snippet' => trim(substr($content, $lineStart, $lineEnd - $lineStart)),
        ];
    }
}
