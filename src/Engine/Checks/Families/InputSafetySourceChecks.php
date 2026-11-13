<?php
declare(strict_types=1);
namespace Magebean\Engine\Checks\Families;
use Magebean\Engine\Context;
use Magebean\Engine\Collectors\CollectorSet;

final class InputSafetySourceChecks extends CodeSearchSupport
{
    public function rawSql(array $args): array
    {
        $roots = $args['paths'] ?? ['app'];
        $inc = $args['include_ext'] ?? ['php', 'phtml'];
        $max = max(1, (int)($args['max_results'] ?? 50));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);
        $capture = $this->captureSafetySource($args + ['paths' => $roots, 'include_ext' => $inc], 'sql');

        $offenders = [];
        foreach ($capture['files'] as $source) {
            $file = $this->ctx->abs($source['file']);
            $content = $source['content'];

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

        if ($capture['gaps'] !== [] || $capture['unresolved'] !== []) return [null, '[UNKNOWN] Source collection or flow resolution is incomplete; no safety conclusion is established', ['collection_gaps' => $capture['gaps'], 'unresolved' => $capture['unresolved']]];
        return [true, 'No enumerated dynamic SQL construction pattern observed in complete bounded source'];
    }

    public function ssrfSafeguards(array $args): array
    {
        $roots = $args['paths'] ?? ['app'];
        $inc = $args['include_ext'] ?? ['php'];
        $max = max(1, (int)($args['max_results'] ?? 50));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);
        $capture = $this->captureSafetySource($args + ['paths' => $roots, 'include_ext' => $inc], 'ssrf');

        $offenders = [];
        foreach ($capture['files'] as $source) {
            $file = $this->ctx->abs($source['file']);
            $content = $source['content'];

            foreach ($this->ssrfFindings($file, $content) as $finding) {
                $offenders[] = $finding;
                if (count($offenders) >= $max) {
                    break 2;
                }
            }
        }

        if ($offenders !== []) {
            return [
                false,
                'Outbound HTTP sinks missing SSRF safeguards in: ' . implode(', ', array_map(
                    static fn(array $match): string => $match['file'] . ':' . $match['line'] . ' [' . $match['kind'] . ']',
                    $offenders
                )),
                $offenders,
            ];
        }

        if ($capture['gaps'] !== [] || $capture['unresolved'] !== []) return [null, '[UNKNOWN] Source collection or flow resolution is incomplete; no safety conclusion is established', ['collection_gaps' => $capture['gaps'], 'unresolved' => $capture['unresolved']]];
        return [true, 'No enumerated unguarded HTTP sink pattern observed; runtime SSRF safety is not established'];
    }

    public function outboundEgressControls(array $args): array
    {
        $roots = $args['paths'] ?? ['app/code', 'app/etc'];
        $inc = $args['include_ext'] ?? ['php'];
        $max = max(1, (int)($args['max_results'] ?? 100));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);
        $capture = $this->captureSafetySource($args + ['paths' => $roots, 'include_ext' => $inc], 'egress');

        $sinks = [];
        $failures = [];
        $filesRead = 0;
        foreach ($capture['files'] as $source) {
            $file = $this->ctx->abs($source['file']);
            $content = $source['content'];

            $filesRead++;
            foreach ($this->outboundEgressFindings($file, $content) as $finding) {
                $sinks[] = $finding;
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
            'sinks' => $sinks,
            'failures' => $failures,
            'truncated' => count($failures) >= $max,
        ];

        if ($filesRead === 0) {
            return [null, '[UNKNOWN] Outbound egress scan could not read any target files', $evidence];
        }

        if ($failures !== []) {
            $lines = ['Outbound HTTP sinks missing allowlist/timeout controls:'];
            foreach ($failures as $failure) {
                $lines[] = sprintf(
                    '    - %s:%d [%s] missing %s',
                    $failure['file'],
                    $failure['line'],
                    $failure['kind'],
                    implode('+', $failure['controls']['missing'] ?? ['egress_controls'])
                );
            }
            if ($evidence['truncated']) {
                $lines[] = sprintf('    - output truncated at %d findings', $max);
            }

            return [false, implode("\n", $lines), $evidence];
        }

        if ($sinks === [] && $capture['gaps'] === [] && $capture['unresolved'] === []) return [true, 'No enumerated app-level outbound sinks observed in complete bounded source', $evidence];

        if ($capture['gaps'] !== [] || $capture['unresolved'] !== []) return [null, '[UNKNOWN] Source collection or flow resolution is incomplete; no safety conclusion is established', ['collection_gaps' => $capture['gaps'], 'unresolved' => $capture['unresolved']]];
        return [true, 'No enumerated unguarded outbound sink pattern observed; effective network restrictions are not established', $evidence];
    }

    public function unserializeSafety(array $args): array
    {
        $roots = $args['paths'] ?? ['app'];
        $inc = $args['include_ext'] ?? ['php'];
        $max = max(1, (int)($args['max_results'] ?? 50));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);
        $capture = $this->captureSafetySource($args + ['paths' => $roots, 'include_ext' => $inc], 'unserialize');

        $offenders = [];
        foreach ($capture['files'] as $source) {
            $file = $this->ctx->abs($source['file']);
            $content = $source['content'];

            foreach ($this->unserializeFindings($file, $content) as $finding) {
                $offenders[] = $finding;
                if (count($offenders) >= $max) {
                    break 2;
                }
            }
        }

        if ($offenders !== []) {
            return [
                false,
                'Unsafe unserialize usage found in: ' . implode(', ', array_map(
                    static fn(array $match): string => $match['file'] . ':' . $match['line'] . ' [' . $match['risk'] . ']',
                    $offenders
                )),
                $offenders,
            ];
        }

        if ($capture['gaps'] !== [] || $capture['unresolved'] !== []) return [null, '[UNKNOWN] Source collection or flow resolution is incomplete; no safety conclusion is established', ['collection_gaps' => $capture['gaps'], 'unresolved' => $capture['unresolved']]];
        return [true, 'No enumerated unsafe native unserialize pattern observed in complete bounded source'];
    }

    public function commandExecutionSafety(array $args): array
    {
        $roots = $args['paths'] ?? ['app'];
        $inc = $args['include_ext'] ?? ['php'];
        $max = max(1, (int)($args['max_results'] ?? 50));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);
        $capture = $this->captureSafetySource($args + ['paths' => $roots, 'include_ext' => $inc], 'command');

        $offenders = [];
        foreach ($capture['files'] as $source) {
            $file = $this->ctx->abs($source['file']);
            $content = $source['content'];

            foreach ($this->commandExecutionFindings($file, $content) as $finding) {
                $offenders[] = $finding;
                if (count($offenders) >= $max) {
                    break 2;
                }
            }
        }

        if ($offenders !== []) {
            return [
                false,
                'Unsafe command execution found in: ' . implode(', ', array_map(
                    static fn(array $match): string => $match['file'] . ':' . $match['line'] . ' [' . $match['kind'] . '/' . $match['risk'] . ']',
                    $offenders
                )),
                $offenders,
            ];
        }

        if ($capture['gaps'] !== [] || $capture['unresolved'] !== []) return [null, '[UNKNOWN] Source collection or flow resolution is incomplete; no safety conclusion is established', ['collection_gaps' => $capture['gaps'], 'unresolved' => $capture['unresolved']]];
        return [true, 'No enumerated unsafe command pattern observed in complete bounded source'];
    }

    public function dynamicExecutionSafety(array $args): array
    {
        $roots = $args['paths'] ?? ['app'];
        $inc = $args['include_ext'] ?? ['php'];
        $max = max(1, (int)($args['max_results'] ?? 50));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);
        $capture = $this->captureSafetySource($args + ['paths' => $roots, 'include_ext' => $inc], 'dynamic');

        $offenders = [];
        foreach ($capture['files'] as $source) {
            $file = $this->ctx->abs($source['file']);
            $content = $source['content'];

            foreach ($this->dynamicExecutionFindings($file, $content) as $finding) {
                $offenders[] = $finding;
                if (count($offenders) >= $max) {
                    break 2;
                }
            }
        }

        if ($offenders !== []) {
            return [
                false,
                'Unsafe dynamic execution found in: ' . implode(', ', array_map(
                    static fn(array $match): string => $match['file'] . ':' . $match['line'] . ' [' . $match['kind'] . '/' . $match['risk'] . ']',
                    $offenders
                )),
                $offenders,
            ];
        }

        if ($capture['gaps'] !== [] || $capture['unresolved'] !== []) return [null, '[UNKNOWN] Source collection or flow resolution is incomplete; no safety conclusion is established', ['collection_gaps' => $capture['gaps'], 'unresolved' => $capture['unresolved']]];
        return [true, 'No enumerated dynamic execution pattern observed in complete bounded source'];
    }

    public function pathTraversalSafety(array $args): array
    {
        $roots = $args['paths'] ?? ['app'];
        $inc = $args['include_ext'] ?? ['php'];
        $max = max(1, (int)($args['max_results'] ?? 50));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);
        $capture = $this->captureSafetySource($args + ['paths' => $roots, 'include_ext' => $inc], 'path');

        $offenders = [];
        foreach ($capture['files'] as $source) {
            $file = $this->ctx->abs($source['file']);
            $content = $source['content'];

            foreach ($this->pathTraversalFindings($file, $content) as $finding) {
                $offenders[] = $finding;
                if (count($offenders) >= $max) {
                    break 2;
                }
            }
        }

        if ($offenders !== []) {
            return [
                false,
                'Potential path traversal sinks found in: ' . implode(', ', array_map(
                    static fn(array $match): string => $match['file'] . ':' . $match['line'] . ' [' . $match['kind'] . '/' . $match['risk'] . ']',
                    $offenders
                )),
                $offenders,
            ];
        }

        if ($capture['gaps'] !== [] || $capture['unresolved'] !== []) return [null, '[UNKNOWN] Source collection or flow resolution is incomplete; no safety conclusion is established', ['collection_gaps' => $capture['gaps'], 'unresolved' => $capture['unresolved']]];
        return [true, 'No enumerated unguarded path sink pattern observed; filesystem containment is not established'];
    }

    public function uploadSafety(array $args): array
    {
        $roots = $args['paths'] ?? ['app'];
        $inc = $args['include_ext'] ?? ['php'];
        $max = max(1, (int)($args['max_results'] ?? 50));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);
        $capture = $this->captureSafetySource($args + ['paths' => $roots, 'include_ext' => $inc], 'upload');

        $offenders = [];
        foreach ($capture['files'] as $source) {
            $file = $this->ctx->abs($source['file']);
            $content = $source['content'];

            foreach ($this->uploadFindings($file, $content) as $finding) {
                $offenders[] = $finding;
                if (count($offenders) >= $max) {
                    break 2;
                }
            }
        }

        if ($offenders !== []) {
            return [
                false,
                'Potential unsafe upload flows found in: ' . implode(', ', array_map(
                    static fn(array $match): string => $match['file'] . ':' . $match['line'] . ' [' . $match['kind'] . '/' . $match['risk'] . ']',
                    $offenders
                )),
                $offenders,
            ];
        }

        if ($capture['gaps'] !== [] || $capture['unresolved'] !== []) return [null, '[UNKNOWN] Source collection or flow resolution is incomplete; no safety conclusion is established', ['collection_gaps' => $capture['gaps'], 'unresolved' => $capture['unresolved']]];
        return [true, 'No enumerated unsafe upload pattern observed; complete upload handling is not established'];
    }

    public function csprngSafety(array $args): array
    {
        $roots = $args['paths'] ?? ['app'];
        $inc = $args['include_ext'] ?? ['php'];
        $max = max(1, (int)($args['max_results'] ?? 50));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);
        $capture = $this->captureSafetySource($args + ['paths' => $roots, 'include_ext' => $inc], 'random');

        $offenders = [];
        foreach ($capture['files'] as $source) {
            $file = $this->ctx->abs($source['file']);
            $content = $source['content'];

            foreach ($this->csprngFindings($file, $content) as $finding) {
                $offenders[] = $finding;
                if (count($offenders) >= $max) {
                    break 2;
                }
            }
        }

        if ($offenders !== []) {
            return [
                false,
                'Weak PRNG used in security-sensitive context: ' . implode(', ', array_map(
                    static fn(array $match): string => $match['file'] . ':' . $match['line'] . ' [' . $match['kind'] . '/' . $match['risk'] . ']',
                    $offenders
                )),
                $offenders,
            ];
        }

        if ($capture['gaps'] !== [] || $capture['unresolved'] !== []) return [null, '[UNKNOWN] Source collection or flow resolution is incomplete; no safety conclusion is established', ['collection_gaps' => $capture['gaps'], 'unresolved' => $capture['unresolved']]];
        return [true, 'No enumerated weak-randomness pattern observed in complete bounded source'];
    }

    /** Complete bounded source is distinct from unsupported dynamic flow resolution. */
    private function captureSafetySource(array $args, string $kind): array
    {
        $capture=(new \Magebean\Engine\Collectors\BoundedSourceInventory($this->collectors->session))->collect($this->ctx, $args + ['verify_stable'=>true]);
        $unresolved=[];
        $sinks=[
            'ssrf'=>['curl_init','curl_exec','curl_setopt','curl_setopt_array','file_get_contents','fopen','fsockopen','stream_socket_client'],
            'egress'=>['curl_init','curl_exec','curl_setopt','curl_setopt_array','file_get_contents','fopen','fsockopen','stream_socket_client'],
            'path'=>['file_get_contents','fopen','readfile','file_put_contents','unlink','rename','copy','mkdir','rmdir'],
            'upload'=>['move_uploaded_file'], 'unserialize'=>['unserialize'],
            'command'=>['exec','system','shell_exec','passthru','popen','proc_open','pcntl_exec'],
            'random'=>['rand','mt_rand','uniqid','lcg_value','shuffle','array_rand'],
        ];
        foreach($capture['files'] as $source){
            if (!in_array($source['extension'],['php','phtml'],true)) continue;
            try{$nodes=(new \Magebean\Engine\Collectors\MagentoStaticPhp())->parse($source['content']);}
            catch(\PhpParser\Error){$unresolved[]=['file'=>$source['file'],'reason'=>'php_parse_unavailable'];continue;}
            foreach((new \PhpParser\NodeFinder())->find($nodes,static fn($n):bool=>$n instanceof \PhpParser\Node\Expr\CallLike || $n instanceof \PhpParser\Node\Expr\Eval_) as $node){
                if ($node instanceof \PhpParser\Node\Expr\Eval_){if($kind==='dynamic')$unresolved[]=['file'=>$source['file'],'reason'=>'dynamic_execution_context_unresolved'];continue;}
                $dynamic=($node instanceof \PhpParser\Node\Expr\FuncCall && !$node->name instanceof \PhpParser\Node\Name)
                    || (($node instanceof \PhpParser\Node\Expr\MethodCall || $node instanceof \PhpParser\Node\Expr\NullsafeMethodCall || $node instanceof \PhpParser\Node\Expr\StaticCall) && !$node->name instanceof \PhpParser\Node\Identifier);
                $name=$node instanceof \PhpParser\Node\Expr\FuncCall && $node->name instanceof \PhpParser\Node\Name?strtolower(ltrim($node->name->toString(),'\\')):'';
                if($dynamic || in_array($name,['call_user_func','call_user_func_array','forward_static_call','forward_static_call_array'],true)){
                    $unresolved[]=['file'=>$source['file'],'reason'=>'indirect_call_unresolved'];continue;
                }
                if(in_array($name,$sinks[$kind]??[],true))$unresolved[]=['file'=>$source['file'],'reason'=>'sink_flow_or_guard_unresolved'];
                if($kind==='sql' && in_array($name,['mysqli_query','mysql_query'],true)){
                    $argument=$node->args[1]->value??null;
                    if(!$argument instanceof \PhpParser\Node\Scalar\String_ && !$argument instanceof \PhpParser\Node\Expr\BinaryOp\Concat && !$argument instanceof \PhpParser\Node\Scalar\InterpolatedString)$unresolved[]=['file'=>$source['file'],'reason'=>'query_argument_unresolved'];
                }
                if($kind==='sql' && ($node instanceof \PhpParser\Node\Expr\StaticCall || $node instanceof \PhpParser\Node\Expr\NullsafeMethodCall) && $node->name instanceof \PhpParser\Node\Identifier
                    && in_array(strtolower($node->name->toString()),['query','rawquery','fetchall','fetchrow','fetchone','fetchcol','fetchpairs'],true))$unresolved[]=['file'=>$source['file'],'reason'=>'query_receiver_flow_unresolved'];
                if($kind==='sql' && $node instanceof \PhpParser\Node\Expr\MethodCall && $node->name instanceof \PhpParser\Node\Identifier
                    && in_array(strtolower($node->name->toString()),['query','rawquery','fetchall','fetchrow','fetchone','fetchcol','fetchpairs'],true)){
                    $argument=$node->args[0]->value??null;
                    if(!$argument instanceof \PhpParser\Node\Scalar\String_ && !$argument instanceof \PhpParser\Node\Expr\BinaryOp\Concat && !$argument instanceof \PhpParser\Node\Scalar\InterpolatedString)$unresolved[]=['file'=>$source['file'],'reason'=>'query_argument_unresolved'];
                }
            }
        }
        return $capture+['unresolved'=>array_slice($unresolved,0,100)];
    }

    private function rawSqlFindings(string $file, string $content): array
    {
        try { $nodes = (new \Magebean\Engine\Collectors\MagentoStaticPhp())->parse($content); }
        catch (\PhpParser\Error) { return []; }
        $findings = [];
        foreach ((new \PhpParser\NodeFinder())->find($nodes, static fn($node): bool => $node instanceof \PhpParser\Node\Expr\MethodCall || $node instanceof \PhpParser\Node\Expr\FuncCall) as $node) {
            $argument = null;
            if ($node instanceof \PhpParser\Node\Expr\MethodCall && $node->name instanceof \PhpParser\Node\Identifier
                && in_array(strtolower($node->name->toString()), ['query','rawquery','fetchall','fetchrow','fetchone','fetchcol','fetchpairs'], true)) $argument=$node->args[0]->value??null;
            if ($node instanceof \PhpParser\Node\Expr\FuncCall && $node->name instanceof \PhpParser\Node\Name
                && in_array(strtolower(ltrim($node->name->toString(),'\\')), ['mysqli_query','mysql_query'], true)) $argument=$node->args[1]->value??null;
            $literal = static function ($expression) use (&$literal): bool {
                return $expression instanceof \PhpParser\Node\Scalar\String_
                    || ($expression instanceof \PhpParser\Node\Expr\BinaryOp\Concat && $literal($expression->left) && $literal($expression->right));
            };
            if ($literal($argument)) continue;
            if ($argument instanceof \PhpParser\Node\Expr\BinaryOp\Concat || $argument instanceof \PhpParser\Node\Scalar\InterpolatedString) {
                $findings[]=['file'=>$file,'line'=>$node->getStartLine(),'kind'=>'dynamic_sql_argument','scope'=>'SQL argument construction only; receiver type and exploitability unresolved'];
            }
        }
        return $findings;
    }

    private function outboundEgressFindings(string $file, string $content): array
    {
        $findings = [];
        $seen = [];
        $patterns = [
            'curl_init' => '~\bcurl_init\s*\((?P<arg>.{0,300})~is',
            'curl_url' => '~\bcurl_setopt\s*\([^;]{0,300}\bCURLOPT_URL\b(?P<arg>[^;]{0,300})~is',
            'curl_setopt_array_url' => '~\bcurl_setopt_array\s*\([^;]{0,500}\bCURLOPT_URL\b(?P<arg>[^;]{0,300})~is',
            'php_stream' => '~\b(?:file_get_contents|fopen)\s*\((?P<arg>.{0,300})~is',
            'socket_client' => '~\b(?:fsockopen|stream_socket_client)\s*\((?P<arg>.{0,300})~is',
            'http_client' => '~->\s*(?:request|get|post|put|patch|delete|send)\s*\((?P<arg>.{0,500})~is',
        ];

        foreach ($patterns as $kind => $regex) {
            $matchCount = preg_match_all($regex, $content, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER);
            if ($matchCount === false || $matchCount < 1) {
                continue;
            }

            foreach ($matches as $match) {
                $offset = (int)$match[0][1];
                $arg = isset($match['arg']) && is_array($match['arg']) ? (string)$match['arg'][0] : '';
                $lookupKind = $kind === 'curl_setopt_array_url' ? 'curl_url' : $kind;
                if (!$this->looksLikeOutboundEgressArgument($lookupKind, $arg)) {
                    continue;
                }

                $evidence = $this->matchEvidence($file, $content, $kind, $offset);
                $key = $evidence['file'] . ':' . $evidence['line'] . ':' . $kind;
                if (isset($seen[$key])) {
                    continue;
                }

                $seen[$key] = true;
                $window = $this->codeWindow($content, $offset, 2200);
                $evidence['kind'] = $kind;
                $evidence['controls'] = $this->outboundEgressControlEvidence($window);
                $findings[] = $evidence;
            }
        }

        return $findings;
    }

    private function looksLikeOutboundEgressArgument(string $kind, string $arg): bool
    {
        if ($kind === 'curl_url') {
            return true;
        }

        $trimmed = trim($arg);
        if ($trimmed === '') {
            return false;
        }

        if ($kind === 'php_stream'
            && preg_match('~\b(?:getPathname|getRealPath|__DIR__|dirname|realpath|DirectoryIterator|RecursiveDirectoryIterator|SplFileInfo)\b~i', $trimmed) === 1) {
            return false;
        }

        return preg_match('~^[\'\"]https?://~i', $trimmed) === 1
            || str_contains($trimmed, '$')
            || preg_match('~\b(?:url|uri|endpoint|callback|webhook|host|domain|remote|target|api|base_uri)\b~i', $trimmed) === 1;
    }

    private function outboundEgressControlEvidence(string $window): array
    {
        $hasAllowlist = preg_match('~\b(?:allowedHosts?|allowedDomains?|allowlist|whitelist|trustedHosts?|isAllowedHost|validateHost|validateUrl|allowedBaseUrls?|originAllowlist)\b~i', $window) === 1
            || preg_match('~\b(?:parse_url|getHost|UriInterface)\b[\s\S]{0,260}\b(?:in_array|array_key_exists|isset|contains|allowed|allowlist|whitelist)\b~i', $window) === 1;
        $hasTimeout = preg_match('~\b(?:CURLOPT_TIMEOUT|CURLOPT_CONNECTTIMEOUT|CURLOPT_TIMEOUT_MS|CURLOPT_CONNECTTIMEOUT_MS|timeout|connect_timeout|read_timeout|setTimeout|setConnectTimeout|RequestOptions::(?:TIMEOUT|CONNECT_TIMEOUT))\b~i', $window) === 1;

        $missing = [];
        if (!$hasAllowlist) {
            $missing[] = 'allowlist';
        }
        if (!$hasTimeout) {
            $missing[] = 'timeout';
        }

        return [
            'ok' => $missing === [],
            'has_allowlist' => $hasAllowlist,
            'has_timeout' => $hasTimeout,
            'missing' => $missing,
        ];
    }

    private function ssrfFindings(string $file, string $content): array
    {
        $findings = [];
        $patterns = [
            'curl_init' => '~\bcurl_init\s*\((?P<arg>.{0,300})~is',
            'curl_url' => '~\bcurl_setopt\s*\([^;]{0,300}\bCURLOPT_URL\b(?P<arg>[^;]{0,300})~is',
            'php_stream' => '~\b(?:file_get_contents|fopen)\s*\((?P<arg>.{0,300})~is',
            'socket_client' => '~\b(?:fsockopen|stream_socket_client)\s*\((?P<arg>.{0,300})~is',
            'http_client' => '~->\s*(?:request|get|post|put|send)\s*\((?P<arg>.{0,300})~is',
        ];

        foreach ($patterns as $kind => $regex) {
            $matchCount = preg_match_all($regex, $content, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER);
            if ($matchCount === false || $matchCount < 1) {
                continue;
            }

            foreach ($matches as $match) {
                $offset = (int)$match[0][1];
                $arg = isset($match['arg']) && is_array($match['arg']) ? (string)$match['arg'][0] : '';
                if (!$this->looksLikeOutboundUrlArgument($kind, $arg)) {
                    continue;
                }

                $window = $this->codeWindow($content, $offset, 1800);
                if ($this->hasSsrfSafeguards($window)) {
                    continue;
                }

                $evidence = $this->matchEvidence($file, $content, $kind, $offset);
                $evidence['kind'] = $kind;
                $findings[] = $evidence;
            }
        }

        return $findings;
    }

    private function unserializeFindings(string $file, string $content): array
    {
        $findings = [];
        if (preg_match_all('~(?<!->)(?<!::)(?<!function\s)\b\\\\?unserialize\s*\((?P<args>.{0,500})~is', $content, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) < 1) {
            return [];
        }

        foreach ($matches as $match) {
            $offset = (int)$match[0][1];
            $args = isset($match['args']) && is_array($match['args']) ? (string)$match['args'][0] : '';
            if (preg_match('~[\'"]?allowed_classes[\'"]?\s*=>~i', $args) === 1) {
                continue;
            }

            $evidence = $this->matchEvidence($file, $content, 'unsafe_unserialize', $offset);
            $evidence['kind'] = 'unsafe_unserialize';
            $evidence['risk'] = $this->unserializeRisk($content, $offset, $args);
            $findings[] = $evidence;
        }

        return $findings;
    }

    private function commandExecutionFindings(string $file, string $content): array
    {
        $findings = [];
        $searchable = $this->maskPhpStringsAndComments($content);
        $patterns = [
            'command_function' => '~(?<!->)(?<!::)(?<!function\s)\b\\\\?(?:exec|shell_exec|system|passthru|proc_open|popen|pcntl_exec)\s*\((?P<args>.{0,500})~is',
            'backtick_operator' => '~`(?P<args>[^`\r\n]{0,500})`~',
        ];

        foreach ($patterns as $kind => $regex) {
            if (preg_match_all($regex, $searchable, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) < 1) {
                continue;
            }

            foreach ($matches as $match) {
                $offset = (int)$match[0][1];
                $args = isset($match['args']) && is_array($match['args']) ? (string)$match['args'][0] : '';
                $risk = $this->commandExecutionRisk($content, $offset, $args);
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

    private function dynamicExecutionFindings(string $file, string $content): array
    {
        $findings = [];
        $searchable = $this->maskPhpStringsAndComments($content);
        $patterns = [
            'dynamic_code_function' => '~(?<!->)(?<!::)(?<!function\s)\b\\\\?(?:eval|assert|create_function)\s*\((?P<args>.{0,500})~is',
            'dynamic_include' => '~\b(?:include|include_once|require|require_once)\s*(?:\(\s*)?(?P<args>[^;\r\n]{0,500})~i',
            'dynamic_callable' => '~\b(?:call_user_func|call_user_func_array|new\s+\\\\?ReflectionFunction)\s*\((?P<args>.{0,500})~is',
            'variable_function' => '~(?<!function\s)(?P<args>\$[A-Za-z_][A-Za-z0-9_]*)\s*\(~',
        ];

        foreach ($patterns as $kind => $regex) {
            if (preg_match_all($regex, $searchable, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) < 1) {
                continue;
            }

            foreach ($matches as $match) {
                $offset = (int)$match[0][1];
                $args = isset($match['args']) && is_array($match['args']) ? (string)$match['args'][0] : '';
                $risk = $this->dynamicExecutionRisk($kind, $content, $offset, $args);
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

    private function pathTraversalFindings(string $file, string $content): array
    {
        $findings = [];
        $searchable = $this->maskPhpStringsAndComments($content);
        $patterns = [
            'file_read_sink' => '~\b(?:file_get_contents|fopen|readfile|file)\s*\((?P<args>.{0,500})~is',
            'file_write_sink' => '~\b(?:file_put_contents|unlink|copy|rename)\s*\((?P<args>.{0,500})~is',
            'include_sink' => '~\b(?:include|include_once|require|require_once)\s*(?:\(\s*)?(?P<args>[^;\r\n]{0,500})~i',
        ];

        foreach ($patterns as $kind => $regex) {
            if (preg_match_all($regex, $searchable, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) < 1) {
                continue;
            }

            foreach ($matches as $match) {
                $offset = (int)$match[0][1];
                $args = isset($match['args']) && is_array($match['args']) ? (string)$match['args'][0] : '';
                $risk = $this->pathTraversalRisk($kind, $content, $offset, $args);
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

    private function uploadFindings(string $file, string $content): array
    {
        $findings = [];
        $searchable = $this->maskPhpStringsAndComments($content);
        $patterns = [
            'move_uploaded_file' => '~\bmove_uploaded_file\s*\((?P<args>.{0,600})~is',
            'tmp_name_storage' => '~\$_FILES\s*\[[^\]]+\]\s*\[\s*[\'"]tmp_name[\'"]\s*\][\s\S]{0,260}\b(?:copy|rename|file_put_contents|fopen)\s*\((?P<args>.{0,500})~is',
            'magento_uploader_save' => '~(?:UploaderFactory|\\\\Magento\\\\Framework\\\\File\\\\Uploader|\\\\Magento\\\\MediaStorage\\\\Model\\\\File\\\\Uploader|getUploader|createUploader)[\s\S]{0,900}->\s*save\s*\((?P<args>.{0,500})~is',
            'uploaded_file_save' => '~->\s*(?:save|moveTo)\s*\((?P<args>.{0,500})~is',
        ];

        foreach ($patterns as $kind => $regex) {
            if (preg_match_all($regex, $searchable, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) < 1) {
                continue;
            }

            foreach ($matches as $match) {
                $offset = (int)$match[0][1];
                $window = $this->codeWindow($content, $offset, 1600);
                if (!$this->looksLikeUploadFlow($kind, $window)) {
                    continue;
                }
                if ($this->hasUploadSafeguards($window)) {
                    continue;
                }

                $evidence = $this->matchEvidence($file, $content, $kind, $offset);
                $evidence['kind'] = $kind;
                $evidence['risk'] = 'high';
                $evidence['missing'] = $this->missingUploadSafeguards($window);
                $findings[] = $evidence;
            }
        }

        return $findings;
    }

    private function csprngFindings(string $file, string $content): array
    {
        $findings = [];
        $searchable = $this->maskPhpStringsAndComments($content);
        $regex = '~\b(?P<fn>rand|mt_rand|array_rand|shuffle|str_shuffle|uniqid)\s*\(~i';

        if (preg_match_all($regex, $searchable, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) < 1) {
            return [];
        }

        foreach ($matches as $match) {
            $offset = (int)$match[0][1];
            $risk = $this->weakPrngRisk($content, $offset);
            if ($risk === null) {
                continue;
            }

            $evidence = $this->matchEvidence($file, $content, 'weak_prng', $offset);
            $evidence['kind'] = (string)$match['fn'][0];
            $evidence['risk'] = $risk;
            $findings[] = $evidence;
        }

        return $findings;
    }

    private function unserializeRisk(string $content, int $offset, string $args): string
    {
        $window = $this->codeWindow($content, $offset, 1200) . "\n" . $args;
        if (preg_match('~\b(?:getParam|getPost|getPostValue|getCookie|COOKIE|REQUEST|POST|GET|FILES|SERVER|php://input)\b~i', $window) === 1) {
            return 'high';
        }

        return 'medium';
    }

    private function commandExecutionRisk(string $content, int $offset, string $args): ?string
    {
        $window = $this->codeWindow($content, $offset, 1200) . "\n" . $args;
        $command = trim($args);

        if ($this->hasCommandInjectionGuard($window)) {
            return null;
        }

        if (preg_match('~\b(?:getParam|getPost|getPostValue|getQuery|getCookie|getHeader|REQUEST|POST|GET|COOKIE|FILES|SERVER|php://input)\b~i', $window) === 1) {
            return 'high';
        }

        if (preg_match('~\$(?:_?[A-Za-z][A-Za-z0-9_]*|{)~', $command) === 1
            || preg_match('~(?:["\']\s*\.|\.\s*\$|\$\w+\s*\.)~', $command) === 1
            || str_contains($command, '{$')) {
            return 'medium';
        }

        return null;
    }

    private function dynamicExecutionRisk(string $kind, string $content, int $offset, string $args): ?string
    {
        $window = $this->codeWindow($content, $offset, 1200) . "\n" . $args;
        $hasUserInput = preg_match('~\b(?:getParam|getPost|getPostValue|getQuery|getCookie|getHeader|REQUEST|POST|GET|COOKIE|FILES|SERVER|php://input)\b~i', $window) === 1;
        $hasDynamicArg = preg_match('~\$(?:_?[A-Za-z][A-Za-z0-9_]*|{)~', $args) === 1
            || preg_match('~(?:["\']\s*\.|\.\s*\$|\$\w+\s*\.)~', $args) === 1
            || str_contains($args, '{$');

        if ($kind === 'dynamic_code_function') {
            return $hasUserInput ? 'high' : 'medium';
        }

        if ($kind === 'dynamic_include') {
            if (!$hasDynamicArg) {
                return null;
            }
            if ($this->isTrustedLocalConfigArrayIncludeContext($window)) {
                return null;
            }
            if ($hasUserInput) {
                return 'high';
            }
            if (preg_match('~\b(?:upload|tmp|temp|cache|media|var|remote|url|uri)\b|(?:\.\./|php://|data://|phar://|https?://)~i', $window) === 1) {
                return 'medium';
            }
            return null;
        }

        if ($kind === 'dynamic_callable' || $kind === 'variable_function') {
            if ($hasUserInput) {
                return 'high';
            }
            if ($kind === 'variable_function' && preg_match('~\b(?:callback|callable|handler|action|method)\b~i', $window) === 1) {
                return 'medium';
            }
            return null;
        }

        return null;
    }

    private function pathTraversalRisk(string $kind, string $content, int $offset, string $args): ?string
    {
        $window = $this->codeWindow($content, $offset, 1400) . "\n" . $args;
        $hasUserInput = preg_match('~\b(?:getParam|getPost|getPostValue|getQuery|getCookie|getHeader|REQUEST|POST|GET|COOKIE|FILES|SERVER|php://input|getClientOriginalName|getUploadedFileName)\b~i', $window) === 1;
        $hasDynamicPath = preg_match('~\$(?:_?[A-Za-z][A-Za-z0-9_]*|{)~', $args) === 1
            || preg_match('~(?:["\']\s*\.|\.\s*\$|\$\w+\s*\.)~', $args) === 1
            || str_contains($args, '{$');
        $hasDangerousPath = preg_match('~(?:\.\./|php://|data://|phar://|zip://|https?://|\\\\0)~i', $window) === 1;

        if (!$hasDynamicPath && !$hasUserInput && !$hasDangerousPath) {
            return null;
        }

        if ($this->isLocalEnumeratedPathContext($window)) {
            return null;
        }

        if ($kind === 'include_sink' && $this->isTrustedLocalConfigArrayIncludeContext($window)) {
            return null;
        }

        if ($this->hasPathTraversalGuard($window)) {
            return null;
        }

        if ($hasUserInput || preg_match('~\$_(?:GET|POST|REQUEST|FILES|COOKIE|SERVER)\b~', $args) === 1) {
            return 'high';
        }

        if ($hasDangerousPath) {
            return 'medium';
        }

        if (preg_match('~\b(?:upload|tmp|temp|cache|media|var|filename|filepath|path|relative|template)\b~i', $window) === 1) {
            return 'medium';
        }

        return null;
    }

    private function looksLikeUploadFlow(string $kind, string $window): bool
    {
        if ($kind === 'uploaded_file_save') {
            return preg_match('~\b(?:UploadedFileInterface|getUploadedFile|getUploadedFiles|UploaderFactory|\$_FILES|tmp_name|getClientFilename|getClientMediaType)\b~i', $window) === 1;
        }

        return true;
    }

    private function weakPrngRisk(string $content, int $offset): ?string
    {
        $window = $this->codeWindow($content, $offset, 900);
        $identifierContext = $this->identifierContext($content, $offset);

        if ($this->hasSecurityRandomnessSignal($window . "\n" . $identifierContext)) {
            return 'high';
        }

        if (preg_match('~\b(?:generate|create|build|make|issue|reset|verify|activate|auth)\w*\s*\(~i', $identifierContext) === 1
            && preg_match('~\b(?:token|code|key|secret|nonce|otp|salt|password|passcode)\b~i', $window . "\n" . $identifierContext) === 1) {
            return 'high';
        }

        return null;
    }

    private function identifierContext(string $content, int $offset): string
    {
        $before = substr($content, max(0, $offset - 700), min(700, $offset));
        $context = '';

        if (preg_match('~function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*$~s', $before, $match)) {
            $context .= ' function ' . $match[1];
        }
        if (preg_match('~\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*$~s', $before, $match)) {
            $context .= ' variable ' . $match[1];
        }
        if (preg_match('~[\'"]([A-Za-z0-9_.-]*(?:token|otp|password|passcode|reset|nonce|secret|api[_-]?key|salt|verify|activation|auth|code)[A-Za-z0-9_.-]*)[\'"]\s*=>\s*$~is', $before, $match)) {
            $context .= ' array_key ' . $match[1];
        }

        return $context;
    }

    private function hasUploadSafeguards(string $window): bool
    {
        $missing = $this->missingUploadSafeguards($window);
        return $missing === [];
    }

    private function missingUploadSafeguards(string $window): array
    {
        $missing = [];
        $hasMimeValidation = preg_match('~\b(?:finfo_(?:open|file)|mime_content_type|get(?:MimeType|ClientMimeType|ClientMediaType)|validateMime|checkMimeType|isValid|validateFile|addValidateCallback)\b~i', $window) === 1;
        $hasExtensionAllowlist = preg_match('~\b(?:setAllowedExtensions|allowedExtensions?|PATHINFO_EXTENSION|checkAllowedExtension|getClientOriginalExtension|extensionAllowlist|validateExtension)\b~i', $window) === 1;
        $hasSizeLimit = preg_match('~\b(?:getSize|size|MAX_FILE_SIZE|maxFileSize|setAllowCreateFolders|validateSize|filesize)\b~i', $window) === 1
            && preg_match('~(?:<=|<|max|limit|allowed)~i', $window) === 1;
        $hasStoragePolicy = preg_match('~\b(?:setAllowRenameFiles|setFilesDispersion|random_bytes|uniqid|hash|sha1|md5|DirectoryList|VAR_DIR|TMP|MEDIA|outsideWebroot|pub/media|media/tmp|uploadDir|destination)\b~i', $window) === 1;

        if (!$hasMimeValidation) {
            $missing[] = 'mime_validation';
        }
        if (!$hasExtensionAllowlist) {
            $missing[] = 'extension_allowlist';
        }
        if (!$hasSizeLimit) {
            $missing[] = 'size_limit';
        }
        if (!$hasStoragePolicy) {
            $missing[] = 'storage_policy';
        }

        return $missing;
    }

    private function isLocalEnumeratedPathContext(string $window): bool
    {
        return preg_match('~\b(?:collectFiles|RecursiveDirectoryIterator|DirectoryIterator|FilesystemIterator|SplFileInfo|getPathname|getRealPath|scandir|glob)\b~i', $window) === 1
            || preg_match('~foreach\s*\(\s*\$[A-Za-z_][A-Za-z0-9_]*\s+as\s+\$file\s*\)~i', $window) === 1;
    }

    private function isTrustedLocalConfigArrayIncludeContext(string $window): bool
    {
        return preg_match('~\b\$file\s*=\s*\$this->ctx->abs\s*\(\s*\$relativeFile\s*\)~', $window) === 1
            && preg_match('~\bis_file\s*\(\s*\$file\s*\)~', $window) === 1
            && preg_match('~\binclude\s+\$file\b~', $window) === 1
            && preg_match('~\bis_array\s*\(\s*\$[A-Za-z_][A-Za-z0-9_]*\s*\)~', $window) === 1;
    }

    private function hasPathTraversalGuard(string $window): bool
    {
        $hasNormalize = preg_match('~\b(?:realpath|basename|pathinfo|normalizePath|resolvePath|getPath|DirectoryList)\b~i', $window) === 1;
        $hasBaseCheck = preg_match('~\b(?:str_starts_with|strpos|strncmp|preg_match|in_array|allowedPaths?|allowedDirs?|baseDir|basePath|DirectoryList|ROOT|MEDIA|VAR_DIR)\b~i', $window) === 1;
        $hasTraversalReject = preg_match('~(?:\.\./|\.\.\\\\|basename\s*\(|PATHINFO_BASENAME|FILTER_SANITIZE|validatePath|isValidPath)~i', $window) === 1;

        return ($hasNormalize && $hasBaseCheck) || ($hasNormalize && $hasTraversalReject);
    }

    private function hasCommandInjectionGuard(string $window): bool
    {
        return preg_match('~\b(?:escapeshellarg|escapeshellcmd)\s*\(~i', $window) === 1
            || preg_match('~\b(?:preg_match|in_array|array_key_exists|match)\b[\s\S]{0,240}\b(?:allowlist|whitelist|allowed|^[A-Za-z0-9_.:/ -]+$|^[a-z0-9_-]+$)\b~i', $window) === 1
            || preg_match('~\b(?:allowlist|whitelist|allowedCommands?|allowedBins?|validateCommand|isAllowedCommand)\b~i', $window) === 1;
    }

    private function looksLikeOutboundUrlArgument(string $kind, string $arg): bool
    {
        if ($kind === 'curl_url') {
            return true;
        }

        $trimmed = trim($arg);
        if ($trimmed === '') {
            return false;
        }

        if (preg_match('~^[\'"]https?://[^\'"$]+[\'"]~i', $trimmed) === 1) {
            return false;
        }

        if ($kind === 'php_stream') {
            if (preg_match('~\b(?:getPathname|getRealPath|__DIR__|dirname|realpath|DirectoryIterator|RecursiveDirectoryIterator|SplFileInfo)\b~i', $trimmed) === 1) {
                return false;
            }

            return preg_match('~\b(?:getParam|getPost|getQuery|getBody|REQUEST|POST|GET|COOKIE|SERVER)\b~i', $trimmed) === 1
                || preg_match('~^[\'"]https?://~i', $trimmed) === 1
                || (
                    str_contains($trimmed, '$')
                    && preg_match('~\b(?:url|uri|endpoint|callback|webhook|host|domain|remote|target|api)\b~i', $trimmed) === 1
                );
        }

        return str_contains($trimmed, '$')
            || preg_match('~\b(?:getParam|getPost|getQuery|getBody|REQUEST|POST|GET|COOKIE|SERVER)\b~i', $trimmed) === 1
            || preg_match('~^[\'"]https?://~i', $trimmed) === 1;
    }

    private function hasSsrfSafeguards(string $window): bool
    {
        $hasHostValidation = preg_match('~\b(?:allowedHosts?|allowlist|whitelist|isAllowedHost)\b~i', $window) === 1;
        $hasPrivateIpGuard = preg_match('~\b(?:FILTER_FLAG_NO_PRIV_RANGE|FILTER_FLAG_NO_RES_RANGE|private|localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254|10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168|::1|fc00|fe80|metadata)\b~i', $window) === 1;
        $hasProtocolGuard = preg_match('~\b(?:https?|scheme|getScheme)\b[\s\S]{0,160}(?:===|==|in_array|allowed|https)~i', $window) === 1;
        $hasTimeout = preg_match('~\b(?:CURLOPT_TIMEOUT|CURLOPT_CONNECTTIMEOUT|timeout|setTimeout|connect_timeout|read_timeout)\b~i', $window) === 1;

        return $hasTimeout && ($hasHostValidation || ($hasPrivateIpGuard && $hasProtocolGuard));
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
}
