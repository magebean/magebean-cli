<?php
declare(strict_types=1);
namespace Magebean\Engine\Checks\Families;
use Magebean\Engine\Context;
use Magebean\Engine\Collectors\CollectorSet;

final class TemplateRequestSourceChecks extends CodeSearchSupport
{
    public function phtmlEscapedOutput(array $args): array
    {
        return (new \Magebean\Engine\Checks\ScopedTemplateOutputCheck($this->ctx, $this->collectors))->run($args);
    }

    public function csrfFormKey(array $args): array
    {
        $roots = $args['paths'] ?? ['app'];
        $max = max(1, (int)($args['max_results'] ?? 50));
        $inventory = (new \Magebean\Engine\Collectors\BoundedSourceInventory($this->collectors->session))->collect($this->ctx, [
            'paths'=>$roots, 'include_ext'=>['php','phtml','html'], 'verify_stable'=>true,
        ]);
        $byPath = []; foreach ($inventory['files'] as $entry) $byPath[$entry['file']] = $entry;
        $templates = array_keys(array_filter($byPath, static fn(array $entry):bool => in_array($entry['extension'], ['phtml','html'], true)));
        $phpFiles = array_keys(array_filter($byPath, static fn(array $entry):bool => $entry['extension']==='php'));

        $offenders = [];
        foreach ($templates as $file) {
            $content = $byPath[$file]['content'];
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

        foreach ($phpFiles as $file) {
            $content = $byPath[$file]['content'];
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

        return [null, '[UNKNOWN] Form-key source signals do not establish effective CSRF validation or rejection paths', ['files_read'=>$inventory['files_read'], 'collection_gaps'=>$inventory['gaps'], 'reason_code'=>'CSRF_CONTROL_FLOW_UNVERIFIED']];
    }

    public function jsContextEscaping(array $args): array
    {
        return (new \Magebean\Engine\Checks\ScopedTemplateOutputCheck($this->ctx, $this->collectors))->run($args, true);
    }

    public function webhookSignatureValidation(array $args): array
    {
        $roots = $args['paths'] ?? ['app/code', 'app/etc', 'routes'];
        $inc = $args['include_ext'] ?? ['php', 'xml'];
        $max = max(1, (int)($args['max_results'] ?? 100));
        $requireTimestamp = (bool)($args['require_timestamp'] ?? false);
        $requireReplayWindow = (bool)($args['require_replay_window'] ?? false);
        $requireIdempotency = (bool)($args['require_idempotency'] ?? false);
        $paymentOnly = (bool)($args['payment_only'] ?? false);
        $inventory = (new \Magebean\Engine\Collectors\BoundedSourceInventory($this->collectors->session))->collect($this->ctx, [
            'paths'=>$roots, 'include_ext'=>$inc, 'verify_stable'=>true,
        ]);
        $source = []; foreach ($inventory['files'] as $entry) $source[$entry['file']] = $entry['content'];
        $evidenceArgs = [
            'require_timestamp' => $requireTimestamp,
            'require_replay_window' => $requireReplayWindow,
            'require_idempotency' => $requireIdempotency,
        ];

        $handlers = [];
        $failures = [];
        $hasApplicationSignatureValidation = false;
        $filesRead = 0;
        foreach (array_keys($source) as $file) {
            $content = $source[$file];
            if ($content === false) {
                continue;
            }

            $filesRead++;
            $extension = strtolower(pathinfo($file, PATHINFO_EXTENSION));
            $scanContent = $this->maskSourceComments($content, $extension);
            if ($extension === 'php'
                && !empty($this->webhookSignatureEvidence($scanContent, 0, $evidenceArgs)['ok'])) {
                $hasApplicationSignatureValidation = true;
            }

            foreach ($this->webhookHandlerFindings($file, $scanContent) as $handler) {
                if ($paymentOnly && !$this->hasPaymentWebhookContext($this->relativeFile($file), $scanContent, (int)$handler['offset'], (string)($handler['target'] ?? ''))) {
                    continue;
                }
                $validation = $this->webhookSignatureEvidence($scanContent, (int)$handler['offset'], $evidenceArgs);
                $handler['signature_evidence'] = $validation;
                unset($handler['offset']);
                $handlers[] = $handler;
                if (empty($validation['ok'])) {
                    $failures[] = $handler;
                    if (count($failures) >= $max) {
                        break 2;
                    }
                }
            }
        }

        if ($hasApplicationSignatureValidation) {
            $failures = array_values(array_filter($failures, static fn(array $failure): bool => !str_starts_with((string)$failure['kind'], 'xml_')));
        }

        $evidence = [
            'paths' => array_values($roots),
            'files_scanned' => $filesRead,
            'require_timestamp' => $requireTimestamp,
            'require_replay_window' => $requireReplayWindow,
            'require_idempotency' => $requireIdempotency,
            'payment_only' => $paymentOnly,
            'has_application_signature_validation' => $hasApplicationSignatureValidation,
            'handlers' => $handlers,
            'failures' => $failures,
            'truncated' => count($failures) >= $max,
        ];

        if ($filesRead === 0) {
            return [null, '[UNKNOWN] Webhook signature scan could not read any target files', $evidence];
        }

        if ($failures !== []) {
            $lines = ['Webhook handlers without required authentication hardening evidence:'];
            foreach ($failures as $failure) {
                $lines[] = sprintf(
                    '    - %s:%d [%s] missing %s',
                    $failure['file'],
                    $failure['line'],
                    $failure['kind'],
                    implode('+', $failure['signature_evidence']['missing'] ?? ['signature_validation'])
                );
            }
            if ($evidence['truncated']) {
                $lines[] = sprintf('    - output truncated at %d findings', $max);
            }

            return [false, implode("\n", $lines), $evidence];
        }

        $evidence['collection_gaps'] = $inventory['gaps'];
        if ($handlers === []) {
            return [null, '[UNKNOWN] No supported webhook handler was independently established in the collected source', $evidence];
        }

        $message = ($requireTimestamp || $requireReplayWindow || $requireIdempotency)
            ? 'Webhook handlers include required authentication hardening evidence'
            : 'Webhook handlers include local signature validation evidence';

        return [null, '[UNKNOWN] Webhook signature keywords are supporting observations; verification and failure control flow remain unverified', $evidence + ['reason_code'=>'WEBHOOK_CONTROL_FLOW_UNVERIFIED']];
    }

    private function phtmlOutputFindings(string $file, string $content, array $escapeFunctions): array
    {
        $findings = [];
        $patterns = [
            'short_echo' => '~<\?=\s*(?P<expr>.*?)\?>~is',
            'echo_statement' => '~<\?php\s+(?:echo|print)\s+(?P<expr>.*?);?\s*\?>~is',
        ];

        foreach ($patterns as $kind => $regex) {
            $count = preg_match_all($regex, $content, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER);
            if ($count === false || $count < 1) {
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
        if (preg_match_all('~<form\b(?P<attrs>[^>]*)>(?P<body>.*?)</form>~is', $content, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) < 1) {
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

    private function jsContextFindings(string $file, string $content): array
    {
        $findings = [];

        if (preg_match_all('~<script\b(?P<attrs>[^>]*)>(?P<body>.*?)</script>~is', $content, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) > 0) {
            foreach ($matches as $match) {
                $attrs = (string)$match['attrs'][0];
                $body = (string)$match['body'][0];
                if (preg_match('~\btype\s*=\s*([\'"])(?:text/template|text/x-magento-template)\1~i', $attrs) === 1) {
                    continue;
                }

                foreach ($this->phpOutputExpressions($body, (int)$match['body'][1]) as $expr) {
                    if ($this->isSafeJsContextExpression($expr['expr'])) {
                        continue;
                    }
                    $evidence = $this->matchEvidence($file, $content, 'script_php_output', $expr['offset']);
                    $evidence['kind'] = 'script_php_output';
                    $evidence['expression'] = trim($expr['expr']);
                    $findings[] = $evidence;
                }
            }
        }

        if (preg_match_all('~\b(?:on[a-z]+|data-mage-init|x-magento-init)\s*=\s*([\'"])(?P<value>.*?)\1~is', $content, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) > 0) {
            foreach ($matches as $match) {
                $value = (string)$match['value'][0];
                foreach ($this->phpOutputExpressions($value, (int)$match['value'][1]) as $expr) {
                    if ($this->isSafeJsContextExpression($expr['expr'])) {
                        continue;
                    }
                    $evidence = $this->matchEvidence($file, $content, 'attribute_js_php_output', $expr['offset']);
                    $evidence['kind'] = 'attribute_js_php_output';
                    $evidence['expression'] = trim($expr['expr']);
                    $findings[] = $evidence;
                }
            }
        }

        return $findings;
    }

    private function webhookHandlerFindings(string $file, string $content): array
    {
        $findings = [];
        $seen = [];
        $relative = $this->relativeFile($file);
        $extension = strtolower(pathinfo($file, PATHINFO_EXTENSION));
        $webhookWord = '(?:webhook|callback|ipn|notification|notify)';

        $patterns = [];
        if ($extension === 'xml') {
            $patterns['xml_route'] = '~<route\b[^>]*\burl\s*=\s*([\'\"])(?P<target>[^\'\"]*' . $webhookWord . '[^\'\"]*)\1[^>]*>~i';
            $patterns['xml_service_anonymous'] = '~<route\b[^>]*\burl\s*=\s*([\'\"])(?P<target>[^\'\"]*)\1[^>]*>\s*<service\b[^>]*\bresource\s*=\s*([\'\"])anonymous\3~is';
        } else {
            $patterns['route_registration'] = '~\bRoute::\s*(?:post|put|patch|any)\s*\(\s*([\'\"])(?P<target>[^\'\"]*' . $webhookWord . '[^\'\"]*)\1~i';
            $patterns['webhook_class'] = '~\bclass\s+\w*' . $webhookWord . '\w*\b~i';
            $patterns['webhook_method'] = '~\bfunction\s+(?:execute|handleWebhook|webhook|callback|ipn|notify|notification)\s*\(~i';
        }

        foreach ($patterns as $kind => $regex) {
            $count = preg_match_all($regex, $content, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER);
            if ($count === false || $count < 1) {
                continue;
            }

            foreach ($matches as $match) {
                $offset = (int)$match[0][1];
                $target = isset($match['target']) && is_array($match['target']) ? (string)$match['target'][0] : '';
                if ($kind === 'webhook_method' && !$this->hasWebhookContext($relative, $content, $offset)) {
                    continue;
                }
                if ($kind === 'xml_service_anonymous' && preg_match('~' . $webhookWord . '~i', $target) !== 1) {
                    continue;
                }

                $evidence = $this->matchEvidence($file, $content, $kind, $offset);
                $key = $evidence['file'] . ':' . $evidence['line'] . ':' . ($target !== '' ? $target : 'handler');
                if (isset($seen[$key])) {
                    continue;
                }

                $seen[$key] = true;
                $evidence['kind'] = $kind;
                $evidence['target'] = $target;
                $evidence['offset'] = $offset;
                $findings[] = $evidence;
            }
        }

        return $findings;
    }

    private function hasWebhookContext(string $relative, string $content, int $offset): bool
    {
        if (preg_match('~(?:webhook|callback|ipn|notification|notify)~i', $relative) === 1) {
            return true;
        }

        $window = substr($content, max(0, $offset - 800), 1600);
        return preg_match('~(?:webhook|callback|ipn|notification|notify)~i', $window) === 1;
    }

    private function hasPaymentWebhookContext(string $relative, string $content, int $offset, string $target): bool
    {
        $window = substr($content, max(0, $offset - 1200), 2400);
        return preg_match('~\b(?:payment|invoice|capture|refund|order|transaction|checkout|gateway|stripe|paypal|braintree|adyen|klarna|authorizenet|authorize(?:\.net)?)\b~i', $relative . "\n" . $target . "\n" . $window) === 1;
    }

    private function webhookSignatureEvidence(string $content, int $offset, array $args = []): array
    {
        $requireTimestamp = (bool)($args['require_timestamp'] ?? false);
        $requireReplayWindow = (bool)($args['require_replay_window'] ?? false);
        $requireIdempotency = (bool)($args['require_idempotency'] ?? false);
        $fileWide = $content;
        $window = substr($content, max(0, $offset - 1600), 3600);
        $haystack = $window . "\n" . $fileWide;

        $constructEvent = preg_match('~\bconstructEvent\s*\(~i', $haystack) === 1;
        $hasHeader = preg_match('~(?:HTTP_[A-Z0-9_]*(?:SIGNATURE|HMAC|TRANSMISSION_SIG)|[\'\"](?:X[-_][^\'\"]*(?:Signature|Hmac|Sha256|Timestamp|Transmission-Time)|Stripe-Signature|Paypal-Transmission-Sig|Paypal-Transmission-Time|X-Hub-Signature-256)[\'\"]|->\s*(?:getHeader|getHeaderLine|header)\s*\(\s*[\'\"][^\'\"]*(?:signature|hmac|transmission-sig|transmission-time)[^\'\"]*[\'\"])~i', $haystack) === 1;
        $hasTimingSafeCompare = preg_match('~\bhash_equals\s*\(~i', $haystack) === 1;
        $hasMac = preg_match('~\bhash_hmac\s*\(~i', $haystack) === 1;
        $hasVerifier = preg_match('~\b(?:openssl_verify|sodium_crypto_sign_verify_detached)\s*\(|\b(?:verifySignature|validateSignature|isSignatureValid|checkSignature|assertSignature|constructEvent)\s*\(~i', $haystack) === 1;
        $hasTimestamp = $constructEvent || preg_match('~\b(?:timestamp|timeStamp|transmission[_-]?time|created_at|event_time|request_time)\b|(?:^|[,;\s])t=\d+~i', $haystack) === 1;
        $hasReplayWindow = $constructEvent || preg_match('~\b(?:replay|tolerance|max[_-]?age|time[_-]?window|expires|ttl|nonce|abs\s*\(|time\s*\(\s*\)|strtotime\s*\(|DateTimeImmutable|300|600|900)\b~i', $haystack) === 1;
        $hasIdempotency = preg_match('~\b(?:idempotenc(?:y|e)|event[_-]?id|webhook[_-]?id|transaction[_-]?id|request[_-]?id|delivery[_-]?id|transmission[_-]?id|already[_-]?processed|processed[_-]?events?|dedupe|deduplication|unique[_-]?key|lock\s*\(|SELECT\s+.*(?:event|webhook|transaction))\b~i', $haystack) === 1;

        $signatureOk = ($hasHeader && (($hasMac && $hasTimingSafeCompare) || $hasVerifier)) || $constructEvent;
        $ok = $signatureOk
            && (!$requireTimestamp || $hasTimestamp)
            && (!$requireReplayWindow || $hasReplayWindow)
            && (!$requireIdempotency || $hasIdempotency);

        $missing = [];
        if (!$hasHeader && !$constructEvent) {
            $missing[] = 'signature_header';
        }
        if (!(($hasMac && $hasTimingSafeCompare) || $hasVerifier)) {
            $missing[] = 'timing_safe_signature_verify';
        }
        if ($requireTimestamp && !$hasTimestamp) {
            $missing[] = 'timestamp';
        }
        if ($requireReplayWindow && !$hasReplayWindow) {
            $missing[] = 'replay_window';
        }
        if ($requireIdempotency && !$hasIdempotency) {
            $missing[] = 'idempotency';
        }

        return [
            'ok' => $ok,
            'has_signature_header' => $hasHeader,
            'has_hmac' => $hasMac,
            'has_timing_safe_compare' => $hasTimingSafeCompare,
            'has_verifier' => $hasVerifier,
            'has_timestamp' => $hasTimestamp,
            'has_replay_window' => $hasReplayWindow,
            'has_idempotency' => $hasIdempotency,
            'missing' => $missing,
        ];
    }

    private function phpOutputExpressions(string $content, int $baseOffset): array
    {
        $expressions = [];
        $patterns = [
            '~<\?=\s*(?P<expr>.*?)\?>~is',
            '~<\?php\s+(?:echo|print)\s+(?P<expr>.*?);?\s*\?>~is',
        ];

        foreach ($patterns as $regex) {
            if (preg_match_all($regex, $content, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) < 1) {
                continue;
            }
            foreach ($matches as $match) {
                $expr = isset($match['expr']) && is_array($match['expr']) ? (string)$match['expr'][0] : '';
                $expressions[] = [
                    'expr' => $expr,
                    'offset' => $baseOffset + (int)$match[0][1],
                ];
            }
        }

        return $expressions;
    }

    private function isSafeJsContextExpression(string $expr): bool
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

        return preg_match('~\b(?:escapeJs|escapeJsQuote|json_encode|serialize|unserialize|JsonHelper|SerializerInterface|Json::encode|->jsonEncode)\s*\(~i', $expr) === 1
            || preg_match('~(?:->|::)\s*(?:escapeJs|escapeJsQuote|jsonEncode|serialize)\s*\(~i', $expr) === 1;
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
}
