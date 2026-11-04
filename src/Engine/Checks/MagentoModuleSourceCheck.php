<?php
declare(strict_types=1);

namespace Magebean\Engine\Checks;

use Composer\Semver\Semver;
use Magebean\Engine\{CheckResult, Context, MagebeanDetectorAnalysis};
use Magebean\Engine\Collectors\{BoundedSourceInventory, CollectorSet, MagentoStaticPhp};
use PhpParser\{Error, Modifiers, Node, NodeFinder};

final class MagentoModuleSourceCheck
{
    private const INPUTS = ['_GET', '_POST', '_REQUEST', '_COOKIE'];
    private const COMMANDS = ['exec', 'shell_exec', 'system', 'passthru', 'popen'];

    public function __construct(private readonly Context $context, private readonly CollectorSet $collectors) {}

    public function run(string $kind, array $modules, array $inventory, array $gaps): CheckResult
    {
        $findings = [];
        if ($kind === 'magento-platform') {
            $installed = $inventory['packages']['magento/framework']['version'] ?? null;
            foreach ($modules as $module) {
                $constraint = $module['composer_require']['magento/framework'] ?? null;
                if ($constraint === null) continue;
                try {
                    if (!is_string($installed) || !preg_match('/^v?\d+\.\d+\.\d+(?:-p\d+)?$/D', $installed)) {
                        throw new \UnexpectedValueException();
                    }
                    if (!Semver::satisfies($installed, $constraint)) {
                        $findings[] = self::finding($module, $module['dependency_manifest'], 1, 'framework-version-constraint',
                            'Installed Magento Framework version does not satisfy the declared Composer constraint.',
                            'The selected module declares a magento/framework constraint that excludes the installed version.',
                            'Use an extension release compatible with the installed framework, or verify the declared constraint.', false);
                    }
                } catch (\UnexpectedValueException|\InvalidArgumentException) {
                    $gaps[] = ['reason' => 'framework_version_or_constraint_unresolved', 'file' => $module['dependency_manifest']];
                }
            }
        } elseif ($kind === 'php-contract') {
            $this->contracts($modules, $findings, $gaps);
        } elseif ($modules !== []) {
            $target = $inventory['target_php'] ?? null;
            if ($kind === 'php-target' && (!is_string($target) || !preg_match('/^8\.[1-4](?:\.\d+)?$/D', $target))) {
                $gaps[] = ['reason' => 'target_php_unresolved', 'file' => 'composer.json'];
            } else {
                $this->scan($kind, $modules, $inventory, (string) $target, $findings, $gaps);
            }
        }
        $diagnostics = [];
        foreach ($gaps as $gap) {
            $file = $gap['file'] ?? '';
            $message = str_replace('_', ' ', $gap['reason']).($file !== '' ? ' · '.$file : '');
            $diagnostics[$message] = [
                'message' => $message,
                'action' => $gap['reason'] === 'target_php_unresolved'
                    ? 'Declare the deployed PHP version (8.1–8.4) in Composer config.platform.php.'
                    : 'Verify the selected module source and installed package metadata.',
            ];
        }
        return MagebeanDetectorAnalysis::result('magento-module-'.$kind, '1.0', $findings, array_values($diagnostics));
    }

    private function contracts(array $modules, array &$findings, array &$gaps): void
    {
        $byName = array_column(array_filter($modules, static fn(array $module): bool => $module['identity'] !== null), null, 'identity');
        if ($byName === []) return;
        $analysis = $this->collectors->magentoAnalysis->collect($this->context, array_keys($byName));
        foreach ($analysis['gaps'] as $gap) {
            if ($gap['reason'] !== 'xml_parse_unavailable') $gaps[] = $gap;
        }
        foreach ($analysis['symbols'] as $rows) {
            if (count($rows) !== 1) continue;
            $child = $rows[0];
            if (!isset($byName[$child['module']])) continue;
            foreach (array_merge($child['extends'], $child['implements']) as $parent) {
                $candidates = $analysis['symbols'][strtolower(ltrim($parent, '\\'))] ?? [];
                if (count($candidates) !== 1) continue;
                foreach ($candidates[0]['methods'] as $name => $required) {
                    $method = $child['methods'][$name] ?? null;
                    if ($method === null || $name === '__construct' || $required['visibility'] !== 'public') continue;
                    if ($method['visibility'] === 'public' && $method['static'] === $required['static']) continue;
                    $finding = self::finding($byName[$child['module']], $child['file'], $method['line'], 'php-method-contract',
                        'PHP method conflicts with an indexed public parent or interface declaration.',
                        'The method changes public visibility or staticness relative to '.$parent.'::'.$required['name'].'.',
                        'Preserve visibility and staticness required by the parent declaration.', false);
                    $finding['locations'][] = ['file' => $candidates[0]['file'], 'line' => $required['line']];
                    $findings[] = $finding;
                }
            }
        }
    }

    private function scan(string $kind, array $modules, array $inventory, string $target, array &$findings, array &$gaps): void
    {
        $roots = array_slice(array_keys($modules), 0, 100);
        if (count($roots) < count($modules)) $gaps[] = ['reason' => 'selected_root_budget_exceeded'];
        $known = array_filter(array_column($inventory['modules'], 'root'), 'is_string');
        $source = (new BoundedSourceInventory($this->collectors->session))->collect($this->context, [
            'paths' => $roots, 'include_ext' => ['php'], 'verify_stable' => true,
            'exclude_paths' => array_values(array_diff($known, $roots)),
        ]);
        array_push($gaps, ...$source['gaps']);
        $parser = new MagentoStaticPhp();
        $finder = new NodeFinder();
        foreach ($source['files'] as $file) {
            $this->collectors->session->checkpoint();
            $path = $file['file'];
            $root = dirname($path);
            while ($root !== '.' && !isset($modules[$root])) $root = dirname($root);
            if (!isset($modules[$root])) continue;
            try {
                $nodes = $parser->parse($file['content']);
            } catch (Error) {
                $gaps[] = ['reason' => 'php_parse_unavailable', 'file' => $path];
                continue;
            }
            if ($kind === 'php-target') {
                foreach ($finder->find($nodes, static fn(Node $n): bool => self::feature($n) !== null) as $node) {
                    [$minimum, $feature] = self::feature($node);
                    if (version_compare($target, $minimum, '>=')) continue;
                    $findings[] = self::finding($modules[$root], $path, $node->getStartLine(), 'php-'.$feature,
                        'PHP syntax requires '.$minimum.' or newer.',
                        'The '.$feature.' feature exceeds the configured PHP target '.$target.'.',
                        'Use syntax compatible with the deployed PHP version or upgrade the target runtime.', false);
                }
                continue;
            }
            if ($kind === 'empty-catch' || $kind === 'loop-query') {
                foreach (self::operations($kind, $nodes, $finder) as [$line, $message, $reason, $fix]) {
                    $finding = self::finding($modules[$root], $path, $line, $kind, $message, $reason, $fix, false);
                    $finding['confidence'] = 'suspected';
                    $finding['severity'] = 'low';
                    if ($kind === 'loop-query') $finding['category'] = 'informational';
                    $findings[] = $finding;
                }
                continue;
            }
            $blocks = [$nodes];
            foreach ($finder->find($nodes, static fn(Node $n): bool => $n instanceof Node\FunctionLike || $n instanceof Node\Stmt\Namespace_) as $scope) {
                if ($scope instanceof Node\Expr\ArrowFunction) continue;
                $blocks[] = $scope instanceof Node\Stmt\Namespace_ ? $scope->stmts : ($scope->getStmts() ?? []);
            }
            foreach ($blocks as $statements) {
                foreach (self::flows($statements) as [$sink, $line, $sourceLine]) {
                    $findings[] = self::finding($modules[$root], $path, $line, $sink,
                        $sink === 'command' ? 'Request input reaches a command call.' : 'Request input reaches query text.',
                        'A request superglobal at line '.$sourceLine.' reaches a supported call directly or through one local assignment.',
                        $sink === 'command' ? 'Avoid passing request data to shell commands. Use fixed operations and validate inputs.'
                            : 'Use bound SQL parameters and validate the input at the boundary.', true, $sourceLine);
                }
            }
        }
    }

    private static function operations(string $kind, array $nodes, NodeFinder $finder): iterable
    {
        if ($kind === 'empty-catch') {
            foreach ($finder->findInstanceOf($nodes, Node\Stmt\Catch_::class) as $catch) {
                if (array_filter($catch->stmts, static fn(Node $stmt): bool => !$stmt instanceof Node\Stmt\Nop) !== []) continue;
                yield [$catch->getStartLine(), 'Empty catch block may suppress an operational failure.',
                    'The catch body has no executable statements. Ignoring the exception may be intentional.',
                    'Verify recovery behavior and add handling or document the intended fallback.'];
            }
            return;
        }
        foreach ($finder->find($nodes, static fn(Node $node): bool => $node instanceof Node\Stmt\Foreach_
            || $node instanceof Node\Stmt\For_ || $node instanceof Node\Stmt\While_ || $node instanceof Node\Stmt\Do_) as $loop) {
            foreach ($loop->stmts as $stmt) {
                if (!$stmt instanceof Node\Stmt\Expression) continue;
                $call = $stmt->expr instanceof Node\Expr\Assign ? $stmt->expr->expr : $stmt->expr;
                if (!$call instanceof Node\Expr\CallLike || $call->isFirstClassCallable() || self::sink($call) !== 'sql') continue;
                yield [$call->getStartLine(), 'Query-like call appears directly in a loop body.',
                    'The syntax allows a call on each iteration. Receiver behavior, loop cardinality and runtime cost are unknown.',
                    'Measure the loop on representative input and consider batching when the cost is material.'];
            }
        }
    }

    private static function feature(Node $node): ?array
    {
        return match (true) {
            $node instanceof Node\Stmt\Property && ($node->hooks !== [] || ($node->flags & (Modifiers::PUBLIC_SET | Modifiers::PROTECTED_SET | Modifiers::PRIVATE_SET))) => ['8.4', 'property-declaration'],
            $node instanceof Node\Stmt\ClassConst && $node->type !== null => ['8.3', 'typed-class-constant'],
            $node instanceof Node\Stmt\Class_ && $node->isReadonly() => [$node->isAnonymous() ? '8.3' : '8.2', 'readonly-class'],
            $node instanceof Node\UnionType && array_filter($node->types, static fn(Node $type): bool => $type instanceof Node\IntersectionType) !== [] => ['8.2', 'dnf-type'],
            default => null,
        };
    }

    private static function flows(array $statements): iterable
    {
        $locals = [];
        foreach ($statements as $statement) {
            $expr = $statement instanceof Node\Stmt\Expression || $statement instanceof Node\Stmt\Return_ ? $statement->expr : null;
            $assignment = $expr instanceof Node\Expr\Assign && $expr->var instanceof Node\Expr\Variable && is_string($expr->var->name);
            $call = $assignment ? $expr->expr : $expr;
            $arg = $call instanceof Node\Expr\CallLike && !$call->isFirstClassCallable() ? ($call->args[0] ?? null) : null;
            if ($arg instanceof Node\Arg && !$arg->unpack && $arg->name === null) {
                $sink = self::sink($call);
                $source = $sink !== null ? self::source($arg->value, $locals) : null;
                if ($source !== null) yield [$sink, $call->getStartLine(), $source];
            }
            // Track one hop only. Drop state at calls, branches and other unsupported statements.
            $locals = $assignment && ($line = self::source($expr->expr, [])) !== null ? [$expr->var->name => $line] : [];
        }
    }

    private static function sink(Node\Expr\CallLike $call): ?string
    {
        if ($call instanceof Node\Expr\FuncCall && $call->name instanceof Node\Name\FullyQualified
            && in_array(strtolower($call->name->toString()), self::COMMANDS, true)) return 'command';
        if (($call instanceof Node\Expr\MethodCall || $call instanceof Node\Expr\NullsafeMethodCall)
            && $call->name instanceof Node\Identifier && in_array(strtolower($call->name->name), ['query', 'rawquery', 'executequery'], true)) return 'sql';
        return null;
    }

    private static function source(Node $node, array $locals): ?int
    {
        if ($node instanceof Node\Expr\Variable && is_string($node->name)) {
            return in_array($node->name, self::INPUTS, true) ? $node->getStartLine() : ($locals[$node->name] ?? null);
        }
        if ($node instanceof Node\Expr\ArrayDimFetch) return self::source($node->var, $locals);
        if ($node instanceof Node\Expr\BinaryOp\Concat) return self::source($node->left, $locals) ?? self::source($node->right, $locals);
        if ($node instanceof Node\Scalar\InterpolatedString) {
            foreach ($node->parts as $part) {
                if (($line = self::source($part, $locals)) !== null) return $line;
            }
        }
        return null;
    }

    private static function finding(array $module, string $file, int $line, string $key, string $message, string $reasoning, string $remediation, bool $suspected, ?int $sourceLine = null): array
    {
        $locations = [['file' => $file, 'line' => $line]];
        if ($sourceLine !== null && $sourceLine !== $line) $locations[] = ['file' => $file, 'line' => $sourceLine];
        return compact('key', 'message', 'reasoning', 'remediation', 'locations') + [
            'category' => $suspected ? 'security' : 'correctness', 'confidence' => $suspected ? 'suspected' : 'confirmed',
            'severity' => $suspected ? 'high' : 'medium',
            'subject' => array_filter(['module' => $module['identity'], 'package' => $module['package'], 'version' => $module['version']]),
            'assumptions' => $suspected ? ['Receiver type, surrounding guards and runtime execution are outside this bounded flow.'] : [],
        ];
    }
}
