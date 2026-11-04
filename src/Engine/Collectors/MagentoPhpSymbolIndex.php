<?php
declare(strict_types=1);

namespace Magebean\Engine\Collectors;

use PhpParser\{Error, Node, NodeFinder};

final class MagentoPhpSymbolIndex
{
    public function __construct(private readonly MagentoStaticPhp $php = new MagentoStaticPhp()) {}

    public function index(array $files, ?CollectionSession $session = null): array
    {
        $symbols = [];
        $gaps = [];
        $patchFiles = [];
        $seen = 0;
        foreach ($files as $file) {
            if ($file['extension'] !== 'php') continue;
            $session?->checkpoint();
            try {
                $nodes = $this->php->parse($file['content']);
            } catch (Error $error) {
                $gaps[] = ['reason' => 'php_parse_unavailable', 'file' => $file['file'], 'line' => $error->getStartLine()];
                continue;
            }

            if (isset($file['module']) && preg_match('~^Setup/Patch/(Data|Schema)/([^/]+)\.php$~D', $file['module_relative_path'] ?? '', $parts)) {
                $patchFiles[$file['file']] = [
                    'module' => $file['module'],
                    'kind' => $parts[1],
                    'expected_class' => str_replace('_', '\\', $file['module']).'\\Setup\\Patch\\'.$parts[1].'\\'.$parts[2],
                ];
            }
            foreach ((new NodeFinder())->findInstanceOf($nodes, Node\Stmt\ClassLike::class) as $node) {
                if ($node->name === null || !isset($node->namespacedName)) continue;
                if (++$seen > 10000) {
                    $gaps[] = ['reason' => 'symbol_budget_exceeded', 'file' => $file['file']];
                    break 2;
                }
                $name = $node->namespacedName->toString();
                $methods = [];
                foreach ($node->getMethods() as $method) {
                    $parameters = [];
                    foreach ($method->params as $parameter) {
                        $parameters[] = [
                            'name' => $parameter->var instanceof Node\Expr\Variable ? $parameter->var->name : null,
                            'type' => self::type($parameter->type),
                            'optional' => $parameter->default !== null || $parameter->variadic,
                            'by_reference' => $parameter->byRef,
                            'variadic' => $parameter->variadic,
                        ];
                    }
                    $methods[strtolower($method->name->toString())] = [
                        'name' => $method->name->toString(),
                        'line' => $method->getStartLine(),
                        'visibility' => $method->isPrivate() ? 'private' : ($method->isProtected() ? 'protected' : 'public'),
                        'static' => $method->isStatic(),
                        'final' => $method->isFinal(),
                        'abstract' => $method->isAbstract() || $method->stmts === null,
                        'return_type' => self::type($method->returnType),
                        'parameters' => $parameters,
                    ];
                }
                $parents = match (true) {
                    $node instanceof Node\Stmt\Interface_ => $node->extends,
                    $node instanceof Node\Stmt\Class_ && $node->extends !== null => [$node->extends],
                    default => [],
                };
                $traits = [];
                foreach ($node->getTraitUses() as $use) {
                    foreach ($use->traits as $trait) $traits[] = $trait->toString();
                }
                $symbols[strtolower($name)][] = [
                    'name' => $name,
                    'kind' => match (true) {
                        $node instanceof Node\Stmt\Interface_ => 'interface',
                        $node instanceof Node\Stmt\Trait_ => 'trait',
                        $node instanceof Node\Stmt\Enum_ => 'enum',
                        default => 'class',
                    },
                    'file' => $file['file'],
                    'module' => $file['module'] ?? null,
                    'module_relative_path' => $file['module_relative_path'] ?? null,
                    'line' => $node->getStartLine(),
                    'abstract' => $node instanceof Node\Stmt\Class_ && $node->isAbstract(),
                    'final' => $node instanceof Node\Stmt\Class_ && $node->isFinal(),
                    'extends' => array_map(static fn(Node\Name $parent): string => $parent->toString(), $parents),
                    'implements' => array_map(static fn(Node\Name $interface): string => $interface->toString(), $node->implements ?? []),
                    'traits' => $traits,
                    'methods' => $methods,
                    'patch_dependencies' => self::patchDependencies($node, $file['module_relative_path'] ?? ''),
                ];
            }
        }
        ksort($symbols);
        return ['symbols' => $symbols, 'patch_files' => $patchFiles, 'gaps' => $gaps, 'complete' => $gaps === []];
    }

    private static function patchDependencies(Node\Stmt\ClassLike $node, string $path): ?array
    {
        if (!preg_match('~^Setup/Patch/(?:Data|Schema)/[^/]+\.php$~D', $path)) return null;
        $method = $node->getMethod('getDependencies');
        $body = $method?->stmts ?? [];
        if (count($body) !== 1 || !$body[0] instanceof Node\Stmt\Return_
            || !$body[0]->expr instanceof Node\Expr\Array_) return null;

        $dependencies = [];
        foreach ($body[0]->expr->items as $item) {
            if ($item->unpack || $item->key !== null) return null;
            $value = $item->value;
            if ($value instanceof Node\Expr\ClassConstFetch && $value->class instanceof Node\Name\FullyQualified
                && $value->name instanceof Node\Identifier && strtolower($value->name->name) === 'class') {
                $dependencies[] = $value->class->toString();
            } elseif ($value instanceof Node\Scalar\String_ && preg_match('/^\\\\?(?:[A-Za-z_][A-Za-z0-9_]*\\\\)+[A-Za-z_][A-Za-z0-9_]*$/D', $value->value)) {
                $dependencies[] = ltrim($value->value, '\\');
            } else {
                return null;
            }
        }
        return $dependencies;
    }

    private static function type(?Node $type): ?string
    {
        return match (true) {
            $type instanceof Node\NullableType => '?'.self::type($type->type),
            $type instanceof Node\UnionType => implode('|', array_map(static fn(Node $arm): string =>
                $arm instanceof Node\IntersectionType ? '('.self::type($arm).')' : self::type($arm), $type->types)),
            $type instanceof Node\IntersectionType => implode('&', array_map(self::type(...), $type->types)),
            $type instanceof Node\Identifier, $type instanceof Node\Name => $type->toString(),
            default => null,
        };
    }
}
