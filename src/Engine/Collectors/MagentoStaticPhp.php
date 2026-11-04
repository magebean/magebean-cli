<?php
declare(strict_types=1);

namespace Magebean\Engine\Collectors;

use PhpParser\{Node, NodeFinder, NodeTraverser, Parser, ParserFactory};
use PhpParser\NodeVisitor\NameResolver;

final class MagentoStaticPhp
{
    private ?Parser $parser = null;

    public function parse(string $source): array
    {
        $this->parser ??= (new ParserFactory())->createForNewestSupportedVersion();
        $nodes = $this->parser->parse($source) ?? [];
        return (new NodeTraverser(new NameResolver()))->traverse($nodes);
    }

    /** The generated deployment config is a literal return array. Other expressions are never evaluated. */
    public function moduleStates(string $source): ?array
    {
        $nodes = $this->parse($source);
        foreach ($nodes as $node) {
            if (!$node instanceof Node\Stmt\Return_ && !$node instanceof Node\Stmt\Declare_ && !$node instanceof Node\Stmt\Nop) return null;
            if ($node instanceof Node\Stmt\Declare_ && $node->stmts !== null) return null;
        }
        $returns = array_values(array_filter($nodes, static fn(Node $node): bool => $node instanceof Node\Stmt\Return_));
        if (count($returns) !== 1 || !$returns[0]->expr instanceof Node\Expr\Array_) return null;
        $modules = null;
        foreach ($returns[0]->expr->items as $item) {
            if ($item->unpack || !$item->key instanceof Node\Scalar\String_) return null;
            if ($item->key->value !== 'modules') continue;
            if ($modules !== null || !$item->value instanceof Node\Expr\Array_) return null;
            $modules = [];
            foreach ($item->value->items as $module) {
                if ($module->unpack || !$module->key instanceof Node\Scalar\String_
                    || !$module->value instanceof Node\Scalar\Int_
                    || !in_array($module->value->value, [0, 1], true)
                    || array_key_exists($module->key->value, $modules)) return null;
                $modules[$module->key->value] = $module->value->value === 1;
            }
        }
        return $modules;
    }

    public function registrations(string $source): array
    {
        $registrations = [];
        $nodes = $this->parse($source);
        $direct = [];
        foreach ($nodes as $node) {
            foreach ($node instanceof Node\Stmt\Namespace_ ? $node->stmts : [$node] as $statement) {
                if ($statement instanceof Node\Stmt\Expression && $statement->expr instanceof Node\Expr\StaticCall) {
                    $direct[spl_object_id($statement->expr)] = true;
                }
            }
        }
        $unresolved = false;
        foreach ((new NodeFinder())->findInstanceOf($nodes, Node\Expr\StaticCall::class) as $call) {
            if (!self::registrar($call->class) || !$call->name instanceof Node\Identifier
                || strtolower($call->name->name) !== 'register') continue;
            [$type, $name, $path] = array_pad($call->args, 3, null);
            if (!isset($direct[spl_object_id($call)]) || count($call->args) !== 3 || !$type instanceof Node\Arg || !$name instanceof Node\Arg || !$path instanceof Node\Arg
                || $type->name !== null || $name->name !== null || $path->name !== null
                || $type->unpack || $name->unpack || $path->unpack
                || !$type->value instanceof Node\Expr\ClassConstFetch
                || !self::registrar($type->value->class)
                || !$type->value->name instanceof Node\Identifier
                || !$name->value instanceof Node\Scalar\String_
                || !$path->value instanceof Node\Scalar\MagicConst\Dir) {
                $unresolved = true;
                continue;
            }
            $registrations[] = [
                'type' => strtolower($type->value->name->name),
                'name' => $name->value->value,
                'line' => $call->getStartLine(),
            ];
        }
        return ['entries' => $registrations, 'unresolved' => $unresolved];
    }

    private static function registrar(Node $class): bool
    {
        return $class instanceof Node\Name
            && strcasecmp($class->toString(), 'Magento\Framework\Component\ComponentRegistrar') === 0;
    }
}
