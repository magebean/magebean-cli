<?php
declare(strict_types=1);
namespace Magebean\Engine\Collectors;

final class PhpArrayCollector
{
    public function __construct(private readonly ?CollectionSession $session = null) {}

    /** Literal declarations share one scan observation; executable/dynamic configuration stays fresh. */
    public function load(string $file, string $label, callable $evaluate): array
    {
        if (!is_file($file)) return ['__ERROR__'=>"$label not found"];
        $literal=$this->literal($file);
        if ($literal!==null) return $literal;
        $data=$evaluate();
        return is_array($data)?$data:['__ERROR__'=>"$label did not return array"];
    }

    /** Never executes target PHP. Null means unsupported or unreadable, never a clean empty config. */
    public function literal(string $file): ?array
    {
        $load=static function () use ($file): ?array {
            if (!is_file($file) || (@filesize($file)?:0)>4*1024*1024) return null;
            $source=@file_get_contents($file);
            if (!is_string($source)) return null;
            try {
                $nodes=(new MagentoStaticPhp())->parse($source); $returns=[];
                foreach ($nodes as $node) {
                    if ($node instanceof \PhpParser\Node\Stmt\Nop) continue;
                    if ($node instanceof \PhpParser\Node\Stmt\Declare_ && $node->stmts===null) continue;
                    if (!$node instanceof \PhpParser\Node\Stmt\Return_) return null;
                    $returns[]=$node;
                }
                if (count($returns)!==1 || !$returns[0]->expr instanceof \PhpParser\Node\Expr\Array_) return null;
                $evaluator=new \PhpParser\ConstExprEvaluator(static function (): never { throw new \RuntimeException('Dynamic config'); });
                $data=$evaluator->evaluateDirectly($returns[0]->expr);
                return is_array($data)?$data:null;
            } catch (\PhpParser\Error|\PhpParser\ConstExprEvaluationException|\RuntimeException) { return null; }
        };
        return $this->session!==null?$this->session->remember('literal-config:'.$file,$load):$load();
    }
}
