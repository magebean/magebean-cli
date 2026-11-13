<?php
declare(strict_types=1);
namespace Magebean\Engine\Checks;

use Magebean\Engine\Context;
use Magebean\Engine\Collectors\{BoundedSourceInventory, CollectorSet, MagentoStaticPhp};
use PhpParser\{Node, NodeFinder, Error};

/** Exact template-output syntax observations; unsupported contexts never become clean coverage. */
final class ScopedTemplateOutputCheck
{
    public function __construct(private readonly Context $context, private readonly CollectorSet $collectors) {}

    public function run(array $args, bool $jsOnly = false): array
    {
        $inventory = (new BoundedSourceInventory($this->collectors->session))->collect($this->context, [
            'paths'=>$args['paths']??['app'], 'include_ext'=>$jsOnly?['phtml','html']:['phtml'],
            'verify_stable'=>true,
        ] + array_intersect_key($args, array_flip(['max_files','max_file_bytes','max_total_bytes','timeout_seconds'])));
        $gaps = $inventory['gaps']; $findings = []; $outputs = 0;
        $limit = max(1, min(1000, (int)($args['max_results']??50)));
        foreach ($inventory['files'] as $file) {
            $sourceHash=hash('sha256',$file['content']);
            $this->collectors->session->checkpoint();
            try { $nodes = (new MagentoStaticPhp())->parse($file['content']); }
            catch (Error) { $gaps[] = ['file'=>$file['file'], 'reason'=>'template_php_parse_unavailable']; continue; }
            if (preg_match('~<\?(?!php\b|=|xml\b)~i', $file['content'])) $gaps[] = ['file'=>$file['file'], 'reason'=>'short_php_tag_mode_unresolved'];
            $finder = new NodeFinder();
            foreach ($finder->find($nodes, static fn(Node $node):bool => $node instanceof Node\Expr\Include_ || $node instanceof Node\Expr\Eval_ || ($node instanceof Node\Stmt\Expression && ($node->expr instanceof Node\Expr\FuncCall || $node->expr instanceof Node\Expr\MethodCall || $node->expr instanceof Node\Expr\StaticCall))) as $opaque) {
                $gaps[] = ['file'=>$file['file'], 'line'=>$opaque->getStartLine(), 'reason'=>'opaque_output_side_effect_unresolved'];
            }

            $functions = $finder->find($nodes, static fn(Node $node):bool => $node instanceof Node\FunctionLike);
            $mask = ''; foreach (token_get_all($file['content']) as $token) {
                $text = is_array($token)?$token[1]:$token;
                $mask .= is_array($token)&&$token[0]===T_INLINE_HTML ? $text : preg_replace('/[^\r\n]/', ' ', $text);
            }
            $receiverReassigned = $finder->findFirst($nodes, static fn(Node $n):bool => ($n instanceof Node\Expr\Assign || $n instanceof Node\Expr\AssignRef || $n instanceof Node\Expr\AssignOp) && $n->var instanceof Node\Expr\Variable && in_array($n->var->name, ['escaper','block'], true)) !== null;
            if ($receiverReassigned) $gaps[] = ['file'=>$file['file'], 'reason'=>'template_receiver_reassigned'];
            $outputNodes = $finder->find($nodes, static fn(Node $node):bool => $node instanceof Node\Stmt\Echo_ || $node instanceof Node\Expr\Print_);
            $dynamicMarkup = false;
            foreach ($outputNodes as $node) {
                $context = $dynamicMarkup ? 'unsupported_dynamic_markup' : self::outputContext(substr($mask, 0, $node->getStartFilePos()));
                if ($jsOnly && !in_array($context, ['js_string','js_expression','js_attribute','unsupported_script'], true)) {
                    if ($context === 'html_text' || $context === 'html_attribute' || $context === 'url_attribute') continue;
                    $gaps[] = ['file'=>$file['file'], 'line'=>$node->getStartLine(), 'reason'=>'template_context_unsupported']; continue;
                }
                ++$outputs;
                $deferred = false;
                foreach ($functions as $function) if ($node->getStartFilePos() > $function->getStartFilePos() && $node->getEndFilePos() < $function->getEndFilePos()) $deferred = true;
                if ($deferred || str_starts_with($context, 'unsupported') || $context === 'js_attribute') {
                    $gaps[] = ['file'=>$file['file'], 'line'=>$node->getStartLine(), 'reason'=>'template_context_unsupported']; continue;
                }
                $expressions = $node instanceof Node\Stmt\Echo_ ? $node->exprs : [$node->expr];
                foreach ($expressions as $expr) {
                    if ($finder->findFirst([$expr], static fn(Node $n):bool => $n instanceof Node\Scalar\String_ && strpbrk($n->value, '<>\"\'') !== false) !== null) $dynamicMarkup = true;
                    $safe = $receiverReassigned ? null : self::safeExpression($expr, $context);
                    if ($safe === true) continue;
                    $location = ['file'=>$file['file'], 'line'=>$expr->getStartLine(), 'byte_offset'=>$expr->getStartFilePos(), 'source_sha256'=>$sourceHash, 'context'=>$context];
                    if ($safe === null) $gaps[] = $location+['reason'=>'output_expression_or_sanitizer_unresolved'];
                    else $findings[] = $location+['kind'=>'unescaped_dynamic_output'];
                    if (count($findings)>=$limit) { $gaps[]=['file'=>$file['file'],'reason'=>'template_findings_truncated']; break 3; }
                }
            }
        }
        $evidence = ['scope'=>$jsOnly?'supported direct PHP output in script strings/expressions':'supported direct PHP template output contexts', 'files_read'=>$inventory['files_read'], 'outputs_assessed'=>$outputs, 'matches'=>$findings, 'collection_gaps'=>$gaps];
        if ($findings !== []) return [false, 'Dynamic template output lacks the supported context-specific encoding', $evidence];
        if ($gaps !== []) return [null, '[UNKNOWN] Template output scope is incomplete or unsupported', $evidence];
        return [true, 'All collected supported direct template outputs use context-specific encoding or static values', $evidence];
    }

    private static function safeExpression(Node\Expr $expr, string $context): ?bool
    {
        if (($expr instanceof Node\Scalar\String_ || $expr instanceof Node\Scalar\Int_ || $expr instanceof Node\Scalar\Float_) || ($expr instanceof Node\Expr\ConstFetch && in_array(strtolower($expr->name->toString()), ['true','false','null'], true))) return true;
        if ($expr instanceof Node\Expr\Cast\Int_ || $expr instanceof Node\Expr\Cast\Double || $expr instanceof Node\Expr\Cast\Bool_) return true;
        if ($expr instanceof Node\Expr\BinaryOp\Concat) {
            $left=self::safeExpression($expr->left,$context);$right=self::safeExpression($expr->right,$context);
            return $left===false||$right===false?false:($left===true&&$right===true?true:null);
        }
        if ($expr instanceof Node\Expr\Ternary && $expr->if !== null) {
            $a=self::safeExpression($expr->if,$context);$b=self::safeExpression($expr->else,$context);
            return $a===false||$b===false?false:($a===true&&$b===true?true:null);
        }
        $name = null;
        if ($expr instanceof Node\Expr\StaticCall) return null;
        if ($expr instanceof Node\Expr\MethodCall) {
            if (!$expr->var instanceof Node\Expr\Variable || !in_array($expr->var->name, ['escaper','block'], true)) return null;
            if (!$expr->name instanceof Node\Identifier) return null;
            $name = strtolower($expr->name->name);
        } elseif ($expr instanceof Node\Expr\FuncCall) {
            if (!$expr->name instanceof Node\Name) return null;
            $name = strtolower(ltrim($expr->name->toString(),'\\'));
            if ($name !== 'json_encode' || (!$expr->name instanceof Node\Name\FullyQualified && $expr->name->getAttribute('namespacedName') instanceof Node\Name)) return null;
        }
        $helpers = ['html_text'=>['escapehtml'], 'html_attribute'=>['escapehtmlattr'], 'url_attribute'=>['escapeurl'], 'js_string'=>['escapejs'], 'js_expression'=>['json_encode']];
        if ($name !== null) {
            if ($name === 'escapejsquote') return null; // Legacy/custom quote-only helpers are outside the verified syntax set.
            if ($context==='js_expression' && $name==='json_encode' && !$expr instanceof Node\Expr\FuncCall) return null;
            if (!in_array($name,$helpers[$context]??[],true)) return in_array($name,['escapehtml','escapehtmlattr','escapeurl','escapejs','escapejsquote','escapecss','json_encode'],true)?false:null;
            if (count($expr->args)!==1 || !$expr->args[0] instanceof Node\Arg || $expr->args[0]->unpack || $expr->args[0]->name!==null) return null;
            // json_encode default slash escaping prevents a dynamic script-end tag;
            // custom flags/options require separate supported analysis.
            return true;
        }
        if ($expr instanceof Node\Expr\Variable || $expr instanceof Node\Expr\ArrayDimFetch || $expr instanceof Node\Expr\PropertyFetch || $expr instanceof Node\Scalar\InterpolatedString || $expr instanceof Node\Expr\Cast\String_) return false;
        return null;
    }

    /** Classify HTML boundaries without letting PHP strings/comments become markup. */
    private static function outputContext(string $html): string
    {
        $mode='text';$tag='';$quote='';$rawStart=0;$length=strlen($html);
        for($i=0;$i<$length;++$i){
            if($mode==='comment'){if(substr($html,$i,3)==='-->'){$mode='text';$i+=2;}continue;}
            if($mode==='script'||$mode==='style'){
                if(strncasecmp(substr($html,$i),'</'.$mode,strlen($mode)+2)===0){$mode='tag';$tag='<';$quote='';}
                else continue;
            }
            if($mode==='text'){
                if(substr($html,$i,4)==='<!--'){$mode='comment';$i+=3;continue;}
                if($html[$i]==='<'){$mode='tag';$tag='<';$quote='';}continue;
            }
            if($mode==='tag'){
                if($html[$i]==='<'&&$tag==='<')continue;
                $tag.=$html[$i];
                if($quote!==''){if($html[$i]===$quote)$quote='';continue;}
                if($html[$i]==='"'||$html[$i]==="'"){$quote=$html[$i];continue;}
                if($html[$i]==='>'){
                    if(preg_match('~^<script\b~i',$tag)){
                        if(preg_match('~\btype\s*=\s*([\x22\x27])(?:text/template|text/x-magento-template)\1~i',$tag))return 'unsupported_script';
                        $mode='script';$rawStart=$i+1;
                    }elseif(preg_match('~^<style\b~i',$tag)){$mode='style';$rawStart=$i+1;}
                    else $mode='text';
                }
            }
        }
        if($mode==='comment'||$mode==='style')return 'unsupported_context';
        if($mode==='script'){
            $js=substr($html,$rawStart);if(preg_match('~\\\\\s*$~',$js))return 'unsupported_script';$state='';$escaped=false;$comment='';
            for($i=0,$n=strlen($js);$i<$n;++$i){$c=$js[$i];$next=$js[$i+1]??'';
                if($comment==='line'){if($c==="\n")$comment='';continue;}
                if($comment==='block'){if($c==='*'&&$next==='/'){$comment='';++$i;}continue;}
                if($state!==''){if($escaped){$escaped=false;continue;}if($c==='\\'){$escaped=true;continue;}if($c===$state)$state='';continue;}
                if($c==='/'&&$next==='/'){$comment='line';++$i;continue;}
                if($c==='/'&&$next==='*'){$comment='block';++$i;continue;}
                if($c==='/')return 'unsupported_script';
                if($c==="'"||$c==='"'||$c==='`')$state=$c;
            }
            if($comment!==''||$state==='`')return 'unsupported_script';
            return $state!==''?'js_string':'js_expression';
        }
        if($mode==='tag'){
            if($quote===''||!preg_match('~([a-z_:][a-z0-9_:.-]*)\s*=\s*[\x22\x27][^\x22\x27]*$~is',$tag,$m))return 'unsupported_context';
            $attribute=strtolower($m[1]);
            if(str_starts_with($attribute,'on')||in_array($attribute,['data-mage-init','x-magento-init'],true))return 'js_attribute';
            if($attribute==='style'||$attribute==='srcdoc')return 'unsupported_context';
            return in_array($attribute,['href','src','action','formaction','poster'],true)?'url_attribute':'html_attribute';
        }
        return 'html_text';
    }
}
