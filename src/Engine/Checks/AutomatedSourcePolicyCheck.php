<?php
declare(strict_types=1);
namespace Magebean\Engine\Checks;

use Magebean\Engine\{Context,CheckOutcome,CheckResult,SourceInspectionIssue};
use Magebean\Engine\Collectors\BoundedSourceInventory;
use PhpParser\{Node, NodeFinder, NodeTraverser, ParserFactory};
use PhpParser\NodeVisitor\NameResolver;

/** Exact syntactic policies, not evidence of global exploitability or absence of vulnerabilities. */
final class AutomatedSourcePolicyCheck
{
    private const BANS=[
        'native_unserialize'=>['unserialize'],
        'shell_execution'=>['exec','system','passthru','shell_exec','popen','proc_open','pcntl_exec'],
        'dynamic_execution'=>['eval','create_function'],
        'weak_prng'=>['rand','mt_rand','lcg_value','uniqid','srand','mt_srand'],
        'raw_crypto_session'=>['session_start','session_id','session_regenerate_id','session_set_save_handler','mcrypt_encrypt','mcrypt_decrypt','md5','sha1','crypt','openssl_encrypt','openssl_decrypt'],
        'native_network'=>['curl_exec','curl_multi_exec','fsockopen','pfsockopen','stream_socket_client','file_get_contents'],
        'native_filesystem'=>['file_get_contents','file_put_contents','fopen','readfile','unlink','rename','copy','scandir','glob'],
        'native_upload'=>['move_uploaded_file'],
    ];
    public function __construct(private readonly Context $ctx,private readonly ?BoundedSourceInventory $inventory=null){}
    public function run(array $args):CheckResult
    {
        $deadline=microtime(true)+max(0.001,min(30,(float)($args['timeout_seconds']??5)));
        $kind=(string)($args['kind']??'');
        if(!isset(self::BANS[$kind])&&!in_array($kind,['sql_literal_query','xml_external_features','literal_https','csrf_unconditional_bypass','direct_request_logging'],true))throw new \InvalidArgumentException('Unsupported automated source policy kind.');
        $inventory=($this->inventory??new BoundedSourceInventory())->collect($this->ctx,$args);
        $evidence=$inventory;unset($evidence['files']);$evidence['policy']=$kind;$evidence['violations']=[];
        $evidence['limitations']=['Exact syntactic policy only; excludes dependencies, generated code and files outside the declared scope.','No dataflow, business authorization or runtime exploitability conclusion.'];
        if($this->emptyOptionalCustomScope($inventory)){
            $evidence['scope_state']='empty_optional_custom_source';
            $evidence['complete']=true;$evidence['gaps']=[];$evidence['analysis_gaps']=[];$evidence['inspection_issues']=[];
            return CheckResult::of(CheckOutcome::Pass,'No custom PHP/PHTML files exist in the optional app/code scope of this Magento deployment; no source finding was produced.',$evidence,'SOURCE_SCOPE_EMPTY');
        }
        $gaps=[];
        foreach($inventory['files'] as $file){
            if(microtime(true)>$deadline){$gaps[]=['file'=>$file['file'],'reason'=>'analysis_deadline_exceeded'];break;}
            if(!in_array($file['extension'],['php','phtml'],true)){$gaps[]=['file'=>$file['file'],'reason'=>'unsupported_parser'];continue;}
            try{$raw=token_get_all($file['content'],TOKEN_PARSE);}catch(\ParseError $error){$gap=['file'=>$file['file'],'reason'=>'malformed_php'];if($error->getLine()>0)$gap['line']=$error->getLine();$gaps[]=$gap;continue;}
            $tokens=[];$line=1;$byte=0;
            foreach($raw as $token){$value=is_array($token)?$token[1]:$token;$start=is_array($token)?$token[2]:$line;$line+=substr_count($value,"\n");$offset=$byte;$byte+=strlen($value);if(is_array($token)&&in_array($token[0],[T_WHITESPACE,T_COMMENT,T_DOC_COMMENT,T_OPEN_TAG,T_CLOSE_TAG],true))continue;$tokens[]=['id'=>is_array($token)?$token[0]:null,'text'=>$value,'line'=>$start,'byte_offset'=>$offset];}
            $sourceHash=hash('sha256',$file['content']);
            $violate=function(int $line,string $construct,?int $offset=null)use(&$evidence,$file,$sourceHash):void{if(count($evidence['violations'])<100)$evidence['violations'][]=['file'=>$file['file'],'line'=>$line,'construct'=>$construct,'source_sha256'=>$sourceHash]+($offset!==null&&$offset>=0?['byte_offset'=>$offset]:[]);else $evidence['violations_truncated']=true;};
            $uncertain=function(int $line,string $reason)use(&$gaps,$file):void{if(count($gaps)<100)$gaps[]=['file'=>$file['file'],'line'=>$line,'reason'=>$reason];};
            if ($kind === 'csrf_unconditional_bypass' || isset(self::BANS[$kind])) {
                try {
                    $nodes = (new ParserFactory())->createForNewestSupportedVersion()->parse($file['content']) ?? [];
                    $nodes = (new NodeTraverser(new NameResolver(null, ['preserveOriginalNames' => true])))->traverse($nodes);
                    $this->resolvedPolicies($kind, $nodes, $violate, $uncertain);
                } catch (\PhpParser\Error) {
                    $uncertain(1, 'source_name_resolution_unavailable');
                }
            }
            foreach($tokens as $i=>$token){
                if(($i&255)===0&&microtime(true)>$deadline){$gaps[]=['file'=>$file['file'],'reason'=>'analysis_deadline_exceeded'];break 2;}
                $text=strtolower($token['text']);$prev=$tokens[$i-1]['text']??'';$next=$tokens[$i+1]['text']??'';
                if($kind==='csrf_unconditional_bypass')continue;
                if($kind==='direct_request_logging'){
                    if($next==='('&&in_array($prev,['->','?->','::'],true)&&in_array($text,['log','debug','info','notice','warning','error','critical','alert','emergency'],true)){
                        $depth=1;
                        for($j=$i+2;$j<count($tokens)&&$depth>0;$j++){
                            if($tokens[$j]['text']==='(')$depth++;elseif($tokens[$j]['text']===')')$depth--;
                            if($depth>0&&$tokens[$j]['id']===T_VARIABLE&&in_array($tokens[$j]['text'],['$_GET','$_POST','$_REQUEST','$_COOKIE','$_SERVER','$_FILES'],true))$violate($tokens[$j]['line'],'request_superglobal_in_log_arguments',$tokens[$j]['byte_offset']);
                        }
                    }
                    continue;
                }
                if($kind==='literal_https'){
                    if($token['id']===T_CONSTANT_ENCAPSED_STRING){$literal=substr($token['text'],1,-1);if(preg_match('~^http://~i',$literal))$violate($token['line'],'plain_http_literal');}
                    continue;
                }
                if($kind==='xml_external_features'){
                    if(in_array(ltrim($text,'\\'),['libxml_noent','libxml_dtdload','libxml_dtdattr'],true)&&in_array($token['id'],[T_STRING,T_NAME_FULLY_QUALIFIED],true))$violate($token['line'],'prohibited_xml_constant');
                    if(in_array($text,['resolveexternals','substituteentities','validateonparse'],true)&&$prev==='->'&&$next==='='){
                        $value=strtolower($tokens[$i+2]['text']??'');if($value!=='false')$violate($token['line'],'prohibited_xml_property_assignment');
                    }
                    if($next==='('&&in_array($text,['xinclude','xml_set_external_entity_ref_handler'],true))$violate($token['line'],'prohibited_xml_call');
                    continue;
                }
                if($kind==='sql_literal_query'){
                    if($next!=='('||!in_array($text,['query','rawquery','exec','executequery'],true)||!in_array($prev,['->','?->','::'],true))continue;
                    $arg=$tokens[$i+2]??null;
                    if($arg===null)continue;
                    if($arg['text']==='"'){$violate($token['line'],'sql_first_argument_interpolated');continue;}
                    if($arg['id']!==T_CONSTANT_ENCAPSED_STRING){$uncertain($token['line'],'sql_first_argument_not_static_literal');continue;}
                    $after=$tokens[$i+3]['text']??'';
                    if($after==='.')$violate($token['line'],'sql_first_argument_concatenated');
                    elseif(!in_array($after,[',',')'],true))$uncertain($token['line'],'sql_first_argument_expression_unresolved');
                    continue;
                }
                // Backtick commands are emitted once from their AST ShellExec node above.
                if($kind==='dynamic_execution'&&$token['id']===T_EVAL){$violate($token['line'],'eval');continue;}
                if($kind==='dynamic_execution'&&in_array($token['id'],[T_INCLUDE,T_INCLUDE_ONCE,T_REQUIRE,T_REQUIRE_ONCE],true)){
                    $offset=($tokens[$i+1]['text']??'')==='('?2:1;
                    if(($tokens[$i+$offset]['id']??null)!==T_CONSTANT_ENCAPSED_STRING)$uncertain($token['line'],'dynamic_include_target');
                }
                // Function aliases and indirect call targets cannot be certified by a lexical name ban.
                if($token['id']===T_USE&&strtolower($tokens[$i+1]['text']??'')==='function')$uncertain($token['line'],'function_alias_requires_resolution');
                if($next==='('&&($token['id']===T_VARIABLE||$prev===')'))$uncertain($token['line'],'indirect_callable');
                if($next!=='('||in_array($prev,['->','?->','::','function','new'],true))continue;
                if(!in_array($token['id'],[T_STRING,T_NAME_FULLY_QUALIFIED,T_NAME_QUALIFIED],true))continue;
                $name=ltrim($text,'\\');
                if(str_contains($name,'\\'))continue;
                // Native identity is resolved from the AST above; lexical spelling cannot distinguish namespace-local functions.
                if(in_array($name,['call_user_func','call_user_func_array','forward_static_call','forward_static_call_array'],true))$uncertain($token['line'],'indirect_dispatch');
                if($kind==='dynamic_execution'&&$name==='assert'&&($tokens[$i+2]['id']??null)!==T_VARIABLE)$uncertain($token['line'],'assertion_expression_requires_version_resolution');
            }
        }
        $evidence['analysis_gaps']=$gaps;
        $evidence['inspection_issues']=SourceInspectionIssue::fromGaps($inventory['gaps'],$gaps,$inventory['scope']);
        // A proven syntactic violation remains actionable even if other files could not be collected.
        if($evidence['violations']!==[])return CheckResult::of(CheckOutcome::Fail,'Source violates the declared '.$kind.' policy; see file and line evidence.',$evidence,'SOURCE_POLICY_VIOLATION');
        if(!$inventory['complete']||$gaps!==[]){
            $first=$evidence['inspection_issues'][0]??null;
            $message=$first!==null?$first['message'].' '.$first['action']:'No complete supported source observation is available; verify the configured local source scope and scanner compatibility.';
            $remaining=count($evidence['inspection_issues'])-1;
            if($remaining>0)$message.=' '.$remaining.' additional inspection issue'.($remaining===1?'':'s').' listed in evidence.';
            return CheckResult::of(CheckOutcome::Unknown,'[UNKNOWN] '.$message,$evidence,'SOURCE_POLICY_INCOMPLETE');
        }
        return CheckResult::of(CheckOutcome::Pass,'Every collected eligible source file satisfies the declared '.$kind.' syntax policy.',$evidence,'SOURCE_POLICY_SATISFIED');
    }

    private function resolvedPolicies(string $kind, array $nodes, callable $violate, callable $uncertain): void
    {
        $finder = new NodeFinder();
        if ($kind === 'csrf_unconditional_bypass') {
            foreach ($finder->findInstanceOf($nodes, Node\Stmt\ClassMethod::class) as $method) {
                if (strtolower($method->name->toString()) !== 'validateforcsrf') continue;
                $body = array_values(array_filter($method->stmts ?? [], static fn(Node $n): bool => !$n instanceof Node\Stmt\Nop));
                if (count($body) === 1 && $body[0] instanceof Node\Stmt\Return_
                    && $body[0]->expr instanceof Node\Expr\ConstFetch
                    && strtolower($body[0]->expr->name->toString()) === 'true') $violate($method->getStartLine(), 'unconditional_csrf_acceptance');
            }
            return;
        }
        if ($kind==='shell_execution') foreach ($finder->findInstanceOf($nodes,Node\Expr\ShellExec::class) as $shell) $violate($shell->getStartLine(),'shell_backtick',$shell->getStartFilePos());
        $declared = [];
        foreach ($finder->findInstanceOf($nodes, Node\Stmt\Function_::class) as $function) {
            if (isset($function->namespacedName)) $declared[strtolower($function->namespacedName->toString())] = true;
        }
        foreach ($finder->findInstanceOf($nodes, Node\Expr\FuncCall::class) as $call) {
            if (!$call->name instanceof Node\Name || $call->isFirstClassCallable()) continue;
            $name = strtolower($call->name->toString());
            $original = $call->name->getAttribute('originalName', $call->name);
            // Aliases retain the existing explicit collection gap until the complete alias scope is supported.
            if (!in_array(strtolower(ltrim($original->toString(), '\\')), self::BANS[$kind], true)) continue;
            if (isset($declared[$name])) continue;
            if ($call->name instanceof Node\Name\FullyQualified) {
                if (in_array($name, self::BANS[$kind], true)) $violate($call->getStartLine(), $name, $call->getStartFilePos());
                continue;
            }
            $candidate = $call->name->getAttribute('namespacedName');
            if ($candidate instanceof Node\Name && isset($declared[strtolower($candidate->toString())])) continue;
            $uncertain($call->getStartLine(), 'native_function_namespace_resolution_unavailable');
        }
    }

    private function emptyOptionalCustomScope(array $inventory):bool
    {
        if(($inventory['files_read']??0)!==0||array_map(static fn(string $p):string=>trim(str_replace('\\','/',$p),'/'),$inventory['scope']??[])!==['app/code'])return false;
        if(($this->ctx->get('meta',[])['target_mode']??'')==='REMOTE')return false;
        foreach(['bin/magento','app/etc/config.php']as$marker)if(!is_file($this->ctx->abs($marker))||!is_readable($this->ctx->abs($marker))||is_link($this->ctx->abs($marker)))return false;
        foreach($inventory['gaps']??[]as$gap)if(!in_array($gap['reason']??'', ['missing_source_path','no_eligible_source_files'],true))return false;
        $source=$this->ctx->abs('app/code');
        return !is_link($source)&&(!file_exists($source)||(is_dir($source)&&is_readable($source)));
    }
}
