<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\{Context,RequirementAssessmentEvaluator,MagebeanRiskObservation};
use Magebean\Engine\Checks\CheckRegistry;
$catalog=array_column(json_decode(file_get_contents(__DIR__.'/../src/Rules/requirements/magebean-catalog.json'),true)['requirements'],null,'id');
$root=sys_get_temp_dir().'/mb-current-state-qa-'.bin2hex(random_bytes(5));mkdir($root);$results=[];
$put=static function(string $path,string $source)use($root):void{if(!is_dir(dirname($root.'/'.$path)))mkdir(dirname($root.'/'.$path),0700,true);file_put_contents($root.'/'.$path,$source);};
$observe=static function(string $id,string $case)use($catalog,$root,&$results):void{
 $registry=CheckRegistry::fromContext(new Context($root,''));$r=$catalog[$id];$binding=$r['checks'][0];$out=$registry->runResult($binding['name'],$binding['args']);
 $explicitCapability=$r['applicability']['capability']??null; if($explicitCapability!==null)$r['applicability']['state']='APPLICABLE';
 $assessment=RequirementAssessmentEvaluator::evaluate($r,fn($name,$args)=>$registry->runResult($name,$args));
 $risk=MagebeanRiskObservation::fromAssessment($r,$assessment);
 $results[]=['id'=>$id,'explicit_capability'=>$explicitCapability,'case'=>$case,'check_outcome'=>$out->outcome->value,'severity'=>$r['severity'],'message'=>$out->message,'risk_kind'=>$risk['findings'][0]['kind']??null,'confidence'=>$risk['findings'][0]['confidence']??null,'category'=>$risk['findings'][0]['category']??null,'needs_attention'=>$risk['needs_attention']];
};
try{
 $source='app/code/Acme/Probe/Probe.php';
 $put($source,'<?php $bytes = \\file_get_contents("/tmp/internal-report.txt");');
 $observe('MB-0788','fixed_local_file_read');$observe('MB-0792','same_fixed_local_file_read');
 $put($source,'<?php $theme = \\mt_rand(0, 1) ? "blue" : "green";');$observe('MB-0794','nonsecurity_ui_color_randomness');
 $put($source,'<?php $data = \\unserialize("a:1:{i:0;s:4:\"blue\";}", ["allowed_classes"=>false]);');$observe('MB-0789','constant_serialized_value_allowed_classes_false');
 $put($source,'<?php \\exec("/usr/bin/true");');$observe('MB-0790','fixed_command_no_request_input');
 $put($source,'<?php $label = "header"; $translator->query("label_".$label);');$observe('MB-0786','query_named_non_sql_receiver');
 $put($source,'<?php $select = $db->select()->from("products")->where("id = ?", (int)$input); $db->query($select);');$observe('MB-0786','approved_query_builder_passed_as_variable');
 $put($source,'<?php $db->query("SELECT id FROM products WHERE id = ?", [$input]);');$observe('MB-0786','literal_sql_and_bound_value');
 $put($source,'<?php class Callback { public function validateForCsrf($r): ?bool { return true; } public function execute(){ $provider->verifySignature($request); } }');$observe('MB-0787','csrf_exemption_with_alternate_auth_unverified');
 $put('app/design/Acme/theme/sample.phtml','<script>const label = "<?= $value ?>";</script>');
 $observe('MB-0733','inline_js_phtml_output');$observe('MB-0736','same_inline_js_phtml_output');
 unlink($root.'/app/design/Acme/theme/sample.phtml');
 $put('app/etc/env.php','<?php return ["system"=>["default"=>["admin/security/minimum_password_length"=>7]]];');
 $observe('MB-0728','declared_admin_minimum_seven');$observe('MB-0731','same_declared_admin_minimum_seven');
 unlink($root.'/'.$source);
 $put('app/etc/env.php','<?php return ["db"=>["connection"=>["default"=>["password"=>"qaSyntheticCredential123456789"]]]];');
 chmod($root.'/app/etc/env.php',0600);
 $observe('MB-0072','protected_deployment_env_not_vcs_history');$observe('MB-0730','same_env_excluded_from_deployed_secret_scope');
 echo json_encode(['scope'=>'read-only detector evaluation of inert temporary source; no sample source is executed, no external network','results'=>$results],JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES)."\n";
}finally{$it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST);foreach($it as$f){if($f->isDir()&&!$f->isLink())rmdir($f->getPathname());else unlink($f->getPathname());}rmdir($root);}

