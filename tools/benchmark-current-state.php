<?php
declare(strict_types=1);
$root=$argv[1]??'';$archive=$argv[2]??'';
require $archive!==''?'phar://'.realpath($archive).'/vendor/autoload.php':__DIR__.'/../vendor/autoload.php';
use Magebean\Engine\{Context,ScanPlanner,ScanRequest,ScanRunner};
use Magebean\Engine\Checks\CheckRegistry;
use Magebean\Engine\Collectors\CollectorSet;
$ctx=new Context($root,'','',['meta'=>['target_mode'=>'LOCAL','launch_profile'=>'development']]);
$c=new CollectorSet();$registry=CheckRegistry::fromContext($ctx,$c);
$start=hrtime(true);$plan=(new ScanPlanner())->planCli(new ScanRequest($ctx->toScanContext(),['profile'=>'development']),$registry);
$report=(new ScanRunner($ctx,$plan->pack,null,$registry))->run();$scanSeconds=(hrtime(true)-$start)/1e9;
$checks=[];foreach($plan->pack['rules'] as $r)foreach($r['checks']??[] as $check)$checks[]=$check['name'];
$risks=[];$gaps=[];foreach($report['findings'] as $f){if($f['risk_observation']['needs_attention']??false)$risks[]=$f['id'];if(!($f['risk_observation']['collection_complete']??true))$gaps[]=$f['id'];}
$modules=array_keys((require $root.'/app/etc/config.php')['modules']);
$c->session->begin();$start=hrtime(true);$analysis=$c->magentoAnalysis->collect($ctx,$modules);$analysisSeconds=(hrtime(true)-$start)/1e9;$stats=$c->session->stats();$c->session->end();
$limited=(new \Magebean\Engine\Collectors\BoundedSourceInventory())->collect($ctx,['paths'=>['app/code'],'include_ext'=>['php'],'max_files'=>10]);
if($limited['complete']||$limited['files_read']!==10||!in_array('file_budget_exceeded',array_column($limited['gaps'],'reason'),true))throw new RuntimeException('Bounded collection must expose its limit.');
echo json_encode(['limit_probe'=>array_intersect_key($limited,array_flip(['complete','files_read','bytes_read','gaps'])),'scan_seconds'=>$scanSeconds,'analysis_seconds'=>$analysisSeconds,'php_peak_bytes'=>memory_get_peak_usage(true),'selected_rules'=>count($plan->pack['rules']),'checks'=>array_values(array_unique($checks)),'risk_rule_ids'=>$risks,'incomplete_rule_ids'=>$gaps,'analysis'=>array_intersect_key($analysis,array_flip(['complete','coverage','files_read','bytes_read','gaps','gaps_truncated'])),'collection_cache'=>$stats],JSON_THROW_ON_ERROR),"\n";
