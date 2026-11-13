<?php
declare(strict_types=1);
$repository=dirname(__DIR__);chdir($repository);require $repository.'/vendor/autoload.php';
use Magebean\Engine\Checks\CheckRegistry;use Magebean\Engine\Context;
$archive=array_column(array_slice(json_decode(file_get_contents('src/Rules/requirements/magebean-retirements.json'),true)['requirements'],20,20),null,'id');
$cases=json_decode(<<<'CASES'
{
  "MB-0077": [
    {
      "label": "outbound_passport",
      "files": {
        "app/code/Acme/Probe/Probe.php": "<?php $payload=[\"passport_number\"=>$_POST[\"p\"]]; $client->post(\"https://vendor.invalid/\",$payload);"
      },
      "database": false
    },
    {
      "label": "same_outbound_plus_unrelated_token",
      "files": {
        "app/code/Acme/Probe/Probe.php": "<?php $token=\"unused\"; $payload=[\"passport_number\"=>$_POST[\"p\"]]; $client->post(\"https://vendor.invalid/\",$payload);"
      },
      "database": false
    }
  ],
  "MB-0078": [
    {
      "label": "strong_repository_config",
      "files": {
        "nginx.conf": "ssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers ECDHE-RSA-AES128-GCM-SHA256;\n"
      },
      "database": false
    },
    {
      "label": "strong_first_file_and_weak_other_gateway",
      "files": {
        "nginx.conf": "ssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers ECDHE-RSA-AES128-GCM-SHA256;\n",
        "apache.conf": "SSLProtocol all\nSSLCipherSuite ALL\n"
      },
      "database": false
    }
  ],
  "MB-0079": [
    {
      "label": "literal_api_key",
      "files": {
        "app/code/Acme/Probe/Probe.php": "<?php return [\"api_key\"=>\"fixture_VALUE_1234567890\"];"
      },
      "database": false
    },
    {
      "label": "secret_in_actual_sqlite_not_source",
      "files": {
        "app/code/Acme/Probe/Probe.php": "<?php return [];",
        "app/etc/env.php": "<?php return [\"integration\"=>[\"api_key\"=>\"fixture_VALUE_1234567890\"]];"
      },
      "database": true
    }
  ],
  "MB-0081": [
    {
      "label": "saas_callback_no_control",
      "files": {
        "app/code/Acme/Probe/Controller/Webhook/Index.php": "<?php class Webhook { function execute(){ $gateway=\"stripe\"; $service->process(); } }"
      },
      "database": false
    },
    {
      "label": "same_callback_unused_remote_addr",
      "files": {
        "app/code/Acme/Probe/Controller/Webhook/Index.php": "<?php class Webhook { function execute(){ $remote_addr=\"unused\"; $gateway=\"stripe\"; $service->process(); } }"
      },
      "database": false
    }
  ],
  "MB-0082": [
    {
      "label": "card_number_schema",
      "files": {
        "app/code/Acme/Probe/etc/db_schema.xml": "<schema><table name=\"vault\"><column name=\"card_number\" xsi:type=\"varchar\"/></table></schema>"
      },
      "database": false
    },
    {
      "label": "actual_sqlite_pan_with_benign_source",
      "files": {
        "app/code/Acme/Probe/Probe.php": "<?php return [];"
      },
      "database": true
    }
  ],
  "MB-0083": [
    {
      "label": "pan_in_csv",
      "files": {
        "var/export/cards.csv": "number\n4111111111111111\n"
      },
      "database": false
    },
    {
      "label": "same_pan_near_token_label",
      "files": {
        "var/export/cards.csv": "token number\n4111111111111111\n"
      },
      "database": false
    }
  ],
  "MB-0085": [
    {
      "label": "raw_card_form",
      "files": {
        "app/design/Acme/theme/checkout.phtml": "<input name=\"card_number\" />"
      },
      "database": false
    },
    {
      "label": "dynamic_field_no_documentation",
      "files": {
        "app/design/Acme/theme/checkout.phtml": "<input name=\"<?= base64_decode(\"Y2FyZF9udW1iZXI=\") ?>\" />"
      },
      "database": false
    }
  ],
  "MB-0086": [
    {
      "label": "raw_card_form",
      "files": {
        "app/design/Acme/theme/checkout.phtml": "<input name=\"card_number\" />"
      },
      "database": false
    },
    {
      "label": "dynamic_field_no_documentation",
      "files": {
        "app/design/Acme/theme/checkout.phtml": "<input name=\"<?= base64_decode(\"Y2FyZF9udW1iZXI=\") ?>\" />"
      },
      "database": false
    }
  ],
  "MB-0087": [
    {
      "label": "unlisted_script",
      "files": {
        "app/design/Acme/theme/checkout.phtml": "<script src=\"https://unapproved.invalid/payment.js\"></script>"
      },
      "database": false
    },
    {
      "label": "same_script_unrelated_inventory",
      "files": {
        "app/design/Acme/theme/checkout.phtml": "<script src=\"https://unapproved.invalid/payment.js\"></script>",
        ".magebean/payment-scripts.json": "[{\"source\":\"https://other.invalid/different.js\"}]"
      },
      "database": false
    }
  ],
  "MB-0088": [
    {
      "label": "script_without_controls",
      "files": {
        "app/design/Acme/theme/checkout.phtml": "<script src=\"https://unapproved.invalid/payment.js\"></script>"
      },
      "database": false
    },
    {
      "label": "script_unused_nonce_word",
      "files": {
        "app/design/Acme/theme/checkout.phtml": "<script src=\"https://unapproved.invalid/payment.js\"></script><?php $label=\"getNonce\"; ?>"
      },
      "database": false
    }
  ],
  "MB-0089": [
    {
      "label": "no_runtime_or_config",
      "files": {
        "app/code/Acme/Probe/Probe.php": "<?php return [];"
      },
      "database": false
    },
    {
      "label": "directive_words_in_unused_string",
      "files": {
        "app/code/Acme/Probe/Probe.php": "<?php $unused=\"script-src connect-src frame-src form-action object-src base-uri report-uri\";"
      },
      "database": false
    }
  ],
  "MB-0090": [
    {
      "label": "no_monitoring",
      "files": {
        "app/code/Acme/Probe/Probe.php": "<?php return [];"
      },
      "database": false
    },
    {
      "label": "marker_string_only",
      "files": {
        "app/code/Acme/Probe/Probe.php": "<?php $unused=\"checkout checksum scheduled alert\";"
      },
      "database": false
    }
  ],
  "MB-0092": [
    {
      "label": "payment_callback_no_verifier",
      "files": {
        "app/code/Acme/Probe/Controller/Webhook/Index.php": "<?php class Webhook { function execute(){ $payment=\"stripe\"; $service->process(); } }"
      },
      "database": false
    },
    {
      "label": "same_callback_unused_signature_string",
      "files": {
        "app/code/Acme/Probe/Controller/Webhook/Index.php": "<?php class Webhook { function execute(){ $payment=\"stripe\"; $unused=\"constructEvent( event_id\"; $service->process(); } }"
      },
      "database": false
    }
  ],
  "MB-0093": [
    {
      "label": "absent_checklist",
      "files": {
        "app/code/Acme/Probe/Probe.php": "<?php return []; "
      },
      "database": false
    },
    {
      "label": "headings_only_no_evidence",
      "files": {
        "SECURITY.md": "checkout SAQ access review incident response vendor responsibilities"
      },
      "database": false
    }
  ],
  "MB-0094": [
    {
      "label": "controller_no_authorization",
      "files": {
        "app/code/Acme/Probe/Controller/Export/Index.php": "<?php class Export { function execute(){ $service->export(); } }"
      },
      "database": false
    },
    {
      "label": "same_controller_unused_isAllowed_word",
      "files": {
        "app/code/Acme/Probe/Controller/Export/Index.php": "<?php class Export { function execute(){ $unused=\"isAllowed\"; $service->export(); } }"
      },
      "database": false
    }
  ],
  "MB-0095": [
    {
      "label": "anonymous_order_api",
      "files": {
        "app/code/Acme/Probe/etc/webapi.xml": "<routes><route url=\"/V1/orders/:id\" method=\"GET\"><service class=\"Acme\\Api\" method=\"get\"/><resources><resource ref=\"anonymous\"/></resources></route></routes>"
      },
      "database": false
    },
    {
      "label": "undeclared_specific_acl",
      "files": {
        "app/code/Acme/Probe/etc/webapi.xml": "<routes><route url=\"/V1/orders/:id\" method=\"GET\"><service class=\"Acme\\Api\" method=\"get\"/><resources><resource ref=\"Acme_Probe::missing\"/></resources></route></routes>"
      },
      "database": false
    }
  ],
  "MB-0096": [
    {
      "label": "no_header_declarations",
      "files": {
        "app/code/Acme/Probe/Probe.php": "<?php return []; "
      },
      "database": false
    },
    {
      "label": "unused_header_strings",
      "files": {
        "app/code/Acme/Probe/Probe.php": "<?php $unused=\"Content-Security-Policy default-src self\nX-Frame-Options DENY\nX-Content-Type-Options nosniff\";"
      },
      "database": false
    }
  ],
  "MB-0097": [
    {
      "label": "literal_password",
      "files": {
        "app/code/Acme/Probe/Probe.php": "<?php $config=[\"password\"=>\"fixture_VALUE_1234567890\"];"
      },
      "database": false
    },
    {
      "label": "computed_password_literal_parts",
      "files": {
        "app/code/Acme/Probe/Probe.php": "<?php $config=[\"password\"=>\"fixture_\".\"VALUE_1234567890\"];"
      },
      "database": false
    }
  ],
  "MB-0098": [
    {
      "label": "literal_unsafe_flag",
      "files": {
        "app/code/Acme/Probe/Probe.php": "<?php $flags=LIBXML_NOENT; $dom->loadXML($xml,$flags);"
      },
      "database": false
    },
    {
      "label": "same_flag_unrelated_blocked_word",
      "files": {
        "app/code/Acme/Probe/Probe.php": "<?php $blocked=true; $flags=LIBXML_NOENT; $dom->loadXML($xml,$flags);"
      },
      "database": false
    }
  ],
  "MB-0099": [
    {
      "label": "download_no_authorization",
      "files": {
        "app/code/Acme/Probe/Controller/Export/Index.php": "<?php class Export { function execute(){ $service->export(); } }"
      },
      "database": false
    },
    {
      "label": "same_export_unused_isAllowed_word",
      "files": {
        "app/code/Acme/Probe/Controller/Export/Index.php": "<?php class Export { function execute(){ $unused=\"isAllowed\"; $service->export(); } }"
      },
      "database": false
    }
  ]
}
CASES, true);$results=[];
$active=array_column(json_decode(file_get_contents('src/Rules/requirements/magebean-catalog.json'),true)['requirements'],null,'id');
foreach($cases as$id=>$rows)foreach($rows as$case){
 $root=sys_get_temp_dir().'/mb-retirement-proof-'.bin2hex(random_bytes(6));mkdir($root);
 try{
  foreach($case['files']as$file=>$source){if(!is_dir(dirname($root.'/'.$file)))mkdir(dirname($root.'/'.$file),0700,true);file_put_contents($root.'/'.$file,$source);}
  $extra=[];$pdo=null;
  if($case['database']){$pdo=new PDO('sqlite::memory:');$pdo->exec('CREATE TABLE audit_private(card_number TEXT, api_key TEXT)');$pdo->exec("INSERT INTO audit_private VALUES ('4111111111111111','fixture_VALUE_1234567890')");$extra['pdo']=$pdo;}
  $registry=CheckRegistry::fromContext(new Context($root,'','',$extra));$check=$archive[$id]['checks'][0];$r=$registry->run($check['name'],$check['args']);
  $successor=null;
  if(in_array($id,['MB-0079','MB-0097','MB-0098'],true)){
   $activeId=$id==='MB-0098'?'MB-0797':'MB-0730';$binding=$active[$activeId]['checks'][0];$observed=$registry->run($binding['name'],$binding['args']);
   $successor=['id'=>$activeId,'method'=>'real file scanner','outcome'=>$observed[0]===true?'PASS':($observed[0]===false?'FAIL':'UNKNOWN')];
  }
  if(in_array($id,['MB-0089','MB-0096'],true)){
   $runtime=new \Magebean\Engine\Checks\ProductionRuntimeCheck(new Context($root,'https://fixture.invalid'),static fn(string $url):array=>['status'=>200,'complete_headers'=>true,'headers'=>[],'final_url'=>$url]);
   $observed=$id==='MB-0089'?$runtime->checkoutCspResponse(['path'=>'/checkout/','require_reporting'=>true]):$runtime->runtimeNosniff(['path'=>'/']);
   $successor=['id'=>$id==='MB-0089'?'MB-0802':'MB-0803','method'=>'injected complete successful HTTPS response with no headers; no network/TLS claim','outcome'=>$observed[0]===true?'PASS':($observed[0]===false?'FAIL':'UNKNOWN')];
  }
  $results[$id][]=['case'=>$case['label'],'outcome'=>$r[0]===true?'PASS':($r[0]===false?'FAIL':'UNKNOWN'),'message'=>$r[1],'findings'=>count($r[2]['findings']??[]),'successor'=>$successor,'database_rows'=>$pdo?(int)$pdo->query('SELECT COUNT(*) FROM audit_private')->fetchColumn():null];
 }finally{$it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST);foreach($it as$f){if($f->isDir()&&!$f->isLink())rmdir($f->getPathname());else unlink($f->getPathname());}rmdir($root);}
}
if(in_array('--json',$argv,true)){echo json_encode($results,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES)."\n";exit;}
if(count($results)!==20)throw new RuntimeException('Expected20 retired criteria');
if(in_array('--assert-historical',$argv,true))foreach($results as$id=>$rows)if(count($rows)!==2||$rows[1]['outcome']!=='PASS'||($id!=='MB-0078'&&$rows[0]['outcome']!=='FAIL'))throw new RuntimeException('Observed implementation changed; review evidence for '.$id);
foreach($results as$id=>$rows)echo $id.' '.implode(' | ',array_map(fn($r)=>$r['case'].':'.$r['outcome'],$rows))."\n";
