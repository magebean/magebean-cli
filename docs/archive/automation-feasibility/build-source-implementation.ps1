$ErrorActionPreference='Stop'
$review=Get-Content "$PSScriptRoot/source.json" -Raw|ConvertFrom-Json
$recipes=@{
 'MB-0732'=@('sql_literal_query','Direct named query methods use a literal first argument','Every syntactically named query/rawQuery/exec/executeQuery method call in collected custom PHP/PHTML uses one static string first argument, without direct concatenation or interpolation. Unresolved variables yield UNKNOWN. This does not prove parameter binding or SQL injection safety.');
 'MB-0015'=@('csrf_unconditional_bypass','No unconditional validateForCsrf acceptance override','Collected custom PHP/PHTML contains no validateForCsrf method whose complete body is an unconditional return true. This exact bypass ban does not establish form tokens or server-side CSRF effectiveness.');
 'MB-0016'=@('native_network','Custom source avoids enumerated native network primitives','Collected custom PHP/PHTML has no direct global calls to curl_exec, curl_multi_exec, fsockopen, pfsockopen, stream_socket_client or file_get_contents. Dynamic callable/alias ambiguity yields UNKNOWN. This explicit API restriction does not establish SSRF safety of framework adapters.');
 'MB-0734'=@('native_unserialize','Custom source avoids native unserialize calls','Collected custom PHP/PHTML contains no direct unqualified or fully-qualified global unserialize call, irrespective of allowed_classes options. Indirect calls and function aliases yield UNKNOWN. Other serializers remain outside this syntax policy.');
 'MB-0735'=@('shell_execution','Custom source avoids enumerated shell/process primitives','Collected custom PHP/PHTML contains no direct global exec/system/passthru/shell_exec/popen/proc_open/pcntl_exec invocation or shell backtick expression. Indirect calls and function aliases yield UNKNOWN; framework process adapters are outside this API ban.');
 'MB-0019'=@('dynamic_execution','Custom source avoids eval and create_function constructs','Collected custom PHP/PHTML contains no eval construct or direct global create_function call. Dynamic include targets, indirect calls, function aliases and unresolved assertion semantics yield UNKNOWN. This is a construct policy, not general runtime execution assurance.');
 'MB-0020'=@('native_filesystem','Custom source avoids enumerated raw filesystem primitives','Collected custom PHP/PHTML contains no direct global file_get_contents/file_put_contents/fopen/readfile/unlink/rename/copy/scandir/glob call. Indirect calls and aliases yield UNKNOWN. This explicit API restriction does not establish path safety of framework adapters.');
 'MB-0021'=@('native_upload','Custom source avoids native upload move calls','Collected custom PHP/PHTML contains no direct global move_uploaded_file invocation. Indirect calls and aliases yield UNKNOWN. This is an explicit native API restriction, not proof that other upload handlers validate content or authorization.');
 'MB-0023'=@('weak_prng','Custom source avoids enumerated weak randomness APIs','Collected custom PHP/PHTML contains no direct global rand/mt_rand/lcg_value/uniqid/srand/mt_srand call. Indirect calls and aliases yield UNKNOWN. This deliberately strict coding policy includes non-security uses; it does not establish entropy or token lifetime.');
 'MB-0737'=@('direct_request_logging','No direct request superglobals in named log method arguments','Collected custom PHP/PHTML contains no $_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER/$_FILES token inside arguments of syntactically named log/debug/info/notice/warning/error/critical/alert/emergency method calls. This exact syntax rule does not prove absence of sensitive data in arbitrary logs.');
 'MB-0743'=@('direct_request_logging','No direct request superglobals in named log method arguments','Collected custom PHP/PHTML contains no direct request-superglobal tokens inside named log method call arguments. Share one new policy with MB-0737 and MB-0746; do not claim all PII is absent.');
 'MB-0746'=@('direct_request_logging','No direct request superglobals in named log method arguments','Collected custom PHP/PHTML contains no direct request-superglobal tokens inside named log method call arguments. Share one new policy with MB-0737 and MB-0743; third-party sink sanitization remains unverified.');
 'MB-0025'=@('raw_crypto_session','Custom source avoids enumerated raw crypto and session APIs','Collected custom PHP/PHTML contains no direct global session_start/session_id/session_regenerate_id/session_set_save_handler/mcrypt_encrypt/mcrypt_decrypt/md5/sha1/crypt/openssl_encrypt/openssl_decrypt call. This explicit coding restriction also bans legitimate non-security hash uses; it does not prove framework cryptography/session semantics.');
 'MB-0098'=@('xml_external_features','No enumerated XML external feature constructs in custom source','Collected custom PHP/PHTML contains no token reference to LIBXML_NOENT/LIBXML_DTDLOAD/LIBXML_DTDATTR, no resolveExternals/substituteEntities/validateOnParse assignment except literal false, and no syntactically named xinclude or xml_set_external_entity_ref_handler invocation. This exact construct ban does not establish every parser default or runtime configuration.');
 'MB-0073'=@('literal_https','No plain HTTP standalone PHP string literals in custom source','Collected custom PHP/PHTML contains no standalone constant string literal beginning http://. Comments are excluded. This deliberately strict literal policy includes non-endpoint examples and does not establish effective endpoint inventory, TLS verification or runtime interpolation.');
}
$unavailable=@{
 'MB-0733'='Needs real PHP/HTML context parser and trusted-fragment contracts; generic escaping-name search cannot enforce context correctness.';
 'MB-0736'='Needs nested HTML/JS context parser and installed serializer semantics; no keyword-based PASS implemented.';
 'MB-0094'='Needs complete route/role manifests, real Magento isolated deployment and side-effect oracles; no source-name substitution for authorization.';
 'MB-0099'='Needs real route/role/ownership integration fixtures and protected-byte oracle; no fake runtime adapter.';
 'MB-0075'='Needs declared provider versions, actual adapter signature contracts and isolated side-effect/replay tests; provider-specific details pending.';
 'MB-0079'='Needs real effective config/DB/secret-store provenance adapters and declared credential inventory; secret patterns cannot establish storage provenance.';
}
$rows=foreach($r in $review){
 if($r.id -eq 'MB-0095'){continue}
 if($recipes.ContainsKey($r.id)){
  $v=$recipes[$r.id]
  [pscustomobject][ordered]@{backlog_id=$r.id;original_criterion=$r.criterion;ready=$true;new_id_required=$true;title=$v[1];criterion=$v[2];check='automated_source_policy';check_args=[ordered]@{kind=$v[0];paths=@('app/code');include_ext=@('php','phtml')};why='Implemented and fixture-tested exact coding policy. Narrower than original criterion; never promote original ID or security assurance. Complete inventory and parser required.';validation='tests/AutomatedSourcePolicyTest.php: 64 assertions';reuse_group=$v[0]}
 }elseif($r.id -eq 'MB-0097'){
  [pscustomobject][ordered]@{backlog_id=$r.id;original_criterion=$r.criterion;ready=$true;new_id_required=$false;existing_active_id='MB-0730';title='Reuse existing supported deployment secret signature policy';criterion='Retain the existing MB-0730 bounded supported-signature criterion; do not restore blanket no-secrets criterion.';check='working_tree_secret_scan';check_args=$null;why='Already active scoped coverage; root should reuse existing catalog recipe, not add a duplicate.';reuse_group='MB-0730'}
 }else{
  if(-not $unavailable.ContainsKey($r.id)){throw "Unmapped $($r.id)"}
  [pscustomobject][ordered]@{backlog_id=$r.id;original_criterion=$r.criterion;ready=$false;new_id_required=$true;title=$null;criterion=$null;check=$null;check_args=$null;why=$unavailable[$r.id];reuse_group=$null}
 }
}
if(@($rows).Count -ne 22){throw 'Expected 22 scoped rows'}
[IO.File]::WriteAllText("$PSScriptRoot/source-implementation.json",($rows|ConvertTo-Json -Depth 12),[Text.UTF8Encoding]::new($false))
$rows|Group-Object ready|Select-Object Name,Count|Format-Table


