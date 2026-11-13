<?php
declare(strict_types=1);
require __DIR__.'/../../../vendor/autoload.php';
use Magebean\Engine\{RequirementCatalog,RequirementProfileCatalog};
$index=array_column(RequirementCatalog::loadAll()['rules'],null,'id');
$decisions=[
 'MB-0001'=>['KEEP','Permissions','Keep world-write findings; inventory must disclose symlink/unreadable/traversal gaps.','security'],
 'MB-0002'=>['REVISE','Permissions','Retain env.php protection; configurable deployment ownership and ACL/runtime access evidence instead of treating project-root owner and0640 as Adobe universal policy.','security'],
 'MB-0003'=>['EXPAND','Exposure','Filesystem pub hygiene is partial; add effective document-root/context and safe HTTP sensitive-path observations.','security'],
 'MB-0005'=>['KEEP','Exposure','Keep bounded directory-listing observations; no claim that all routes/hosts are tested.','security'],
 'MB-0006'=>['REVISE','Admin','Only rejects admin; common backend passes. Scope uncommon route policy and effective custom URL overrides; route concealment is not authorization.','security'],
 'MB-0007'=>['REPLACE_BINDING','MFA','Provider engines/required-provider settings and native-versus-IMS applicability must replace the separate-provider-module assumption. Enrollment/enforcement remains separate evidence.','security'],
 'MB-0011'=>['SPLIT_OR_REPORT_COMPONENTS','Admin','CAPTCHA OR bounded lockout does not report both protections independently; add reset throttling and do not label all Admin security satisfied. Current resolver already reads locked files/database/installed defaults.','security'],
 'MB-0728'=>['KEEP_WITH_POLICY_LABEL','Admin','Current resolver uses installed config/validator. Threshold8 is Magebean policy, not an Adobe universal minimum; version capability and IMS scope required.','security'],
 'MB-0026'=>['REVISE','Transport','Split storefront/admin evidence; URL-only admin route unavailable leads UNKNOWN. Explicit admin context or separate omission must preserve storefront results.','security'],
 'MB-0028'=>['KEEP','Transport','Bounded legacy TLS rejection is useful; independently report certificate/hostname validity and proxy endpoint scope.','security'],
 'MB-0029'=>['KEEP_SCOPED','Transport','Literal HTTP references in assessed markup are partial; include deployed/theme/storefront scope and omitted dynamic assets.','security'],
 'MB-0030'=>['REVISE','Cookies','Observed anonymous cookie emissions are partial; authenticated Admin/session and integration-specific SameSite exceptions need context.','security'],
 'MB-0031'=>['KEEP_SCOPED','Deployment','Persisted production mode is useful; report that environment/runtime can override it.','readiness'],
 'MB-0729'=>['KEEP_SCOPED','Debug','Default-scope declarations are useful; do not confuse absence with web-worker/website/store runtime proof. Current resolver already supports database/installed defaults.','security'],
 'MB-0035'=>['STRENGTHEN','Deployment','Keep static deployment topic; a single nonempty artifact is not active theme/locale/asset readiness.','readiness'],
 'MB-0037'=>['STRENGTHEN_AND_SPLIT_MODE','Cache','Keep cache/FPC readiness; distinguish declaration/current status/observed runtime behavior. HTTP cache signals cannot prove local env.php declaration.','readiness'],
 'MB-0046'=>['STRENGTHEN','Cron','Keep scheduler readiness; entry presence accepts yearly schedule and does not establish recent successful execution. External orchestrator context required.','readiness'],
 'MB-0049'=>['KEEP_SCOPED','Dependencies','Known advisory inventory remains valuable; show coverage/freshness/hotfix evidence and excluded runtime/browser dependencies. No claim zero unknown vulnerabilities.','security'],
 'MB-0050'=>['KEEP_SCOPED','Patches','Keep branch security patch and alternative evidence assessment; distinguish edition/support entitlement/isolated patch applicability from latest-major upgrade preference.','security'],
 'MB-0730'=>['KEEP_SCOPED','Secrets','Keep bounded deployed pattern discovery with redaction; env.php is intentionally excluded from secret matching, so exposure/source-control checks are complementary.','security'],
];
$rows=[];
foreach(RequirementProfileCatalog::load('basic')['requirement_ids']as$id){if(!isset($decisions[$id]))throw new RuntimeException('Missing review row '.$id);$r=$index[$id];if($r['family']!=='magebean')throw new RuntimeException('Basic source-family contamination');[$decision,$topic,$action,$lane]=$decisions[$id];$rows[]=['id'=>$id,'title'=>$r['title'],'family'=>$r['family'],'current_criterion'=>$r['criterion'],'checks'=>$r['checks'],'execution_variants'=>$r['execution_variants']??[],'decision'=>$decision,'topic'=>$topic,'lane'=>$lane,'action'=>$action];}
file_put_contents(__DIR__.'/requirements-review.json',json_encode(['reviewed_at'=>'2026-10-17','scope'=>'Current20 Basic Magebean definitions and implementation/source review; not20 completed integration validations. Decision changes not applied.','catalog_sha256'=>hash_file('sha256',__DIR__.'/../../src/Rules/requirements/magebean-catalog.json'),'profiles_sha256'=>hash_file('sha256',__DIR__.'/../../src/Rules/requirements/internal-profiles.json'),'requirements'=>$rows],JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR)."\n");
echo count($rows)," current Basic requirements reviewed; behavior unchanged.\n";
