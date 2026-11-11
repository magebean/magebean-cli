<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\{ScanContext,ScanRequest,ScanPlanner,ScanService,ScanReportAssembler,CheckResult,CheckOutcome,RequirementProfileCatalog};
use Magebean\Engine\Checks\CheckRegistry;
use Magebean\Console\ScanConsoleRenderer;
use Symfony\Component\Console\Output\BufferedOutput;
$context=new ScanContext(sys_get_temp_dir(),'');
$plan=(new ScanPlanner())->planCli(new ScanRequest($context,['profile'=>'hardening']),CheckRegistry::fromContext($context->toLegacy()));
$fake=new CheckRegistry();
foreach($plan->pack['rules']as$rule)foreach($rule['checks']as$check)if(!$fake->has($check['name']))$fake->register($check['name'],static fn(array$args):CheckResult=>CheckResult::of(CheckOutcome::Pass,'Fixture observation'));
$result=(new ScanReportAssembler())->assemble((new ScanService())->run($plan,null,$fake),$plan)->toLegacy();
$inventory=count(RequirementProfileCatalog::load('hardening')['requirement_ids']);
if($result['coverage_summary']['inventory']!==$inventory||$result['coverage_summary']['executed']!==count($plan->pack['rules'])||$result['coverage_summary']['not_evaluated']<1||$result['coverage_summary']['assessment_complete'])throw new RuntimeException('Passing selected checks must not hide omitted machine-context requirements');
foreach($result['not_evaluated_requirements']as$omitted)if($omitted['reason_code']!=='CAPABILITY_CONTEXT_MISSING')throw new RuntimeException('Missing capability must have an explicit technical omission reason');
if(!empty($result['evidence_tasks']))throw new RuntimeException('Machine context must not create human evidence tasks');
$output=new BufferedOutput();(new ScanConsoleRenderer())->renderPrettySummary($output,$result,sys_get_temp_dir());$text=$output->fetch();
if(str_contains($text,'rules not evaluated')||str_contains($text,'external evidence'))throw new RuntimeException('Overview hides missing-context messages while result metadata retains omissions');
echo "AutomatedCoverageContextTest: PASS\n";
