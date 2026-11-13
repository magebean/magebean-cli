<?php
declare(strict_types=1);
require_once __DIR__.'/../vendor/autoload.php';
use Magebean\Application;
use Symfony\Component\Console\Tester\CommandTester;
function assertProfileCount(bool $condition,string $message):void{if(!$condition)throw new RuntimeException($message);}
$command=(new Application())->find('rules:list');
$profiles=['basic','asvs-l1','asvs-l2','asvs-l3','owasp','pci','hardening'];
foreach($profiles as $profile){
    $definitions=\Magebean\Engine\RequirementCatalog::forProfile($profile)['rules'];
    $total=count($definitions);$human=count(array_filter($definitions,[\Magebean\Engine\RequirementPolicy::class,'requiresHuman']));$listed=$total-$human;
    $tester=new CommandTester($command);$tester->execute(['--profile'=>$profile,'--no-ansi'=>true]);$out=$tester->getDisplay();
    assertProfileCount(str_contains($out,"Total Rules Listed: {$listed}"),"{$profile} default listed count is wrong");
    assertProfileCount(!str_contains($out,"Total Profile Rules:"),"{$profile} repeats the rule total");
    if($human>0){assertProfileCount(str_contains($out,"Human verification rules hidden: {$human}"),"{$profile} hidden human count is missing");assertProfileCount(str_contains($out,'Use --include-manual-review to show them.'),"{$profile} manual flag guidance is missing");}
    elseif(in_array($profile,['basic','hardening','owasp'],true)){
        assertProfileCount(!str_contains($out,'--include-manual-review'),"{$profile} should not suggest a human workflow");
    }
    else assertProfileCount(str_contains($out,'Human verification rules: none in this profile.'),"{$profile} zero-human explanation is missing");
}
echo "ProfileRuleCountOutputTest: PASS\n";
