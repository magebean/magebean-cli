<?php
declare(strict_types=1);
namespace Magebean\Console;

use Magebean\Application;
use Symfony\Component\Console\Formatter\OutputFormatter;
use Symfony\Component\Console\Helper\Helper;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Terminal;

/** Width-aware findings view; assessment/wire outcomes are deliberately not badges. */
final class FindingsConsoleRenderer
{
    private int $width;
    public function __construct(?int $width=null) { $this->width=max(40,min(110,$width??(new Terminal())->getWidth())); }

    public function render(OutputInterface $out,array $result,string $path):void
    {
        $detailed=!empty($result['meta']['rules_filter']);
        $risks=array_values(array_filter($result['risk_findings']??[],static fn(array $f):bool=>($f['risk_observation']['needs_attention']??false)===true));
        $issues=$result['collection_issues']??[];
        $covered=[];
        foreach($risks as$f)foreach($f['risk_observation']['findings']??[]as$o)if(($o['kind']??'')==='collection_issue')$covered[($f['id']??'').'|'.($o['check']??'')]=true;
        $issues=array_values(array_filter($issues,static fn(array $i):bool=>!isset($covered[($i['id']??'').'|'.($i['check']??'')])&&!isset($covered[($i['id']??'').'|requirement_assessment'])));
        $order=['critical'=>0,'high'=>1,'medium'=>2,'low'=>3,'info'=>4];
        usort($risks,static fn(array $a,array $b):int=>($order[strtolower($a['severity']??'low')]??4)<=>($order[strtolower($b['severity']??'low')]??4));
        if (!$detailed) {
            foreach ($risks as &$finding) {
                $finding['risk_observation']['findings'] = array_values(array_filter($finding['risk_observation']['findings'] ?? [], static fn(array $o): bool => ($o['kind'] ?? '') !== 'collection_issue'));
            }
            unset($finding);
            $risks = array_values(array_filter($risks, static fn(array $f): bool => $f['risk_observation']['findings'] !== []));
        }
        $out->writeln('');
        $this->line($out, 'MAGEBEAN  /  Audit', '', 'fg=cyan;options=bold');
        $this->line($out, 'CLI '.Application::VERSION, '', 'fg=gray');
        $this->rule($out);
        $out->writeln('');
        $this->line($out, $result['meta']['profile']['title']??$result['meta']['standard']??'Magebean', '  Profile   ');
        $this->line($out, $path, '  Target    ');
        $out->writeln('');
        $this->line($out, count($risks).' finding'.(count($risks)===1?'':'s').' need attention', '  ', $risks?'fg=yellow;options=bold':'fg=green;options=bold');
        $counts=array_count_values(array_map(static fn(array $f):string=>strtolower($f['severity']??'low'),$risks));
        if($risks){
            $out->write('  ');
            $used=2;
            foreach($order as$severity=>$unused)if(!empty($counts[$severity])){
                $badge=ucfirst($severity).' '.$counts[$severity];
                if($used+Helper::width($badge)+3>$this->width){$out->writeln('');$out->write('  ');$used=2;}
                $out->write('<'.$this->severityStyle($severity).'>'.$badge.'</>   ');$used+=Helper::width($badge)+3;
            }
            $out->writeln('');
        }
        $out->writeln('');
        if(!empty($result['coverage_summary'])){
            $c=$result['coverage_summary'];
            $this->line($out, sprintf('%d / %d rules executed', $c['executed'], $c['inventory']), '  Coverage  ', 'fg=gray');
            if ($detailed && !empty($c['not_evaluated'])) $this->line($out, $c['not_evaluated'].' rules not evaluated', '            ', 'fg=gray');
        }
        if($detailed&&($issues||!$covered))$this->line($out, (string)count($issues), '  Scan collection issues  ', 'fg='.($issues?'yellow':'gray'));
        $out->writeln('');
        $this->rule($out);
        foreach ($result['findings'] ?? [] as $finding) {
            $risk = $finding['risk_observation'] ?? [];
            foreach ($risk['observations'] ?? [] as $observation) {
                $symbol = $observation['evidence']['subject']['symbol'] ?? '';
                $this->line($out, 'Information · '.$observation['message'].($symbol !== '' ? ' '.$symbol : ''), '  ', 'fg=gray');
            }
            foreach ($risk['detector_runs'] ?? [] as $run) {
                if ($detailed && $run['suppressed_count'] > 0) {
                    $this->line($out, $run['detector'].' · '.$run['suppressed_count'].' suppressed', '  ', 'fg=gray');
                    if ($detailed) foreach ($run['suppressions'] as $suppression) $this->line($out, $suppression, '    ');
                }
            }
            if ($detailed && (!empty($risk['findings_truncated']) || !empty($risk['collection_gaps_truncated']))) {
                $this->line($out, ($finding['id'] ?? '').' · Observation output truncated.', '  ', 'fg=yellow');
            }
        }
        if(!$risks){$out->writeln('');$this->line($out,'No risk observations requiring attention were collected.','','fg=green');}
        foreach($risks as$i=>$finding){
            $out->writeln('');
            $severity=strtolower($finding['severity']??'low');
            $this->line($out,sprintf('%02d  %s  %s',$i+1,strtoupper($severity),$finding['id']??''),'',$this->severityStyle($severity).';options=bold');
            foreach($finding['risk_observation']['findings']as$observation){
                $this->line($out,$observation['message']??'Observed issue','  ','options=bold');
                if ($detailed && isset($observation['confidence'])) {
                    $labels = array_filter([$observation['severity'] ?? null, $observation['category'] ?? null, $observation['confidence']]);
                    $this->line($out, implode(' · ', array_map('ucfirst', $labels)), '    ', 'fg=gray');
                }
                if (isset($observation['detector'])) {
                    $evidence = $observation['evidence'];
                    $subject = $evidence['subject'];
                    $this->line($out, implode(' · ', array_filter([$subject['module'] ?? '', $subject['package'] ?? '', $subject['area'] ?? '', $observation['detector'].' '.$observation['detector_version']])), '    ', 'fg=gray');
                    if ($detailed && $evidence['remediation'] !== '') $this->line($out, $evidence['remediation'], '    ');
                    if ($detailed) {
                        $this->line($out, $evidence['reasoning'], '    ');
                        foreach ($evidence['assumptions'] as $assumption) $this->line($out, $assumption, '    ');
                    }
                }
                if($detailed&&($observation['kind']??'')==='collection_issue'&&!empty($observation['evidence']['collection_guidance']['action']))$this->line($out,'How to resolve '.($finding['id']??'').': '.$observation['evidence']['collection_guidance']['action'],'    ','fg=gray');
                if($detailed)$this->line($out,'Check: '.($observation['check']??'').' · '.($observation['reason_code']??'observation'),'  ','fg=gray');
                $locations=[];
                foreach(['matches','violations','findings','diagnostics','locations']as$key)foreach($observation['evidence'][$key]??[]as$location){
                    if(!is_array($location))continue;
                    $file=$location['file']??$location['path']??$location['package']??'';
                    if($file==='')continue;
                    $locations[]=$file.(isset($location['line'])?':'.(int)$location['line']:'');
                }
                $locations=array_values(array_unique($locations));$limit=$detailed?20:5;
                foreach(array_slice($locations,0,$limit)as$location)$this->line($out,$location,'    ','fg=cyan');
                if(count($locations)>$limit)$this->line($out,'+'.(count($locations)-$limit).' more locations; select this requirement for details.','    ','fg=gray');
            }
            $guide=$finding['requirement']['finding_guidance']??[];
            $collectionOnly=!array_filter($finding['risk_observation']['findings'],static fn(array $o):bool=>($o['kind']??'')!=='collection_issue');
            if($detailed)foreach(['interpretation'=>'Context','risk'=>'Risk','limitations'=>'Scope']as$key=>$label)if(!empty($guide[$key])&&is_string($guide[$key])){$this->line($out,$label,'  ','fg=cyan');$this->line($out,$guide[$key],'    ');}
            foreach(['Remediation guidance'=>(!$detailed||$collectionOnly)?[]:($finding['remediation']??[]),'Verification after remediation'=>$detailed?($guide['verification']??[]):[]]as$label=>$steps){
                $steps=array_values(array_filter($steps,static fn($step):bool=>is_string($step)&&trim($step)!==''));
                if(!$steps)continue;
                $out->writeln('');$this->line($out,$label,'  ','fg=cyan;options=bold');
                foreach($detailed?$steps:array_slice($steps,0,1)as$step)$this->line($out,$step,'    - ');
            }
            if($detailed&&!empty($finding['risk_observation']['collection_gaps'])&&!array_filter($finding['risk_observation']['findings'],static fn(array $o):bool=>($o['kind']??'')==='collection_issue'))$this->line($out,'Additional collection issues are listed separately.','  ','fg=yellow');
        }
        if($detailed&&$issues){
            $out->writeln('');$this->line($out,'Scan collection issues','','fg=yellow;options=bold');
            foreach($issues as$issue){
                $this->line($out,($issue['id']??'').'  '.($issue['message']??$issue['title']??'Observation unavailable'),'  ');
                foreach($issue['risk_observation']['collection_gaps']??$issue['collection_gaps']??[]as$gap)$this->line($out,$gap['message']??$gap['reason_code']??'Observation unavailable','    ');
                if($detailed&&!empty($issue['collection_guidance']['action']))$this->line($out,'How to resolve '.($issue['id']??'').': '.$issue['collection_guidance']['action'],'    ','fg=gray');
            }
        }
        if (!$detailed && $risks) {
            $out->writeln('');
            $this->line($out, 'For issue details and remediation, select one or more rule IDs:', '', 'fg=gray');
            $this->line($out, 'scan --profile='.($result['meta']['profile_selector']??$result['meta']['profile']['id']??'basic').' --rules='.($risks[0]['id']??''), '  ', 'fg=gray');
        }
        $out->writeln('');
    }

    private function severityStyle(string $severity):string{return match($severity){'critical'=>'fg=white;bg=red','high'=>'fg=red','medium'=>'fg=yellow','low'=>'fg=blue',default=>'fg=cyan'};}
    private function rule(OutputInterface $out):void{$out->writeln('<fg=gray>'.str_repeat('─',$this->width).'</>');}
    private function line(OutputInterface $out,string $text,string $prefix='',string $style=''):void
    {
        // Strip terminal controls before escaping markup; scan evidence is untrusted text.
        $text=preg_replace('/\x1B\[[0-?]*[ -\/]*[@-~]|[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/','',$text)??'';
        $limit=max(10,$this->width-Helper::width($prefix));$first=true;
        foreach(preg_split('/\R/u',$text)?:['']as$paragraph){
            $line='';
            foreach(preg_split('/\s+/u',trim($paragraph))?:[]as$word){
                if($line!==''&&Helper::width($line.' '.$word)>$limit){$this->emit($out,$line,$first?$prefix:str_repeat(' ',Helper::width($prefix)),$style);$first=false;$line='';}
                if(Helper::width($word)>$limit){
                    foreach(preg_split('//u',$word,-1,PREG_SPLIT_NO_EMPTY)?:[]as$char){
                        if(Helper::width($line.$char)>$limit){$this->emit($out,$line,$first?$prefix:str_repeat(' ',Helper::width($prefix)),$style);$first=false;$line='';}
                        $line.=$char;
                    }
                }else $line.=($line===''?'':' ').$word;
            }
            $this->emit($out,$line,$first?$prefix:str_repeat(' ',Helper::width($prefix)),$style);$first=false;
        }
    }
    private function emit(OutputInterface $out,string $text,string $prefix,string $style):void
    {
        $content=OutputFormatter::escape($text);
        $out->writeln($prefix.($style!==''?'<'.$style.'>'.$content.'</>':$content));
    }
}
