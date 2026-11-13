#!/usr/bin/env python3
"""Synthetic bounded development scans; each measurement uses a fresh PHP process."""
import hashlib,json,os,platform,statistics,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'docs/archive/current-state/phase6';OUT.mkdir(exist_ok=True)
results=[]
for name,modules,classes in [('small',4,20),('medium',20,50)]:
 with tempfile.TemporaryDirectory(prefix='mb-phase6-'+name+'-') as tmp:
  target=Path(tmp)
  def put(path,value):
   p=target/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(value)
  put('composer.json',json.dumps({'require':{'magento/framework':'103.0.7'},'config':{'platform':{'php':'8.1.0'}}}))
  put('composer.lock',json.dumps({'content-hash':'fixture-unverified','packages':[{'name':'magento/framework','version':'103.0.7'}],'packages-dev':[]}))
  put('vendor/composer/installed.json',json.dumps({'packages':[{'name':'magento/framework','version':'103.0.7','install-path':'../magento/framework'}]}))
  put('vendor/magento/framework/.keep','')
  names=[]
  for i in range(modules):
   mod='Fixture_Module'+str(i);names.append(mod);base='app/code/Fixture/Module'+str(i)
   put(base+'/registration.php',"<?php \\Magento\\Framework\\Component\\ComponentRegistrar::register(\\Magento\\Framework\\Component\\ComponentRegistrar::MODULE,'"+mod+"',__DIR__);")
   put(base+'/etc/module.xml','<config><module name="'+mod+'"/></config>')
   for j in range(classes):
    put(base+'/Model/C'+str(j)+'.php','<?php\nnamespace Fixture\\Module'+str(i)+'\\Model;\nclass C'+str(j)+' { public function value(string $value): string { return $value; } }\n'+'// inert fixture padding\n'*20)
   put(base+'/view/frontend/templates/item.phtml','<script>const item="<?= $escaper->escapeJs($value) ?>";</script>')
  put('app/etc/config.php',"<?php return ['modules'=>["+','.join("'"+n+"'=>1" for n in names)+"]];")
  # One stable, observable bad call verifies that bounded measurements still retain a real finding.
  put('app/code/Fixture/Module0/Model/Sink.php','<?php namespace Fixture\\Module0\\Model; class Sink { public function run(){ \\exec($_GET["command"]); } }')
  fixture_files=list(p for p in target.rglob('*') if p.is_file())
  fixture={'modules':modules,'files':len(fixture_files),'bytes':sum(p.stat().st_size for p in fixture_files)}
  for label,archive in [('source',''),('standard','magebean.phar'),('one-time','artifacts/magebean-one-time.phar')]:
   runs=[]
   for repeat in range(3):
    timefile=target/'process.time'
    cmd=['/usr/bin/time','-f','%e %M','-o',str(timefile),'php',str(ROOT/'tools/benchmark-current-state.php'),tmp,archive]
    run=subprocess.run(cmd,cwd=ROOT,text=True,capture_output=True,timeout=60,check=True)
    value=json.loads(run.stdout);elapsed,rss=timefile.read_text().split();value.update(process_seconds=float(elapsed),process_peak_rss_kib=int(rss));timefile.unlink()
    assert value['selected_rules']==29 and 'MB-0822' in value['risk_rule_ids'],value
    assert not any(c.endswith('_api') or c.startswith(('http_', 'tls_')) for c in value['checks']),value['checks']
    assert value['analysis']['complete'] and not value['analysis']['gaps'],value['analysis']
    runs.append(value)
   results.append({'fixture':name,'runtime':label,'input':fixture,'median_scan_seconds':statistics.median(r['scan_seconds'] for r in runs),'median_process_seconds':statistics.median(r['process_seconds'] for r in runs),'max_process_peak_rss_kib':max(r['process_peak_rss_kib'] for r in runs),'runs':runs})
   print(name,label,'median',results[-1]['median_scan_seconds'],'seconds',flush=True)
report={'artifact_sha256':{f:hashlib.sha256((ROOT/f).read_bytes()).hexdigest() for f in ['magebean.phar','artifacts/magebean-one-time.phar']},'scope':'Synthetic current-state development profile, 3 fresh processes per fixture/runtime; warm filesystem cache possible, fixture generation excluded; not live-store throughput','php':subprocess.check_output(['php','-r','echo PHP_VERSION;'],text=True),'platform':platform.platform(),'results':results}
(OUT/'performance.json').write_text(json.dumps(report,indent=2)+'\n')
