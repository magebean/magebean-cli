#!/usr/bin/env python3
"""Run existing Console catalog/eligibility regressions with an explicit in-memory SQLite override."""
import json,os,re,subprocess,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];CONSOLE=ROOT.parent/'console-magebean'
paths=[]
override=r"""
    public function createApplication(): \Illuminate\Foundation\Application
    {
        $app=require '__BOOTSTRAP__';
        $app->make(\Illuminate\Contracts\Console\Kernel::class)->bootstrap();
        $app['config']->set('database.default','sqlite');
        $app['config']->set('database.connections.sqlite.database',':memory:');
        $app['config']->set('database.connections.sqlite.url',null);
        $app['config']->set('mail.default','array');
        $app['config']->set('cache.default','array');
        $app['config']->set('queue.default','sync');
        return $app;
    }
""".replace('__BOOTSTRAP__',str(CONSOLE/'bootstrap/app.php'))
for relative in ['tests/Feature/InternalRequirementCatalogImportTest.php','tests/Feature/Agent/CurrentCatalogScanEligibilityTest.php']:
 source=CONSOLE/relative;s=source.read_text();name=source.stem
 s=s.replace('class '+name+' extends TestCase','class Phase6'+name+' extends TestCase')
 anchor='    use RefreshDatabase;';assert anchor in s
 s=s.replace(anchor,anchor+'\n'+override)
 p=ROOT/'build'/('Phase6'+name+'.php');p.write_text(s);paths.append(str(p))
env=dict(os.environ);env.update(APP_ENV='testing',DB_CONNECTION='sqlite',DB_DATABASE=':memory:',DB_URL='',MAIL_MAILER='array',CACHE_STORE='array',QUEUE_CONNECTION='sync',SESSION_DRIVER='array',APP_CONFIG_CACHE=str(ROOT/'build'/('unused-'+uuid.uuid4().hex+'.php')))
run=subprocess.run(['php',str(CONSOLE/'vendor/bin/phpunit'),'--configuration',str(CONSOLE/'phpunit.xml'),'--colors=never',*paths],cwd=CONSOLE,env=env,text=True,capture_output=True)
output=run.stdout+run.stderr
(ROOT/'docs/archive/current-state/phase6/console-catalog-regression.json').write_text(json.dumps({'scope':'Existing Console catalog import, rollback, retirement and current-catalog eligibility tests; explicit isolated SQLite','exit_code':run.returncode,'output':output},indent=2)+'\n')
print(output);raise SystemExit(run.returncode)
