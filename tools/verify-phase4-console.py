#!/usr/bin/env python3
"""Run the existing Console ingestion contract with shared canonical refs in isolated SQLite."""
import json
import os
import subprocess
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONSOLE = ROOT.parent / 'console-magebean'
source = CONSOLE / 'tests/Feature/Agent/InstanceScanApiTest.php'
if not source.is_file():
    raise SystemExit('This optional integration check needs the sibling Console workspace.')
code = source.read_text().replace('class InstanceScanApiTest extends TestCase', 'class Phase4CanonicalTransportTest extends TestCase')
code = code.replace('    private function payload(): array', '    private function basePayload(): array')
code = code.replace("'evidence_requirement' => false,", "'standard_mapping'=>['family'=>'magebean'], 'evidence_requirement' => false,")
pairs = json.loads((ROOT / 'docs/archive/current-state/phase4/acceptance-results.json').read_text())['pairs']
pair = next(p for p in pairs if p['issue_family'] == 'source-command-call')
ref = {'issue_id': pair['issue_id'], 'issue_family': pair['issue_family'], 'correlation_status': 'evidence_identity', 'related_rule_ids': pair['rules']}
ref_json = json.dumps([ref])

# Exercise the archived mapper with freshly captured real policy + typed-flow evidence.
mapper = ROOT / 'build/phase4-console-wire.php'
mapper.write_text("""<?php
require 'phar://'.__DIR__.'/../magebean.phar/vendor/autoload.php';
$data=json_decode(file_get_contents(__DIR__.'/../docs/archive/current-state/phase4/overlap-probes.json'),true,512,JSON_THROW_ON_ERROR);
$rows=[];foreach($data['results'] as $row)if(in_array($row['id'],['MB-0790','MB-0822'],true))$rows[]=[
 'id'=>$row['id'],'severity'=>$row['severity'],'status'=>$row['risk_observation']['assessment_outcome'],
 'message'=>$row['messages'][0],'evidence'=>[],'detail'=>[],'risk_observation'=>$row['risk_observation'],
];
$bindings=[['canonical_id'=>'MB-0790','requested_key'=>'MB-INSTANCE-001','assessment_item_id'=>'policy'],['canonical_id'=>'MB-0822','requested_key'=>'MB-INSTANCE-002','assessment_item_id'=>'flow']];
$wire=(new \\Magebean\\Agent\\AgentResultMapper())->map(['findings'=>$rows,'summary'=>[]],[],[],[],'/unused-fixture-root',$bindings);
foreach($wire['results'] as &$row)unset($row['assessment_item_id']);unset($row);
echo json_encode($wire,JSON_THROW_ON_ERROR);
""")
wire_run=subprocess.run(['php',str(mapper)],cwd=ROOT,capture_output=True,text=True,check=True)
wire=json.loads(wire_run.stdout)
assert [r['status'] for r in wire['results']]==['fail','error']
assert wire['summary']['canonical_issue_count']==1
wire_path=ROOT/'docs/archive/current-state/phase4/agent-protocol-fixture.json'
wire_path.write_text(json.dumps(wire,indent=2)+'\n')

extra = r"""
    public function createApplication(): \Illuminate\Foundation\Application
    {
        $app = require __CONSOLE_BOOTSTRAP__;
        $app->make(\Illuminate\Contracts\Console\Kernel::class)->bootstrap();
        $app['config']->set('database.default', 'sqlite');
        $app['config']->set('database.connections.sqlite.database', ':memory:');
        $app['config']->set('database.connections.sqlite.url', null);
        $app['config']->set('mail.default', 'array');
        $app['config']->set('cache.default', 'array');
        $app['config']->set('queue.default', 'sync');
        return $app;
    }

    private function payload(): array
    {
        $payload=$this->basePayload();
        $wire=json_decode(file_get_contents(__WIRE_PATH__),true,512,JSON_THROW_ON_ERROR);
        $payload['results']=$wire['results'];
        $payload['summary']=$wire['summary'];
        return $payload;
    }
"""
# Values are PHP string literals, never shell interpolation.
def php_string(text):
    return "'" + text.replace('\\', '\\\\').replace("'", "\\'") + "'"
extra = extra.replace('__CONSOLE_BOOTSTRAP__', php_string(str(CONSOLE / 'bootstrap/app.php'))).replace('__REFERENCE_JSON__', php_string(ref_json)).replace('__WIRE_PATH__', php_string(str(wire_path)))
code = code.replace('    private function fixture(): array', extra + '\n    private function fixture(): array')
anchor = "        $profile->rules()->attach($rule, ['default_included' => true, 'sort_order' => 1]);"
assert anchor in code
code = code.replace(anchor, anchor + r"""
        $secondRule=Rule::query()->create(['standard_mapping'=>['family'=>'magebean'],'rule_key'=>'MB-INSTANCE-002','title'=>'Second instance rule','description'=>'Independent transport fixture.','severity'=>Severity::High,'verification_method'=>VerificationMethod::Automated,'evidence_requirement'=>false,'status'=>'active']);
        $profile->rules()->attach($secondRule,['default_included'=>true,'sort_order'=>2]);
""")
# The current Console keeps one current assessment per instance. Use a focused
# two-rule test rather than the older multi-assessment fanout fixture's assumptions.
start = code.index('    public function test_instance_scan_fans_out_to_relevant_assessments_and_is_idempotent')
helpers = code.index('    private function basePayload(): array', start)
method = r"""
    public function test_canonical_refs_preserve_instance_observations_and_idempotency(): void
    {
        [$owner,$company,$instance,$baseline,$token]=$this->fixture();
        $assessment=app(CreateAssessment::class)->handle($owner,$company,$instance,$baseline,['name'=>'Canonical transport fixture']);
        $this->assertCount(2,$assessment->items);
        $this->assertSame('sqlite',config('database.default'));
        $this->assertSame(':memory:',config('database.connections.sqlite.database'));
        $payload=$this->payload();
        $response=$this->withToken($token)->withHeader('Idempotency-Key','canonical-001')
            ->postJson("/api/v1/instances/{$instance->id}/scans",$payload)
            ->assertCreated()->assertJsonPath('observations',2)->assertJsonPath('projections',2);
        $scanId=$response->json('scan_id');
        $this->assertDatabaseCount('scan_runs',1);
        $this->assertDatabaseCount('scan_observations',2);
        $this->assertDatabaseCount('assessment_item_results',2);
        $this->assertDatabaseCount('scan_results',2);
        $this->assertDatabaseCount('findings',2);
        $observations=\App\Models\ScanObservation::query()->where('scan_run_id',$scanId)->get();
        $this->assertCount(2,$observations);
        foreach($observations as $observation) {
            $this->assertSame(__ISSUE_ID__,$observation->evidence['canonical_issue_refs'][0]['issue_id']);
            $this->assertSame(['MB-0790','MB-0822'],$observation->evidence['canonical_issue_refs'][0]['related_rule_ids']);
        }
        $byKey=$observations->keyBy('rule_key');
        $this->assertSame('fail',$byKey['MB-INSTANCE-001']->status->value);
        $this->assertSame('error',$byKey['MB-INSTANCE-002']->status->value);
        $this->assertArrayHasKey('source_sha256',$byKey['MB-INSTANCE-002']->evidence['risk_observation']['findings'][0]['evidence']['locations'][0]);
        $this->assertArrayHasKey('byte_offset',$byKey['MB-INSTANCE-002']->evidence['risk_observation']['findings'][0]['evidence']['locations'][0]);
        $this->withToken($token)->withHeader('Idempotency-Key','canonical-001')
            ->postJson("/api/v1/instances/{$instance->id}/scans",$payload)
            ->assertCreated()->assertJsonPath('scan_id',$scanId)->assertJsonPath('observations',2)->assertJsonPath('projections',2);
        $this->assertDatabaseCount('scan_runs',1);
        $this->assertDatabaseCount('scan_observations',2);
        $this->assertDatabaseCount('assessment_item_results',2);
        $this->assertDatabaseCount('findings',2);
        $this->withToken($token)->withHeader('Idempotency-Key','canonical-001')
            ->postJson("/api/v1/instances/{$instance->id}/scans",[...$payload,'status'=>'partial'])
            ->assertConflict()->assertJsonPath('error.code','scan_uuid_conflict');
        $payload['results'][0]['message']='Updated source observation; canonical reference is unchanged.';
        $this->withToken($token)->withHeader('Idempotency-Key','canonical-002')
            ->postJson("/api/v1/instances/{$instance->id}/scans",$payload)
            ->assertCreated()->assertJsonPath('observations',2)->assertJsonPath('projections',2);
        $this->assertDatabaseCount('scan_runs',2);
        $this->assertDatabaseCount('scan_observations',4);
        $this->assertDatabaseCount('assessment_item_results',4);
    }

""".replace('__ISSUE_ID__', php_string(ref['issue_id']))
code=code[:start]+method+code[helpers:]

path = ROOT / 'build/Phase4CanonicalTransportTest.php'
path.write_text(code)
env = dict(os.environ)
env.update({'APP_ENV':'testing', 'DB_CONNECTION':'sqlite', 'DB_DATABASE':':memory:', 'DB_URL':'',
            'MAIL_MAILER':'array', 'CACHE_STORE':'array', 'QUEUE_CONNECTION':'sync', 'SESSION_DRIVER':'array',
            'APP_CONFIG_CACHE':str(ROOT / ('build/unused-config-' + uuid.uuid4().hex + '.php'))})
run = subprocess.run(['php', str(CONSOLE / 'vendor/bin/phpunit'), '--configuration', str(CONSOLE / 'phpunit.xml'),
    '--colors=never', '--filter', 'test_canonical_refs_preserve_instance_observations_and_idempotency', str(path)],
    cwd=CONSOLE, env=env, capture_output=True, text=True)
text = run.stdout + run.stderr
out = ROOT / 'docs/archive/current-state/phase4/console-validation.json'
out.write_text(json.dumps({'scope':'Archived mapper + freshly executed real policy and typed-flow evidence, requested-key fixture bindings, raw fail/error statuses; one current assessment with 2 items; isolated SQLite only',
    'exit_code':run.returncode, 'output':text, 'expected_observations':2, 'expected_projections':2,
    'expected_findings':2, 'canonical_issue_count':1, 'production_console_files_changed':False}, indent=2) + '\n')
print(text[-5000:])
raise SystemExit(run.returncode)
