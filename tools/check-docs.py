#!/usr/bin/env python3
"""Offline documentation links, profile counts and relocation checks."""
import json,re,subprocess,sys
from pathlib import Path
from urllib.parse import unquote,urlsplit
ROOT=Path(__file__).resolve().parents[1]
errors=[];links=0
files=[ROOT/'README.md',ROOT/'CONTRIBUTING.md',ROOT/'SECURITY.md',*(ROOT/'docs').rglob('*.md')]
pattern=re.compile(r'!?\[[^\]\n]*\]\(([^\s)]+)\)')
for p in files:
 text=p.read_text()
 for m in pattern.finditer(text):
  target=m[1].strip('<>');url=urlsplit(target)
  if url.scheme or target.startswith(('#','//')):continue
  if not url.path:continue
  path=(p.parent/unquote(url.path)).resolve();links+=1
  if not path.exists():errors.append(f'{p.relative_to(ROOT)}: missing link {target}')
# Compare current tables against executable selection, including human evidence gates.
php=r"""<?php
require 'vendor/autoload.php';$rows=[];
foreach(\Magebean\Engine\RequirementProfileCatalog::all() as $key=>$p){$pack=\Magebean\Engine\RequirementCatalog::forProfile($key);$rows[$key]=[count($p['requirement_ids']),count(array_filter($pack['rules'],static fn(array $r):bool=>!\Magebean\Engine\RequirementPolicy::requiresHuman($r)))];}
echo json_encode($rows,JSON_THROW_ON_ERROR);
"""
run=subprocess.run(['php'],input=php,cwd=ROOT,text=True,capture_output=True)
if run.returncode:errors.append('Cannot read runtime profiles: '+run.stderr)
else:
 expected=json.loads(run.stdout);alias={'owasp':'owasp-top-10-2025','pci':'pci-dss-v4.0.1'}
 for relative in ['README.md','docs/guides/profiles.md','docs/magebean-baseline-v1.md']:
  rows=0
  for line in (ROOT/relative).read_text().splitlines():
   if not line.startswith('|'):continue
   cells=[c.strip().strip('`') for c in line.strip('|').split('|')];key=alias.get(cells[0],cells[0])
   if key not in expected:continue
   counts=[int(c) for c in cells[1:] if c.isdigit()]
   if counts[:2]!=expected[key]:errors.append(f'{relative}: {key} counts {counts[:2]}, runtime {expected[key]}')
   rows+=1
  target=11 if relative.endswith('magebean-baseline-v1.md') else 15
  if rows!=target:errors.append(f'{relative}: expected {target} profile rows, got {rows}')
manifest=json.loads((ROOT/'docs/archive/relocation-manifest.json').read_text())['files']
for item in manifest:
 if not (ROOT/item['to']).is_file():errors.append('Missing relocated file '+item['to'])
 if (ROOT/item['from']).exists():errors.append('Superseded documentation still occupies '+item['from'])
# Old repo-relative path literals must not survive in executable references.
for directory in ['src','tests','tools']:
 for p in (ROOT/directory).rglob('*'):
  if not p.is_file() or p.suffix not in ['.php','.py','.ps1','.json']:continue
  text=p.read_text()
  for item in manifest:
   if item['from'] in text:errors.append(f'{p.relative_to(ROOT)}: stale reference {item["from"]}')
if errors:
 print('\n'.join('FAIL '+e for e in errors));raise SystemExit(1)
print(f'Documentation: {len(files)} Markdown files, {links} local links, 41 profile-table rows and {len(manifest)} relocations verified.')
