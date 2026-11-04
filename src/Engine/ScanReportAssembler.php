<?php
declare(strict_types=1);
namespace Magebean\Engine;
use Magebean\Engine\Pci\{PciApplicabilityCompiler, PciExternalEvidenceImporter, PciAssessmentReportBuilder};
final class ScanReportAssembler
{
    private const MODE_REMOTE = 'REMOTE';
    /** Preserves legacy metadata, PCI extensions and side-effect ordering. */
    public function assemble(ScanReport $report, ScanPlan $plan, ?array $remoteDetection = null, ?callable $written = null): ScanReport
    {
        $written ??= static function (string $path): void {};
        $result = $report->toLegacy();
        $configBasePath = $plan->metadata['configBasePath'];
        $configFile = $plan->metadata['configFile'];
        $activeProfile = $plan->metadata['activeProfile'];
        $standard = $plan->metadata['standard'];
        $isPciProfile = $plan->metadata['isPciProfile'];
        $profileRulesTotal = $plan->metadata['profileRulesTotal'];
        $profileManualRulesTotal = $plan->metadata['profileManualRulesTotal'];
        $manualRulesExcluded = $plan->metadata['manualRulesExcluded'];
        $includeManualReview = $plan->metadata['includeManualReview'];
        $hasExplicitRuleSelection = $plan->metadata['hasExplicitRuleSelection'];
        $requestedIds = $plan->metadata['requestedIds'];
        $controlsFilter = $plan->metadata['controlsFilter'];
        $projectPath = $plan->request->context->path;
        $projectUrl = $plan->request->context->url;
        $targetMode = (string)($plan->request->context->get('meta', [])['target_mode'] ?? 'LOCAL');
        $pciContextOpt = trim((string)($plan->request->options['pci-context'] ?? ''));
        $pciEvidenceOpt = trim((string)($plan->request->options['pci-evidence'] ?? ''));
        $pciReportOpt = trim((string)($plan->request->options['pci-report'] ?? ''));
        // attach meta
        $result['meta']['standard'] = $standard;
        $result['meta']['profile'] = $activeProfile;
        $result['meta']['target_mode'] = $targetMode;
        $result['meta']['rules_filter'] = $requestedIds;
        $result['meta']['controls_filter'] = $controlsFilter;
        $result['meta']['project_config'] = $configFile;
        $result['meta']['profile_rules_total'] = $profileRulesTotal;
        $result['meta']['profile_manual_rules_total'] = $profileManualRulesTotal;
        $result['meta']['manual_rules_hidden'] = $manualRulesExcluded;
        $result['meta']['manual_rules_included'] = $includeManualReview || $hasExplicitRuleSelection;
        if (($plan->metadata['assessment_model'] ?? $plan->pack['assessment_model'] ?? '') === 'internal-requirement-v1') {
            $result['meta']['assessment_model'] = 'internal-requirement-v1';
            if(isset($activeProfile['family']))$result['meta']['requirement_family']=$activeProfile['family'];
            $result['meta']['capabilities'] = $plan->metadata['capabilities'] ?? [];
            $selector = (string)($plan->metadata['profileSelector'] ?? $plan->metadata['profile_selector'] ?? $plan->request->options['profile'] ?? '');
            $result['meta']['profile_selector'] = $selector !== '' ? $selector : (string)($activeProfile['id'] ?? 'basic');
            $result['meta']['url'] = $projectUrl;
            $result['meta']['profile_inventory_count'] = (int)($plan->metadata['profileInventoryCount'] ?? $profileRulesTotal);
            $result['meta']['omitted_requirements'] = $plan->metadata['omittedRequirements'] ?? [];
            foreach ($result['findings'] as &$finding) {
                if (($finding['status'] ?? '') !== 'UNKNOWN') continue;
                if (($finding['risk_observation']['collection_complete'] ?? false) && !empty($finding['risk_observation']['detector_runs'])) continue;
                $finding['collection_guidance'] ??= RequirementDiagnostics::forFinding($finding);
                $finding['evidence']['collection_guidance'] = $finding['collection_guidance'];
                $finding['message'] = preg_replace('/^Necessary requirement evidence is missing, incomplete or indeterminate\.\s*/', '', (string)($finding['message'] ?? '')) ?: 'Required scan input is unavailable.';
            }
            unset($finding);
        }

        if (($plan->metadata['automationOnly'] ?? $activeProfile['automation_only'] ?? false) === true && ($result['meta']['assessment_model'] ?? '') === 'internal-requirement-v1') {
            $executionErrors = [];
            foreach ($result['findings'] as &$finding) {
                $risk = $finding['risk_observation'] ?? null;
                if (is_array($risk)) {
                    if ($risk['collection_complete']) continue;
                } elseif (!in_array(strtoupper((string)($finding['status'] ?? '')), ['UNKNOWN', 'MANUAL_REVIEW'], true)) continue;
                $finding['message'] = preg_replace('/^Necessary requirement evidence is missing, incomplete or indeterminate\.\s*/', '', (string)($finding['message'] ?? '')) ?: 'Automated check could not complete; inspect collection details.';
                $finding['classification'] = !empty($risk['needs_attention']) ? 'risk_observation' : 'execution_error';
                $finding['execution_status'] = 'ERROR';
                $executionErrors[] = ['id' => $finding['id'], 'message' => $finding['message'] ?? '', 'reason_code' => $finding['reason_code'] ?? null, 'collection_guidance' => $finding['collection_guidance'] ?? null];
            }
            unset($finding);
            $result['meta']['automation_only'] = true;
            $result['meta']['scan_complete'] = $executionErrors === [];
            $result['execution_errors'] = $executionErrors;
            $result['summary']['execution_errors'] = count($executionErrors);
        }

        $result['summary']['path'] = $projectPath;
        $result['summary']['url'] = $projectUrl;

        // Presentation lanes describe the criterion; they never change its outcome.
        $definitions = array_column($plan->pack['rules'] ?? [], null, 'id');
        $lanes = [];
        foreach ($result['findings'] as &$finding) {
            $lane = $definitions[$finding['id'] ?? '']['lane'] ?? null;
            if (!in_array($lane, ['security', 'readiness'], true)) continue;
            $finding['requirement']['lane'] = $lane;
            $lanes[$lane] ??= ['total' => 0, 'passed' => 0, 'failed' => 0, 'unresolved' => 0];
            ++$lanes[$lane]['total'];
            $bucket = match ($finding['status'] ?? '') { 'PASS' => 'passed', 'FAIL' => 'failed', default => 'unresolved' };
            ++$lanes[$lane][$bucket];
        }
        unset($finding);
        if ($lanes !== []) $result['summary']['lanes'] = $lanes;
        if (($activeProfile['family'] ?? '') === 'magebean' && !empty($result['meta']['automation_only'])) {
            $result['meta']['findings_first'] = true;
            $result['risk_findings'] = [];
            $result['collection_issues'] = [];
            foreach ($result['findings'] as $finding) {
                $risk = $finding['risk_observation'] ?? null;
                if (!is_array($risk)) continue;
                if ($risk['needs_attention']) {
                    $attention = $finding;
                    $attention['message'] = $risk['findings'][0]['message'] ?? $finding['message'];
                    $attention['classification'] = 'risk_observation';
                    $severities = ['critical', 'high', 'medium', 'low', 'info'];
                    $observedSeverities = [];
                    foreach ($risk['findings'] as $row) {
                        if (($row['kind'] ?? '') !== 'collection_issue') $observedSeverities[] = $row['severity'] ?? $finding['severity'];
                    }
                    $attention['severity'] = array_values(array_intersect($severities, $observedSeverities))[0] ?? $finding['severity'];
                    if (array_filter($risk['findings'], static fn(array $row):bool => ($row['kind'] ?? '') !== 'collection_issue') === []) {
                        $attention['severity'] = 'info';
                        $attention['title'] = $attention['message'];
                        $attention['requirement']['lane'] = 'collection';
                        $attention['requirement']['finding_guidance'] = [];
                        $attention['remediation'] = array_values(array_unique(array_filter(array_map(static fn(array $row):string => $row['evidence']['collection_guidance']['action'] ?? '', $risk['findings']))));
                    }
                    $result['risk_findings'][] = $attention;
                }
                foreach ($risk['collection_gaps'] as $gap) {
                    foreach ($finding['detail'] ?? [] as $detail) {
                        if (($detail['check'] ?? '') === ($gap['check'] ?? '') && !empty($detail['collection_guidance'])) {
                            $gap['collection_guidance'] = $detail['collection_guidance'];
                            break;
                        }
                    }
                    $gap['collection_guidance'] ??= $finding['collection_guidance'] ?? [];
                    $result['collection_issues'][] = ['id'=>$finding['id']] + $gap;
                }
            }
            $categories = [];
            foreach ($result['risk_findings'] as $finding) {
                foreach ($finding['risk_observation']['findings'] as $row) {
                    if (!isset($row['category'])) continue;
                    $categories[$row['category']] = ($categories[$row['category']] ?? 0) + 1;
                }
            }
            if ($categories !== []) $result['summary']['detector_findings_by_category'] = $categories;
            $result['summary']['needs_attention'] = count($result['risk_findings']);
            $result['summary']['collection_issues'] = count($result['collection_issues']);
        }
        if (!empty($activeProfile['evidence_tasks'])) {
            $result['evidence_tasks'] = array_map(static fn(array $task): array => array_merge($task, ['status' => 'NOT_ASSESSED']), $activeProfile['evidence_tasks']);
        }
        if (!empty($activeProfile['show_unassessed_requirements']) || !empty($activeProfile['automation_only'])) {
            $profile = RequirementProfileCatalog::load($plan->metadata['profile_selector'] ?? $activeProfile['id']);
            $catalog=array_column(RequirementCatalog::loadAll()['rules'],null,'id');
            $executed=array_column($result['findings'],null,'id');
            $omitted=array_column($result['meta']['omitted_requirements']??[],null,'id');
            $notEvaluated=[];
            foreach ($profile['requirement_ids'] as $id) {
                if (isset($executed[$id])) continue;
                $definition=$catalog[$id];
                $reason=$omitted[$id]['reason_code']??(!$includeManualReview&&!$hasExplicitRuleSelection&&RequirementPolicy::requiresHuman($definition)?'HUMAN_EVIDENCE_NOT_INCLUDED':'NOT_SELECTED');
                $notEvaluated[]=['id'=>$id,'title'=>$definition['title'],'status'=>'NOT_ASSESSED','reason_code'=>$reason];
            }
            $result['not_evaluated_requirements']=$notEvaluated;
            $unresolved=count(array_filter($result['findings'],static fn(array $f):bool=>!in_array($f['status'],['PASS','FAIL'],true)));
            $result['coverage_summary']=['inventory'=>count($profile['requirement_ids']),'executed'=>count(array_intersect(array_keys($executed),$profile['requirement_ids'])),'not_evaluated'=>count($notEvaluated),'unresolved'=>$unresolved,'external_evidence_groups'=>count($result['evidence_tasks']??[]),'assessment_complete'=>$notEvaluated===[]&&$unresolved===0&&empty($result['evidence_tasks'])];
        }

        if ($isPciProfile) {
            $registryData = $this->loadJsonDocument(__DIR__ . '/../Rules/standards/pci-dss-v4.0.1.json', 'PCI DSS registry');
            $coverageData = $this->loadJsonDocument(__DIR__ . '/../Rules/standards/pci-dss-v4.0.1-coverage.json', 'PCI DSS coverage matrix');
            $triageData = $this->loadJsonDocument(__DIR__ . '/../Rules/standards/pci-dss-v4.0.1-gap-triage.json', 'PCI DSS gap triage');
            $criterionReviewData = $this->loadJsonDocument(__DIR__ . '/../Rules/standards/pci-dss-v4.0.1-automation-candidate-review.json', 'PCI DSS criterion review');
            $requirement02ReviewData = $this->loadJsonDocument(__DIR__ . '/../Rules/standards/pci-dss-v4.0.1-requirement-02-review.json', 'PCI DSS Requirement 2 review');
            $criterionReviewData['requirements'] = array_merge($requirement02ReviewData['requirements'] ?? [], $criterionReviewData['requirements'] ?? []);
            if (($plan->metadata['assessment_model'] ?? $plan->pack['assessment_model'] ?? '') === 'internal-requirement-v1') {
                // Every registered criterion needs the primary assessment scope, even when
                // a default scan omits human-only execution from its finding selection.
                $primaryReviews = [];
                foreach (RequirementCatalog::loadAll()['rules'] as $definition) {
                    foreach ($definition['alignments'] ?? [] as $alignment) {
                        if (($alignment['standard'] ?? '') !== 'PCI-DSS' || ($alignment['version'] ?? '') !== '4.0.1') continue;
                        $primaryReviews[] = [
                            'requirement' => (string)$alignment['reference'],
                            'internal_requirement_id' => $definition['id'],
                            'criterion' => $alignment['scoped_criterion'] ?? $definition['criterion'],
                            'criterion_summary' => $alignment['scoped_criterion'] ?? $definition['criterion'],
                            'human_assessment_scope' => $alignment['scoped_human_instructions'] ?? $definition['human_evidence']['instructions'] ?? $definition['criterion'],
                            'testing_methods' => $alignment['testing_methods'] ?? $definition['human_evidence']['evidence_types'] ?? [],
                            'source_metadata' => $alignment['source_metadata'] ?? $definition['source_metadata'] ?? [],
                        ];
                    }
                }
                $criterionReviewData['requirements'] = array_merge($criterionReviewData['requirements'], $primaryReviews);
            }

            $compiler = new PciApplicabilityCompiler();
            $pciContext = $pciContextOpt !== '' ? $compiler->load(ProjectPath::resolve($pciContextOpt, $configBasePath)) : [
                'schema_version' => 1, 'entity_type' => 'merchant', 'issuer_or_issuing_services' => false,
                'scope_confirmed' => false, 'payment_architecture' => 'unknown', 'pan_handling' => 'unknown',
                'overlays' => [], 'requirement_overrides' => [],
            ];
            $applicability = $compiler->compile($registryData, $pciContext);
            if (($applicability['valid'] ?? false) !== true) throw new \RuntimeException("Invalid PCI applicability context:\n- " . implode("\n- ", $applicability['errors'] ?? []));
            $externalEvidence = ['valid' => true, 'errors' => [], 'evidence_by_requirement' => [], 'summary' => ['items' => 0, 'requirements' => 0, 'credential_material_processed' => false]];
            if ($pciEvidenceOpt !== '') {
                $externalEvidence = (new PciExternalEvidenceImporter(array_column($registryData['requirements'] ?? [], 'id')))->import(ProjectPath::resolve($pciEvidenceOpt, $configBasePath));
                if (($externalEvidence['valid'] ?? false) !== true) throw new \RuntimeException("Invalid PCI external evidence package:\n- " . implode("\n- ", $externalEvidence['errors'] ?? []));
            }
            $pciReport = (new PciAssessmentReportBuilder())->build($result, $coverageData, $triageData, $applicability, $externalEvidence, $includeManualReview, $criterionReviewData);
            $pciReport['context_source'] = $pciContextOpt !== '' ? $pciContextOpt : 'default:unconfirmed';
            $pciReport['evidence_source'] = $pciEvidenceOpt !== '' ? $pciEvidenceOpt : null;
            $result['pci'] = $pciReport;
            if ($pciReportOpt !== '') {
                $pciReportFile = ProjectPath::resolve($pciReportOpt, $configBasePath);
                $pciReportDir = dirname($pciReportFile);
                if (!is_dir($pciReportDir) && !mkdir($pciReportDir, 0777, true) && !is_dir($pciReportDir)) throw new \RuntimeException('Cannot create PCI report directory: ' . $pciReportDir);
                if (file_put_contents($pciReportFile, json_encode($pciReport, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n") === false) throw new \RuntimeException('Cannot write PCI report: ' . $pciReportFile);
                $written($pciReportFile);
            }
        }
        if ($targetMode === self::MODE_REMOTE) {
            $planned = (int)($result['meta']['planned_rules'] ?? 0);
            $executed = (int)($result['meta']['executed_rules'] ?? 0);
            $transportTotal = (int)($result['meta']['transport_total'] ?? 0);
            $transportOk = (int)($result['meta']['transport_ok'] ?? 0);
            $coveragePercent = $planned > 0
                ? (int)round(($executed / $planned) * 100)
                : 0;
            $transportPercent = $transportTotal > 0
                ? (int)round(($transportOk / $transportTotal) * 100)
                : 0;
            $detectionConfidence = (int)($remoteDetection['confidence'] ?? 0);

            $result['meta']['detected'] = $remoteDetection ?? [
                'confirmed' => false,
                'confidence' => 0,
                'message' => 'Magento fingerprint was not checked.',
                'signals' => [],
            ];
            $result['meta']['coverage_percent'] = $coveragePercent;
            $result['meta']['transport_success_percent'] = $transportPercent;
            $result['meta']['overall_confidence'] = (int)round(
                ($detectionConfidence * 0.4)
                + ($transportPercent * 0.3)
                + ($coveragePercent * 0.3)
            );
            $result['meta']['assurance'] = 'externally_observable';
        }

        $result['cve_audit'] = null;

        return ScanReport::fromLegacy($result, $report->checkResults);
    }
    private function loadJsonDocument(string $path, string $label): array
    {
        try { $data = json_decode((string)file_get_contents($path), true, 512, JSON_THROW_ON_ERROR); }
        catch (\JsonException) { throw new \RuntimeException($label . ' contains malformed JSON.'); }
        if (!is_array($data)) throw new \RuntimeException($label . ' root must be an object.');
        return $data;
    }
}
