<?php
declare(strict_types=1);
namespace Magebean\Engine;

/** Interpretation of observed predicates, not a replacement for their evidence or assessments. */
final class MagebeanFindingSemantics
{
    private const POLICY = ['MB-0002','MB-0006','MB-0009','MB-0014','MB-0031','MB-0034','MB-0037','MB-0038','MB-0040','MB-0043','MB-0047','MB-0048','MB-0057','MB-0059','MB-0061','MB-0062','MB-0063','MB-0065','MB-0066','MB-0067','MB-0069','MB-0728','MB-0731','MB-0741','MB-0744','MB-0774','MB-0783','MB-0785','MB-0786','MB-0788','MB-0789','MB-0790','MB-0791','MB-0792','MB-0793','MB-0794','MB-0795','MB-0796','MB-0797','MB-0798','MB-0799','MB-0801','MB-0802','MB-0805','MB-0814'];
    private const MAINTENANCE = ['MB-0057','MB-0059','MB-0061','MB-0062','MB-0063','MB-0069','MB-0744'];
    private const SOURCE_POLICY = ['MB-0014','MB-0786','MB-0788','MB-0789','MB-0790','MB-0791','MB-0792','MB-0793','MB-0794','MB-0795','MB-0796','MB-0797','MB-0798','MB-0814'];
    private const SUSPECTED = ['MB-0072','MB-0730','MB-0733','MB-0736','MB-0780','MB-0782','MB-0787','MB-0800','MB-0813','MB-0822'];
    private const CORRECTNESS = ['MB-0035','MB-0039','MB-0046','MB-0056','MB-0070','MB-0100','MB-0784','MB-0808','MB-0809','MB-0810','MB-0811','MB-0812','MB-0815','MB-0816','MB-0817','MB-0818','MB-0819','MB-0820','MB-0821','MB-0823','MB-0824','MB-0825','MB-0826'];
    private const SECURITY = ['MB-0001','MB-0003','MB-0005','MB-0007','MB-0011','MB-0026','MB-0027','MB-0028','MB-0029','MB-0030','MB-0042','MB-0049','MB-0050','MB-0055','MB-0729','MB-0739','MB-0740','MB-0742','MB-0773','MB-0775','MB-0776','MB-0777','MB-0778','MB-0779','MB-0781','MB-0803','MB-0804','MB-0807','MB-0828'];
    private const EVIDENCE_LINT = ['MB-0093','MB-0806'];

    public static function profile(string $id): array
    {
        if (in_array($id,self::EVIDENCE_LINT,true)) return ['category'=>'informational','confidence'=>'informational','claim_type'=>'evidence_record_lint'];
        if ($id==='MB-0827') return ['category'=>'informational','confidence'=>'informational','claim_type'=>'review_context'];
        if (in_array($id,self::POLICY,true)) return ['category'=>'policy','confidence'=>'confirmed','claim_type'=>in_array($id,self::MAINTENANCE,true)?'maintenance_context':'observed_policy_violation'];
        if (in_array($id,self::SUSPECTED,true)) return ['category'=>'security','confidence'=>'suspected','claim_type'=>'review_candidate'];
        if (in_array($id,self::CORRECTNESS,true)) return ['category'=>'correctness','confidence'=>$id==='MB-0826'?'suspected':'confirmed','claim_type'=>$id==='MB-0826'?'review_candidate':'observed_relationship_defect'];
        if (in_array($id,self::SECURITY,true)) return ['category'=>'security','confidence'=>'confirmed','claim_type'=>in_array($id,['MB-0049','MB-0050','MB-0055','MB-0828'],true)?'advisory_or_patch_match':'observed_technical_condition'];
        // Custom/unreviewed rules never gain a security claim from proof metadata alone.
        return ['category'=>'policy','confidence'=>'suspected','claim_type'=>'unclassified_check_observation'];
    }

    public static function decorate(array $definition, array $row, bool $typed = false): array
    {
        $id=$definition['id'];$semantic=self::profile($id);
        if ($typed && !in_array($id,self::EVIDENCE_LINT,true)) {
            if ($semantic['category']!==$row['category']) $semantic['claim_type']=match($row['category']) {
                'informational'=>'review_context', 'correctness'=>'observed_relationship_defect', 'security'=>'observed_technical_condition', default=>'observed_policy_violation',
            };
            $semantic['category']=$row['category'];$semantic['confidence']=$row['confidence'];
            if ($row['confidence']==='suspected') $semantic['claim_type']='review_candidate';
        }
        if (!$typed && ($row['evidence']??[])===[] && $semantic['confidence']==='confirmed') {
            $semantic['confidence']='suspected'; $semantic['claim_type']='review_candidate';
        }
        $row=array_replace($row,$semantic);
        $row['confidence_basis']='Confidence describes the observed condition or relationship only; exploitation, runtime reachability and business impact are not established by this label.';
        $row['exploitability']='not_established';
        $severity=!empty($definition['presentation_severity_override']) ? $definition['severity'] : ($row['severity']??$definition['severity']??'info');
        if ($semantic['category']==='informational') $severity='info';
        elseif ($semantic['category']==='policy' && empty($definition['presentation_severity_override'])) {
            $limit=in_array($id,self::MAINTENANCE,true)||in_array($id,self::SOURCE_POLICY,true)?'low':'medium';
            $rank=['info'=>0,'low'=>1,'medium'=>2,'high'=>3,'critical'=>4];
            if (($rank[$severity]??0)>$rank[$limit]) $severity=$limit;
        }
        $row['severity']=$severity;
        $row['guidance']=self::guidance($definition,$semantic);
        if ($semantic['category']==='policy' && $semantic['claim_type']!=='unclassified_check_observation' && !str_starts_with($row['message'],'Policy: ')) $row['message']='Policy: '.$row['message'];
        if ($semantic['claim_type']==='evidence_record_lint' && !str_starts_with($row['message'],'Evidence record: ')) $row['message']='Evidence record: '.$row['message'];
        return $row;
    }

    public static function guidance(array $definition, ?array $semantic = null): array
    {
        $id=$definition['id'];$semantic??=self::profile($id);
        $impact=$definition['finding_guidance']['risk']??'Review the observed condition in the collected store context.';
        $action=$definition['remediation'][0]??'Inspect the named evidence and correct the observed condition.';
        $verify=$definition['remediation'][1]??'Verify the changed file, configuration or component independently.';
        if (in_array($id,self::SOURCE_POLICY,true)) {
            $impact='The reported file/line contains the named construct. This is a coding-policy observation; local file access, a fixed command, UI randomness or a query-named method alone does not establish data exposure or injection.';
            $action='Inspect each named call and argument at the reported file/line. Trace input origin, receiver identity, authorization and output use before deciding whether to replace the API or document an approved exception to this explicit coding policy.';
            $verify='Test the affected behavior and its real trust boundary. Replacing an API or wrapping a call does not by itself validate input or remove an exploit path.';
            if ($id==='MB-0014') $action.=' Use Magento RequestInterface where the project policy requires it; changing the input-access API does not validate or authorize its values.';
            if ($id==='MB-0786') $action.=' Confirm the receiver is a SQL interface before interpreting a query-named method as database access; verify binding and identifier handling separately.';
            if ($id==='MB-0794') $action.=' A random UI color or nonsecurity identifier does not require a cryptographic claim; determine whether the value protects a secret or access decision.';
        } elseif (in_array($id,self::MAINTENANCE,true)) {
            $impact='The observed upstream status or age threshold is maintenance context. Latest-release age, archival, abandonment, withdrawal or advisory publication age alone is not proof of EOL, installed exposure duration or exploitability.';
            $action='Match the reported package/version, source status and observation time. Confirm affected advisories and vendor support separately; apply a reviewed update, replacement or approved maintenance exception as appropriate.';
            $verify='Verify the current package metadata and upstream response again. Test Magento/module compatibility after any dependency change; a newer version number alone does not prove the store safe.';
        } elseif (in_array($id,['MB-0038','MB-0040','MB-0741'],true)) {
            $impact='The declared backend differs from this named backend/authentication policy. A file backend or non-Redis alternative alone does not establish unauthorized access or an unsafe session store.';
            $action='Review the exact declared backend/key in app/etc/env.php against the intended deployment baseline. If Redis is used, verify authentication and network/ACL access separately before changing the backend.';
            $verify='Test cache/session correctness and effective access with the deployed worker configuration. A declaration alone does not prove runtime enforcement.';
        } elseif (in_array($id,self::EVIDENCE_LINT,true)) {
            $impact='This checks supplied document/record structure, topics or expiry only. It does not verify a mitigation, PCI compliance or a technical vulnerability.';
            $action='Review the named supplied document or record and the explicit expected topics/identities. Link its claim to independently observed technical evidence; correct only the missing or invalid record fields.';
            $verify='Verify the actual implementation and relevant technical finding separately. Passing document lint does not close a security issue or satisfy a standard clause.';
        } elseif (in_array($id,self::SUSPECTED,true)) {
            $impact='The reported pattern or supported output/declaration relationship warrants review. Credential validity, executable serving, alternate authorization and actual input influence require evidence specific to this location.';
        } elseif ($semantic['category']==='policy') {
            $impact='The exact observed value or construct differs from the stated Magebean or supplied baseline. This confirms that scoped policy comparison only, not an exploitable vulnerability.';
        }
        return ['claim_type'=>$semantic['claim_type'],'impact'=>$impact,'action'=>$action,'verification'=>$verify,
            'recheck'=>'Rerun '.$id.' against the same release, profile and relevant file/key/package scope; compare the new evidence and inspect any independent collection gaps.'];
    }
}
