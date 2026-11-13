# Independent requirement catalog migration

The primary runtime model uses one internal `MB-…` identity per requirement and a persisted definition independent of the legacy MB-R catalog. Profiles select these identities. Registered check functions supply reusable observations; requirement-owned obligations determine how those observations can support its assessment.

## Layers and accounting

| Layer | Role |
|---|---|
| Primary requirement catalog | Identity, revision, criterion, obligations, applicability and alignment |
| Profiles | Membership and assessment context; no duplicate requirement logic |
| Check registry/library | Reusable evidence-producing functions with explicit arguments |
| Standard registries | Version-qualified ASVS and PCI reference identities |
| Compatibility adapter | Historical MB-R and former ASVS selectors; historical findings/manifests |
| Reporters | One finding per selected internal identity; standard views from alignment |

The former `371 MB-R + 345 ASVS = 716` figure combined a source layer and a compiled layer, and omitted the 280-entry PCI reference registry. It was not a unique inventory count. The 338 MB-R sources mapped to ASVS were mapping overlaps, not proven semantic duplicates. The 10 external MB-R selectors are target-mode variants of existing local IDs.

The primary inventory contains **684 active internal definition IDs** after criterion-level consolidation: 83 Magebean-only definitions, 344 ASVS-aligned definitions and 257 PCI-aligned definitions. All **345 ASVS and 280 PCI reference identities** remain represented once in alignment metadata. A combined criterion retains every required source clause and standard-specific scope; shared functions alone do not establish equivalence.

| Profile | Default listed | With human review, no optional capabilities | Human-only entries |
|---|---:|---:|---:|
| basic | 20 | 20 | 0 |
| hardening | 81 | 82 | 1 |
| owasp | 69 | 69 | 0 |
| asvs-l1 | 41 | 69 | 28 |
| asvs-l2 | 89 | 197 | 108 |
| asvs-l3 | 97 | 267 | 170 |
| pci | 32 | 257 | 225 |
| external | 9 | 9 | 0 |

The allocator retains 727 historical allocations: the previously confirmed Composer duplicate plus 42 identities retired through 13 approved semantic consolidation groups. Retired IDs redirect to surviving IDs and are never reassigned. Definitions with combined criteria increment their revisions and retain mandatory human review; consolidation does not approve detector sufficiency.

Complete ASVS profile memberships are 69/252/344 with all optional capabilities enabled. Reports preserve `profile_inventory_count` and `omitted_requirements`; contextual omissions do not establish non-applicability. The original ten remote selectors now produce nine canonical assessments while preserving their evidence recipes. PCI selection contains 257 canonical definitions with 280 standard references, including 32 definitions with runnable technical observations. PCI reports retain all atomic standard-scoped criteria and human instructions.

Merged definitions preserve multiple `control_tags`; catalog, CLI and listing filters match any retained tag. Excluding one of those controls excludes the canonical requirement rather than removing an obligation from it. CLI selectors and custom profiles resolve retired internal IDs and deduplicate membership. Agent manifests may request several different keys that redirect to one canonical definition: execution occurs once, while results retain each requested key and assessment item. Summary totals count unique executed assessments and may differ from transported result cardinality.

Global catalog totals can be checked in `src/Rules/requirements/internal-catalog.json`; use `rules:list --profile=hardening --include-manual-review` for the hardening selection, with capability and mode filters labeled explicitly. ASVS and PCI reference counts are 345 and 280; they must not be treated as automation coverage or added to alias counts.

## Consumers

Normal CLI planning and `rules:list` select the primary catalog. Existing option names remain. Internal requirement rerun commands retain profile context; standard aliases retain their compatibility requirements. Project policy cannot mutate criterion identity or proof declarations into stronger guarantees.

PCI assessment reports use a primary finding's `alignment` entries with standard `PCI-DSS`, version `4.0.1` and criterion `reference` (legacy fixtures may use `id`). Persisted definitions use plural `alignments`; finding/report metadata uses singular `alignment`. Relationships `partial` and `supporting` retain their limited evidence classification. Primary findings never inherit authoritative PCI mappings from stale profile metadata. The primary PCI standard view also derives all 280 human-assessment criteria and instructions from the persisted primary catalog, including human-only identities omitted from the default 32-finding execution selection. Rows and human actions retain `internal_requirement_id`, the atomic `criterion` and `source_metadata`; they do not reuse an objective-group label as the criterion. Historical reports keep their original metadata contract. Historical findings continue using the old profile mapping adapter. Alignment metadata does not itself prove PCI compliance, and collected technical/external evidence still leaves required human assessment visible.

JSON emits the singular requirement identity and alignment from the result. SARIF uses the internal finding ID and adds requirement, alignment, coverage and applicability to its properties; historical SARIF retains its existing property contract. Primary UNKNOWN findings are shown as insufficient evidence rather than presumed missing CVE data. Internal IDs are not linked to unverified legacy documentation URLs.

Schema 1.0 agent envelope fields remain compatible. Historical manifests preserve requested historical IDs. Dashboard registration of internal IDs, assignment to `assessment_item_id` and deployed backend acceptance require coordinated verification; new identity support in CLI is not a server migration. Exactly one result per requested manifest item remains the transport acceptance gate.

## Semantic migration gates

1. Every primary identity has one revisioned criterion and its own explicit obligations. No primary obligation invokes another requirement or depends on an MB-R rule object.
2. Every obligation check name resolves to a registered reusable function. Standard citations live in alignment metadata; they do not determine a check function's identity.
3. Profile selection cannot create a second assessment of the same primary identity. Inheritance, aliases and filters are deduplicated by internal identity.
4. Missing mandatory evidence never produces PASS. Heuristic/supporting observations cannot claim full criterion coverage; unresolved human evidence remains required.
5. Local, hybrid and remote evidence variants preserve the criterion and identify the assessed scope. Missing target support remains explicit rather than being represented as successful verification.
6. Primary PCI reports derive standard views from alignment; legacy adapters retain their old mappings and output IDs.
7. Differential fixtures verify historical explicit selectors and agent manifests, primary selection and finding cardinality, evidence interpretation, exit behavior, JSON/SARIF/HTML and source/PHAR parity. Intentional inventory/output changes require reviewed baseline diffs.

## Scope and limitations

This migration reorganizes assessment ownership and consumers. It does not prove that every historic detector fully assesses its criterion, automatically merge ASVS and PCI obligations, certify non-applicability, or implement an independent human-evidence approval workflow. Metadata triage requires substantive security review and test evidence before promoting proof or coverage. Compatibility source removal and dashboard deployment are separate subsequent actions.

## Definition provenance and review status

ASVS criterion descriptions use the pinned OWASP 5.0.0 source with CC BY-SA 4.0 attribution in `src/Rules/requirements/NOTICE.md`. PCI definitions use each atomic Defined Approach Requirement from the repository PDF; their provenance records actual normative pages, excluding inline cross-references. Technical mapping notes are evidence scope instructions, not substitutes for these criteria.

Only `MB-0031` currently has an accepted verified predicate, scoped to the declared `MAGE_MODE` value in `app/etc/env.php`; it does not attest the runtime process environment. Other baseline bindings and the standard-oriented technical evidence remain subject to security review. Automated selection means that technical observations can run, not that complete conformance can be determined automatically. See [semantic review and remaining check limits](../reviews/requirement-review.md).


## PCI criterion source validation

`pci-criterion-definitions.json` records 280 source-derived atomic criteria, testing methods, entity restrictions, effective dates and normative PDF-page provenance. The source PDF SHA-256 is `5e6b9093b84007b973097d20126a3768ea2f0a1d4200255c849b0fb3bf04ebc7`. Extraction separates the Defined Approach Requirements column from testing procedures, guidance and customized objectives, and identifies bold atomic criterion labels rather than inline references.

PCI 12.3.1 illustrates why existing page pointers were not copied blindly: its normative definition is on PDF page 300 (printed page 296), while the older registry pointer to PDF page 254 identifies a cross-reference in 10.4.2.1. The new source metadata records `normative_pdf_pages: [300]`; the historical registry remains unchanged. Representative visual/source checks and full identity/non-empty/duplicate validation establish the source mapping; they are not an independently signed-off security review of all clauses or proof that the existing checks cover them completely. Mandatory human verification and pending evidence-mapping review remain.

The consumer contract test exercises a real primary PCI planner/service/assembler workflow: one selected technical criterion still yields 280 distinct criterion-specific human actions in a fully applicable fixture, maps the executed internal finding, and retains the corrected source page. Historical PCI workflow/report fixtures retain their output boundary.

## Basic deployment automation profile

Basic now selects twenty reviewed automated deployment predicates with no human obligations. It uses MB-0728/0729/0730 for observed admin-password policy, declared project debug flags, and deployed working-tree pattern scanning. Broad ASVS MB-0209/0379 and Git-history MB-0072 remain unchanged outside basic. Use a named assessment profile or explicit `--rules` selection; the former full-inventory profile and its `all`/`magebean` aliases are no longer available. The global inventory is 687 identities; historical allocations730, next ID731, all625 standard references preserved.

Basic marks missing/invalid collection as execution errors, scan_complete=false and exit3; its console has no INCONCLUSIVE or human-review section. Internal UNKNOWN remains compatible with existing transport; classification=execution_error and execution_status=ERROR explicitly distinguish incomplete execution from policy violations. Existing security exit codes0/1/2 remain unchanged for completed scans. This policy does not convert missing evidence to PASS or security FAIL.
