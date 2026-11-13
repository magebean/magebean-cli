# External standards

ASVS and PCI DSS are independent source families. Their official criteria are outside the 110-rule Magebean baseline. The Magebean owasp profile uses Top 10 taxonomy and is not an ASVS assessment or certification.

| Source | Inventory | Official document | CLI scope |
|---|---:|---|---|
| OWASP ASVS 5.0.0 | 345 | [Version-pinned PDF](../OWASP_Application_Security_Verification_Standard_5.0.0_en.pdf) | [Native evidence](asvs-native-evidence.md) |
| PCI DSS 4.0.1 | 280 | [Version-pinned PDF](../PCI-DSS-v4_0_1.pdf) | [Workflow](pci-workflow.md), [coverage](pci-coverage.md) |

ASVS level membership is 70/253/345; PCI has 280. Human obligations and evidence gates remain; `--include-manual-review` includes those assessment entries. A technical predicate PASS does not establish full compliance. See [source families](../reference/requirement-source-families.md) and [CLI reference](../guides/cli-reference.md).

PDFs retain their existing paths because version-pinned source metadata and tests reference them. Historical design/review records are in [archive](../archive/README.md).
