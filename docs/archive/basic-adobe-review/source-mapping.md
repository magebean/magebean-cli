# Adobe recommendation mapping for Basic

Reviewed 2026-10-17. Read-only source/catalog review; no implementation changes or live Magento scan. Catalog: 20 Basic Magebean requirements. This is an assessment of evidence sufficiency, not an Adobe certification. Requirements remain Magebean-owned; Adobe references are provenance, not imported ASVS/PCI criteria.

## Conclusion

Basic is a useful partial implementation, not a complete Adobe best-practices profile. It combines security configuration and deployment readiness. Completeness must therefore be reported by topic and capability, not only a 20-check count. Preserve a fast default technical scan, plus a concise evidence checklist for Adobe recommendations that a passive CLI cannot verify.

## Recommendation-to-requirement matrix

| Topic | Current Basic | Review and action |
|---|---|---|
| MFA | MB-0007 | Declared modules are evidence only. Detect native vs Adobe IMS authentication; avoid failing legitimate IMS deployments because native 2FA is disabled. Separately assess provider configuration and bypass modules. SSH MFA is external evidence. |
| Admin route | MB-0006 | Rejecting only `admin` is narrower than Adobe guidance, which also discourages common names. Resolve effective custom URL/path overrides; env.php alone may not be effective. Route hiding reduces automated exposure, not authorization strength. |
| Admin login security | MB-0011, MB-0728 | Partial. Add secret-key URLs, case sensitivity, bounded session lifetime (available MB-0009), reset throttling, account sharing, lockout duration, and configurable password policies. Native vs IMS applicability required. |
| Least privilege | None | MB-0100 and MB-0101 can support role/ACL inventory. Relational integrity is not proof of least privilege. Require approval/evidence for global roles. |
| Patch/update hygiene | MB-0049, MB-0050 | Good foundation for observed locked versions and known advisories. Services, uncollected runtime components, custom code, and maintenance governance remain gaps. Newest stable release and latest security release in a supported branch are distinct policies. |
| Sensitive configuration locking | None | New scoped requirement for critical configuration exported/locked with effective precedence. Do not infer lock status from existence of env.php. No exact current counterpart found in the 104 Magebean requirement titles/checks. |
| Security monitoring | None | Add evidence for scheduled Commerce Security Scan or equivalent monitoring and notification ownership. Running Magebean once does not prove monitoring or malware absence. |
| Extension/custom-code hygiene | MB-0049, MB-0730 | Partial technical evidence. Support provenance, maintenance and extension inventory; code-security checks belong deeper in OWASP. Partner selection and review workflow require human evidence. |
| Exposed development artifacts | MB-0003, MB-0005, MB-0729 | Expand HTTP probes to sensitive root paths, dumps, logs, phpinfo, setup and backup artifacts; local absence in pub is not proof of inaccessible root. Available candidates MB-0042, MB-0738, MB-0739, MB-0748 need predicate validation. |
| Ownership and permissions | MB-0001, MB-0002 | Add production code write restrictions (MB-0004). 0640 and matching project-root owner/group are Magebean policy, not universal Adobe ownership rules. Include ACL/mount/web-user scope and cloud write-path exceptions. |
| Document root | None explicit | Add effective pub docroot observation and sensitive-path HTTP denial. A document_root_is_pub declaration alone does not prove effective web server behavior. |
| HTTPS / browser protection | MB-0026, MB-0028, MB-0029, MB-0030 | Partial bounded entrypoint/markup/cookie observation. Add HSTS MB-0027 and clickjacking evidence via MB-0096 after scope review. Validate certificate and hostname, multi-store URLs, proxy behavior and authenticated cookies. |
| WAF / Admin access restriction | None | MB-0010 supports Admin exposure review; WAF effectiveness needs provider/config evidence. Do not impose Adobe Fastly-specific checks on on-premise or Open Source installations. |
| Recovery and backups | None | New evidence workflow for recovery plan, backup/restore tests and exported configuration. File presence is not successful recovery. |
| Production deployment | MB-0031, MB-0035 | Retain as readiness; declared production mode/static artifacts do not alone prove effective deployment. DI completeness MB-0034 may help but avoid checking arbitrary generated-file counts. |
| Cache | MB-0037 | FPC declaration is useful readiness. Report separately from exploitable security findings; do not force a single cache backend across valid architectures. |
| Cron | MB-0046 | Crontab presence is partial. MB-0047/0048 can support execution/backlog observations; account for scheduler/container/cloud alternatives and multi-node ownership. |

## Applicability and policy boundaries

- Main security guide is for supported Adobe Commerce cloud/on-premise deployments; several linked Admin docs also explicitly discuss Magento Open Source. Do not claim every Commerce cloud responsibility or feature applies unchanged to Magento Open Source.
- SaaS is outside the local Magento deployment scan model. Cloud infra controls need provider evidence, not inference from source files.
- Adobe IMS authentication intentionally disables native Admin 2FA. Native configuration checks must branch on authentication mode.
- Admin minimum 8, timeout 900 seconds, HSTS 1 year, env.php 0640, project-root ownership, cron age 900 seconds and backlog 1000 are Magebean defaults/thresholds. Adobe documentation does not establish these as universal best-practice limits.
- Adobe Admin documentation currently describes a 7-character default/minimum and organizational configuration; do not label Magento default behavior an Adobe violation merely because Magebean chooses 8.
- Password lifetime advice and historic PCI references on Adobe pages are not an independent PCI assessment. Keep family boundaries intact and expose configurable policy.
- A missing optional collector must yield unavailable evidence, not clean PASS. Declared settings, observed runtime responses, and human operating evidence need distinct labels.

## Priority

P0: correct MFA/IMS interpretation and effective configuration scope; restore high-signal exposure/code-write/media checks with negative fixtures. P1: Admin configuration gaps, pub docroot and HSTS/header scope, monitoring and configuration-lock evidence. P2: recovery/extension governance and operational readiness detail. Do not convert every external responsibility into a misleading automated pass/fail.

## Primary sources

- [Secure your Commerce site and infrastructure](https://experienceleague.adobe.com/en/docs/commerce-operations/implementation-playbook/best-practices/launch/security-best-practices): topical guidance; mapped briefly above, no claim that CLI can verify all responsibilities.
- [Configure Admin security](https://experienceleague.adobe.com/en/docs/commerce-admin/systems/security/security-admin): native settings and IMS exception.
- [Store URLs](https://experienceleague.adobe.com/en/docs/commerce-admin/stores-sales/site-store/store-urls): secure URLs, HSTS, custom Admin URL precedence.
- [File systems access permissions](https://experienceleague.adobe.com/en/docs/commerce-operations/configuration-guide/deployment/file-system-permissions): production ownership/write restrictions.
- [File ownership and permissions](https://experienceleague.adobe.com/en/docs/commerce-operations/installation-guide/prerequisites/file-system/overview): deployment-specific ownership models.
- [Modify docroot to improve security](https://experienceleague.adobe.com/en/docs/commerce-operations/installation-guide/tutorials/docroot): pub document root and verification.
- [Configure cron jobs](https://experienceleague.adobe.com/en/docs/commerce-operations/configuration-guide/cli/configure-cron-jobs): execution ownership and operational behavior.
- [Code compiler](https://experienceleague.adobe.com/en/docs/commerce-operations/configuration-guide/cli/code-compiler): compilation as deployment readiness.
- [Commerce PHP Extensions security](https://developer.adobe.com/commerce/php/best-practices/security/): developer-focused code risks; deeper OWASP scope.
- [Prevent clickjacking exploits](https://experienceleague.adobe.com/en/docs/commerce-operations/configuration-guide/security/xframe-options): response header protection.
