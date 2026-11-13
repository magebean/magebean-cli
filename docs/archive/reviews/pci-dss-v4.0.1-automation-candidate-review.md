# PCI DSS 4.0.1 Automation-Candidate Criterion Review

This review covers all 71 candidates remaining after PCI DSS 2.2.2 implementation. Every decision is evidence-scoped and still requires human verification.

| Requirement | Decision | Magebean rules | Human assessment scope |
|---|---|---|---|
| 3.3.1.1 | REUSE_EXISTING_RULES | MB-R082, MB-R083, MB-R084 | Assess all in-scope data sources and confirm full track data is not retained after authorization. |
| 3.3.1.2 | REUSE_EXISTING_RULES | MB-R082, MB-R083, MB-R084 | Assess all in-scope data sources and confirm card verification codes are not retained after authorization. |
| 3.3.1.3 | REUSE_EXISTING_RULES | MB-R082 | Assess all in-scope data sources and confirm PINs and PIN blocks are not retained after authorization. |
| 3.3.2 | EXTERNAL_SYSTEM_EVIDENCE | - | Assess any pre-authorization SAD storage and confirm strong cryptography protects it. |
| 3.3.3 | CONTEXTUAL_APPLICABILITY | - | For issuer or issuing-service scope, assess the documented business need and protection of retained SAD. |
| 3.4.1 | EXTERNAL_SYSTEM_EVIDENCE | - | Assess PAN displays, role authorization, and masking so unauthorized roles cannot see more than permitted digits. |
| 3.4.2 | EXTERNAL_SYSTEM_EVIDENCE | - | Assess remote-access controls and authorization records that prevent unauthorized copying or relocation of PAN. |
| 4.2.1.1 | EXTERNAL_SYSTEM_EVIDENCE | - | Assess certificate and key inventories and confirm trusted, valid cryptography protects PAN over open public networks. |
| 4.2.1.2 | EXTERNAL_SYSTEM_EVIDENCE | - | Assess wireless technologies transmitting PAN and confirm strong cryptography secures authentication and transmission. |
| 4.2.2 | EXTERNAL_SYSTEM_EVIDENCE | - | Assess end-user messaging channels and confirm unprotected PAN is never sent through them. |
| 6.2.1 | HUMAN_ONLY | - | Assess the software-development lifecycle and confirm bespoke and custom software is developed securely. |
| 6.2.2 | HUMAN_ONLY | - | Assess annual role-relevant secure-software training records for personnel working on bespoke and custom software. |
| 6.2.3 | HUMAN_ONLY | - | Assess pre-production code-review procedures and evidence for bespoke and custom software changes. |
| 6.2.3.1 | HUMAN_ONLY | - | Assess manual code-review independence and reviewer knowledge for changes entering production. |
| 6.3.2 | EXTERNAL_SYSTEM_EVIDENCE | - | Assess the inventory of bespoke, custom, and third-party software components and their ownership. |
| 6.4.1 | EXTERNAL_SYSTEM_EVIDENCE | - | Assess recurring application-security reviews or automated protection for public-facing web applications. |
| 6.4.2 | EXTERNAL_SYSTEM_EVIDENCE | - | Assess the automated technical solution in front of public-facing web applications, including detection, prevention, currency, and logging. |
| 6.5.1 | HUMAN_ONLY | - | Assess change-control procedures and records for all in-scope system components. |
| 6.5.3 | HUMAN_ONLY | - | Assess separation between pre-production and production environments and access controls. |
| 6.5.4 | HUMAN_ONLY | - | Assess separation of duties between development/test and production roles. |
| 6.5.5 | HUMAN_ONLY | - | Assess controls preventing live PAN from entering pre-production unless protected under all applicable requirements. |
| 6.5.6 | HUMAN_ONLY | - | Assess production launch evidence confirming test data and test accounts were removed. |
| 7.2.2 | REUSE_EXISTING_RULES | MB-R100, MB-R101 | Assess assigned privileges against job function, least privilege, and documented approval. |
| 7.2.3 | HUMAN_ONLY | - | Assess required-privilege approval records from authorized personnel. |
| 7.2.4 | HUMAN_ONLY | - | Assess all user and system-account access assignments and confirm they match documented job functions. |
| 7.2.5 | HUMAN_ONLY | - | Assess periodic access reviews, reviewer evidence, and remediation of inappropriate access. |
| 7.2.5.1 | CONTEXTUAL_APPLICABILITY | - | For service-provider scope, assess six-monthly access reviews and customer-environment access controls. |
| 7.2.6 | HUMAN_ONLY | - | Assess application and system account access, least privilege, and management controls. |
| 7.3.1 | REUSE_EXISTING_RULES | MB-R101 | Assess access-control system configuration and confirm access is restricted by need to know. |
| 7.3.2 | EXTERNAL_SYSTEM_EVIDENCE | - | Assess default-deny configuration for access-control systems. |
| 7.3.3 | EXTERNAL_SYSTEM_EVIDENCE | - | Assess access-control enforcement on all system components and data resources. |
| 8.2.1 | HUMAN_ONLY | - | Assess account inventories and confirm every user has a unique identity before access is granted. |
| 8.2.2 | HUMAN_ONLY | - | Assess shared or generic account exceptions, approvals, identity attribution, and time-bounded use. |
| 8.2.4 | HUMAN_ONLY | - | Assess account lifecycle records and confirm terminated-user access is revoked immediately. |
| 8.2.5 | EXTERNAL_SYSTEM_EVIDENCE | - | Assess inactive-account reports and confirm accounts are removed or disabled within 90 days. |
| 8.2.6 | EXTERNAL_SYSTEM_EVIDENCE | - | Assess controls for inactive accounts that must remain enabled, including authorization and monitoring. |
| 8.2.7 | EXTERNAL_SYSTEM_EVIDENCE | - | Assess third-party remote-access account activation, monitoring, and disabling when not in use. |
| 8.3.1 | EXTERNAL_SYSTEM_EVIDENCE | - | Assess authentication coverage and confirm all user and administrator access uses required factors. |
| 8.3.2 | EXTERNAL_SYSTEM_EVIDENCE | - | Assess cryptographic protection of authentication factors during transmission and storage. |
| 8.3.3 | HUMAN_ONLY | - | Assess identity confirmation before authentication factors are modified or replaced. |
| 8.3.5 | HUMAN_ONLY | - | Assess initial and reset passwords and confirm unique values are changed immediately after first use. |
| 8.3.7 | EXTERNAL_SYSTEM_EVIDENCE | - | Assess password history settings and confirm the last four passwords cannot be reused. |
| 8.3.8 | HUMAN_ONLY | - | Assess documented authentication guidance and evidence that it is communicated to users. |
| 8.3.9 | EXTERNAL_SYSTEM_EVIDENCE | - | Assess password change or dynamic-account-analysis controls for non-consumer user accounts. |
| 8.3.11 | HUMAN_ONLY | - | Assess token, smart-card, and certificate assignment so each factor is individual and non-shareable. |
| 8.4.1 | REUSE_EXISTING_RULES | MB-R007 | Assess MFA enforcement for all non-console administrative access into the CDE. |
| 8.5.1 | EXTERNAL_SYSTEM_EVIDENCE | - | Assess MFA implementation and confirm factors are independent and resistant to replay and bypass. |
| 8.6.1 | EXTERNAL_SYSTEM_EVIDENCE | - | Assess application and system account use, ownership, interactive-use restrictions, and exception controls. |
| 8.6.3 | EXTERNAL_SYSTEM_EVIDENCE | - | Assess protection and rotation of passwords for application and system accounts. |
| 10.2.1 | HUMAN_ONLY | - | Assess audit-log coverage for anomaly detection, suspicious activity, and forensic analysis. |
| 10.2.1.1 | EXTERNAL_SYSTEM_EVIDENCE | - | Assess logging of all individual user access to cardholder data. |
| 10.2.1.2 | EXTERNAL_SYSTEM_EVIDENCE | - | Assess logging of all actions performed by administrative users. |
| 10.2.1.3 | EXTERNAL_SYSTEM_EVIDENCE | - | Assess logging of all access to audit logs. |
| 10.2.1.4 | EXTERNAL_SYSTEM_EVIDENCE | - | Assess logging of invalid logical-access attempts. |
| 10.2.1.5 | EXTERNAL_SYSTEM_EVIDENCE | - | Assess logging of identity and authentication changes, including privileged-account changes. |
| 10.2.1.6 | EXTERNAL_SYSTEM_EVIDENCE | - | Assess logging of audit-log initialization, stopping, and pausing. |
| 10.2.1.7 | EXTERNAL_SYSTEM_EVIDENCE | - | Assess logging of creation and deletion of system-level objects. |
| 10.2.2 | HUMAN_ONLY | - | Assess audit records for user, event, time, outcome, origin, and affected resource details. |
| 10.3.2 | REUSE_EXISTING_RULES | MB-R042 | Assess controls preventing unauthorized reading, modification, and deletion of audit logs. |
| 10.3.3 | EXTERNAL_SYSTEM_EVIDENCE | - | Assess prompt backup of audit logs to a secure central log server or protected media. |
| 10.3.4 | EXTERNAL_SYSTEM_EVIDENCE | - | Assess file-integrity or change-detection monitoring for audit logs and alert handling. |
| 10.4.1 | HUMAN_ONLY | - | Assess daily review of security events and logs from critical and security-function systems. |
| 10.4.1.1 | HUMAN_ONLY | - | Assess automated mechanisms used to perform required audit-log reviews. |
| 10.4.2 | HUMAN_ONLY | - | Assess risk-based review frequency for logs outside the daily-review scope. |
| 10.4.2.1 | CONTEXTUAL_APPLICABILITY | - | For service-provider scope, assess daily review of logs for customer-facing security services. |
| 10.4.3 | HUMAN_ONLY | - | Assess follow-up and resolution records for exceptions and anomalies found during log reviews. |
| 10.6.1 | EXTERNAL_SYSTEM_EVIDENCE | - | Assess time-synchronization configuration against designated time servers. |
| 10.6.2 | EXTERNAL_SYSTEM_EVIDENCE | - | Assess controls protecting time data and settings from unauthorized changes. |
| 10.6.3 | EXTERNAL_SYSTEM_EVIDENCE | - | Assess receipt of time settings from accepted industry sources. |
| 10.7.2 | EXTERNAL_SYSTEM_EVIDENCE | - | Assess detection and alerting when critical security control systems fail. |
| 10.7.3 | HUMAN_ONLY | - | Assess documented and tested response procedures for critical security-control failures. |
