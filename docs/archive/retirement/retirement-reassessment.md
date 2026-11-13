# Evidence-based reassessment of the 60 archived Magebean rules

The original archive remains unchanged. This review changes current selection only where a revised automatic predicate has executed tests; it does not rewrite historical conclusions or claim that all original broad criteria have become fully automated.

## Current decisions

- Partial active coverage: **29**.
- Detector rework required: **12**.
- Restored: scoped automation: **10**.
- Insufficient evidence: **6**.
- External context required: **3**.

There are now **110 active Magebean criteria**, plus 345 ASVS and 280 PCI (735 total). Ten existing archived IDs return as higher scoped revisions; no new allocation is consumed. There remain 50 inactive IDs from this archive. Historical allocations and retired definitions stay preserved.

Built-in profile memberships are unchanged to avoid automatically duplicating existing canonical coverage. Restored rules can be selected directly or placed in custom profiles:

```bash
php magebean.phar audit --path=/var/www/magento --rules=MB-0733,MB-0736
php magebean.phar audit --path=/var/www/magento --rules=MB-0043
```

## Rule-by-rule classification

| ID | Archived title | Current decision | Related active rules |
|---|---|---|---|
| MB-0004 | Code directories are read-only | Partial active coverage | MB-0799 |
| MB-0010 | Admin URL exposure restricted | Detector rework required | Not established |
| MB-0015 | Forms include CSRF tokens (form_key) | Partial active coverage | MB-0787 |
| MB-0016 | SSRF protections present | Partial active coverage | MB-0788 |
| MB-0019 | No eval/assert/dynamic execution | Partial active coverage | MB-0791 |
| MB-0020 | Path traversal protections | Partial active coverage | MB-0792 |
| MB-0021 | Secure file upload handling | Partial active coverage | MB-0793, MB-0800 |
| MB-0023 | Use CSPRNG; avoid weak PRNG | Partial active coverage | MB-0794 |
| MB-0025 | No unsafe raw crypto or session APIs in custom code | Partial active coverage | MB-0796 |
| MB-0043 | Log rotation configured | Restored: scoped automation | Same ID, revised predicate |
| MB-0051 | Dependency vulnerability remediation plan identifies an actionable resolution | Insufficient evidence | Not established |
| MB-0052 | Enabled high-risk modules are maintained | Insufficient evidence | Not established |
| MB-0053 | Temporary mitigations documented | Partial active coverage | MB-0806 |
| MB-0054 | Known-exploited packages prioritized (CISA KEV) | Insufficient evidence | Not established |
| MB-0058 | Marketplace extensions are current and maintained | Insufficient evidence | Not established |
| MB-0060 | Marketplace extensions have vendor support evidence | Insufficient evidence | Not established |
| MB-0064 | No risky forks replacing upstream libs | Insufficient evidence | Not established |
| MB-0073 | HTTPS-only endpoints configured | Partial active coverage | MB-0798 |
| MB-0075 | Webhook signature validation present | Detector rework required | Not established |
| MB-0076 | Outbound connections restricted by allow-list | Detector rework required | Not established |
| MB-0077 | PII minimization for third-party flows | Detector rework required | Not established |
| MB-0078 | Strong TLS ciphers on upstream gateways | Detector rework required | Not established |
| MB-0079 | API keys stored in env.php (not in DB/plain code) | Partial active coverage | MB-0730 |
| MB-0081 | SaaS integrations scoped by ACL (least privilege/IP allowlist) | Partial active coverage | MB-0812, MB-0813 |
| MB-0082 | No PAN or sensitive authentication data stored in database | Detector rework required | Not established |
| MB-0083 | No cardholder data in files, exports, or backups | Detector rework required | Not established |
| MB-0085 | Payment method inventory and data-flow scope are documented | External context required | Not established |
| MB-0086 | No raw card collection in Magento checkout | Detector rework required | Not established |
| MB-0087 | Payment page script inventory maintained | Detector rework required | Not established |
| MB-0088 | Payment page script allowlist and integrity controls | Detector rework required | Not established |
| MB-0089 | Checkout Content Security Policy enforced | Partial active coverage | MB-0802 |
| MB-0090 | Payment page tamper monitoring readiness | External context required | Not established |
| MB-0092 | Payment webhook endpoint authentication hardening | Detector rework required | Not established |
| MB-0093 | PCI manual evidence checklist present | Restored: scoped automation | Same ID, revised predicate |
| MB-0094 | Custom controllers and APIs include function-level authorization | Partial active coverage | MB-0811, MB-0812, MB-0813 |
| MB-0095 | GraphQL and API exposure minimized | Partial active coverage | MB-0812, MB-0813 |
| MB-0096 | Security headers baseline enforced | Partial active coverage | MB-0027, MB-0779, MB-0802, MB-0803 |
| MB-0097 | Secrets are not hardcoded in custom code | Partial active coverage | MB-0730 |
| MB-0098 | Unsafe XML parsing disabled | Partial active coverage | MB-0797 |
| MB-0099 | File download and export endpoints require authorization | Partial active coverage | MB-0813 |
| MB-0101 | Global Admin ACL limited to approved roles | Partial active coverage | MB-0801 |
| MB-0102 | PCI vendor default account evidence assessment | External context required | Not established |
| MB-0731 | Admin passwords require at least 8 characters | Restored: scoped automation | Same ID, revised predicate |
| MB-0732 | No raw SQL without abstraction | Partial active coverage | MB-0786, MB-0822 |
| MB-0733 | Template output is escaped | Restored: scoped automation | Same ID, revised predicate |
| MB-0734 | No unsafe deserialization | Partial active coverage | MB-0789 |
| MB-0735 | Command execution is guarded | Partial active coverage | MB-0790, MB-0822 |
| MB-0736 | Escaping for JS context | Restored: scoped automation | Same ID, revised predicate |
| MB-0737 | Sensitive data not logged | Partial active coverage | MB-0795, MB-0814 |
| MB-0738 | Xdebug disabled in production | Partial active coverage | MB-0729, MB-0807 |
| MB-0739 | display_errors is Off | Restored: scoped automation | Same ID, revised predicate |
| MB-0740 | No dev debug configs on production (template hints off) | Restored: scoped automation | Same ID, revised predicate |
| MB-0741 | No dev cache backends (avoid file backend) | Restored: scoped automation | Same ID, revised predicate |
| MB-0742 | Debug template hints disabled in production | Restored: scoped automation | Same ID, revised predicate |
| MB-0743 | PII not logged in application logs | Partial active coverage | MB-0795 |
| MB-0744 | No abandoned libraries allowed | Restored: scoped automation | Same ID, revised predicate |
| MB-0745 | Debug/verbose off for third-party integrations | Partial active coverage | MB-0804 |
| MB-0746 | Third-party logging sanitized (mask/redact) | Partial active coverage | MB-0795, MB-0814 |
| MB-0747 | No cardholder data in application logs | Detector rework required | Not established |
| MB-0748 | No executable code in media or upload paths | Partial active coverage | MB-0780, MB-0800 |

Related active rules are partial coverage, not equivalence or automatic redirects. Inactive selectors now explain this evidence classification instead of claiming that human metadata proves they cannot be automated.

## Detector repairs

- Scoped template parsing distinguishes HTML, attributes and supported inline JavaScript contexts. Unused helper names, wrong-context helpers, raw concatenated output and unsupported dynamic rendering cannot produce an unrestricted clean result. PHP config is parsed as literal data, never included as executable customer code.
- Source input/SQL/command policies use bounded collection and unsupported-dispatch gaps. Marker-only Admin ACL/config hints, mitigation prose and default-deny firewall headlines no longer certify broader effective controls.
- Source-only PAN/API-key, provider, CSP/header and monitoring claims remain unavailable without the required evidence. Concrete supported dangerous patterns remain findings. Unrelated token/redact/nonce/isAllowed strings cannot establish protection.
- Script inventories are correlated with collected script sources; integrity evidence must be attached to the corresponding tag and have supported structure. This does not certify fetched script bytes or a running monitor.
- Logrotate candidate checks validate supported cadence, positive retention and compression across relevant stanzas, preserving known violations even with other gaps. Candidate syntax is separate from installation and host activation.

## Evidence and verification

Initial per-rule evidence and raw probe snapshots are linked from [the evidence review](retirement-evidence-review.md). Those snapshots describe behavior before these repairs. Current regression tests record corrected outcomes. The old probe can be run with --assert-historical only to compare historical behavior; current diagnostic output may intentionally differ.

Machine-readable current decisions: src/Rules/requirements/magebean-retirement-review.json. Each decision links to the evidence report and raw fixtures. Six dependency topics remain unqualified because unavailable data is not evidence of either safety or inability to automate. External context can be machine-supplied; this category does not declare a permanently manual control.


## Final verification

- All **137 CLI test files passed**. New focused regressions cover unsupported source/keyword cases, corrected manifest correlation, configuration-only predicates, template contexts and actual canonical CLI selection. The latest template regression has 47 assertions, part1 has 40, middle detector fixes have 31, and canonical reassessment has 323.
- Both standard and one-time PHAR builds passed release gates, including direct execution of nine restored local rules, an explicit display_errors violation, and a wrong-context template violation through each candidate PHAR. The library advisory binding was independently exercised with controlled maintenance-status responses in the evidence suite; release tests do not call the public advisory service.
- A real Console catalog import and repeat import on SQLite in-memory passed **1 test / 34 assertions**: 735 rules, 14 profiles, and all10 restored rules imported as automated with the exact revised criterion. No customer database was touched.
- CLI log: /tmp/magebean-retirement-restoration-final-suite.log. Build logs: /tmp/magebean-restored-rules-{standard,one-time}-build.log.

Remaining limits are intentional: recognized template helper syntax is not a proof of every custom implementation; arbitrary JS/CSS/DOM contexts, dynamic markup and unresolved source are unavailable. Supplied logrotate/ini/config declarations do not establish installed worker or host behavior. Partial active replacements do not certify the full archived criteria, and missing provider/operational data is not proof that a topic is inherently manual.
