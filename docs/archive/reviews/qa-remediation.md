# QA remediation after architecture phases 1–6

Base revision: `0e54a76`. Scope: the 14 confirmed findings in the original QA audit, plus follow-up triage of cron, mixed content and firewall evidence. Changes are in the working tree; this is not a deployment or release certification.

## Issue ledger

| Finding | Correction | Regression evidence |
|---|---|---|
| QA-01 | MB-R014 routes to code_grep; MB-R017 routes to code_unserialize_safety. | Real rule-pack ScanRunner cases and source/PHAR clean and unsafe scans. |
| QA-02 | Source detectors process every positive preg_match_all count, rather than requiring exactly one match. | Two POST forms and two unserialize calls; existing detector suite. |
| QA-03 | URL format parsing no longer qualifies as host allowlisting; scheme-only checks do not establish a destination guard. | Public SSRF check with FILTER_VALIDATE_URL and timeout. |
| QA-04 | Missing/failed admin HTTP observations produce UNKNOWN rather than PASS. | Closed loopback-port probe. |
| QA-05 | Each response status line starts a fresh header block; stream fallback uses the final status. | Redirect HSTS isolation under both cURL and php -n streams; duplicate-cookie assertions retained. |
| QA-06 | Shared OSV range evaluation supports exclusive fixed/limit and inclusive last_affected, including multiple intervals. Only fixed is considered remediation metadata. | Endpoint equality, disjoint intervals, public Composer auditOffline and standalone auditor. |
| QA-07 | OR with failure plus unknown remains UNKNOWN; inconclusive/manual OR outcomes carry passed:null. | Frozen 32-pair truth table and explicit failure/unknown regression. |
| QA-08 | Cipher parsing tracks exclusions and ordering. Broad aliases/unresolved expressions return UNKNOWN instead of assumed PASS. | Six original/expanded expression categories, unknown suite, DES versus 3DES and public TLS check. |
| QA-09 | Retention and compression must hold for each detected log target block, with global defaults and local overrides. rotate 0 and delaycompress alone fail; rotate -1 retains logs. | Positive/default/override/cross-block/includes/retention fixtures. |
| QA-10 | Out-of-scope PCI components do not produce confirmed account failures; excluded scope requires manual confirmation. | Unsafe account on excluded components and existing PCI reports. |
| QA-11 | Issuer applicability must be a JSON boolean when supplied. | String false rejected; existing context compiler suite. |
| QA-12 | Evidence timestamps require an absolute timestamp with timezone and valid calendar/time fields. | Relative dates, impossible dates/hours/offsets, leap day and timezone/fraction examples. |
| QA-13 | SARIF classifies by status, preserves reason/status and includes required tool metadata. | PASS omitted, FAIL error, UNKNOWN/manual note. CLI export availability is unchanged. |
| QA-14 | Standalone missing/empty data is UNKNOWN; upgrade candidates must avoid all matching dataset advisories; unpublished severity no longer aggregates to None. | Missing dataset, two overlapping advisories requiring 2.5.0, unscored advisory. |

## Follow-up triage

- Cron: commented deployment lines are excluded. Deployment evidence alone stays UNKNOWN. Installed Magento jobs need evidence of the scanned project path; an unrelated/ambiguous installation is UNKNOWN. Matching remains heuristic; dynamic wrapper jobs may require manual review.
- Mixed content: ordinary anchor navigation is not treated as a loaded resource. HTTP script/image/stylesheet and CSS URLs remain findings. HTML comments are excluded. Runtime JavaScript-generated requests are outside this markup check.
- Firewall: UFW uses verbose output and explicitly parses the outgoing default, including the normal incoming/outgoing combined line. Missing default information is UNKNOWN. iptables ACCEPT plus rules is not assumed unrestricted; unconditional ACCEPT bypassing DROP is recognized. Seven cases use fake commands in an isolated PATH and do not modify the host firewall. This remains static IPv4/default-policy evidence, not a complete effective packet-flow/IPv6/nftables audit.
- Effective Magento DB configuration: still unconfirmed. The reviewed reader obtains the default connection from env.php; no controlled Magento runtime/environment override fixture establishes a report error. This concern is not counted among the 14 closed findings and is not claimed fixed. A future reproduction must compare effective bootstrapped configuration with the CLI observation without using production credentials.

## Compatibility and verification

`php tests/run.php`: **53/53 test scripts pass**. New `QaRegressionTest.php`: **65 cases pass**. New `QaSystemEvidenceTest.php`: **7 cases pass**. Existing CLI, agent, PCI/reporting, architecture boundary, deadline and cache tests remain green. Changed PHP files pass syntax checks; `git diff --check` passes.

The original compatibility snapshot was not blindly regenerated. A separate candidate showed exactly 16 semantic leaf differences: two rule definition hashes for QA-01 and 14 truth-table/count differences for QA-07. Only these reviewed differences were accepted. Catalog size (371), profiles, CLI options/help, existing agent mapping and PCI snapshots are otherwise unchanged.

Box 4.6.7 built `/tmp/magebean-qa-build/magebean-qa.phar` with an alternate output path. Clean fixtures PASS with exit 0; dangerous MB-R014/MB-R017 fixtures FAIL with exit 1, matching source CLI. Scan help also matches. The repository's existing magebean.phar was not overwritten. Build output is temporary, not a published release.

Conservative UNKNOWN results are intentional when evidence cannot support a conclusion, especially cipher aliases, unreadable HTTP probes and logrotate includes/unsupported syntax. A green fixture suite does not establish absence of every false result on arbitrary projects. Source/markup checks still have heuristic limits; complete TLS negotiation, deployment cron and effective DB behavior require appropriate runtime evidence.

## References

- [OSV range event semantics](https://ossf.github.io/osv-schema/#affectedranges-events-fields)
- [OpenSSL cipher-list syntax](https://docs.openssl.org/3.0/man1/openssl-ciphers/)
- [logrotate directives](https://man7.org/linux/man-pages/man8/logrotate.8.html)
