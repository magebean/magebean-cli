# Magebean documentation

This index points to current product documentation. The baseline and runtime catalogue own current criteria and membership. Archived plans and QA reports describe their recorded revisions and do not override current behavior.

## Start here

- [Project README](../README.md): installation, examples and current profile counts.
- [Security Baseline v1](magebean-baseline-v1.md): all 110 current Magebean criteria, revisions, categories, target modes and profile memberships.
- [Profiles](guides/profiles.md): all 15 profiles, default selection and context gates.
- [CLI reference](guides/cli-reference.md): commands, filters, exit codes and agent operation.
- [Findings and output](guides/findings-and-output.md): evidence, uncertainty, canonical issues and diagnostics.

## Guides

- [Development and prelaunch](guides/development-prelaunch.md)
- [Agency takeover](guides/takeover.md)
- [Module audit](guides/module-audit.md)
- [Production context and optional checks](guides/production-context.md)
- [Runtime URL discovery](guides/runtime-url-discovery.md)
- [Hotfix verification](guides/hotfix-verification.md)
- [Troubleshooting incomplete scans](guides/troubleshooting.md)
- [Provider webhook diagnostics](guides/provider-webhook-diagnostics.md)

## Reference

- [Source families](reference/requirement-source-families.md) and [requirement model](reference/requirement-model.md)
- [Architecture](reference/architecture.md), [planning](reference/scan-planning.md) and [contracts](reference/scan-contracts.md)
- [Collectors](reference/scan-collectors.md) and [reliability](reference/scan-reliability.md)
- [API reference and data disclosure](reference/api-reference.md)
- [Release packaging](reference/release-packaging.md)
- [Compatibility regression](reference/compatibility-baseline.md)

## Standards, examples and history

[ASVS/PCI workflows](standards/README.md) cover their separate official source families; they are not chapters of the Magebean baseline. The version-pinned official PDFs remain at their existing paths for source-catalogue compatibility.

[Examples](examples/README.md) are templates requiring real project values. [Archive](archive/README.md) contains superseded proposals, implementation phases and QA evidence. No historical evidence was discarded during cleanup.

To maintain the baseline and check local links:

```sh
php tools/update-baseline-doc.php
php tools/update-baseline-doc.php --check
python3 tools/check-docs.py
```
