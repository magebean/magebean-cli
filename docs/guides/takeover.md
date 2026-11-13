# Agency takeover audit

Takeover helps an agency identify observable technical risks, inconsistencies and maintenance backlog to consider during project handover. It has **86 members**, with **82 selected locally by default**. It reuses existing Magebean criteria and does not estimate business impact, remediation effort or complete functional coverage.

```sh
php magebean.phar audit --profile=takeover --path=/var/www/magento
php magebean.phar rules:list --profile=takeover
```

Scope includes deployed configuration, exposed files, permissions, source/module/DI/REST declarations, supported runtime probes, dependency advisories and lifecycle maintenance, cron/indexer observations and supported reliability review candidates. Findings distinguish observed technical conditions, declarations, suspected risks and explicit maintenance/policy comparisons. Package abandonment or release age is maintenance context, not proof of exploitation.

The four default contextual omissions are MB-0799 (worker permissions), MB-0807 (worker/Xdebug inventory), MB-0043 (supplied logrotate candidate) and MB-0741 (strict cache baseline). Enable only applicable [production context](production-context.md). Online library maintenance is selected by default. Document/mitigation lint lives in the separate opt-in evidence profile.

Findings should provide an inspectable file/key/package/process/endpoint, explain relevance and uncertainty, and give a reproducible remediation/recheck. Missing data stays diagnostic. Local and HTTP evidence do not automatically establish the same deployed build. Use [detailed output](findings-and-output.md); the [baseline](../magebean-baseline-v1.md) is the complete per-ID membership reference.
