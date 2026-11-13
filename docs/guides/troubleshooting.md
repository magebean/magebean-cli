# Incomplete scans and missing evidence

A rule can be selected without having enough evidence to conclude. Missing permissions, input, runtime access, unsupported source expressions, API failures and collection budgets are diagnostics. They are not vulnerabilities or implicit PASS results.

## Selection versus execution

`Rules 80 selected · 6 require additional context` describes a default hardening selection. It does not mean 80 complete assessments. Context omissions and explicit selection/filter omissions are distinguished. `rules:list --profile=hardening` lists selected rules; [production context](production-context.md) explains optional gates and required inputs.

Inspect a specific rule when an incomplete scan needs investigation:

```sh
php magebean.phar audit --path=/var/www/magento --profile=hardening --rules=MB-0807 --capabilities=runtime_worker_inventory
```

Only enable that example when worker identities have actually been supplied. Native automated scans retain exit code 3 for incomplete execution, including when useful findings coexist with gaps. Resolve the diagnostic relevant to the evidence you need; do not create arbitrary placeholder files to silence it.

| Observation | What to check |
|---|---|
| Runtime URL unavailable | Read Magento store configuration through the shared local resolver. `--url` does not override local configuration. See [URL discovery](runtime-url-discovery.md). |
| TLS trust failure | Verify the host, certificate chain and scanner CA trust. Keep certificate verification enabled; a trust failure does not prove a missing response header. |
| Missing module XSD, framework or symbols | Ensure installed metadata/source/schema is readable. Static declarations do not prove effective runtime activation. |
| File/byte/time budget exceeded | Inspect the rule's bounded scope. Observed issues remain while coverage is unresolved. |
| Advisory/release/repository data unavailable | Check the selected API and input scope. Missing data is diagnostic; it must not be appended as a long package list to a genuine finding. |
| Policy or worker context missing | Supply applicable typed inputs from [production context](production-context.md); a capability flag alone does not provide them. |
| Local advisory snapshot absent | This check is opt-in. Supply a trusted snapshot only if needed; the CLI does not create or distribute it. |

The ordinary issue list stays quiet. Use detailed rule output and structured diagnostics for investigation, and preserve observed findings while resolving gaps. [Output contract](findings-and-output.md).
