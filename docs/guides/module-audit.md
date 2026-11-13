# Module audit

| Profile | Current members | Scope |
|---|---:|---|
| module-integrity | 11 | Static identity, supported XML, REST references/ACL and DI |
| module-source | 4 | PHP target compatibility, method contracts, framework constraints and supported request-to-sink review |
| module-lifecycle | 3 | Declarative schema, setup patch and cron/queue handler declarations |
| module-reliability | 2 | Supported empty-catch/query-loop review candidates |

```sh
php magebean.phar audit --path=/var/www/magento --profile=module-integrity
php magebean.phar audit --path=/var/www/magento --profile=module-source --modules=Vendor_Module
```

Module-aware checks default to application modules and can select explicitly named Composer-installed modules. Referenced framework/vendor source may be collected as bounded context, without treating every dependency as an additional audit subject. Reads are passive: source/configuration is parsed, not bootstrapped as Magento application code.

Missing/conflicting identity, unsupported expressions, absent schemas/symbols and collection limits remain unresolved evidence. Source findings do not prove runtime module activation, route exposure, full taint analysis or every Magento merge behavior. Development/prelaunch/takeover reuse these criteria; profile counts overlap. See [baseline](../magebean-baseline-v1.md), [development/prelaunch](development-prelaunch.md) and [collectors](../reference/scan-collectors.md).
