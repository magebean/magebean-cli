# Magento agency takeover audit

`takeover` selects 78 existing automated Magebean requirements for discovery of inherited risks and maintenance backlog. No new requirement identities are introduced.

```bash
php magebean.phar audit --profile takeover --path=/var/www/magento
php magebean.phar rules:list --profile takeover
php magebean.phar audit --profile takeover --path=/var/www/magento --rules=MB-0039
```

Default LOCAL selection executes 76 requirements. Two additional worker checks require explicit context: `--capabilities=runtime_worker_access,runtime_worker_inventory`. Enable these only when the scanner has the matching worker access and inventory.

## Evidence scope

Run against an installed Magento project. The existing LOCAL target resolver applies: runtime HTTP checks use the configured store URL; adding --url alongside --path does not override it. This profile does not use the special prelaunch endpoint selection. A URL-only run covers only applicable remote checks, not the whole takeover scope.

Provide read access to source, installed Composer metadata, deployment configuration, relevant scheduler evidence and deployment database. Existing dependency/advisory checks may contact Magebean APIs. Missing access or unavailable services remain collection gaps. The scanner does not repair the application.

Module checks default to discovered app/code modules; use --modules=Vendor_Module to select discovered modules, including installed Composer modules. This does not change the scope of other application source checks.

Findings are scope candidates requiring triage, not effort estimates or proof of exploitation. Informational loop-query observations remain informational. API package age/activity observations describe returned metadata, not a mandatory upgrade decision.

Repository/hosting ownership, commercial licenses, restore drills, business flows, integration ownership and handover documentation need a separate discovery checklist. This profile does not certify them. The VCS secret check covers its configured collected scope, not a guaranteed complete Git history.

## Membership

The groups below are deduplicated in order. Existing rule criteria and exit codes are unchanged. The local snapshot-only advisory rule MB-0828 is omitted because Basic already includes the online advisory check MB-0049. Agency-specific dependency policies and exact-latest-version requirements are omitted.

### security-and-production

| Rule | Scope |
|---|---|
| MB-0001 | No world-writable files or directories |
| MB-0002 | env.php satisfies configured mode and ownership policy |
| MB-0003 | Webroot hygiene (no .git/.env/backups in pub/) |
| MB-0005 | Directory listing absent on probed Magento paths |
| MB-0006 | Declared Admin route avoids common names |
| MB-0007 | Native Admin MFA provider configuration declared |
| MB-0728 | Configured admin password minimum is at least eight |
| MB-0011 | Configured admin login CAPTCHA or bounded lockout |
| MB-0026 | Observed storefront entrypoint redirects to HTTPS |
| MB-0028 | Runtime endpoint rejects legacy TLS |
| MB-0029 | Literal HTTP asset references absent in assessed markup/CSS |
| MB-0030 | Sensitive cookies use Secure, HttpOnly, and SameSite |
| MB-0031 | Declared Magento deployment mode is production |
| MB-0729 | Declared project debug settings are disabled |
| MB-0035 | Published static artifacts present in assessed deployment |
| MB-0037 | Declared Full Page Cache type enabled |
| MB-0046 | Installed Magento scheduler observed |
| MB-0049 | Composer dependency OSV advisory matches |
| MB-0050 | Adobe security release patch assessment |
| MB-0730 | No configured secret patterns in deployed application files |
| MB-0009 | Configured admin session lifetime is at most 900 seconds |
| MB-0027 | Observed HTTPS response has HSTS max-age of at least one year |
| MB-0042 | Log/report paths are absent from the collected webroot |
| MB-0100 | Recorded Admin role assignments have relational integrity |
| MB-0773 | Admin secret URL keys enabled |
| MB-0774 | Admin login names are case sensitive |
| MB-0775 | Admin account sharing disabled |
| MB-0776 | Admin password reset protection configured |
| MB-0777 | Observed Admin entrypoint redirects to HTTPS |
| MB-0778 | Observed TLS certificate has trusted hostname and renewal margin |
| MB-0779 | Observed page restricts framing |
| MB-0780 | Media inventory has no executable PHP-like filenames |
| MB-0781 | Named sensitive HTTP paths are denied or absent |
| MB-0782 | Sensitive deployment configuration excluded from Git index |
| MB-0783 | Installed Magento cron has every-minute cadence |
| MB-0784 | Published theme and locale static scopes have representative assets |
| MB-0785 | Magento cron execution has recent success and bounded backlog |

### source-and-modules

| Rule | Scope |
|---|---|
| MB-0808 | Consistent static Magento module identity |
| MB-0809 | Supported module XML satisfies its local schema |
| MB-0810 | Declared Composer package names are available |
| MB-0811 | REST declaration references a public service method |
| MB-0812 | REST ACL references are declared in collected context |
| MB-0813 | Review sensitive anonymous REST declarations |
| MB-0814 | Avoid direct request superglobals in module log calls |
| MB-0815 | DI preferences resolve to compatible concrete targets |
| MB-0816 | DI virtual types resolve to concrete classes |
| MB-0817 | DI constructor arguments match supported signatures |
| MB-0818 | DI plugins target interceptable declarations |
| MB-0819 | Module PHP syntax matches the configured target |
| MB-0820 | Indexed public method declarations preserve their contracts |
| MB-0821 | Declared Magento Framework constraints match the installed version |
| MB-0822 | Review request data reaching command and query calls |
| MB-0823 | Declarative schema XML satisfies its installed schema |
| MB-0824 | Setup patch declarations and dependencies are compatible |
| MB-0825 | Cron and queue declarations reference public handlers |
| MB-0070 | Composer lock hash and dependency identities are consistent |
| MB-0787 | No unconditional validateForCsrf acceptance override |
| MB-0789 | Custom source avoids native unserialize calls |
| MB-0790 | Custom source avoids enumerated shell/process primitives |
| MB-0791 | Custom source avoids eval and create_function constructs |
| MB-0793 | Custom source avoids native upload move calls |
| MB-0797 | No enumerated XML external feature constructs in custom source |

### reliability

| Rule | Scope |
|---|---|
| MB-0826 | Review empty exception handlers |
| MB-0827 | Review query-like calls in loops |

### operations-and-maintenance

| Rule | Scope |
|---|---|
| MB-0034 | Generated DI PHP artifacts are present |
| MB-0038 | Declared cache backends use Redis or Varnish |
| MB-0039 | Recorded Magento indexers have valid state |
| MB-0040 | Declared Redis session storage has authentication configured |
| MB-0061 | Collected dependencies are not reported abandoned |
| MB-0062 | Reported latest package releases are within 24 months |
| MB-0063 | Reported source repositories remain available and active |
| MB-0065 | No wildcard constraints in composer.json |
| MB-0066 | No dev branches in composer.json |
| MB-0067 | prefer-stable=true in composer.json |
| MB-0072 | No configured secret-pattern matches in collected VCS scope |
| MB-0799 | Application worker code paths are read-only |
| MB-0800 | Upload inventory has no configured PHP or handler signatures |
| MB-0807 | Configured PHP-FPM workers have no mapped Xdebug binary module |

