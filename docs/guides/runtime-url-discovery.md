# Runtime URL discovery

LOCAL scans do not require `--url`. HTTP checks read the default Magento store URL through the configuration resolver: deployment `system/default` overrides in env.php/config.php, then read-only default-scope core_config_data values. The secure base URL is preferred to the unsecure base URL. Preserve the configured hostname, port and base path; never invent a hostname or disable TLS verification.

`--url` is the external target for REMOTE scans only. With an explicit Magento path, the scan is LOCAL and any --url argument is ignored. REMOTE scans do not read local Magento configuration. Default-scope discovery does not enumerate every website/store-view URL; selecting additional local website/store-view scopes requires a separate scope selector rather than a URL override.

The common discovery path is used by HttpCheck, sensitive artifact probes, production response checks, response evidence and legacy Magento HTTP probes. CodeQueryChecks also records an explicitly supplied target URL as source-policy evidence; it is not an HTTP probe or an additional required URL input.

Missing scanner URL input is retained as incomplete execution metadata, not promoted into a Magebean risk finding. This does not establish a clean result or close an existing security finding. Concrete observed response or source risks retain their independent findings.
