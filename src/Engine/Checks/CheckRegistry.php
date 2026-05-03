<?php

declare(strict_types=1);

namespace Magebean\Engine\Checks;

use Magebean\Engine\Context;

final class CheckRegistry
{
    /** @var array<string, callable(array): array> */
    private array $checks = [];
    /** @var array<string, callable(string,array): array> */
    private array $prefixChecks = [];
    /** @var array<string, object> */
    private array $services = [];

    public static function fromContext(Context $ctx): self
    {
        $registry = new self();

        $fs = new FilesystemCheck($ctx);
        $phpc = new PhpConfigCheck($ctx);
        $comp = new ComposerCheck($ctx);
        $mage = new MagentoCheck($ctx);
        $http = new HttpCheck($ctx);
        $code = new CodeSearchCheck($ctx);
        $web = new WebServerConfigCheck($ctx);
        $git = new GitHistoryCheck($ctx);
        $cron = new CronCheck($ctx);
        $sys = new SystemCheck($ctx);

        $registry->services['http'] = $http;

        $registry->register('http_header', fn(array $args): array => $http->stub($args));
        $registry->registerPrefix('http_', fn(string $name, array $args): array => $http->dispatch($name, $args));

        foreach (['code_grep', 'text_grep', 'file_grep', 'grep'] as $name) {
            $registry->register($name, fn(array $args): array => $code->grep($args));
        }
        $registry->register('code_raw_sql', fn(array $args): array => $code->rawSql($args));
        $registry->register('code_phtml_escaped_output', fn(array $args): array => $code->phtmlEscapedOutput($args));
        $registry->register('code_csrf_form_key', fn(array $args): array => $code->csrfFormKey($args));

        $registry->register('fs_no_world_writable', fn(array $args): array => $fs->noWorldWritable($args));
        $registry->register('file_mode_max', fn(array $args): array => $fs->fileModeMax($args));
        $registry->register('file_owner_group_matches', fn(array $args): array => $fs->fileOwnerGroupMatches($args));
        $registry->register('webroot_hygiene', fn(array $args): array => $fs->webrootHygiene($args));
        $registry->register('code_dirs_readonly', fn(array $args): array => $fs->codeDirsReadonly($args));
        $registry->register('no_directory_listing', fn(array $args): array => $fs->noDirectoryListing($args));
        $registry->register('fs_exists', fn(array $args): array => $fs->fsExists($args));
        $registry->register('fs_mtime_max_age', fn(array $args): array => $fs->mtimeMaxAge($args));

        $registry->register('system_egress_restricted', fn(array $args): array => $sys->egressRestricted($args));

        foreach (['php_array_exists', 'php_array_eq', 'php_array_neq', 'php_array_numeric_compare', 'php_array_absent'] as $name) {
            $registry->register($name, fn(array $args): array => $phpc->dispatch($name, $args));
        }
        $registry->register('php_array_key_search', fn(array $args): array => $phpc->keySearch($args));

        $registry->register('magento_config', fn(array $args): array => $mage->stub($args));
        $registry->register('magento_admin_frontname_strong', fn(array $args): array => $mage->adminFrontNameStrong($args));
        $registry->register('magento_admin_2fa_enabled', fn(array $args): array => $mage->adminTwoFactorAuthEnabled($args));
        $registry->register('magento_admin_password_policy_strong', fn(array $args): array => $mage->adminPasswordPolicyStrong($args));
        $registry->register('magento_admin_session_timeout', fn(array $args): array => $mage->adminSessionTimeout($args));
        $registry->register('magento_admin_exposure_restricted', fn(array $args): array => $mage->adminExposureRestricted($args));
        $registry->register('magento_admin_captcha_or_rate_limit', fn(array $args): array => $mage->adminCaptchaOrRateLimit($args));
        $registry->register('nginx_directive', fn(array $args): array => $web->nginxDirective($args));
        $registry->register('apache_htaccess_directive', fn(array $args): array => $web->apacheDirective($args));

        $registry->register('composer_audit_offline', fn(array $args): array => $comp->auditOffline($args));
        $registry->register('composer_core_advisories_offline', fn(array $args): array => $comp->coreAdvisoriesOffline($args));
        $registry->register('composer_fix_version', fn(array $args): array => $comp->fixVersion($args));
        $registry->register('composer_risk_surface_tag', fn(array $args): array => $comp->riskSurfaceTag($args));
        $registry->register('composer_match_list', fn(array $args): array => $comp->matchList($args));
        $registry->register('composer_constraints_conflict', fn(array $args): array => $comp->constraintsConflict($args));
        $registry->register('composer_yanked_offline', fn(array $args): array => $comp->yankedOffline($args));
        $registry->register('composer_outdated_offline', fn(array $args): array => $comp->outdatedOffline($args));
        $registry->register('composer_advisory_latency', fn(array $args): array => $comp->advisoryLatency($args));
        $registry->register('composer_vendor_support_offline', fn(array $args): array => $comp->vendorSupportOffline($args));
        $registry->register('composer_abandoned_offline', fn(array $args): array => $comp->abandonedOffline($args));
        $registry->register('composer_release_recency_offline', fn(array $args): array => $comp->releaseRecencyOffline($args));
        $registry->register('composer_repo_archived_offline', fn(array $args): array => $comp->repoArchivedOffline($args));
        $registry->register('composer_risky_fork_offline', fn(array $args): array => $comp->riskyForkOffline($args));
        $registry->register('composer_json_constraints', fn(array $args): array => $comp->jsonConstraints($args));
        $registry->register('composer_json_kv', fn(array $args): array => $comp->jsonKv($args));
        $registry->register('composer_lock_integrity', fn(array $args): array => $comp->lockIntegrity($args));

        $registry->register('git_history_scan', fn(array $args): array => $git->secretScan($args));
        $registry->register('crontab_grep', fn(array $args): array => $cron->crontabGrep($args));

        return $registry;
    }

    public function register(string $name, callable $check): void
    {
        $this->checks[$name] = $check;
    }

    public function registerPrefix(string $prefix, callable $check): void
    {
        $this->prefixChecks[$prefix] = $check;
    }

    public function has(string $name): bool
    {
        if (isset($this->checks[$name])) {
            return true;
        }
        foreach ($this->prefixChecks as $prefix => $_) {
            if (str_starts_with($name, $prefix)) {
                return true;
            }
        }
        return false;
    }

    public function run(string $name, array $args): array
    {
        if (isset($this->checks[$name])) {
            return ($this->checks[$name])($args);
        }
        foreach ($this->prefixChecks as $prefix => $check) {
            if (str_starts_with($name, $prefix)) {
                return $check($name, $args);
            }
        }
        return [null, '[UNKNOWN] Unknown check: ' . $name, []];
    }

    public function transportCounts(): array
    {
        $http = $this->services['http'] ?? null;
        if (is_object($http) && method_exists($http, 'getTransportCounts')) {
            return $http->getTransportCounts();
        }
        return ['ok' => 0, 'total' => 0];
    }
}
