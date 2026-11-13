<?php
declare(strict_types=1);
namespace Magebean\Engine\Collectors;

/** Explicit dependency shared by checks registered for one target. */
final class CollectorSet
{
    public readonly FileCollector $files;
    public readonly CodeInventoryCollector $code;
    public readonly ComposerCollector $composer;
    public readonly DependencyInventory $dependencies;
    public readonly PhpArrayCollector $php;
    public readonly HttpCollector $http;
    public readonly MagentoModuleInventory $magentoModules;
    public readonly MagentoModuleAnalysis $magentoAnalysis;

    public function __construct(public readonly CollectionSession $session = new CollectionSession())
    {
        $this->files = new FileCollector($session);
        $this->code = new CodeInventoryCollector($session);
        $this->composer = new ComposerCollector($this->files);
        $this->dependencies = new DependencyInventory($this->files, $session);
        $this->php = new PhpArrayCollector($session);
        $this->http = new HttpCollector($session);
        $this->magentoModules = new MagentoModuleInventory($session, $this->dependencies);
        $this->magentoAnalysis = new MagentoModuleAnalysis($this->magentoModules, $session);
    }
}
