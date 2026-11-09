<?php
declare(strict_types=1);
namespace Magebean\Engine;
final class ResolvedScanTarget
{
    public function __construct(public readonly string $path, public readonly string $url, public readonly string $mode, private readonly ?string $profile = null) {}
    public function context(): ScanContext { return new ScanContext($this->path, $this->url, '', ['meta' => ['target_mode' => $this->mode] + ($this->profile === null ? [] : ['launch_profile' => $this->profile])]); }
}
