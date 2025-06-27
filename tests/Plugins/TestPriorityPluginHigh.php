<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Plugins;

use Kanopi\Firewall\Plugins\PluginInterface;
use Symfony\Component\HttpFoundation\Request;

class TestPriorityPluginHigh implements PluginInterface {
    public function __construct(public array $metadata = [], array $config = []) {}
    public function getName(): string { return 'high'; }
    public function getDescription(): string { return 'High priority'; }
    public function evaluate(Request $request): bool {
        $this->metadata['order'][] = static::class;
        return false;
    }
    public function getStatusCode(?Request $requst = null): int { return 200; }
    public function getExpirationTime(?Request $requst = null): int { return 10; }
}