<?php

namespace Kanopi\Firewall\Tests\Plugins;

use Kanopi\Firewall\Plugins\PluginInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Plugin with priority 1 (calls first).
 */
class TestPriorityPluginA implements PluginInterface {
    public function __construct(public array $metadata = [], array $config = []) {}
    public function getName(): string { return 'priorityA'; }
    public function getDescription(): string { return 'priority 1'; }
    public function evaluate(Request $request): bool {
        $this->metadata['tracker'][] = static::class;
        return false;
    }
    public function getStatusCode(?Request $requst = null): int { return 0; }
    public function getExpirationTime(?Request $requst = null): int { return 0; }
}