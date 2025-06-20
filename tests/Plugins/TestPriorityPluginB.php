<?php

namespace Kanopi\Firewall\Tests\Plugins;

use Kanopi\Firewall\Plugins\PluginInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Plugin with priority 10 (calls after).
 */
class TestPriorityPluginB implements PluginInterface {
    public function __construct(public array $metadata = [], array $config = []) {}
    public function getName(): string { return 'priorityB'; }
    public function getDescription(): string { return 'priority 10'; }
    public function evaluate(Request $request): bool {
        $this->metadata['tracker'][] = static::class;
        return false;
    }
    public function getStatusCode(): int { return 0; }
    public function getExpirationTime(): int { return 0; }
}