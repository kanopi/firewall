<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Plugins;

use Kanopi\Firewall\Plugins\PluginInterface;
use Symfony\Component\HttpFoundation\Request;

class TestPriorityPluginLow implements PluginInterface {
    public function __construct(public array $metadata = [], array $config = []) {}
    public function getName(): string { return 'low'; }
    public function getDescription(): string { return 'Low priority'; }
    public function evaluate(Request $request): bool {
        $this->metadata['order'][] = static::class;
        return false;
    }
    public function getStatusCode(): int { return 200; }
    public function getExpirationTime(): int { return 10; }
}