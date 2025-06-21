<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Plugins;

use Kanopi\Firewall\Plugins\PluginInterface;
use Symfony\Component\HttpFoundation\Request;
use Kanopi\Firewall\Tests\Plugins\TestPluginWithPriority1;

class TestPluginWithPriority5 implements PluginInterface
{
    public static array $callOrder = [];

    public function getName(): string { return 'test-priority-5'; }

    public function getDescription(): string { return 'Test plugin with priority 5'; }

    public function evaluate(Request $request): bool
    {
        TestPluginWithPriority1::$callOrder[] = self::class;
        return false;
    }

    public function getStatusCode(): int { return 402; }

    public function getExpirationTime(): int { return 0; }
}
