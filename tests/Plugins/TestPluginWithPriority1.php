<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Plugins;

use Kanopi\Firewall\Plugins\PluginInterface;
use Symfony\Component\HttpFoundation\Request;

class TestPluginWithPriority1 implements PluginInterface
{
    public static array $callOrder = [];

    public function getName(): string { return 'test-priority-1'; }

    public function getDescription(): string { return 'Test plugin with priority 1'; }

    public function evaluate(Request $request): bool
    {
        self::$callOrder[] = self::class;
        return false;
    }

    public function getStatusCode(?Request $requst = null): int { return 401; }

    public function getExpirationTime(?Request $requst = null): int { return 0; }
}
