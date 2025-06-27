<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Plugins;

use Kanopi\Firewall\Plugins\PluginInterface;
use Symfony\Component\HttpFoundation\Request;

class TestPluginWithPriority10 implements PluginInterface
{
    public static array $callOrder = [];

    public function getName(): string { return 'test-priority-10'; }

    public function getDescription(): string { return 'Test plugin with priority 10'; }

    public function evaluate(Request $request): bool
    {
        TestPluginWithPriority1::$callOrder[] = self::class;
        return false;
    }

    public function getStatusCode(?Request $requst = null): int { return 403; }

    public function getExpirationTime(?Request $requst = null): int { return 0; }
}
