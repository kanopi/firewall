<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Plugins;

use Kanopi\Firewall\Plugins\PluginInterface;
use Symfony\Component\HttpFoundation\Request;

class TestPluginWithCounter implements PluginInterface
{
    public static int $callCount = 0;

    public function getName(): string { return 'test-counter'; }

    public function getDescription(): string { return 'Test plugin with counter'; }

    public function evaluate(Request $request): bool
    {
        self::$callCount++;
        return false;
    }

    public function getStatusCode(): int { return 429; }

    public function getExpirationTime(): int { return 300; }
}
