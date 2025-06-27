<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Plugins;

use Kanopi\Firewall\Plugins\PluginInterface;
use Symfony\Component\HttpFoundation\Request;

class TestPluginReturnsTrue implements PluginInterface
{
    public function getName(): string { return 'test-true'; }

    public function getDescription(): string { return 'Test plugin that returns true'; }

    public function evaluate(Request $request): bool { return true; }

    public function getStatusCode(?Request $requst = null): int { return 200; }

    public function getExpirationTime(?Request $requst = null): int { return 0; }
}
