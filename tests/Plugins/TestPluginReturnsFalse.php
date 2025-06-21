<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Plugins;

use Kanopi\Firewall\Plugins\PluginInterface;
use Symfony\Component\HttpFoundation\Request;

class TestPluginReturnsFalse implements PluginInterface
{
    public function getName(): string { return 'test-false'; }

    public function getDescription(): string { return 'Test plugin that returns false'; }

    public function evaluate(Request $request): bool { return false; }

    public function getStatusCode(): int { return 403; }

    public function getExpirationTime(): int { return 0; }
}
