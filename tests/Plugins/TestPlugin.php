<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Plugins;

use Kanopi\Firewall\Plugins\PluginInterface;
use Symfony\Component\HttpFoundation\Request;

class TestPlugin implements PluginInterface
{
    public function __construct(protected array $metadata = [], protected array $config = []) {}

    public function getName(): string { return 'test'; }

    public function getDescription(): string { return 'Test plugin'; }

    public function evaluate(Request $request): bool { return false; }

    public function getStatusCode(?Request $requst = null): int { return 400; }

    public function getExpirationTime(?Request $requst = null): int { return 0; }
}
