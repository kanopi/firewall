<?php

namespace Kanopi\Firewall\Tests\Plugins;

use Kanopi\Firewall\Plugins\PluginInterface;
use Symfony\Component\HttpFoundation\Request;

class TestTruePlugin implements PluginInterface {
    public function __construct(array $metadata = [], array $config = []) {}
    public function getName(): string { return 'true'; }
    public function getDescription(): string { return 'true desc'; }
    public function evaluate(Request $request): bool { return true; }
    public function getStatusCode(?Request $requst = null): int { return 403; }
    public function getExpirationTime(?Request $requst = null): int { return 300; }
}