<?php

namespace Kanopi\Firewall\Tests\Plugins;

use Kanopi\Firewall\Plugins\PluginInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * A plugin that always returns false.
 */
class TestFalsePlugin implements PluginInterface {
    public function __construct(array $metadata = [], array $config = []) {}
    public function getName(): string { return 'false'; }
    public function getDescription(): string { return 'always false'; }
    public function evaluate(Request $request): bool { return false; }
    public function getStatusCode(): int { return 403; }
    public function getExpirationTime(): int { return 60; }
}