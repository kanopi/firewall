<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Plugins;

use Kanopi\Firewall\Plugins\AbstractPluginBase;
use Symfony\Component\HttpFoundation\Request;

/**
 * Always matches, and extends the base so it inherits observe mode.
 */
class TestObservablePlugin extends AbstractPluginBase
{
    protected function defaultName(): string
    {
        return 'test-observable';
    }

    public function getDescription(): string
    {
        return 'Always matches, for observe-mode tests';
    }

    public function evaluate(Request $request): bool
    {
        return true;
    }

    public function getStatusCode(?Request $request = null): int
    {
        return 403;
    }

    public function getExpirationTime(?Request $request = null): int
    {
        return 0;
    }
}
