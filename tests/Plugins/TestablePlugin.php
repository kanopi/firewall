<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Plugins;

use Kanopi\Firewall\Plugins\AbstractPluginBase;
use Symfony\Component\HttpFoundation\Request;

/**
 * Minimal concrete implementation of AbstractPluginBase for testing.
 */
class TestablePlugin extends AbstractPluginBase
{
    public function getName(): string { return 'TestablePlugin'; }

    public function getDescription(): string { return 'Test plugin description.'; }

    public function evaluate(Request $request): bool { return true; }

    public function triggerLog(): void
    {
        $this->log('info', 'Testing log call');
    }

    public function getRawConfig(): array
    {
        return $this->config;
    }

    public function getRawMetadata(): array
    {
        return $this->metadata;
    }
}