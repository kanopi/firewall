<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Plugins;

use Kanopi\Firewall\Plugins\AbstractPluginBase;
use Symfony\Component\HttpFoundation\Request;

/**
 * A rule that always matches, and counts how often it was asked (#205).
 *
 * The count is the assertion that matters for scheduling: a sleeping rule has to be skipped
 * *before* it evaluates, not have its answer discarded afterwards.
 */
class TestScheduledPlugin extends AbstractPluginBase
{
    public static int $evaluations = 0;

    public function getName(): string
    {
        return is_string($this->metadata['name'] ?? null) ? $this->metadata['name'] : 'scheduled';
    }

    public function getDescription(): string
    {
        return 'Always matches, and says how often it was asked.';
    }

    public function evaluate(Request $request): bool
    {
        self::$evaluations++;

        return true;
    }
}
