<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Plugins;

use Kanopi\Firewall\Plugins\PluginInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Counts how many times it is constructed, to prove laziness.
 */
class TestConstructionCountingPlugin implements PluginInterface
{
    public static int $constructions = 0;

    public function __construct(array $metadata = [], array $config = [])
    {
        self::$constructions++;
    }

    public function getName(): string { return 'construction-counter'; }

    public function getDescription(): string { return 'Counts its own constructions'; }

    public function evaluate(Request $request): bool { return false; }

    public function getStatusCode(?Request $request = null): int { return 403; }

    public function getExpirationTime(?Request $request = null): int { return 0; }
}
