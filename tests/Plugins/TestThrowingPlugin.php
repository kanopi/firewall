<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Plugins;

use Kanopi\Firewall\Plugins\PluginInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Throws from its constructor, as a plugin with an unreachable storage backend does.
 */
class TestThrowingPlugin implements PluginInterface
{
    public static int $constructions = 0;

    public function __construct(array $metadata = [], array $config = [])
    {
        self::$constructions++;
        throw new \RuntimeException('cannot connect to storage');
    }

    public function getName(): string { return 'throwing'; }

    public function getDescription(): string { return 'Throws on construction'; }

    public function evaluate(Request $request): bool { return true; }

    public function getStatusCode(?Request $request = null): int { return 403; }

    public function getExpirationTime(?Request $request = null): int { return 0; }
}
