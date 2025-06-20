<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Plugins;

use Kanopi\Firewall\Plugins\PluginInterface;
use Symfony\Component\HttpFoundation\Request;

class TestPluginWithMetadata implements PluginInterface
{
    public static array $lastMetadata = [];
    public static array $lastConfig = [];

    public function __construct(protected array $metadata = [], protected array $config = [])
    {
        self::$lastMetadata = $metadata;
        self::$lastConfig = $config;
    }

    public function getName(): string { return 'test-metadata'; }

    public function getDescription(): string { return 'Test plugin with metadata'; }

    public function evaluate(Request $request): bool { return false; }

    public function getStatusCode(): int { return 400; }

    public function getExpirationTime(): int { return 0; }
}
