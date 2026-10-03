<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Storage;

use Kanopi\Firewall\Storage\InMemoryStorage;

/**
 * A store that fails mid-request, as a backend that went away would.
 */
class ThrowingStorage extends InMemoryStorage
{
    public function isBlocked(string $key): array|false
    {
        throw new \RuntimeException('the block list went away');
    }
}
