<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Plugins;

use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;

/**
 * A PSR-6 pool that cannot be constructed.
 *
 * Stands in for an adaptor whose backing store is unreachable at construction --
 * a Redis pool pointed at a host that is not there, say.
 */
class ThrowingCachePool implements CacheItemPoolInterface
{
    public function __construct()
    {
        throw new \RuntimeException('cache backend unavailable');
    }

    public function getItem(string $key): CacheItemInterface
    {
        throw new \RuntimeException('unreachable');
    }

    public function getItems(array $keys = []): iterable
    {
        return [];
    }

    public function hasItem(string $key): bool
    {
        return false;
    }

    public function clear(): bool
    {
        return true;
    }

    public function deleteItem(string $key): bool
    {
        return true;
    }

    public function deleteItems(array $keys): bool
    {
        return true;
    }

    public function save(CacheItemInterface $item): bool
    {
        return true;
    }

    public function saveDeferred(CacheItemInterface $item): bool
    {
        return true;
    }

    public function commit(): bool
    {
        return true;
    }
}
