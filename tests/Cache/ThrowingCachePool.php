<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Cache;

use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;

/**
 * A pool whose constructor throws.
 *
 * Registered by class name in `metadata.cache.adaptor`, it passes the
 * `is_subclass_of()` check and then fails at `new` — the shape of a real
 * misconfiguration, such as a Redis adaptor pointed at an unreachable host or
 * a filesystem adaptor given a path it cannot use. Losing the cache costs
 * roughly 600ms per request; taking the site down would be worse, so the
 * plugin must degrade rather than propagate.
 */
class ThrowingCachePool implements CacheItemPoolInterface
{
    public function __construct()
    {
        throw new \RuntimeException('cannot reach the cache backend');
    }

    public function getItem(string $key): CacheItemInterface
    {
        throw new \LogicException('unreachable');
    }

    /**
     * @param array<int, string> $keys
     *   Keys to fetch.
     *
     * @return iterable<string, CacheItemInterface>
     *   Never returns.
     */
    public function getItems(array $keys = []): iterable
    {
        throw new \LogicException('unreachable');
    }

    public function hasItem(string $key): bool
    {
        throw new \LogicException('unreachable');
    }

    public function clear(): bool
    {
        throw new \LogicException('unreachable');
    }

    public function deleteItem(string $key): bool
    {
        throw new \LogicException('unreachable');
    }

    /**
     * @param array<int, string> $keys
     *   Keys to delete.
     */
    public function deleteItems(array $keys): bool
    {
        throw new \LogicException('unreachable');
    }

    public function save(CacheItemInterface $item): bool
    {
        throw new \LogicException('unreachable');
    }

    public function saveDeferred(CacheItemInterface $item): bool
    {
        throw new \LogicException('unreachable');
    }

    public function commit(): bool
    {
        throw new \LogicException('unreachable');
    }
}
