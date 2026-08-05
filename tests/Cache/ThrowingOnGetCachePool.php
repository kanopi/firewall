<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Cache;

use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;

/**
 * A pool that throws as soon as it is touched.
 *
 * Injected pools are third-party code — Redis dropping the connection mid
 * probe, an APCu pool on a worker without the extension. The probe has to
 * survive that and report the pool unusable rather than letting the exception
 * escape plugin construction.
 */
class ThrowingOnGetCachePool implements CacheItemPoolInterface
{
    public function getItem(string $key): CacheItemInterface
    {
        throw new \RuntimeException('cache backend went away');
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
        throw new \RuntimeException('cache backend went away');
    }

    public function hasItem(string $key): bool
    {
        throw new \RuntimeException('cache backend went away');
    }

    public function clear(): bool
    {
        return false;
    }

    public function deleteItem(string $key): bool
    {
        return false;
    }

    /**
     * @param array<int, string> $keys
     *   Keys to delete.
     */
    public function deleteItems(array $keys): bool
    {
        return false;
    }

    public function save(CacheItemInterface $item): bool
    {
        throw new \RuntimeException('cache backend went away');
    }

    public function saveDeferred(CacheItemInterface $item): bool
    {
        return false;
    }

    public function commit(): bool
    {
        return false;
    }
}
