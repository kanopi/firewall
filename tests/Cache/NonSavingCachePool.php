<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Cache;

use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

/**
 * A pool that accepts writes and silently discards them.
 *
 * Stands in for the case the cache probe exists to catch: a pool that
 * constructs happily and reports nothing wrong, but does not persist.
 * `FilesystemAdapter` behaves this way against an unwritable directory — it
 * only fails per write — which is why the probe is a round trip rather than a
 * permissions check.
 */
class NonSavingCachePool implements CacheItemPoolInterface
{
    private ArrayAdapter $delegate;

    public function __construct()
    {
        $this->delegate = new ArrayAdapter();
    }

    public function getItem(string $key): CacheItemInterface
    {
        return $this->delegate->getItem($key);
    }

    /**
     * @param array<int, string> $keys
     *   Keys to fetch.
     *
     * @return iterable<string, CacheItemInterface>
     *   The requested items.
     */
    public function getItems(array $keys = []): iterable
    {
        return $this->delegate->getItems($keys);
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

    /**
     * @param array<int, string> $keys
     *   Keys to delete.
     */
    public function deleteItems(array $keys): bool
    {
        return true;
    }

    /**
     * Always reports failure — the whole point of this double.
     */
    public function save(CacheItemInterface $item): bool
    {
        return false;
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
