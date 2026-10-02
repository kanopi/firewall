<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Cache;

use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;

/**
 * An in-memory pool that records what was saved, and with what lifetime.
 *
 * Values are kept as given rather than serialised, so a test can plant an
 * entry -- valid, stale or malformed -- and read back exactly what Config
 * stored, including the expiry a real pool would hide.
 */
class RecordingCachePool implements CacheItemPoolInterface
{
    /**
     * Stored values, by key.
     *
     * @var array<string, mixed>
     */
    public array $values = [];

    /**
     * The lifetime each key was last saved with, null for none.
     *
     * @var array<string, int|null>
     */
    public array $lifetimes = [];

    /**
     * Every key `save()` was called with, in order.
     *
     * @var array<int, string>
     */
    public array $saved = [];

    /**
     * Every key `deleteItem()` was called with, in order.
     *
     * @var array<int, string>
     */
    public array $deleted = [];

    /**
     * Whether `deleteItem()` throws, as a backend gone away mid-request would.
     */
    public bool $throwOnDelete = false;

    public function getItem(string $key): CacheItemInterface
    {
        return new RecordingCacheItem($key, array_key_exists($key, $this->values), $this->values[$key] ?? null);
    }

    /**
     * @param array<int, string> $keys
     *   Keys to fetch.
     *
     * @return iterable<string, CacheItemInterface>
     *   The items.
     */
    public function getItems(array $keys = []): iterable
    {
        $items = [];

        foreach ($keys as $key) {
            $items[$key] = $this->getItem($key);
        }

        return $items;
    }

    public function hasItem(string $key): bool
    {
        return array_key_exists($key, $this->values);
    }

    public function clear(): bool
    {
        $this->values = [];
        $this->lifetimes = [];

        return true;
    }

    public function deleteItem(string $key): bool
    {
        $this->deleted[] = $key;

        if ($this->throwOnDelete) {
            throw new \RuntimeException('cache backend went away');
        }

        unset($this->values[$key], $this->lifetimes[$key]);

        return true;
    }

    /**
     * @param array<int, string> $keys
     *   Keys to delete.
     */
    public function deleteItems(array $keys): bool
    {
        foreach ($keys as $key) {
            $this->deleteItem($key);
        }

        return true;
    }

    public function save(CacheItemInterface $item): bool
    {
        $key = $item->getKey();
        $this->saved[] = $key;
        $this->values[$key] = $item->get();
        $this->lifetimes[$key] = $item instanceof RecordingCacheItem ? $item->lifetime : null;

        return true;
    }

    public function saveDeferred(CacheItemInterface $item): bool
    {
        return $this->save($item);
    }

    public function commit(): bool
    {
        return true;
    }
}
