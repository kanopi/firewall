<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\RateLimitStorage;

use Psr\Cache\CacheItemPoolInterface;

/**
 * Generic Symfony cache-based rate limit storage.
 */
class CacheRateLimitStorage extends AbstractRateLimitStorage
{
    /**
     * Symfony cache instance.
     */
    protected ?CacheItemPoolInterface $cache = null;

    /**
     * Cache TTL for each key, in seconds.
     */
    protected int $ttl;

    /**
     * Constructor.
     *
     * @param array $config
     *   Configuration array with nested structure. Must include:
     *   - ['adaptor' => class-string<CacheInterface>|CacheInterface, optional 'ttl' => int, 'args' => array]
     */
    public function __construct(array $config = [])
    {
        parent::__construct($config);

        $cache = $config['adaptor'] ?? null;
        $args = $config['args'] ?? [];

        $instance = null;
        if (is_object($cache) && in_array(CacheItemPoolInterface::class, class_implements($cache), true)) {
            $instance = $cache;
        } elseif (!is_null($cache) && class_exists($cache)) {
            /** @var CacheItemPoolInterface $instance */
            $instance = new $cache(...$args);
        }

        if ($instance !== null) {
            /** @phpstan-ignore assign.propertyType */
            $this->cache = $instance;
        }

        $this->ttl = intval($config['ttl'] ?? 3600); // Default TTL: 1 hour
    }

    /**
     * {@inheritdoc}
     */
    public function recordRequest(string $key, int $timestamp): void
    {
        if (!$this->cache instanceof \Psr\Cache\CacheItemPoolInterface) {
            return;
        }

        $key = $this->alterKey($key);
        $cacheItem = $this->cache->getItem($key);

        $timestamps = $cacheItem->isHit() ? $cacheItem->get() : [];
        $timestamps[] = $timestamp;

        $cacheItem->set($timestamps)->expiresAfter($this->ttl);
        $this->cache->save($cacheItem);
    }

    /**
     * {@inheritdoc}
     */
    public function countRequests(string $key, int $start, int $end): int
    {
        if (!$this->cache instanceof \Psr\Cache\CacheItemPoolInterface) {
            return 0;
        }

        $key = $this->alterKey($key);
        $cacheItem = $this->cache->getItem($key);
        $timestamps = $cacheItem->isHit() ? $cacheItem->get() : [];

        $filtered = array_filter(
            $timestamps,
            fn(int $ts): bool => $ts >= $start && $ts <= $end
        );

        return count($filtered);
    }

    /**
     * Alter the key to be safe.
     *
     * @param string $key
     *   Key to review.
     *
     * @return string
     *   Altered key.
     */
    protected function alterKey(string $key): string
    {
        return str_ireplace(':', '__', $key);
    }
}
