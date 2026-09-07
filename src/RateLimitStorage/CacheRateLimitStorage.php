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
class CacheRateLimitStorage extends AbstractRateLimitStorage implements PrunableRateLimitStorageInterface
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

        // If there are no cache adaptors end this.
        if ($cache === null) {
            return;
        }

        $instance = null;
        if (is_object($cache) && in_array(CacheItemPoolInterface::class, class_implements($cache), true)) {
            $instance = $cache;
        } elseif (class_exists($cache)) {
            /** @var CacheItemPoolInterface $instance */
            $instance = new $cache(...$args);
        }

        if ($instance !== null) {
            /** @phpstan-ignore assign.propertyType */
            $this->cache = $instance;
            $this->getLogger()->info('Cache rate limit storage initialized', [
                'cache_type' => $instance::class,
                'ttl' => intval($config['ttl'] ?? 3600),
            ]);
        } else {
            $this->getLogger()->warning('Cache rate limit storage failed to initialize', [
                /** @phpstan-ignore classConstant.nonObject */
                'adaptor' => is_string($cache) ? $cache : $cache::class,
            ]);
        }

        $this->ttl = intval($config['ttl'] ?? 3600); // Default TTL: 1 hour
    }

    /**
     * {@inheritdoc}
     */
    public function recordRequest(string $key, int $timestamp): void
    {
        if (!$this->cache instanceof \Psr\Cache\CacheItemPoolInterface) {
            $this->getLogger()->warning('Cannot record request - cache not available');
            return;
        }

        $originalKey = $key;
        $key = $this->alterKey($key);
        $cacheItem = $this->cache->getItem($key);

        $timestamps = $cacheItem->isHit() ? $cacheItem->get() : [];
        $timestamps[] = $timestamp;

        $cacheItem->set($timestamps)->expiresAfter($this->ttl);
        $saved = $this->cache->save($cacheItem);

        if ($saved) {
            $this->getLogger()->debug('Cache rate limit request recorded', [
                'key' => $originalKey,
                'cache_key' => $key,
                'timestamp' => $timestamp,
                'total_requests' => count($timestamps),
                'ttl' => $this->ttl,
            ]);
        } else {
            $this->getLogger()->error('Failed to save rate limit request to cache', [
                'key' => $originalKey,
                'cache_key' => $key,
            ]);
        }
    }

    /**
     * {@inheritdoc}
     *
     * The `ttl` bounds how long a key survives, not how large it gets. Every
     * request appended a timestamp to one array and nothing removed any until
     * the whole key expired, so a key taking sustained traffic held an hour of
     * timestamps by default -- and `countRequests()` filtered the lot on every
     * request to answer a question about the last few seconds.
     */
    public function forget(string $key, int $before): int
    {
        if (!$this->cache instanceof \Psr\Cache\CacheItemPoolInterface) {
            $this->getLogger()->warning('Cannot drop rate limit records - cache not available');
            return 0;
        }

        $originalKey = $key;
        $key = $this->alterKey($key);
        $cacheItem = $this->cache->getItem($key);

        if (!$cacheItem->isHit()) {
            return 0;
        }

        $timestamps = $cacheItem->get();

        if (!is_array($timestamps)) {
            return 0;
        }

        $kept = array_values(array_filter($timestamps, static fn($timestamp): bool => $timestamp >= $before));
        $dropped = count($timestamps) - count($kept);

        if ($dropped === 0) {
            return 0;
        }

        // Deleted outright when nothing is left, rather than written back as
        // an empty array: an empty entry holds a key in the pool for the whole
        // TTL to say nothing.
        if ($kept === []) {
            $this->cache->deleteItem($key);
        } else {
            // The TTL is reset here, as it is on every record. It measures
            // idleness either way -- a key nothing touches still ages out.
            $this->cache->save($cacheItem->set($kept)->expiresAfter($this->ttl));
        }

        $this->getLogger()->debug('Dropped rate limit records outside the window', [
            'key' => $originalKey,
            'cache_key' => $key,
            'before' => $before,
            'dropped' => $dropped,
            'remaining' => count($kept),
        ]);

        return $dropped;
    }

    /**
     * {@inheritdoc}
     */
    public function countRequests(string $key, int $start, int $end): int
    {
        if (!$this->cache instanceof \Psr\Cache\CacheItemPoolInterface) {
            $this->getLogger()->warning('Cannot count requests - cache not available');
            return 0;
        }

        $originalKey = $key;
        $key = $this->alterKey($key);
        $cacheItem = $this->cache->getItem($key);
        $timestamps = $cacheItem->isHit() ? $cacheItem->get() : [];

        $filtered = array_filter(
            $timestamps,
            fn(int $ts): bool => $ts >= $start && $ts <= $end
        );

        $count = count($filtered);

        $this->getLogger()->debug('Cache rate limit request count', [
            'key' => $originalKey,
            'cache_key' => $key,
            'start' => $start,
            'end' => $end,
            'count' => $count,
            'cache_hit' => $cacheItem->isHit(),
            'total_timestamps' => count($timestamps),
        ]);

        return $count;
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
