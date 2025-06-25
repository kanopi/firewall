<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\RateLimitStorage;

use Redis;

/**
 * Redis-based rate limit storage.
 */
class RedisRateLimitStorage extends AbstractRateLimitStorage
{
    /**
     * Redis Connection class.
     */
    protected Redis $redis;

    /**
     * Redis Prefix.
     */
    protected string $redisPrefix;

    /**
     * Constructs a new RedisRateLimitStorage object.
     */
    public function __construct(array $config = [])
    {
        parent::__construct($config);

        try {
            $this->redis = (($config['instance'] ?? null) instanceof Redis) ? $config['instance'] : new Redis($config['redis']);
            $this->redisPrefix = strval($config['redis']['prefix'] ?? 'ratelimit:');

            $this->getLogger()->info('Redis rate limit storage initialized', [
                'prefix' => $this->redisPrefix,
                'ttl' => $config['ttl'] ?? 3600,
            ]);
        } catch (\Exception $exception) {
            $this->getLogger()->error('Failed to initialize Redis rate limit storage', [
                'error' => $exception->getMessage(),
            ]);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function recordRequest(string $key, int $timestamp): void
    {
        $redisKey = $this->redisPrefix . $key;
        $ttl = $this->config['ttl'] ?? 3600;

        try {
            $added = $this->redis->zAdd($redisKey, $timestamp, (string)$timestamp);
            $this->redis->expire($redisKey, $ttl);

            $this->getLogger()->debug('Redis rate limit request recorded', [
                'key' => $key,
                'redis_key' => $redisKey,
                'timestamp' => $timestamp,
                'ttl' => $ttl,
                'added' => $added,
            ]);
        } catch (\Exception $exception) {
            $this->getLogger()->error('Failed to record rate limit request in Redis', [
                'key' => $key,
                'redis_key' => $redisKey,
                'error' => $exception->getMessage(),
            ]);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function countRequests(string $key, int $start, int $end): int
    {
        $redisKey = $this->redisPrefix . $key;

        try {
            $count = $this->redis->zCount($redisKey, (string)$start, (string)$end);

            $this->getLogger()->debug('Redis rate limit request count', [
                'key' => $key,
                'redis_key' => $redisKey,
                'start' => $start,
                'end' => $end,
                'count' => $count,
                'window_seconds' => $end - $start,
            ]);

            return $count;
        } catch (\Exception $exception) {
            $this->getLogger()->error('Failed to count rate limit requests in Redis', [
                'key' => $key,
                'redis_key' => $redisKey,
                'error' => $exception->getMessage(),
            ]);
            return 0;
        }
    }
}
