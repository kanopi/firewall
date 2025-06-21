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

        $this->redis = (($config['instance'] ?? null) instanceof Redis) ? $config['instance'] : new Redis($config['redis']);
        $this->redisPrefix = strval($config['redis']['prefix'] ?? 'ratelimit:');
    }

    /**
     * {@inheritdoc}
     */
    public function recordRequest(string $key, int $timestamp): void
    {
        $redisKey = $this->redisPrefix . $key;
        $this->redis->zAdd($redisKey, $timestamp, (string)$timestamp);
        $this->redis->expire($redisKey, $this->config['ttl'] ?? 3600);
    }

    /**
     * {@inheritdoc}
     */
    public function countRequests(string $key, int $start, int $end): int
    {
        $redisKey = $this->redisPrefix . $key;
        return $this->redis->zCount($redisKey, $start, $end);
    }
}
