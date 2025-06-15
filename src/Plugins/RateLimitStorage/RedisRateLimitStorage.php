<?php

namespace Kanopi\Firewall\Plugins\RateLimitStorage;

use Redis;

/**
 * Redis-based rate limit storage.
 */
class RedisRateLimitStorage extends AbstractRateLimitStorage
{
    /**
     * Redis Connection class.
     *
     * @var Redis
     */
    protected Redis $redis;

    /**
     * Redis Prefix.
     *
     * @var string
     */
    protected string $redisPrefix;

    /**
     * Constructs a new RedisRateLimitStorage object.
     */
    public function __construct(array $config = [])
    {
        parent::__construct($config);

        $this->redis = new Redis();
        $this->redis->connect(
            strval($config['redis']['host'] ?? '127.0.0.1'),
            intval($config['redis']['port'] ?? 6379)
        );

        if (!empty($config['redis']['auth'])) {
            $this->redis->auth(strval($config['redis']['auth']));
        }

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
        $count = $this->redis->zCount($redisKey, $start, $end);
        return $count;
    }
}
