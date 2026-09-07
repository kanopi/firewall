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
class RedisRateLimitStorage extends AbstractRateLimitStorage implements PrunableRateLimitStorageInterface
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
        if (isset($config['redis']['port']) && is_numeric($config['redis']['port'])) {
            $config['redis']['port'] = intval($config['redis']['port']);
        }

        parent::__construct($config);

        try {
            $redisOptions = is_array($config['redis'] ?? null) ? $config['redis'] : [];
            $this->redisPrefix = strval($redisOptions['prefix'] ?? 'ratelimit:');

            // `prefix` is ours, not ext-redis's. Leaving it in the array makes
            // Redis::__construct() emit "Skip unknown option 'prefix'" on every
            // single construction — a warning nobody can act on, from a config
            // key the documentation tells them to set.
            unset($redisOptions['prefix']);

            $this->redis = (($config['instance'] ?? null) instanceof Redis)
                ? $config['instance']
                : new Redis($redisOptions);
            $this->redis->echo('Connected');

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
            // The score is the timestamp, which is what `countRequests()`
            // ranges over. The MEMBER has to be unique per request: a sorted
            // set holds each member once, so using the timestamp for both
            // collapsed every request arriving in the same second into a
            // single entry. A burst of 25 counted as 1, which meant no limit
            // finer than one request per second per key could ever fire —
            // against precisely the traffic rate limiting exists to stop.
            $member = $timestamp . ':' . bin2hex(random_bytes(8));
            $added = $this->redis->zAdd($redisKey, $timestamp, $member);
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
     *
     * `ZREMRANGEBYSCORE` is the canonical other half of the sorted-set sliding
     * window, and its absence is why the `ttl` was doing all the work here.
     * The TTL bounds how long a key survives, not how large it gets: a key
     * taking 1,000 requests a second accumulated 3.6 million members before
     * the hour was up, and every `zCount()` ranged over all of them.
     */
    public function forget(string $key, int $before): int
    {
        $redisKey = $this->redisPrefix . $key;

        try {
            // `(` makes the upper bound exclusive, so a member scored exactly
            // at the cutoff survives -- `countRequests()` treats its `$start`
            // as inclusive, and dropping it would lose a request the current
            // window still counts.
            $dropped = (int) $this->redis->zRemRangeByScore($redisKey, '-inf', '(' . $before);
        } catch (\Exception $exception) {
            $this->getLogger()->error('Failed to drop rate limit records outside the window in Redis', [
                'key' => $key,
                'redis_key' => $redisKey,
                'before' => $before,
                'error' => $exception->getMessage(),
            ]);

            return 0;
        }

        if ($dropped > 0) {
            $this->getLogger()->debug('Dropped rate limit records outside the window', [
                'key' => $key,
                'redis_key' => $redisKey,
                'before' => $before,
                'dropped' => $dropped,
            ]);
        }

        return $dropped;
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
