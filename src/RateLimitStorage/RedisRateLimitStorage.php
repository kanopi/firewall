<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\RateLimitStorage;

use Kanopi\Firewall\Utility\DegradedBackends;
use Kanopi\Firewall\Utility\RedisConnections;
use Redis;

/**
 * Redis-based rate limit storage.
 */
class RedisRateLimitStorage extends AbstractRateLimitStorage implements PrunableRateLimitStorageInterface
{
    /**
     * Redis Connection class, or NULL when it could not be opened.
     *
     * Nullable so a failed construction leaves something every method can
     * check. It was a non-nullable typed property, which meant a failed
     * construction left it *uninitialized* -- and reading an uninitialized
     * typed property throws `\Error`, which the `catch (\Exception …)` in each
     * method below does not catch either. The backend degraded at startup and
     * then fataled on the first request that used it (#356).
     */
    protected ?Redis $redis = null;

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

            // Through the registry, so a deployment using Redis for both the
            // block list and rate limiting opens one connection rather than two
            // to the same server on every request (#263). An injected instance
            // still wins.
            $this->redis = (($config['instance'] ?? null) instanceof Redis)
                ? $config['instance']
                : RedisConnections::get($redisOptions);
            $this->redis->echo('Connected');

            $this->getLogger()->info('Redis rate limit storage initialized', [
                'prefix' => $this->redisPrefix,
                'ttl' => $config['ttl'] ?? 3600,
            ]);
        } catch (\Throwable $throwable) {
            // `\Throwable`, not `\Exception`. A server that is not answering
            // throws an exception and degrades correctly; `ext-redis` not being
            // installed throws an `\Error` from `new Redis()`, which was caught
            // by nothing -- not here, and not by a host catching `\Exception`
            // or `FirewallException` either. The firewall simply did not start
            // (#356, the same shape as #277).
            //
            // Left null, and every method below degrades rather than fatals.
            // A storage backend that cannot connect must say so and let the
            // firewall carry on enforcing what it can -- taking the site down
            // because the rate limit counters are unreachable helps nobody.

            // "Class \"Redis\" not found" is the truth and not the sentence an
            // operator needs; the extension being absent is a different fix
            // from the server being down, and this is the only place that
            // knows which one happened.
            $reason = extension_loaded('redis')
                ? $throwable->getMessage()
                : 'the redis extension is not installed on this host';

            $this->getLogger()->error('Failed to initialize Redis rate limit storage', [
                'error' => $reason,
            ]);

            // Logged and also recorded, so a host application's status report
            // can say the rate limit counters are unreachable rather than leaving it to
            // a log scraper. The rule still runs; it just has nothing to
            // consult (#273).
            DegradedBackends::record('rate limit', self::class, $reason);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function recordRequest(string $key, int $timestamp): void
    {
        if (!$this->redis instanceof Redis) {
            return;
        }

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
        if (!$this->redis instanceof Redis) {
            return 0;
        }

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
        if (!$this->redis instanceof Redis) {
            // Zero, which is what a counter that recorded nothing holds. A
            // rate limit that cannot count does not match, which is the
            // fail-open this backend has always chosen deliberately.
            return 0;
        }

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
