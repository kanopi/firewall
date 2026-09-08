<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Storage;

use Kanopi\Firewall\Traits\AddressMatchTrait;
use Kanopi\Firewall\Utility\DegradedBackends;
use Kanopi\Firewall\Utility\RedisConnections;
use Redis;

/**
 * Blocked-client storage backed by Redis.
 *
 * The rate limiter has had a Redis backend since 2.x; the block list has not, so a
 * multi-server deployment had to reach for `DatabaseStorage` and pay a SQL round trip on the
 * hot path for what is a key lookup. `FileStorage` was the other option and it degrades with
 * the size of the block list -- measured at 15.66 ms per request with 2,000 blocked clients
 * against 7.58 ms for the database, and rising *during* an attack, which is when it matters
 * (#17, and see #225).
 *
 * Two shapes are stored, both namespaced by `prefix`:
 *
 * - `{prefix}block:{key}` holds the record as JSON, with the block's lifetime expressed as a
 *   Redis TTL rather than a stored timestamp. Expiry is then the server's job, which is why
 *   `expire()` here has nothing to do.
 * - `{prefix}offense:{key}` is a sorted set scored by unix timestamp, matching how
 *   `RedisRateLimitStorage` keeps its windows. Offenses outlive the block that earned them,
 *   deliberately: `blocking_escalation` needs that history to give a repeat offender a
 *   longer ban next time.
 *
 * JSON rather than `serialize()`, as everywhere else this library writes and reads back --
 * a store an attacker can reach is exactly what should not be deserialised (CWE-502).
 */
class RedisStorage extends AbstractStorageBase implements QueryableStorageInterface
{
    use AddressMatchTrait;

    /**
     * Redis connection, or null when one could not be established.
     */
    protected ?Redis $redis = null;

    /**
     * Namespace for every key this backend owns.
     */
    protected string $redisPrefix;

    /**
     * How many keys SCAN asks for per round trip.
     *
     * SCAN rather than KEYS throughout. KEYS walks the entire keyspace in one blocking
     * command, which on a shared Redis stalls every other client -- including the rate
     * limiter, mid-request.
     */
    protected const SCAN_COUNT = 500;

    /**
     * Constructs a new RedisStorage object.
     */
    public function __construct(array $config = [])
    {
        if (isset($config['redis']['port']) && is_numeric($config['redis']['port'])) {
            $config['redis']['port'] = intval($config['redis']['port']);
        }

        parent::__construct($config);

        try {
            $redisOptions = is_array($config['redis'] ?? null) ? $config['redis'] : [];
            $this->redisPrefix = strval($redisOptions['prefix'] ?? 'firewall:');

            // `prefix` is ours, not ext-redis's. Leaving it in the array makes
            // Redis::__construct() emit "Skip unknown option 'prefix'" on every
            // construction -- a warning nobody can act on, from a key the
            // documentation tells them to set. Same reason as the rate limiter.
            unset($redisOptions['prefix']);

            // Through the registry, so a deployment using Redis for both the
            // block list and rate limiting opens one connection rather than two
            // to the same server on every request (#263). An injected instance
            // still wins.
            $this->redis = (($config['instance'] ?? null) instanceof Redis)
                ? $config['instance']
                : RedisConnections::get($redisOptions);
            $this->redis->echo('Connected');

            $this->getLogger()->info('Redis storage initialized', [
                'prefix' => $this->redisPrefix,
            ]);
        } catch (\Exception $exception) {
            // Left null, and every method below degrades rather than fatals.
            // A storage backend that cannot connect must say so and let the
            // firewall carry on enforcing what it can -- taking the site down
            // because the block list is unreachable helps nobody.
            $this->redis = null;
            $this->getLogger()->error('Failed to initialize Redis storage', [
                'error' => $exception->getMessage(),
            ]);

            // Logged and also recorded, so a host application's status report
            // can say the block list is unreachable rather than leaving it to
            // a log scraper. The rule still runs; it just has nothing to
            // consult (#273).
            DegradedBackends::record('block list', self::class, $exception->getMessage());
        }
    }

    /**
     * {@inheritdoc}
     */
    public function set(string $key, array $value, int $expire = 0): bool
    {
        if (!$this->redis instanceof Redis) {
            return false;
        }

        try {
            $encoded = json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        } catch (\JsonException $jsonException) {
            $this->getLogger()->error('Failed to encode value for Redis storage', [
                'key' => $key,
                'error' => $jsonException->getMessage(),
            ]);

            return false;
        }

        try {
            // `$expire` is a TTL in seconds, matching InMemoryStorage. Zero
            // means no expiry at all -- a permanent ban -- so no TTL is set.
            $stored = $expire > 0
                ? $this->redis->setex($this->blockKey($key), $expire, $encoded)
                : $this->redis->set($this->blockKey($key), $encoded);

            $this->recordOffense($key);

            return (bool) $stored;
        } catch (\Exception $exception) {
            $this->getLogger()->error('Failed to write to Redis storage', [
                'key' => $key,
                'error' => $exception->getMessage(),
            ]);

            return false;
        }
    }

    /**
     * {@inheritdoc}
     */
    public function get(string $key, mixed $default = null): mixed
    {
        if (!$this->redis instanceof Redis) {
            return $default;
        }

        try {
            $raw = $this->redis->get($this->blockKey($key));
        } catch (\Exception $exception) {
            $this->getLogger()->error('Failed to read from Redis storage', [
                'key' => $key,
                'error' => $exception->getMessage(),
            ]);

            return $default;
        }

        if (!is_string($raw)) {
            return $default;
        }

        try {
            $decoded = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $jsonException) {
            // A value that cannot be decoded is not the same fact as no value.
            // Reported rather than silently answered with the default, which
            // for a block list would read as "this client is not blocked".
            $this->getLogger()->error('Redis storage value could not be decoded', [
                'key' => $key,
                'error' => $jsonException->getMessage(),
            ]);

            return $default;
        }

        return $decoded;
    }

    /**
     * {@inheritdoc}
     */
    public function delete(string $key): bool
    {
        if (!$this->redis instanceof Redis) {
            return false;
        }

        try {
            return $this->redis->del($this->blockKey($key)) > 0;
        } catch (\Exception $exception) {
            $this->getLogger()->error('Failed to delete from Redis storage', [
                'key' => $key,
                'error' => $exception->getMessage(),
            ]);

            return false;
        }
    }

    /**
     * {@inheritdoc}
     */
    public function exists(string $key): bool
    {
        if (!$this->redis instanceof Redis) {
            return false;
        }

        try {
            return (bool) $this->redis->exists($this->blockKey($key));
        } catch (\Exception $exception) {
            $this->getLogger()->error('Failed to check Redis storage', [
                'key' => $key,
                'error' => $exception->getMessage(),
            ]);

            return false;
        }
    }

    /**
     * {@inheritdoc}
     *
     * Nothing to do: every block is stored with a Redis TTL, so the server has
     * already removed what has lapsed. This is the one backend where the sweep
     * that cost 185 ms on a file store (#250) is free.
     */
    public function expire(): bool
    {
        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function addToExpire(string $key, int $amount): bool
    {
        if (!$this->redis instanceof Redis) {
            return false;
        }

        try {
            $remaining = $this->redis->ttl($this->blockKey($key));

            // -2 is "no such key" and -1 is "no expiry". Neither can be
            // extended: there is nothing to extend, or it is already permanent.
            if (!is_int($remaining) || $remaining < 0) {
                return false;
            }

            return (bool) $this->redis->expire($this->blockKey($key), $remaining + $amount);
        } catch (\Exception $exception) {
            $this->getLogger()->error('Failed to extend expiry in Redis storage', [
                'key' => $key,
                'error' => $exception->getMessage(),
            ]);

            return false;
        }
    }

    /**
     * {@inheritdoc}
     */
    public function reset(): bool
    {
        if (!$this->redis instanceof Redis) {
            return false;
        }

        try {
            $cleared = $this->deleteByScan($this->redisPrefix . '*');

            $this->getLogger()->info('Redis storage reset', ['keys_deleted' => $cleared]);

            return true;
        } catch (\Exception $exception) {
            $this->getLogger()->error('Failed to reset Redis storage', [
                'error' => $exception->getMessage(),
            ]);

            return false;
        }
    }

    /**
     * {@inheritdoc}
     */
    public function recordOffense(string $key): bool
    {
        if (!$this->redis instanceof Redis) {
            return false;
        }

        try {
            $now = time();

            // A unique member per offense, so two in the same second both
            // count. A sorted set deduplicates by member, not by score.
            $this->redis->zAdd(
                $this->offenseKey($key),
                $now,
                $now . ':' . bin2hex(random_bytes(4))
            );

            return true;
        } catch (\Exception $exception) {
            $this->getLogger()->error('Failed to record offense in Redis storage', [
                'key' => $key,
                'error' => $exception->getMessage(),
            ]);

            return false;
        }
    }

    /**
     * {@inheritdoc}
     */
    public function countOffenses(string $key, int $start = 0, int $end = PHP_INT_MAX): int
    {
        if (!$this->redis instanceof Redis) {
            return 0;
        }

        try {
            return (int) $this->redis->zCount($this->offenseKey($key), (string) $start, (string) $end);
        } catch (\Exception $exception) {
            // Logged rather than answered with a silent zero. A count that
            // could not be taken is not the same fact as a count of none --
            // the mistake #181 fixed in DatabaseStorage.
            $this->getLogger()->error('Failed to count offenses in Redis storage', [
                'key' => $key,
                'error' => $exception->getMessage(),
            ]);

            return 0;
        }
    }

    /**
     * {@inheritdoc}
     */
    public function listOffenses(string $key, int $start = 0, int $end = PHP_INT_MAX, int $limit = 50): array
    {
        if (!$this->redis instanceof Redis) {
            return [];
        }

        try {
            $scores = $this->redis->zRangeByScore(
                $this->offenseKey($key),
                (string) $start,
                (string) $end,
                ['withscores' => true]
            );
        } catch (\Exception $exception) {
            $this->getLogger()->error('Failed to list offenses in Redis storage', [
                'key' => $key,
                'error' => $exception->getMessage(),
            ]);

            return [];
        }

        if (!is_array($scores)) {
            return [];
        }

        $moments = array_map(intval(...), array_values($scores));
        rsort($moments);

        return $limit > 0 ? array_slice($moments, 0, $limit) : $moments;
    }

    /**
     * {@inheritdoc}
     */
    public function find(string $pattern): array
    {
        if (!$this->redis instanceof Redis) {
            return [];
        }

        if (!$this->isValidPattern($pattern)) {
            $this->getLogger()->warning('Storage find skipped - not a valid address or CIDR range', [
                'pattern' => $pattern,
            ]);

            return [];
        }

        $matches = [];
        $blockPrefix = $this->redisPrefix . 'block:';

        try {
            foreach ($this->scan($blockPrefix . '*') as $redisKey) {
                $address = substr($redisKey, strlen($blockPrefix));

                if (!$this->addressMatches($address, $pattern)) {
                    continue;
                }

                // No need to skip lapsed blocks the way the other backends do:
                // Redis has already removed them, so anything SCAN returns is
                // live. A key can still vanish between the scan and the read,
                // which is what the null check below is for.
                $value = $this->get($address);

                if ($value === null) {
                    continue;
                }

                $remaining = $this->redis->ttl($redisKey);
                $expire = is_int($remaining) && $remaining > 0 ? time() + $remaining : 0;

                $matches[$address] = [
                    'value' => $value,
                    'expire' => $expire,
                    'expires_at' => $expire > 0 ? date('c', $expire) : null,
                    'offenses' => $this->countOffenses($address),
                ];
            }
        } catch (\Exception $exception) {
            $this->getLogger()->error('Failed to search Redis storage', [
                'pattern' => $pattern,
                'error' => $exception->getMessage(),
            ]);

            return [];
        }

        $this->getLogger()->debug('Storage find completed', [
            'pattern' => $pattern,
            'matches' => count($matches),
        ]);

        return $matches;
    }

    /**
     * {@inheritdoc}
     */
    public function deleteMatching(array $patterns): int
    {
        if (!$this->redis instanceof Redis) {
            return 0;
        }

        $patterns = $this->validPatterns($patterns);

        if ($patterns === []) {
            return 0;
        }

        $deleted = 0;
        $blockPrefix = $this->redisPrefix . 'block:';

        try {
            foreach ($this->scan($blockPrefix . '*') as $redisKey) {
                $address = substr($redisKey, strlen($blockPrefix));

                foreach ($patterns as $pattern) {
                    if (!$this->addressMatches($address, $pattern)) {
                        continue;
                    }

                    // Offenses go with the block. Leaving them behind would
                    // mean an address an operator just un-blocked is escalated
                    // straight back to a longer ban by `blocking_escalation` on
                    // its next offence -- the block would look lifted and would
                    // not be. This is the opposite of what expiry does, where
                    // the history is the point.
                    $this->redis->del($redisKey, $this->offenseKey($address));
                    $deleted++;
                    break;
                }
            }
        } catch (\Exception $exception) {
            $this->getLogger()->error('Failed to delete matching records from Redis storage', [
                'patterns' => $patterns,
                'error' => $exception->getMessage(),
            ]);

            return $deleted;
        }

        $this->getLogger()->info('Storage records deleted by pattern', [
            'patterns' => $patterns,
            'deleted' => $deleted,
        ]);

        return $deleted;
    }

    /**
     * Walk the keyspace without blocking it.
     *
     * @param string $match
     *   Glob-style pattern.
     *
     * @return \Generator<int, string>
     *   Matching keys.
     */
    protected function scan(string $match): \Generator
    {
        // @codeCoverageIgnoreStart
        // Every caller has already returned on a null connection, so nothing
        // can reach this. Kept because the property is nullable and static
        // analysis is right to insist -- a future caller may not check first.
        if (!$this->redis instanceof Redis) {
            return;
        }

        // @codeCoverageIgnoreEnd

        $iterator = null;

        // ext-redis signals "done" by setting the iterator to 0. The loop has
        // to run at least once, which is why the sentinel starts as null.
        while ($iterator !== 0) {
            $keys = $this->redis->scan($iterator, $match, self::SCAN_COUNT);

            if ($keys === false) {
                continue;
            }

            foreach ($keys as $key) {
                yield (string) $key;
            }
        }
    }

    /**
     * Delete everything matching a pattern.
     *
     * @param string $match
     *   Glob-style pattern.
     *
     * @return int
     *   How many keys were removed.
     */
    protected function deleteByScan(string $match): int
    {
        $deleted = 0;

        foreach ($this->scan($match) as $key) {
            if ($this->redis instanceof Redis) {
                $deleted += (int) $this->redis->del($key);
            }
        }

        return $deleted;
    }

    /**
     * The Redis key holding a client's block record.
     *
     * @param string $key
     *   Client key, normally an address.
     *
     * @return string
     *   Namespaced Redis key.
     */
    protected function blockKey(string $key): string
    {
        return $this->redisPrefix . 'block:' . $key;
    }

    /**
     * The Redis key holding a client's offense history.
     *
     * @param string $key
     *   Client key, normally an address.
     *
     * @return string
     *   Namespaced Redis key.
     */
    protected function offenseKey(string $key): string
    {
        return $this->redisPrefix . 'offense:' . $key;
    }
}
