<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Utility;

use Redis;

/**
 * Hands out one Redis connection per distinct set of options, per process.
 *
 * `RedisStorage` and `RedisRateLimitStorage` are separate backends and each built its own
 * connection, so a deployment using Redis for both the block list and rate limiting opened
 * two connections to the same server on every request -- measured at 0.3643 ms against
 * 0.1720 ms for one, all of it duplication (#263).
 *
 * That deployment is the one Redis storage was added for, so the pairing is the normal case
 * rather than an exotic one.
 *
 * Keyed on the resolved options, not on the calling class: two backends pointed at
 * different servers, or different databases on one server, still get their own connection.
 * Only genuinely identical targets are shared.
 */
class RedisConnections
{
    /**
     * Connections already opened by this process, keyed by target.
     *
     * @var array<string, Redis>
     */
    private static array $connections = [];

    /**
     * A connection for these options, opened once.
     *
     * @param array<string, mixed> $options
     *   Options as `ext-redis` accepts them.
     *
     * @return Redis
     *   A connection, possibly shared with another backend.
     *
     * @throws \RedisException
     *   When the connection cannot be established. Callers already handle this: a Redis
     *   that cannot be reached is logged and the backend degrades.
     */
    public static function get(array $options): Redis
    {
        $key = self::key($options);

        if (isset(self::$connections[$key])) {
            return self::$connections[$key];
        }

        return self::$connections[$key] = new Redis($options);
    }

    /**
     * Forget every connection this process holds.
     *
     * For tests. Nothing in the request path needs it -- a process ends and its connections
     * go with it -- but a suite that shares them between cases is a suite where one test's
     * server can answer for another's.
     */
    public static function reset(): void
    {
        self::$connections = [];
    }

    /**
     * Identify a connection target.
     *
     * `serialize()` over sorted options rather than a hand-picked subset: `ext-redis`
     * accepts more keys than are worth enumerating, and picking a few would quietly share a
     * connection between targets that differ in one nobody thought of.
     *
     * @param array<string, mixed> $options
     *   Connection options.
     *
     * @return string
     *   Target key.
     */
    private static function key(array $options): string
    {
        ksort($options);

        // Objects can appear here -- a stream context, say -- and are not part of what
        // identifies a server. Serialising one would also be a way to get object state into
        // a cache key, which is not what this is for.
        $scalars = array_filter($options, static fn ($value): bool => !is_object($value));

        return hash('xxh128', serialize($scalars));
    }
}
